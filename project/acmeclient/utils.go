package acmeclient

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const (
	ES256 = "ES256"
)

type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWSProtectedHeader struct {
	Alg         string `json:"alg"`
	ReplayNonce string `json:"nonce"`
	URL         string `json:"url"`
	JWK         *JWK   `json:"jwk,omitempty"`
	KID         string `json:"kid,omitempty"`
}

func getJWKFromKey(publicKey ecdsa.PublicKey) (*JWK, error) {
	keyParams := publicKey.Curve.Params()
	size := (keyParams.BitSize + 7) / 8
	x := publicKey.X.Bytes()
	pad := make([]byte, size-len(x))
	x = append(pad, x...)
	y := publicKey.Y.Bytes()
	pad = make([]byte, size-len(y))
	y = append(pad, y...)

	jwk := &JWK{
		Crv: keyParams.Name,
		Kty: "EC",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}

	return jwk, nil
}

func getJWSProtectedHeader(publicKey ecdsa.PublicKey, alg, nonce, keyId, url string) (string, error) {
	jwsProtected := &JWSProtectedHeader{
		Alg:         alg,
		ReplayNonce: nonce,
		URL:         url,
	}

	// fmt.Println("KeyID: ", keyId)
	if keyId == "" {
		jwk, err := getJWKFromKey(publicKey)
		if err != nil {
			return "", err
		}
		jwsProtected.JWK = jwk
	} else {
		jwsProtected.KID = keyId
	}

	jwsProtectedBytes, err := json.Marshal(jwsProtected)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(jwsProtectedBytes), nil
}

func getJWSignature(privateKey *ecdsa.PrivateKey, hashedBytes []byte) (string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedBytes)
	if err != nil {
		return "", err
	}

	size := (privateKey.Params().BitSize + 7) / 8
	JWSignature := make([]byte, size*2)
	copy(JWSignature[size-len(r.Bytes()):], r.Bytes())
	copy(JWSignature[2*size-len(s.Bytes()):], s.Bytes())

	return base64.RawURLEncoding.EncodeToString(JWSignature), nil

}

func (cli *Client) GetJWSFromPayload(payload interface{}) ([]byte, error) {
	if cli.account.privateKey == nil {
		return nil, errors.New("[jws error]: account not initiated yet")
	}
	protected, err := getJWSProtectedHeader(cli.account.privateKey.PublicKey, ES256, cli.ReplayNonce, cli.account.URL, cli.httpHandler.context.URL)
	if err != nil {
		return nil, err
	}

	var payloadEncoded string
	if payload != nil {
		payloadSerialized, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadEncoded = base64.RawURLEncoding.EncodeToString(payloadSerialized)
	} else {
		payloadEncoded = ""
	}
	hash := sha256.New()
	hash.Write([]byte(protected + "." + payloadEncoded))
	JWSignature, err := getJWSignature(cli.account.privateKey, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	JWSObject := &JWS{
		Protected: protected,
		Payload:   payloadEncoded,
		Signature: JWSignature,
	}

	return json.Marshal(JWSObject)

}

func (cli *Client) getKeyAuthorization(token string) (string, error) {
	jwk, err := getJWKFromKey(cli.account.privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	_, err = hash.Write(jwkBytes)
	if err != nil {
		return "", err
	}

	jwkB64Hash := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

	return token + "." + jwkB64Hash, nil
}

func (auth *Authorization) getDNSChallenge() (*Challenge, error) {
	for _, challenge := range auth.Challenges {
		if challenge.Type == "dns-01" {
			return &challenge, nil
		}
	}
	return nil, errors.New("a DNS challenge could not be found for one of your authorizations")
}

func (auth *Authorization) getHTTPChallenge() (*Challenge, error) {
	for _, challenge := range auth.Challenges {
		if challenge.Type == "http-01" {
			return &challenge, nil
		}
	}
	return nil, errors.New("an HTTP challenge could not be found for one of your authorizations")
}

func (cli *Client) getCSRBytes() ([]byte, error) {

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err = serverPrivateKey.Validate(); err != nil {
		return nil, err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"CH"},
			Organization:       []string{"ETHZ"},
			OrganizationalUnit: []string{"NetSec"},
			Locality:           []string{"Zurich"},
			Province:           []string{"Zurich"},
			CommonName:         "kapostoiNetSec",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           cli.Ctx.Domains,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, serverPrivateKey)
	if err != nil {
		return nil, err
	}

	cli.account.serverPrivateKey = serverPrivateKey

	return derBytes, nil
}

type Step struct {
	execute func(*Client) error
	next    *Step
}

func (s *Step) Insert(f func(*Client) error) {
	s.next = &Step{
		execute: f,
		next:    s.next,
	}
}

func composeFlow(f ...func(*Client) error) *Step {
	head := &Step{
		execute: nil,
		next:    nil,
	}
	init := head
	for _, step := range f {
		init.Insert(step)
		init = init.next
	}
	return head
}
