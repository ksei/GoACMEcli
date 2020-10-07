package acmeclient

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Kty string `json:"kty"`
	Crv string `json:"crv"`
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
		Kty: "EC",
		Crv: keyParams.Name,
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

	fmt.Println("KeyID: ", keyId)
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

	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadSerialized)

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
