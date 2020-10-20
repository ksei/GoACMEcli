package acmeclient

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func (cli *Client) DiscoverDirectories() error {
	cli.httpHandler.context.URL = cli.directory.URL
	cli.httpHandler.context.respBody = &cli.directory
	log.Println("[ACME Client] Discovering Directories")
	defer cli.httpHandler.clearContext()

	return cli.httpHandler.Get()
}

func (cli *Client) RequestNonce() error {
	if cli.directory.NewNonce == "" {
		return errors.New("acme-client: directory for required resource [Replay-Nonce] not found")
	}

	cli.httpHandler.context.URL = cli.directory.NewNonce

	if err := cli.httpHandler.Head(); err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}
	cli.ReplayNonce = nonce[0]

	cli.httpHandler.clearContext()

	return nil
}

//RequestNewAccount issues a new account request to the ACME server
func (cli *Client) RequestNewAccount() error {
	if cli.directory.NewAccount == "" {
		return errors.New("acme-client: directory for required resource [NewAccount] not found")
	}

	cli.httpHandler.context.URL = cli.directory.NewAccount
	reqBody, err := cli.GetJWSFromPayload(
		&NewAccountRequest{
			TermsOfServiceAgreed: true,
			Contact:              []string{"mailto:ksei@netsec.com"},
		})
	if err != nil {
		return err
	}

	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = &cli.account

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}
	cli.ReplayNonce = nonce[0]

	accountURL, ok := cli.httpHandler.context.respHeaders[Location]
	if !ok {
		return errors.New("acme-client: required resource [Location] not found in server response")
	}
	cli.account.URL = accountURL[0]

	return nil
}

func (cli *Client) PlaceNewOrder() error {
	if cli.directory.NewOrder == "" {
		return errors.New("acme-client: directory for required resource [NewOrder] not found")
	}

	cli.httpHandler.context.URL = cli.directory.NewOrder

	var identifiers []OrderIdentifier

	for _, domain := range cli.Ctx.Domains {
		identifiers = append(identifiers, OrderIdentifier{
			Type:  "dns",
			Value: domain,
		})
	}

	reqBody, err := cli.GetJWSFromPayload(
		&NewOrderRequest{
			Identifiers: identifiers,
		})

	if err != nil {
		return err
	}

	newOrder := &Order{}
	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = newOrder

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}
	cli.ReplayNonce = nonce[0]
	orderUrl, ok := cli.httpHandler.context.respHeaders[Location]
	if !ok {
		return errors.New("acme-client: required resource [Location] not found in server response")
	}
	newOrder.URL = orderUrl[0]
	cli.orders = append(cli.orders, newOrder)

	return nil
}

func (cli *Client) RequestAuthorization(authorizationIndex int) error {

	if len(cli.orders) < 1 {
		return errors.New("acme-client: could not find any orders")
	}

	cli.httpHandler.context.URL = cli.orders[0].Authorizations[authorizationIndex]

	reqBody, err := cli.GetJWSFromPayload(nil)
	if err != nil {
		return err
	}

	newAuthorization := &Authorization{}
	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = newAuthorization

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	cli.PendingAuthorizations[newAuthorization.Identifier.Value] = newAuthorization

	return nil
}

func (cli *Client) GetAuthorizations() error {
	var err error
	for i := range cli.orders[0].Authorizations {
		err = cli.RequestAuthorization(i)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cli *Client) CompleteDNSChallenges() error {
	for _, authorization := range cli.PendingAuthorizations {
		dnsChallenge, err := authorization.getDNSChallenge()
		if err != nil {
			return err
		}

		keyAuthorization, err := cli.getKeyAuthorization(dnsChallenge.Token)
		if err != nil {
			return err
		}
		keyAuthorizationDigest := sha256.Sum256([]byte(keyAuthorization))
		cli.Ctx.DnsChallengeChannel <- DNSChallenge{Domain: "_acme-challenge." + authorization.Identifier.Value + ".", TXT: base64.RawURLEncoding.EncodeToString(keyAuthorizationDigest[:])}

		err = cli.ValidateChallenge(authorization.Identifier.Value)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cli *Client) CompleteHTTPChallenges() error {
	for _, authorization := range cli.PendingAuthorizations {
		httpChallenge, err := authorization.getHTTPChallenge()
		if err != nil {
			return err
		}

		keyAuthorization, err := cli.getKeyAuthorization(httpChallenge.Token)
		if err != nil {
			return err
		}

		cli.Ctx.HttpChallengeChannel <- HTTPChallenge{URLParam: httpChallenge.Token, Response: keyAuthorization}

		err = cli.ValidateChallenge(authorization.Identifier.Value)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cli *Client) CompleteChallenges() error {
	if cli.Ctx.ChallengeType == "dns01" {
		return cli.CompleteDNSChallenges()
	}
	return cli.CompleteHTTPChallenges()
}

func (cli *Client) ValidateChallenge(challengeDomain string) error {
	var URL string

	if cli.Ctx.ChallengeType == "dns01" {
		dnsChallenge, err := cli.PendingAuthorizations[challengeDomain].getDNSChallenge()
		if err != nil {
			return err
		}

		URL = dnsChallenge.URL
	} else {
		httpChallenge, err := cli.PendingAuthorizations[challengeDomain].getHTTPChallenge()
		if err != nil {
			return err
		}

		URL = httpChallenge.URL
	}

	cli.httpHandler.context.URL = URL
	var empty struct{}
	reqBody, err := cli.GetJWSFromPayload(empty)
	if err != nil {
		return err
	}

	newChallenge := &Challenge{}
	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = newChallenge

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	return nil
}

func (cli *Client) PollOrder() error {

	cli.httpHandler.context.URL = cli.orders[0].URL

	reqBody, err := cli.GetJWSFromPayload(nil)
	if err != nil {
		return err
	}

	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = cli.orders[0]

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	return nil
}

func (cli *Client) WaitUntilOrderReady() error {
	var err error
	for cli.orders[0].Status != "ready" {
		time.Sleep(3 * time.Second)
		err = cli.PollOrder()
		if err != nil {
			return err
		}
	}
	return nil
}

func (cli *Client) WaitUntilOrderValid() error {
	var err error
	for cli.orders[0].Status != "valid" {
		time.Sleep(3 * time.Second)
		err = cli.PollOrder()
		if err != nil {
			return err
		}
	}
	return nil
}

func (cli *Client) FinalizeOrder() error {

	cli.httpHandler.context.URL = cli.orders[0].Finalize

	var payload struct {
		CSR string `json:"csr"`
	}

	csrBytes, err := cli.getCSRBytes()
	if err != nil {
		return err
	}
	payload.CSR = base64.RawURLEncoding.EncodeToString(csrBytes)

	reqBody, err := cli.GetJWSFromPayload(&payload)
	if err != nil {
		return err
	}

	cli.httpHandler.context.reqBody = reqBody
	cli.httpHandler.context.respBody = cli.orders[0]

	defer cli.httpHandler.clearContext()

	err = cli.httpHandler.Post()
	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]

	return nil

}

func (cli *Client) DownloadCertificate() error {

	cli.httpHandler.context.URL = cli.orders[0].Certificate

	reqBody, err := cli.GetJWSFromPayload(nil)
	if err != nil {
		return err
	}

	cli.httpHandler.context.reqBody = reqBody

	defer cli.httpHandler.clearContext()

	certificate, err := cli.httpHandler.PostRAW()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return errors.New("[ACME Client] could not decode certificate from provided pem")
	}

	cli.account.lastIssuedCert = base64.RawURLEncoding.EncodeToString(block.Bytes)
	// path := "certificate.pem"
	err = ioutil.WriteFile(certificatePath, []byte(certificate), 0644)
	if err != nil {
		return err
	}
	log.Println("[ACME Client] Stored certificate at", certificatePath)

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	return nil
}

func (cli *Client) StoreKey() error {
	// path := "private_key.pem"
	keyPEMBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cli.account.serverPrivateKey),
	}

	certOut, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, keyPEMBlock); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}

	log.Println("[ACME Client] Stored private key at", certificatePath)
	return nil
}

func (cli *Client) RevokeLastIssued() error {
	cli.httpHandler.context.URL = cli.directory.RevokeCert

	var payload struct {
		Certificate string `json:"certificate"`
	}

	payload.Certificate = cli.account.lastIssuedCert

	reqBody, err := cli.GetJWSFromPayload(&payload)
	if err != nil {
		return err
	}

	cli.httpHandler.context.reqBody = reqBody

	defer cli.httpHandler.clearContext()

	_, err = cli.httpHandler.PostRAW()

	if err != nil {
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]

	log.Println("[ACME Client] Certificate successfully revoked")

	return nil

}

func (cli *Client) ExecuteObtainCertificateFlow() {
	var err error
	retriesLeft := 5
	step := composeFlow(func(cli *Client) error { return cli.DiscoverDirectories() }, func(cli *Client) error { return cli.RequestNonce() }, func(cli *Client) error { return cli.RequestNewAccount() }, func(cli *Client) error { return cli.PlaceNewOrder() }, func(cli *Client) error { return cli.GetAuthorizations() }, func(cli *Client) error { return cli.CompleteChallenges() }, func(cli *Client) error { return cli.WaitUntilOrderReady() }, func(cli *Client) error { return cli.FinalizeOrder() }, func(cli *Client) error { return cli.WaitUntilOrderValid() }, func(cli *Client) error { return cli.DownloadCertificate() }, func(cli *Client) error { return cli.StoreKey() })

	for step.next != nil {
		err = step.next.execute(cli)
		if err != nil {
			acmeServerError, ok := err.(*Error)
			if ok && acmeServerError.isBadNonce() && retriesLeft > 0 {
				log.Println("[ACME Client]", acmeServerError)
				step.Insert(func(cli *Client) error { return cli.RequestNonce() })
				retriesLeft--
				continue
			}
			log.Fatalln(err)
		}
		step = step.next
	}

	if cli.Ctx.Revoke {
		cli.RevokeLastIssued()
	}
}

func (cli *Client) Debug() {
	log.Println(cli.PendingAuthorizations["example.com"].getHTTPChallenge())
	log.Println(cli.orders[0].Certificate)
}
