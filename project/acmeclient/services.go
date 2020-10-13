package acmeclient

import (
	"errors"
	"fmt"
)

func (cli *Client) DiscoverDirectories() error {
	cli.httpHandler.context.URL = cli.directory.URL
	cli.httpHandler.context.respBody = &cli.directory

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

	identifiers := OrderIdentifier{
		Type:  "dns",
		Value: "dummysite.org",
	}

	reqBody, err := cli.GetJWSFromPayload(
		&NewOrderRequest{
			Identifiers: []OrderIdentifier{identifiers},
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
		fmt.Println(err)
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	cli.orders = append(cli.orders, newOrder)

	return nil
}

func (cli *Client) RequestAuthorization() error {

	if len(cli.orders) < 1 {
		return errors.New("acme-client: could not find any orders")
	}

	cli.httpHandler.context.URL = cli.orders[0].Authorizations[0]

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
		fmt.Println(err)
		return err
	}

	nonce, ok := cli.httpHandler.context.respHeaders[ReplayNonce]
	if !ok {
		return errors.New("acme-client: required resource [Replay-Nonce] not found in server response")
	}

	cli.ReplayNonce = nonce[0]
	cli.CurrentlyProcessingAuthorization = newAuthorization

	return nil
}

func (cli *Client) Debug() {
	fmt.Println(cli.directory.NewOrder)
	fmt.Println(cli.ReplayNonce)
	fmt.Println(cli.account.URL)
	fmt.Println(cli.orders[0])
	fmt.Println(cli.CurrentlyProcessingAuthorization)
}
