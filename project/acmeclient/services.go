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

func (cli *Client) Debug() {
	fmt.Println(cli.directory.NewOrder)
	fmt.Println(cli.ReplayNonce)
	fmt.Println(cli.account.Status)
}
