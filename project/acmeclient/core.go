package acmeclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

type Client struct {
	httpHandler *HttpHandler
	account     *Account
	directory   *Directory
	orders      []*Order
	ReplayNonce string
}

func NewClient(directoryURL string) (*Client, error) {
	cli := &Client{}
	var err error

	cli.account, err = NewAccount()
	if err != nil {
		return nil, err
	}

	cli.httpHandler, err = NewHttpHandler()
	if err != nil {
		return nil, err
	}

	cli.directory = &Directory{URL: directoryURL}

	return cli, nil
}

func NewAccount() (*Account, error) {
	account := &Account{}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	account.privateKey = privateKey
	return account, nil
}

type Account struct {
	URL        string            `json:"-"`
	Status     string            `json:"status"`
	Contact    []string          `json:"contact"`
	Orders     string            `json:"orders"`
	privateKey *ecdsa.PrivateKey `json:"-"`
}

type NewAccountRequest struct {
	Contact                []string `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool     `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding *Account `json:"externalAccountBinding,omitempty"`
}

type Order struct {
	Status         string            `json:"status"`
	Expires        string            `json:"expires"`
	Identifiers    []OrderIdentifier `json:"identifiers,required"`
	NotBefore      string            `json:"notBefore"`
	NotAfter       string            `json:"notAfter"`
	Authorizations []string          `json:"authorizations"`
	Finalize       string            `json:"finalize"`
	Certificate    string            `json:"certificate"`
}

type NewOrderRequest struct {
	Identifiers []OrderIdentifier `json:"identifiers,required"`
	NotBefore   string            `json:"notBefore,omitempty"`
	NotAfter    string            `json:"notAfter,omitempty"`
}

type OrderIdentifier struct {
	Type  string `json:"type,required"`
	Value string `json:"value,required"`
}

type Directory struct {
	URL        string `json:"-"`
	KeyChange  string `json:"keyChange"`
	NewAuthz   string `json:"newAuthz"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	Meta       struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CaaIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}
