package acmeclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

type Client struct {
	Ctx                   *Context
	httpHandler           *HttpHandler
	account               *Account
	directory             *Directory
	orders                []*Order
	ReplayNonce           string
	PendingAuthorizations map[string]*Authorization
}

func NewClient(ctx *Context) (*Client, error) {
	cli := &Client{
		Ctx:                   ctx,
		PendingAuthorizations: make(map[string]*Authorization),
	}
	var err error

	cli.account, err = NewAccount()
	if err != nil {
		return nil, err
	}

	cli.httpHandler, err = NewHttpHandler()
	if err != nil {
		return nil, err
	}

	cli.directory = &Directory{URL: ctx.AcmeServerDirectory}

	return cli, nil
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

type Account struct {
	URL              string            `json:"-"`
	Status           string            `json:"status"`
	Contact          []string          `json:"contact"`
	Orders           string            `json:"orders"`
	privateKey       *ecdsa.PrivateKey `json:"-"`
	serverPrivateKey *rsa.PrivateKey   `json:"-"`
	lastIssuedCert   string            `json:"-"`
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

type NewAccountRequest struct {
	Contact                []string `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool     `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding *Account `json:"externalAccountBinding,omitempty"`
}

type Order struct {
	URL            string            `json:"-"`
	Status         string            `json:"status"`
	Expires        string            `json:"expires"`
	Identifiers    []OrderIdentifier `json:"identifiers,required"`
	NotBefore      string            `json:"notBefore"`
	NotAfter       string            `json:"notAfter"`
	Authorizations []string          `json:"authorizations"`
	Finalize       string            `json:"finalize"`
	Certificate    string            `json:"certificate"`
	Err            *Error            `json:"error,omitempty"`
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

type Authorization struct {
	Identifier *OrderIdentifier `json:"identifier,required"`
	Status     string           `json:"status"`
	Expires    string           `json:"expires,omitempty"`
	Challenges []Challenge      `json:"challenges,required"`
	Wildcard   bool             `json:"wildcard,omitempty"`
}

type Challenge struct {
	Type      string `json:"type,required"`
	URL       string `json:"url,required"`
	Token     string `json:"token,required"`
	Status    string `json:"status,required"`
	Validated string `json:"validated,omitempty"`
	Err       *Error `json:"error,omitempty"`
}

type Error struct {
	Type        string  `json:"type,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Subproblems []Error `json:"subproblems,omitempty"`
}

func (e *Error) Error() string {
	return e.Type + " " + e.Detail
}

func (e *Error) isBadNonce() bool {
	return e.Type == BadNonce
}
