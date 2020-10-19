package acmeclient

import "strings"

type Context struct {
	ChallengeType        string
	AcmeServerDirectory  string
	Record               string
	Domains              []string
	Revoke               bool
	DnsChallengeChannel  chan DNSChallenge
	HttpChallengeChannel chan HTTPChallenge
}

type DNSChallenge struct {
	Domain string
	TXT    string
}

type HTTPChallenge struct {
	URLParam string
	Response string
}

func InitializeContext(challengeType, dir, record, domain string, revoke bool) *Context {

	ctx := &Context{
		ChallengeType:        challengeType,
		AcmeServerDirectory:  dir,
		Record:               record,
		Domains:              strings.Split(domain, ","),
		Revoke:               revoke,
		DnsChallengeChannel:  make(chan DNSChallenge, 50),
		HttpChallengeChannel: make(chan HTTPChallenge, 50),
	}

	return ctx
}
