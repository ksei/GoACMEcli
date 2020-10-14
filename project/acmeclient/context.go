package acmeclient

import "strings"

type Context struct {
	ChallengeType       string
	AcmeServerDirectory string
	Record              string
	Domains             []string
	Revoke              bool
	DnsChallengeChannel chan DNSChallenge
}

type DNSChallenge struct {
	Domain string
	TXT    string
}

func InitializeContext(challengeType, dir, record, domain string, revoke bool) *Context {

	ctx := &Context{
		ChallengeType:       challengeType[:len(challengeType)-2],
		AcmeServerDirectory: dir,
		Record:              record,
		Domains:             strings.Split(domain, ","),
		Revoke:              revoke,
		DnsChallengeChannel: make(chan DNSChallenge, 50),
	}

	return ctx
}
