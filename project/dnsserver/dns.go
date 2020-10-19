package dnsserver

import (
	"log"
	"net"
	"strconv"
	"sync"

	"acmeProject/acmeclient"

	"github.com/miekg/dns"
)

const (
	port int = 10053
)

type DNSServer struct {
	txtChallenges   map[string]string
	challengeLocker sync.RWMutex
	server          *dns.Server
	ctx             *acmeclient.Context
}

func StartDNSServer(context *acmeclient.Context) {
	dnsSrv := &DNSServer{
		server:        &dns.Server{Addr: "127.0.0.1:" + strconv.Itoa(port), Net: "udp"},
		ctx:           context,
		txtChallenges: make(map[string]string),
	}
	dnsSrv.server.Handler = dnsSrv
	go dnsSrv.ListenForChallenges()
	go dnsSrv.startServing()
}

func (dnsSrv *DNSServer) ListenForChallenges() {
	for challenge := range dnsSrv.ctx.DnsChallengeChannel {
		dnsSrv.addChallenge(&challenge)
	}
}

//ADDChallenge to challenge map
func (dnsSrv *DNSServer) addChallenge(challenge *acmeclient.DNSChallenge) {
	dnsSrv.challengeLocker.Lock()
	defer dnsSrv.challengeLocker.Unlock()

	dnsSrv.txtChallenges[challenge.Domain] = challenge.TXT
}

//getTXT from stores challenge map and remove entry
func (dnsSrv *DNSServer) getTXT(domain string) (string, bool) {
	dnsSrv.challengeLocker.RLock()
	defer dnsSrv.challengeLocker.RUnlock()
	TXT, ok := dnsSrv.txtChallenges[domain]
	// if ok {
	// 	delete(dnsSrv.txtChallenges, domain)
	// }
	return TXT, ok
}

func (dnsSrv *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(dnsSrv.ctx.Record),
		})
	case dns.TypeTXT:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		TXT, ok := dnsSrv.getTXT(domain)
		if ok {
			log.Println("[DNS Server] Resolved TXT query for", domain)
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{TXT},
			})
		}
	}
	w.WriteMsg(&msg)
}

func (dnsSrv *DNSServer) startServing() {
	log.Println("[DNS Server] Starting DNS Server at port", port)
	if err := dnsSrv.server.ListenAndServe(); err != nil {
		log.Fatalf("[DNS Server] Failed to set udp listener %s\n", err.Error())
	}
}
