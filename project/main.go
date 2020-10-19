package main

import (
	// "crypto/tls"
	// "crypto/x509"
	// "flag"
	// "fmt"
	// "io/ioutil"
	// "log"
	// "net/http"

	"acmeProject/acmeclient"
	"acmeProject/dnsserver"
	"acmeProject/httpserver"
	"flag"
	"log"
	"time"
)

const (
	pebbleCertificate = "./pebble.minica.pem"
)

func main() {

	challengeType := flag.String("challengeType", "none", "ACME Challenge Type: Required, either dns01 or http01 supported")
	directory := flag.String("dir", "none", "ACME Server Directory: Required, URL Directory of the ACME Server")
	record := flag.String("record", "none", "Default Type A Record: Required, defualt IP response for all type A queried to the DNS server")
	domain := flag.String("domain", "none", "Domain(s) for which to issue a certificate: Required, Multiple supported")
	revoke := flag.Bool("revoke", false, "Revoke flag: Optional, revokes specified certificate right after it is issued when true")
	flag.Parse()

	ctx := acmeclient.InitializeContext(*challengeType, *directory, *record, *domain, *revoke)

	//https://localhost:14000/dir for the pebble server
	acmeClient, err := acmeclient.NewClient(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	dnsserver.StartDNSServer(ctx)
	httpserver.StartHttpChallengeServer(ctx)
	acmeClient.ExecuteObtainCertificateFlow()
	// Context.DnsChallengeChannel <- acmeclient.DNSChallenge{Domain: "example.org.", TXT: "This is some text you are supposed to get"}
	// err = acmeClient.DiscoverDirectories()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.RequestNonce()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.RequestNewAccount()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.PlaceNewOrder()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.GetAuthorizations()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.CompleteDNSChallenges()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// err = acmeClient.CompleteHTTPChallenges()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	time.Sleep(5 * time.Second)
	log.Println("[ACME Client] Waiting Period Passed")
	err = acmeClient.PollOrder()
	if err != nil {
		log.Fatalln(err)
	}

	// err = acmeClient.FinalizeOrder()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// time.Sleep(5 * time.Second)
	// err = acmeClient.PollOrder()
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// err = acmeClient.DownloadCertificate()
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// err = acmeClient.StoreKey()
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	acmeClient.Debug()

	for true {
	}
}
