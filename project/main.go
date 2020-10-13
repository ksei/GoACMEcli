package main

import (
	// "crypto/tls"
	// "crypto/x509"
	// "flag"
	// "fmt"
	// "io/ioutil"
	// "log"
	// "net/http"

	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"./acmeclient"
)

const (
	pebbleCertificate = "./pebble.minica.pem"
)

func main() {

	// insecure := flag.Bool("insecure-ssl", false, "Accept/Ignore all server SSL certificates")
	// flag.Parse()

	// rootCAs, _ := x509.SystemCertPool()
	// if rootCAs == nil {
	// 	rootCAs = x509.NewCertPool()
	// }

	// certs, err := ioutil.ReadFile(pebbleCertificate)
	// if err != nil {
	// 	log.Fatalf("Failed to append %q to RootCAs: %v", pebbleCertificate, err)
	// }

	// // Append our cert to the system pool
	// if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
	// 	log.Println("No certs appended, using system certs only")
	// }

	// // Trust the augmented cert pool in our client
	// config := &tls.Config{
	// 	InsecureSkipVerify: *insecure,
	// 	RootCAs:            rootCAs,
	// }
	// tr := &http.Transport{TLSClientConfig: config}
	// client := &http.Client{Transport: tr}

	// req, err := http.NewRequest(http.MethodHead, "https://localhost:14000/nonce-plz", nil)
	// resp, err := client.Do(req)

	// // resp, err := http.Get("https://localhost:14000/dir")
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// defer resp.Body.Close()

	// for k, v := range resp.Header {
	// 	fmt.Print(k)
	// 	fmt.Print(" : ")
	// 	fmt.Println(v)
	// }

	acmeClient, err := acmeclient.NewClient("https://localhost:14000/dir")
	if err != nil {
		log.Fatalln(err)
	}

	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// privStr, pubStr := encode(privateKey, privateKey.Public().(*ecdsa.PublicKey))

	// fmt.Println(privStr)
	// fmt.Println(pubStr)

	// account := &acmeclient.Account{
	// 	Status:  "valid",
	// 	Contact: []string{"ksandros"},
	// 	Orders:  "none",
	// }
	acmeClient.DiscoverDirectories()
	acmeClient.RequestNonce()
	acmeClient.RequestNewAccount()
	acmeClient.PlaceNewOrder()
	acmeClient.RequestAuthorization()
	// jws, err := acmeClient.GetJWSFromPayload(*privateKey, account)
	// fmt.Println(string(jws))
	acmeClient.Debug()

}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}
