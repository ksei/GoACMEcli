package acmeclient

import (
	"log"
)

func main() {

	cli, err := NewClient("https://0.0.0.0:14000/dir")
	if err != nil {
		log.Fatalln(err)
	}

	cli.DiscoverDirectories()
	cli.RequestNonce()
	cli.RequestNewAccount()
	cli.PlaceNewOrder()
	cli.RequestAuthorization()
	cli.Debug()
}
