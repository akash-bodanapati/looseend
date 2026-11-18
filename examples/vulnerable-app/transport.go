package main

import (
	"crypto/tls"
	"net/http"
)

func newClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // expect: SEC003
	}
	return &http.Client{Transport: tr}
}

func main() {
	_ = newClient()
}
