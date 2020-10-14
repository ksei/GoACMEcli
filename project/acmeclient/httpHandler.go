package acmeclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	pebbleCertificate string = "./pebble.minica.pem"

	//AcceptLanguage stores the Accept-Language header name
	AcceptLanguage string = "Accept-Language"
	//ContentType holds the Content-Type header name
	ContentType string = "Content-Type"
	//ContentLength holds the Content-Type header name
	ContentLength string = "Content-Length"
	//UserAgent stores the User-Agent header name
	UserAgent string = "User-Agent"
	//UserAgentVal specifies the current value
	UserAgentVal = "kapostoli-acme-client/1.0 Go-http-client/1.1"
	//ReplayNonce stores the Replay-Nonce responce header name
	ReplayNonce = "Replay-Nonce"
	//Location stores the location header string
	Location = "Location"
)

type httpContext struct {
	URL         string
	headers     map[string]string
	reqBody     interface{}
	respHeaders map[string][]string
	respBody    interface{}
}

type HttpHandler struct {
	context    *httpContext
	httpClient *http.Client
}

func NewHttpHandler() (*HttpHandler, error) {

	httpHandler := &HttpHandler{}

	httpTransport, err := getTLSConfig()
	if err != nil {
		return nil, err
	}

	httpHandler.httpClient = &http.Client{Transport: httpTransport}
	httpHandler.setDefaultContext()

	return httpHandler, nil
}

func getTLSConfig() (*http.Transport, error) {
	insecure := flag.Bool("insecure-ssl", false, "Accept/Ignore all server SSL certificates")
	flag.Parse()

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := ioutil.ReadFile(pebbleCertificate)
	if err != nil {
		return nil, fmt.Errorf("Failed to append %q to RootCAs: %v", pebbleCertificate, err)
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, fmt.Errorf("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: *insecure,
		RootCAs:            rootCAs,
	}

	return &http.Transport{TLSClientConfig: config}, nil
}

func (httpHandler *HttpHandler) setDefaultContext() {
	httpHandler.context = &httpContext{
		headers: make(map[string]string),
	}

	httpHandler.context.headers[AcceptLanguage] = "en"
	httpHandler.context.headers[UserAgent] = UserAgentVal
}

func (httpHandler *HttpHandler) setHeaders(req *http.Request) {
	for header, value := range httpHandler.context.headers {
		req.Header.Set(header, value)
	}
}

func (httpHandler *HttpHandler) setBody(req *http.Request) error {
	requestBody, ok := httpHandler.context.reqBody.([]byte)
	if !ok {
		return errors.New("[httpHandler error] : bad request body")
	}

	// fmt.Println(string(requestBody))
	req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	req.ContentLength = int64(len(requestBody))
	return nil

}

func (httpHandler *HttpHandler) clearContext() {
	httpHandler.setDefaultContext()
}

func (httpHandler *HttpHandler) Get() error {
	req, err := http.NewRequest(http.MethodGet, httpHandler.context.URL, nil)
	if err != nil {
		return err
	}

	httpHandler.setHeaders(req)

	resp, err := httpHandler.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(httpHandler.context.respBody)
}

func (httpHandler *HttpHandler) Head() error {

	req, err := http.NewRequest(http.MethodHead, httpHandler.context.URL, nil)
	if err != nil {
		return err
	}

	httpHandler.setHeaders(req)

	resp, err := httpHandler.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	httpHandler.context.respHeaders = resp.Header

	return nil
}

func (httpHandler *HttpHandler) Post() error {
	req, err := http.NewRequest(http.MethodPost, httpHandler.context.URL, nil)
	if err != nil {
		return err
	}

	httpHandler.context.headers[ContentType] = "application/jose+json"
	httpHandler.setHeaders(req)
	err = httpHandler.setBody(req)
	if err != nil {
		return err
	}
	// fmt.Println(req.Header)
	resp, err := httpHandler.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	httpHandler.context.respHeaders = resp.Header

	responseData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	responseString := string(responseData)
	// fmt.Println(responseString)s

	if resp.StatusCode >= 400 {
		err := &Error{}
		json.Unmarshal([]byte(responseString), err)
		return errors.New("Type: " + err.Type + "\nDetail: " + err.Detail)
	}

	json.Unmarshal([]byte(responseString), &httpHandler.context.respBody)
	return nil
	// return json.NewDecoder(resp.Body).Decode(httpHandler.context.respBody)
}
