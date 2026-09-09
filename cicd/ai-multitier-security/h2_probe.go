// Command h2_probe sends one JSON request over TLS with HTTP/2 required.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "", "HTTPS URL")
	caFile := flag.String("ca", "", "server CA certificate")
	certFile := flag.String("cert", "", "optional client certificate")
	keyFile := flag.String("key", "", "optional client private key")
	apiKey := flag.String("api-key", "", "optional X-Api-Key value")
	body := flag.String("body", `{"model":"security-probe","messages":[{"role":"user","content":"probe"}]}`, "JSON request body")
	flag.Parse()

	if *url == "" || *caFile == "" {
		fmt.Fprintln(os.Stderr, "-url and -ca are required")
		os.Exit(2)
	}

	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		panic("CA file contains no certificate")
	}

	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if *certFile != "" || *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			panic(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   tlsConfig,
		},
	}

	req, err := http.NewRequest(http.MethodPost, *url, bytes.NewBufferString(*body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if *apiKey != "" {
		req.Header.Set("X-Api-Key", *apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("STATUS=000 PROTO=none ERROR=%q\n", err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyText := strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", " ")
	fmt.Printf("STATUS=%d PROTO=%s BODY=%q\n", resp.StatusCode, resp.Proto, bodyText)
	if resp.ProtoMajor != 2 {
		os.Exit(3)
	}
}
