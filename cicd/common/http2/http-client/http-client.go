package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	help := flag.Bool("help", false, "Prints help")
	host := flag.String("host", "localhost:8080", "Server IP:port")
	flag.Parse()

	usage := `usage:
	
    http-client -host <serverIP:port> [-help]
	
Options:
  -help       Optional, Prints this message
  -host       Mandatory, the server's IP:port (default: localhost:8080)
 `

	if *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" {
		log.Fatalf("host is mandatory:\n%s", usage)
	}

	// Create HTTP/2 transport without TLS (h2c)
	client := http.Client{
		Transport: &http2.Transport{
			// Allow HTTP URLs
			AllowHTTP: true,
			// Pretend we are dialing a TLS endpoint (h2c)
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
		Timeout: 5 * time.Second,
	}

	for i := 1; i <= 1; i++ {
		urlStr := "http://" + *host
		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
			log.Fatalf("Error creating new http request : %s", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			switch e := err.(type) {
			case *url.Error:
				log.Fatalf("url.Error : %s", e)
			default:
				log.Fatalf("Unexpected error : %s", err)
			}
		}

		body, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			log.Fatalf("Error in reading resp: %s", err)
		}

		fmt.Printf("%s ", body)
	}
}
