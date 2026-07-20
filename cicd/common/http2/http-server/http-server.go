package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	help := flag.Bool("help", false, "prints help")
	host := flag.String("host", "", "server name")
	port := flag.String("port", "8080", "The http port, defaults to 8080")
	flag.Parse()

	usage := `usage:
	
	http-server -host <hostname> [-port <port> -help]
	
	Options:
	-help       Prints usage
	-host       Mandatory, server's name/hostname
	-port       Optional, server's HTTP/2 listening port (default: 8080)`

	args := os.Args[1:]
	if len(args) == 0 || *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" {
		log.Fatalf("host is mandatory:\n%s", usage)
	}

	http.HandleFunc("/health", func(res http.ResponseWriter, req *http.Request) {
		resp := fmt.Sprintf("OK")
		res.Write([]byte(resp))
	})

	// Path-based routing for testing P6 LPM (Longest Prefix Match)
	http.HandleFunc("/v1/users", func(res http.ResponseWriter, req *http.Request) {
		// Handles /v1/users and /v1/users/* paths
		resp := fmt.Sprintf("%s:%s:users", req.Proto, *host)
		res.Write([]byte(resp))
	})

	http.HandleFunc("/v1/users/", func(res http.ResponseWriter, req *http.Request) {
		// Handles /v1/users/* sub-paths explicitly
		resp := fmt.Sprintf("%s:%s:users", req.Proto, *host)
		res.Write([]byte(resp))
	})

	http.HandleFunc("/v1/orders", func(res http.ResponseWriter, req *http.Request) {
		// Handles /v1/orders and /v1/orders/* paths
		resp := fmt.Sprintf("%s:%s:orders", req.Proto, *host)
		res.Write([]byte(resp))
	})

	http.HandleFunc("/v1/orders/", func(res http.ResponseWriter, req *http.Request) {
		// Handles /v1/orders/* sub-paths explicitly
		resp := fmt.Sprintf("%s:%s:orders", req.Proto, *host)
		res.Write([]byte(resp))
	})

	http.HandleFunc("/v1/", func(res http.ResponseWriter, req *http.Request) {
		// Catch-all for /v1/* paths (broader prefix)
		resp := fmt.Sprintf("%s:%s:v1", req.Proto, *host)
		res.Write([]byte(resp))
	})

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		// Default handler (root and all other paths)
		resp := fmt.Sprintf("%s:%s", req.Proto, *host)
		res.Write([]byte(resp))
	})

	// Create HTTP/2 server without TLS using h2c (HTTP/2 Cleartext)
	h2s := &http2.Server{}
	server := &http.Server{
		Addr:    ":" + *port,
		Handler: h2c.NewHandler(http.DefaultServeMux, h2s),
	}

	log.Printf("HTTP/2 server (h2c) listening on port %s without TLS", *port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
