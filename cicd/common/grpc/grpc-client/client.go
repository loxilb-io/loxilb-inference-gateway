package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	pb "grpc-hello/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	help := flag.Bool("help", false, "Prints help")
	host := flag.String("host", "localhost:8080", "Server IP:port")
	caCertFile := flag.String("cacert", "", "Server's CA certificate")
	pcert := flag.String("cert", "", "Client's private certificate")
	pkey := flag.String("key", "", "Client's private key")
	name := flag.String("name", "World", "Name to send in greeting")
	flag.Parse()

	usage := `usage:
	
    grpc-client -host <serverIP:port> -cacert <serverCACertFile> [-cert <privateCertFile> -key <privateKeyFile> -name <name> -help]
	
Options:
  -help       Optional, Prints this message
  -host       Mandatory, the server's IP:port (default: localhost:8080)
  -cacert     Mandatory, Server's CA certificate
  -cert       Optional, Client's private certificate
  -key        Optional, Client's private key
  -name       Optional, Name to send in greeting (default: World)
 `

	if *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" || *caCertFile == "" {
		log.Fatalf("host and cacert are mandatory:\n%s", usage)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("Error opening server's CACert file %s: %v", *caCertFile, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// Load client certificate if provided
	if *pcert != "" && *pkey != "" {
		cert, err := tls.LoadX509KeyPair(*pcert, *pkey)
		if err != nil {
			log.Fatalf("Error loading client cert file %s and client key file %s: %v", *pcert, *pkey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Create gRPC credentials
	creds := credentials.NewTLS(tlsConfig)

	// Set up a connection to the server with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *host,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", *host, err)
	}
	defer conn.Close()

	// Create a client
	c := pb.NewGreeterClient(conn)

	// Make multiple calls
	for i := 1; i <= 1; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		r, err := c.SayHello(ctx, &pb.HelloRequest{Name: *name})
		if err != nil {
			log.Fatalf("Could not greet: %v", err)
		}
		fmt.Printf("%s ", r.GetMessage())
	}
	fmt.Println()
}
