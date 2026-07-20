package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	pb "grpc-hello/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
	hostname string
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: fmt.Sprintf("Hello %s from %s", in.GetName(), s.hostname)}, nil
}

func main() {
	var rootCACert []byte
	var err error
	var certPool *x509.CertPool
	authType := tls.NoClientCert

	help := flag.Bool("help", false, "prints help")
	host := flag.String("host", "", "server name")
	port := flag.String("port", "8080", "The gRPC port, defaults to 8080")
	cert := flag.String("cert", "", "server's certificate")
	caCert := flag.String("cacert", "", "Client's CA certificate")
	key := flag.String("key", "", "server's private key")
	strict := flag.Bool("strict", false, "true if strict client authentication is required")
	flag.Parse()

	usage := `usage:
	
	grpc-server -host <hostname> -cert <CertFile> -key <PrivateKey> [-cacert <caCert> -port <port> -strict <true/false> -help]
	
	Options:
	-help       Prints usage
	-host       Mandatory, server's name
	-cert       Mandatory, server's certificate
	-key        Mandatory, server's private key
	-cacert     Optional, client's CA certificate if strict check is required
	-port       Optional, server's gRPC listening port (default: 8080)
	-strict     Optional, true if client's strict authentication is required`

	args := os.Args[1:]
	if len(args) == 0 || *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" || *cert == "" || *key == "" {
		log.Fatalf("host, cert and key are mandatory:\n%s", usage)
	}

	if *strict == true {
		if *caCert == "" {
			log.Fatal("cacert is required when strict mode is enabled")
		}
		rootCACert, err = ioutil.ReadFile(*caCert)
		if err != nil {
			log.Fatal("Error loading CA cert : ", err)
		}
		certPool = x509.NewCertPool()
		certPool.AppendCertsFromPEM(rootCACert)
		authType = tls.RequireAndVerifyClientCert
	}

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("Failed to load server cert/key: %v", err)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   authType,
		ClientCAs:    certPool,
	}

	// Create gRPC server with TLS credentials
	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	// Register the greeter service
	pb.RegisterGreeterServer(grpcServer, &server{hostname: *host})

	// Listen on the specified port
	lis, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", *port, err)
	}

	log.Printf("gRPC server listening on port %s with TLS (HTTP/2)", *port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
