package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	pb "grpc-hello/proto"

	"google.golang.org/grpc"
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
	help := flag.Bool("help", false, "prints help")
	host := flag.String("host", "", "server name")
	port := flag.String("port", "8080", "The gRPC port, defaults to 8080")
	flag.Parse()

	usage := `usage:
	
	http-server -host <hostname> [-port <port> -help]
	
	Options:
	-help       Prints usage
	-host       Mandatory, server's name/hostname
	-port       Optional, server's gRPC listening port (default: 8080)`

	args := os.Args[1:]
	if len(args) == 0 || *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" {
		log.Fatalf("host is mandatory:\n%s", usage)
	}

	// Create gRPC server without TLS (insecure)
	grpcServer := grpc.NewServer()

	// Register the greeter service
	pb.RegisterGreeterServer(grpcServer, &server{hostname: *host})

	// Listen on the specified port
	lis, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", *port, err)
	}

	log.Printf("gRPC server listening on port %s without TLS (HTTP/2)", *port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
