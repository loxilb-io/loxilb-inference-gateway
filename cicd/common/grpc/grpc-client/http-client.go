package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	pb "grpc-hello/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	help := flag.Bool("help", false, "Prints help")
	host := flag.String("host", "localhost:8080", "Server IP:port")
	name := flag.String("name", "World", "Name to send in greeting")
	flag.Parse()

	usage := `usage:
	
    http-client -host <serverIP:port> [-name <name> -help]
	
Options:
  -help       Optional, Prints this message
  -host       Mandatory, the server's IP:port (default: localhost:8080)
  -name       Optional, Name to send in greeting (default: World)
 `

	if *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" {
		log.Fatalf("host is mandatory:\n%s", usage)
	}

	// Set up a connection to the server without TLS (insecure)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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
