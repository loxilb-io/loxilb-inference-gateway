// Command h2_count_server is a TLS HTTP/2 backend with an append-only oracle.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	cert := flag.String("cert", "", "server certificate")
	key := flag.String("key", "", "server private key")
	logPath := flag.String("log", "/tmp/ai-security-h2-backend.log", "request log")
	flag.Parse()

	if *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "-cert and -key are required")
		os.Exit(2)
	}
	logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	var mu sync.Mutex
	var count int

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		current := count
		fmt.Fprintf(logFile, "count=%d proto=%s method=%s path=%s api_key=%t\n",
			current, r.Proto, r.Method, r.URL.Path, r.Header.Get("X-Api-Key") != "")
		_ = logFile.Sync()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"backend_count":%d,"api_key":%t}`, current,
			r.Header.Get("X-Api-Key") != "")
	})

	server := &http.Server{
		Addr:      *addr,
		Handler:   handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}},
	}
	if err := server.ListenAndServeTLS(*cert, *key); err != nil {
		panic(err)
	}
}
