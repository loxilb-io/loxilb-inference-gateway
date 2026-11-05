package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type recorder struct {
	mu       sync.Mutex
	heads    map[string]int
	receipts map[string]int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/receipts":
			json.NewEncoder(w).Encode(r.receipts)
		case "/heads":
			json.NewEncoder(w).Encode(r.heads)
		default:
			http.NotFound(w, req)
		}
		return
	}
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := req.Header.Get("X-Request-Id")
	if id == "" {
		id = "absent"
	}
	r.mu.Lock()
	r.heads[id]++
	r.mu.Unlock()
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		http.Error(w, "incomplete request", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.receipts[id]++
	r.mu.Unlock()

	const body = "data: {\"id\":\"mock-backend-receipt\",\"choices\":[]}\n\ndata: [DONE]\n\n"
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	io.WriteString(w, body)
}

func main() {
	r := &recorder{heads: make(map[string]int), receipts: make(map[string]int)}
	server := &http.Server{
		Addr:    ":8000",
		Handler: h2c.NewHandler(r, &http2.Server{}),
	}
	log.Fatal(server.ListenAndServe())
}
