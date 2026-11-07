// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type record struct {
	Role   string `json:"role"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
	Case   string `json:"case"`
}

var ledger struct {
	sync.Mutex
	Engine []record `json:"engine"`
	Wire   []record `json:"wire"`
}

func server(addr string, h http.HandlerFunc) {
	s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second}
	log.Fatal(s.ListenAndServe())
}
func body(r *http.Request) string {
	b, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if e != nil {
		log.Print(e)
	}
	return string(b)
}
func serve() {
	for i, role := range []string{"prefill", "decode", "sidecar"} {
		addr := fmt.Sprintf("127.0.0.%d:18080", 10+i)
		go server(addr, func(w http.ResponseWriter, r *http.Request) {
			raw := body(r)
			id := r.Header.Get("X-Bundle-Test")
			if id != "" {
				ledger.Lock()
				ledger.Engine = append(ledger.Engine, record{role, r.Method, r.URL.Path, raw, id})
				ledger.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Test-Engine", role)
			if r.Method != http.MethodPost {
				fmt.Fprintf(w, `{"object":"list","served":%q,"data":[{"id":"alias"}]}`, role)
				return
			}
			if role == "prefill" {
				fmt.Fprint(w, `{"id":"cmpl-p","object":"text_completion","model":"alias","choices":[{"index":0,"text":"","finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5},"kv_transfer_params":{"do_remote_prefill":true,"do_remote_decode":false,"remote_block_ids":[[1,2,3]],"remote_host":"127.0.0.10","remote_port":5600,"remote_engine_id":"prefill","remote_request_id":"rr-1","tp_size":1}}`)
				return
			}
			fmt.Fprintf(w, `{"id":"cmpl-d","object":"text_completion","model":"alias","served":%q,"choices":[{"index":0,"text":"answer","finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`, role)
		})
	}
	go server("127.0.0.14:18082", func(w http.ResponseWriter, r *http.Request) {
		raw := body(r)
		ledger.Lock()
		ledger.Wire = append(ledger.Wire, record{"wire", r.Method, r.URL.Path, raw, ""})
		ledger.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			fmt.Fprint(w, `{"result":"Success"}`)
		} else {
			fmt.Fprint(w, `{"product":"loxilb-inference-gateway","features":["epp"],"version":"v0.9.9.1"}`)
		}
	})
	server("127.0.0.13:18081", func(w http.ResponseWriter, r *http.Request) {
		ledger.Lock()
		defer ledger.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/reset" {
			ledger.Engine = nil
			ledger.Wire = nil
		}
		_ = json.NewEncoder(w).Encode(&ledger)
	})
}
func request() {
	if len(os.Args) != 7 {
		log.Fatal("request METHOD URL MEDIA BODY CASE")
	}
	r, e := http.NewRequest(os.Args[2], os.Args[3], strings.NewReader(os.Args[5]))
	if e != nil {
		log.Fatal(e)
	}
	if os.Args[4] != "" {
		r.Header.Set("Content-Type", os.Args[4])
	}
	if os.Args[6] != "" {
		r.Header.Set("X-Bundle-Test", os.Args[6])
	}
	result := map[string]any{"status": 0, "body": "", "error": ""}
	resp, e := (&http.Client{Timeout: 8 * time.Second}).Do(r)
	if e != nil {
		result["error"] = e.Error()
	} else {
		defer resp.Body.Close()
		result["status"] = resp.StatusCode
		result["headers"] = resp.Header
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		result["body"] = string(raw)
		if e != nil {
			result["error"] = e.Error()
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "request" {
		request()
		return
	}
	serve()
}
