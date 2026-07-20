// server.go — header-reflecting HTTP echo backend for the L7 / KV-cache CICD scenarios.
//
// REPLACES the Phase-76 stdlib-python server.py. Rationale (gate diagnosis): loxilb's fullproxy
// forwards an h2c (cleartext HTTP/2 prior-knowledge) CLIENT request to the backend AS HTTP/2 in
// transit mode (nghttp2 client, no h2->h1 downgrade — an un-built capability, not a gate bug). The
// python stdlib http.server speaks ONLY HTTP/1.1, so it RESETS the h2 transit leg and the H2 asserts
// (a_h2, c_h2) received empty bodies (curl exit 52). This Go server serves BOTH HTTP/1.1 AND h2c
// (prior-knowledge + h2c-upgrade) on the SAME cleartext port via golang.org/x/net/http2/h2c, so the
// transit no longer resets and the reflected headers reach the H2 client too.
//
// Behaviour is BYTE-COMPATIBLE with the prior server.py so validation.sh greps are unchanged:
//   GET/POST  /          -> 200; body reflects EVERY received request header as "Name: value" lines,
//                           PLUS a leading "X-Echo-Backend: <ECHO_NAME or hostname>" line.
//   any (Cookie: ...)    -> the received Cookie header is reflected verbatim in the body AND echoed
//                           back as the X-Echoed-Cookie response header (FR-10 read-back observation).
//   HEAD/GET  /healthz   -> status controlled by HEALTHZ_CODE env (default 200; set 404 to drive the
//                           FR-30 down-marking assert on the l3epHM backend).
//
// Env knobs (identical names/semantics to the old server.py):
//   ECHO_NAME    — backend identity emitted as `X-Echo-Backend` (defaults to the container hostname).
//   HEALTHZ_CODE — status code returned for /healthz (default "200"; set "404" for the HM-down backend).
//   SLOW_MS      — if >0, sleep this many ms before responding (FR-07 slow/blackhole backend).
//   LISTEN_PORT  — bind port (default 80).
//
// SECURITY NOTE (T-76-02-02): reflecting attacker-controlled headers into a response body is a test
// fixture convenience ONLY. This image is NEVER deployed to production — it exists solely as the
// observation point inside the CICD netns. Do not reuse it as a real service.

package main

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func main() {
	hostname, _ := os.Hostname()
	echoName := os.Getenv("ECHO_NAME")
	if echoName == "" {
		echoName = hostname
	}
	healthzCode := envInt("HEALTHZ_CODE", 200)
	slowMS := envInt("SLOW_MS", 0)
	listenPort := envInt("LISTEN_PORT", 80)

	isHealthz := func(p string) bool {
		if i := strings.IndexByte(p, '?'); i >= 0 {
			p = p[:i]
		}
		return p == "/healthz" || strings.TrimRight(p, "/") == "/healthz"
	}

	maybeSlow := func() {
		if slowMS > 0 {
			time.Sleep(time.Duration(slowMS) * time.Millisecond)
		}
	}

	// reflectBody mirrors the python _reflect_body: a leading "X-Echo-Backend: <name>" line followed
	// by EVERY received request header as "Name: value" lines. validation.sh greps anchored lines such
	// as `^X-Forwarded-For: 10.10.10.1$`, `^X-Inj: yes$`, `^X-Echo-Backend:`. Go canonicalises header
	// names (X-Forwarded-For etc.) which matches what loxilb injects and what the greps expect.
	reflectBody := func(r *http.Request) string {
		lines := []string{"X-Echo-Backend: " + echoName}
		// Stable, deterministic order: sort header keys, emit each value (multi-value preserved).
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range r.Header[k] {
				lines = append(lines, k+": "+v)
			}
		}
		// Host is not part of r.Header in Go; surface it so a Host-based grep would still see it.
		if r.Host != "" {
			lines = append(lines, "Host: "+r.Host)
		}
		return strings.Join(lines, "\n") + "\n"
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maybeSlow()

		// Echo received Cookie back as a response header (FR-10), mirroring the python X-Echoed-Cookie.
		if c := r.Header.Get("Cookie"); c != "" {
			w.Header().Set("X-Echoed-Cookie", c)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if isHealthz(r.URL.Path) {
			if r.Method == http.MethodHead {
				w.WriteHeader(healthzCode)
				return
			}
			body := []byte("healthz\n")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(healthzCode)
			if r.Method != http.MethodHead {
				_, _ = w.Write(body)
			}
			return
		}

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		body := []byte(reflectBody(r))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	// h2c.NewHandler serves cleartext HTTP/2 (prior-knowledge AND h2c-upgrade) on the same plaintext
	// listener that http.Server serves HTTP/1.1 on — so a single port answers BOTH protocols. This is
	// exactly what loxilb's h2c transit leg needs (the old python h1-only server could not).
	h2s := &http2.Server{}
	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", listenPort),
		Handler: h2c.NewHandler(handler, h2s),
	}

	fmt.Fprintf(os.Stderr, "reflect-echo(go/h2c) up: name=%s port=%d healthz=%d slow_ms=%d\n",
		echoName, listenPort, healthzCode, slowMS)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "reflect-echo: server error: %v\n", err)
		os.Exit(1)
	}
}
