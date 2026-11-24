/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// upTestHost is the rules' host; the HTTPS listener's certificate is made for it.
const upTestHost = "ws.upgrade.test"

// upSeen is what an upgrade backend received: the first request line and
// header block of every request, in order.
type upSeen struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (s *upSeen) add(r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.mu.Unlock()
}

func (s *upSeen) last() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil
	}
	return s.reqs[len(s.reqs)-1]
}

// upTestBackend is a raw HTTP/1.1 backend.
//   - accept: an upgrade request gets a 101, and from then on every byte the
//     client sends is written back to it unchanged.
//   - otherwise: an upgrade request is declined with a 400 on a kept
//     connection.
//
// Any other request is answered 200 with what it carried:
// {"path":...,"xfp":...,"body":...}.
func upTestBackend(t *testing.T, accept bool) (cmn.LbEndPointArg, *upSeen) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seen := &upSeen{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					r, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					body, _ := io.ReadAll(r.Body)
					seen.add(r)
					if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
						if accept {
							io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
								"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
								"Sec-WebSocket-Accept: "+upAccept(r.Header.Get("Sec-WebSocket-Key"))+"\r\n\r\n")
							io.Copy(c, br) // echo: bytes after the 101, both directions
							return
						}
						io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 8\r\n\r\ndeclined")
						continue
					}
					out := fmt.Sprintf(`{"path":%q,"xfp":%q,"body":%q}`,
						r.URL.Path, r.Header.Get("X-Forwarded-Proto"), body)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
						"Content-Length: %d\r\n\r\n%s", len(out), out)
				}
			}(c)
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	return cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}, seen
}

// upTestCert writes a self-signed certificate for upTestHost where the HTTPS
// listener looks for it (/opt/loxilb/cert/<host>/), and removes it afterwards.
func upTestCert(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: upTestHost},
		DNSNames:     []string{upTestHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("/opt/loxilb/cert", upTestHost)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "server.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func upServ(port uint16, path string, https bool) cmn.LbServiceArg {
	s := cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr,
		HostUrl: upTestHost, PathPrefix: path, PathMatchMode: "prefix",
	}
	if https {
		s.Security = cmn.LBServHTTPS
	}
	return s
}

func upDial(t *testing.T, port uint16, https bool) (net.Conn, *bufio.Reader) {
	t.Helper()
	addr := net.JoinHostPort(eppTestVIP, fmt.Sprint(port))
	var c net.Conn
	var err error
	if https {
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
			&tls.Config{ServerName: upTestHost, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	} else {
		c, err = net.DialTimeout("tcp", addr, 2*time.Second)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c, bufio.NewReader(c)
}

// upHead reads a response's status line and header block.
func upHead(br *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			return b.String(), err
		}
		if line == "\r\n" {
			return b.String(), nil
		}
	}
}

// upAccept is the Sec-WebSocket-Accept a server answers to key (RFC 6455 4.2.2).
func upAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

func upHandshake(path, conn string) string {
	nonce := base64.StdEncoding.EncodeToString([]byte("the sample nonce"))
	return "GET " + path + " HTTP/1.1\r\nHost: " + upTestHost + "\r\nUpgrade: websocket\r\n" +
		"Connection: " + conn + "\r\nSec-WebSocket-Key: " + nonce + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
}

// TestH1UpgradeRelay: an HTTP/1.1 request that switches protocols (a
// WebSocket handshake) takes its own host|path rule, gets the backend's 101,
// and the connection then carries bytes both ways as they are. On HTTPS the
// handshake carries X-Forwarded-Proto like any request, and nothing after
// the 101 gets anything. A declined switch leaves the connection on HTTP/1.1,
// and a body that says "Connection: Upgrade" is an ordinary body. These are
// the paths of Run:ai's exec and attach (a cluster-api WebSocket) and of an
// inference request whose prompt holds the phrase.
func TestH1UpgradeRelay(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	upTestCert(t)
	for _, tc := range []struct {
		name  string
		port  uint16
		https bool
	}{{"http", 28470, false}, {"https", 28472, true}} {
		t.Run(tc.name, func(t *testing.T) {
			_, rootEp, rootSeen := eppTestBackendSeen(t, "root")
			wsEp, wsSeen := upTestBackend(t, true)
			noEp, noSeen := upTestBackend(t, false)
			for _, r := range []struct {
				path string
				ep   cmn.LbEndPointArg
			}{{"/", rootEp}, {"/ws", wsEp}, {"/no-ws", noEp}} {
				s := upServ(tc.port, r.path, tc.https)
				if _, err := eppTestAddRule(s, []cmn.LbEndPointArg{r.ep}); err != nil {
					t.Fatalf("add %s: %v", r.path, err)
				}
				t.Cleanup(func() { eppTestDeleteRule(s) })
			}
			wantXfp := ""
			if tc.https {
				wantXfp = "https"
			}

			// The bytes after the 101: binary (a masked WebSocket frame) and
			// text that reads like an HTTP request, which must not be parsed,
			// routed or edited.
			after := append([]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
				"GET / HTTP/1.1\r\nHost: "+upTestHost+"\r\nX-Api-Key: k\r\n\r\n"...)
			for _, conn := range []string{"Upgrade", "upgrade", "keep-alive, Upgrade"} {
				c, br := upDial(t, tc.port, tc.https)
				if _, err := io.WriteString(c, upHandshake("/ws/exec", conn)); err != nil {
					t.Fatal(err)
				}
				head, err := upHead(br)
				if err != nil || !strings.HasPrefix(head, "HTTP/1.1 101") {
					t.Fatalf("Connection: %s: got %q, %v; want the backend's 101", conn, head, err)
				}
				r := wsSeen.last()
				if r == nil || r.URL.Path != "/ws/exec" {
					t.Fatalf("Connection: %s: the /ws backend did not get the handshake", conn)
				}
				if got := r.Header.Get("X-Forwarded-Proto"); got != wantXfp {
					t.Fatalf("Connection: %s: the handshake carried X-Forwarded-Proto %q, want %q", conn, got, wantXfp)
				}
				for i := 0; i < 3; i++ {
					if _, err := c.Write(after); err != nil {
						t.Fatal(err)
					}
					back := make([]byte, len(after))
					if _, err := io.ReadFull(br, back); err != nil || !bytes.Equal(back, after) {
						t.Fatalf("Connection: %s: round %d after the 101 came back %q, %v; want %q",
							conn, i, back, err, after)
					}
				}
				c.Close()
			}
			rootSeen.mu.Lock()
			rootHits := rootSeen.hits
			rootSeen.mu.Unlock()
			if rootHits != 0 {
				t.Fatalf("the / backend got %d requests; every handshake belongs to /ws", rootHits)
			}

			// Declined: a 400 on a kept connection, then an ordinary request on
			// it is parsed and handled as one.
			c, br := upDial(t, tc.port, tc.https)
			io.WriteString(c, upHandshake("/no-ws/a", "Upgrade"))
			resp, err := http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != 400 {
				t.Fatalf("declined switch: got %v, %v; want the backend's 400", resp, err)
			}
			io.ReadAll(resp.Body)
			io.WriteString(c, "GET /no-ws/next HTTP/1.1\r\nHost: "+upTestHost+"\r\n\r\n")
			resp, err = http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("the request after a declined switch: got %v, %v; want 200", resp, err)
			}
			body, _ := io.ReadAll(resp.Body)
			if want := fmt.Sprintf(`"path":"/no-ws/next","xfp":%q`, wantXfp); !strings.Contains(string(body), want) {
				t.Fatalf("the request after a declined switch was answered %s; want %s", body, want)
			}
			if r := noSeen.last(); r == nil || r.URL.Path != "/no-ws/next" {
				t.Fatalf("the /no-ws backend did not get the request after the declined switch")
			}
			c.Close()

			// A body that says "Connection: Upgrade", on a connection's first
			// request and on the next one: each reaches the backend whole.
			prompt := `{"prompt":"Connection: Upgrade"}`
			post := "POST /v1/completions HTTP/1.1\r\nHost: " + upTestHost + "\r\n" +
				"Content-Type: application/json\r\nContent-Length: " + fmt.Sprint(len(prompt)) + "\r\n\r\n" + prompt
			c, br = upDial(t, tc.port, tc.https)
			for i := 0; i < 2; i++ {
				if _, err := io.WriteString(c, post); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(br, nil)
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("POST %d with the phrase in its body: got %v, %v; want 200", i+1, resp, err)
				}
				io.ReadAll(resp.Body)
				rootSeen.mu.Lock()
				got := rootSeen.body
				rootSeen.mu.Unlock()
				if got != prompt {
					t.Fatalf("POST %d: the backend got the body %q, want %q", i+1, got, prompt)
				}
			}
		})
	}
}
