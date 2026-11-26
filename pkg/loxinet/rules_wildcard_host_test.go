/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// whBackend is a backend named `name` that answers {"served":"<name>"} over
// HTTP/1.1 and over HTTP/2 with prior knowledge, whichever the proxy uses.
func whBackend(t *testing.T, name string) cmn.LbEndPointArg {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served":%q}`, name)
	})
	srv := httptest.NewServer(h2c.NewHandler(h, &http2.Server{}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	return cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
}

func whServ(port uint16, host, path string) cmn.LbServiceArg {
	return cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr,
		HostUrl: host, PathPrefix: path, PathMatchMode: "prefix",
	}
}

// whClient is an HTTP/1.1 client, or an HTTP/2 client with prior knowledge
// (h2c), that sends Host / :authority as asked and never reuses a connection.
func whClient(h2 bool) *http.Client {
	if !h2 {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}

// whServed sends GET host+path to the listener and returns the backend that
// answered, or the status line when none did.
func whServed(t *testing.T, c *http.Client, port uint16, host, path string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d%s", eppTestVIP, port, path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := c.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("status %d", resp.StatusCode)
	}
	s := string(body)
	if i := strings.Index(s, `"served":"`); i >= 0 {
		s = s[i+len(`"served":"`):]
		if j := strings.IndexByte(s, '"'); j >= 0 {
			return s[:j]
		}
	}
	return "body " + string(body)
}

// TestWildcardHostRouting - the wildcard host semantics on the data plane, on
// HTTP/1.1 and HTTP/2: exact host, then the longer wildcard suffix, then the
// shorter, then the listener's host-less rule; a host whose rules match no
// path passes the request on. Hosts compare without case.
func TestWildcardHostRouting(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	for _, tc := range []struct {
		name string
		port uint16
		h2   bool
	}{{"http1", 28480, false}, {"h2c", 28482, true}} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []struct {
				host, path, name string
			}{
				{"a.example.com", "/api", "exact"},
				{"*.example.com", "/", "wide"},
				{"*.B.example.com", "/x", "narrow"}, // stored in lower case
				{"", "/", "hostless"},
			}
			servs := map[string]cmn.LbServiceArg{}
			for _, r := range rules {
				s := whServ(tc.port, r.host, r.path)
				if _, err := eppTestAddRule(s, []cmn.LbEndPointArg{whBackend(t, r.name)}); err != nil {
					t.Fatalf("add %q%s: %v", r.host, r.path, err)
				}
				servs[r.name] = s
				t.Cleanup(func() { eppTestDeleteRule(s) })
			}
			c := whClient(tc.h2)
			// Rule changes reach the data plane asynchronously: the listener
			// comes up some time after its first rule, and a delete lands some
			// time after it returns. A check waits for its answer, five seconds
			// at most; a request on a kept HTTP/2 connection can arrive first.
			check := func(host, path, want string) {
				t.Helper()
				var got string
				for i := 0; i < 50; i++ {
					if got = whServed(t, c, tc.port, host, path); got == want {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				t.Errorf("%s %s%s: served by %q, want %q", tc.name, host, path, got, want)
			}

			check("a.example.com", "/api/1", "exact")
			check("a.example.com", "/other", "wide") // the exact host has no rule for the path
			check("c.b.example.com", "/x/1", "narrow")
			check("c.b.example.com", "/y", "wide")
			check("example.com", "/", "hostless") // a wildcard never matches its own suffix
			check("x.y.example.com", "/z", "wide")
			check("A.EXAMPLE.COM", "/api/1", "exact")
			check("C.B.Example.Com", "/x/1", "narrow")

			// Deleting a wildcard hands its requests to the next candidate, on
			// the HTTP/2 connection already open as well. The delete names the
			// host in another case than the rule was sent in.
			del := servs["narrow"]
			del.HostUrl = "*.b.EXAMPLE.com"
			if _, err := eppTestDeleteRule(del); err != nil {
				t.Fatalf("delete *.b.example.com in another case: %v", err)
			}
			check("c.b.example.com", "/x/1", "wide")
			if _, err := eppTestDeleteRule(servs["wide"]); err != nil {
				t.Fatalf("delete *.example.com: %v", err)
			}
			check("a.example.com", "/other", "hostless")
		})
	}
}

// TestWildcardHostRefused - "*" anywhere but as the whole first label is
// refused as a malformed argument (the REST layer answers 400), before any
// rule state changes.
func TestWildcardHostRefused(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	ep := whBackend(t, "never")
	for _, host := range []string{"*", "*.", "a*.b", "x.*.b", "*.example..com"} {
		s := whServ(28484, host, "/")
		_, err := eppTestAddRule(s, []cmn.LbEndPointArg{ep})
		var argErr *cmn.RuleArgumentError
		if !errors.As(err, &argErr) {
			eppTestDeleteRule(s)
			t.Errorf("add host %q: err = %v, want a RuleArgumentError", host, err)
		}
	}

	// A rule a build before the check stored with such a host is restored as
	// it was, so the restore of the other rules does not fail on it.
	for _, replay := range []string{"snapshot", "lbconfig"} {
		s := whServ(28484, "a*.b", "/")
		s.RestoreReplay = replay == "snapshot"
		s.BootReplay = replay == "lbconfig"
		if _, err := eppTestAddRule(s, []cmn.LbEndPointArg{ep}); err != nil {
			t.Errorf("%s replay of host %q: %v, want it restored", replay, s.HostUrl, err)
		}
		if _, err := eppTestDeleteRule(whServ(28484, "a*.b", "/")); err != nil {
			t.Errorf("delete the restored %q: %v", "a*.b", err)
		}
	}
}
