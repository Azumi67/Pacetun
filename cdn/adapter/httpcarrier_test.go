package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHub(t *testing.T) (*httpHub, *httptest.Server, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{42}, 32)
	h := newHTTPHub(options{httpPath: "/transfer", maxSessions: 2}, key)
	h.dial = func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer b.Close(); io.Copy(b, b) }()
		return a, nil
	}
	server := httptest.NewServer(h)
	t.Cleanup(func() { h.cleanup(true); server.Close() })
	return h, server, key
}
func requestTest(t *testing.T, s *httptest.Server, key []byte, method, path string, b []byte, seq uint64) *http.Response {
	t.Helper()
	r, e := http.NewRequest(method, s.URL+path, bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	if e = signHTTP(r, key, b, seq); e != nil {
		t.Fatal(e)
	}
	c := s.Client()
	c.Timeout = 3 * time.Second
	resp, e := c.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	return resp
}
func createTest(t *testing.T, s *httptest.Server, key []byte) string {
	t.Helper()
	r := requestTest(t, s, key, "POST", "/transfer", nil, 0)
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 201 {
		t.Fatalf("create=%d %s", r.StatusCode, b)
	}
	return string(b)
}
func TestHTTPAuthenticationReplayLimits(t *testing.T) {
	h, s, key := testHub(t)
	bad := requestTest(t, s, bytes.Repeat([]byte{43}, 32), "POST", "/transfer", nil, 0)
	bad.Body.Close()
	if bad.StatusCode != 404 {
		t.Fatal("wrong key accepted")
	}
	r, _ := http.NewRequest("POST", s.URL+"/transfer", nil)
	signHTTP(r, key, nil, 0)
	response, e := s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 201 {
		t.Fatal(response.StatusCode)
	}
	response, e = s.Client().Do(r.Clone(context.Background()))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("create replay accepted")
	}
	createTest(t, s, key)
	response = requestTest(t, s, key, "POST", "/transfer", nil, 0)
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("session limit ignored")
	}
	h.mu.Lock()
	if len(h.sessions) != 2 {
		t.Fatal("session bound")
	}
	h.mu.Unlock()
	response = requestTest(t, s, key, "POST", "/transfer/"+strings.Repeat("a", 64), make([]byte, httpChunk+1), 0)
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("oversized upload accepted")
	}
}
func TestHTTPBidirectionalAndSequence(t *testing.T) {
	_, s, key := testHub(t)
	id := createTest(t, s, key)
	down := requestTest(t, s, key, "GET", "/transfer/"+id, nil, 0)
	defer down.Body.Close()
	if down.StatusCode != 200 {
		t.Fatal(down.StatusCode)
	}
	payload := bytes.Repeat([]byte("encrypted-binary\x00\xff"), 2000)
	response := requestTest(t, s, key, "POST", "/transfer/"+id, payload, 0)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(down.Body, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("corrupt data")
	}
	response = requestTest(t, s, key, "POST", "/transfer/"+id, payload, 0)
	response.Body.Close()
	if response.StatusCode != 409 {
		t.Fatal("duplicate accepted")
	}
	response = requestTest(t, s, key, "POST", "/transfer/"+id, payload, 2)
	response.Body.Close()
	if response.StatusCode != 409 {
		t.Fatal("gap accepted")
	}
	response = requestTest(t, s, key, "DELETE", "/transfer/"+id, nil, 0)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("close failed")
	}
}
func resetStartup() { startupGate.Lock(); startupGate.next = time.Time{}; startupGate.Unlock() }
func TestStartupSameConnectionAndBounds(t *testing.T) {
	for _, body := range []string{"OK", strings.Repeat("x", 32769)} {
		resetStartup()
		a, b := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer b.Close()
			r, e := http.ReadRequest(bufio.NewReader(b))
			if e != nil {
				return
			}
			if r.URL.Path != "/" || r.Header.Get("User-Agent") != browserUA("firefox120") {
				t.Error("incoherent request")
			}
			response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
			response.Write(b)
		}()
		e := startupRequests(context.Background(), a, options{name: "example.test", fingerprint: "firefox120", startupPaths: "/"})
		a.Close()
		wg.Wait()
		if (len(body) > 32768) != (e != nil) {
			t.Fatalf("body bound: %d %v", len(body), e)
		}
	}
	if startupAllowed(time.Now()) {
		t.Fatal("global cooldown bypassed")
	}
	for _, p := range []string{"https://other.test/", "//other.test/", "/a,/b,/c", "/\r\n"} {
		if validStartupPaths(p) {
			t.Fatalf("unsafe path %q", p)
		}
	}
}
func TestHTTPProxyVerifiedTLS(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	h := newHTTPHub(options{httpPath: "/transfer", maxSessions: 2}, key)
	h.dial = func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer b.Close(); io.Copy(b, b) }()
		return a, nil
	}
	s := httptest.NewTLSServer(h)
	defer s.Close()
	defer h.cleanup(true)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	keypath := filepath.Join(t.TempDir(), "http.key")
	os.WriteFile(keypath, []byte(strings.Repeat("2a", 32)), 0600)
	o := options{remote: s.Listener.Addr().String(), name: "example.com", fingerprint: "firefox120", timeout: 3 * time.Second, httpPath: "/transfer", httpKey: keypath}
	a, b := net.Pipe()
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); proxyHTTP(ctx, b, o, roots, "test") }()
	a.SetDeadline(time.Now().Add(8 * time.Second))
	ready := make([]byte, 8)
	if _, e := io.ReadFull(a, ready); e != nil {
		t.Fatal(e)
	}
	if string(ready) != "UTLSOK1\n" {
		t.Fatal("readiness")
	}
	payload := bytes.Repeat([]byte{0x00, 0xff, 0x12}, 10000)
	if e := writeFull(a, payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(a, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("corrupt")
	}
	a.Close()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("proxy did not stop")
	}
}
func TestProductionPoolOverHTTP(t *testing.T)       { productionPool(t, true) }
func TestProductionPoolOverWSSStartup(t *testing.T) { productionPool(t, false) }
func productionPool(t *testing.T, overHTTP bool) {
	binary := os.Getenv("PACETUN_POOL_TEST_BINARY")
	if binary == "" {
		t.Skip("set PACETUN_POOL_TEST_BINARY for C++ production-loop integration")
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	backend := ln.Addr().String()
	ln.Close()
	key := bytes.Repeat([]byte{42}, 32)
	h := newHTTPHub(options{httpPath: "/transfer", httpBackend: backend, maxSessions: 6}, key)
	var handler http.Handler = h
	if !overHTTP {
		resetStartup()
		dest, _ := url.Parse("http://" + backend)
		reverse := httputil.NewSingleHostReverseProxy(dest)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || r.URL.Path == "/assets/site.css" {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, "small site resource")
				return
			}
			reverse.ServeHTTP(w, r)
		})
	}
	s := httptest.NewTLSServer(handler)
	defer s.Close()
	defer h.cleanup(true)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	dir := t.TempDir()
	keypath := filepath.Join(dir, "key")
	os.WriteFile(keypath, []byte(strings.Repeat("2a", 32)), 0600)
	u, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	go func() {
		for {
			c, e := u.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				o := options{remote: s.Listener.Addr().String(), name: "example.com", fingerprint: "firefox120", timeout: 3 * time.Second, httpPath: "/transfer", httpKey: keypath}
				if overHTTP {
					proxyHTTP(ctx, &testReadyConn{Conn: c}, o, roots, "pool-test")
				} else {
					o.startupPaths = "/,/assets/site.css"
					proxy(ctx, &testReadyConn{Conn: c}, o, roots, "pool-test")
				}
			}()
		}
	}()
	testCtx, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	cmd := exec.CommandContext(testCtx, binary)
	cmd.Env = append(os.Environ(), "PACETUN_TEST_LISTEN="+backend, "PACETUN_TEST_ADAPTER_TCP="+u.Addr().String())
	output, e := cmd.CombinedOutput()
	t.Log(string(output))
	u.Close()
	cancel()
	wg.Wait()
	if e != nil {
		t.Fatal(e)
	}
}

type testReadyConn struct {
	net.Conn
	ready bool
}

func (c *testReadyConn) Write(b []byte) (int, error) {
	if !c.ready {
		c.ready = true
		if string(b) != "UTLSOK1\n" {
			return 0, io.ErrUnexpectedEOF
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}
func TestHTTPBodyBindingAndIdleCleanup(t *testing.T) {
	h, s, key := testHub(t)
	id := createTest(t, s, key)
	r, _ := http.NewRequest("POST", s.URL+"/transfer/"+id, strings.NewReader("modified"))
	signHTTP(r, key, []byte("original"), 0)
	resp, e := s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("body tampering accepted")
	}
	h.mu.Lock()
	h.sessions[id].last.Store(time.Now().Add(-2 * httpIdle).UnixNano())
	h.mu.Unlock()
	h.cleanup(false)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) != 0 {
		t.Fatal("idle session retained")
	}
}
func TestHTTPFailedBackendReleasesReservation(t *testing.T) {
	h, s, key := testHub(t)
	h.dial = func(context.Context) (net.Conn, error) { return nil, io.ErrClosedPipe }
	resp := requestTest(t, s, key, "POST", "/transfer", nil, 0)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal(resp.StatusCode)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) != 0 {
		t.Fatal("failed dial leaked slot")
	}
}
