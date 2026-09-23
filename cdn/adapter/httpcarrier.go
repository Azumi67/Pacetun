package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const httpChunk = 64 * 1024
const httpIdle = 75 * time.Second

func validHTTPPath(s string) bool {
	if len(s) < 2 || len(s) > 128 || s[0] != '/' || strings.Contains(s, "..") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, c := range s {
		if !(c == '/' || c == '-' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func loopbackAddress(s string) bool {
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return false
	}
	ip := net.ParseIP(h)
	n, e := strconv.Atoi(p)
	return e == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback()
}
func httpSecret(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return nil, errors.New("HTTP key must be a private regular file, mode 0600, 64 hex characters")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != 32 {
		return nil, errors.New("HTTP key requires 32 random bytes in hex")
	}
	return key, nil
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func httpMAC(key []byte, method, path, stamp, nonce, seq string, body []byte) string {
	hash := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "PaceTun-HTTP-1\n%s\n%s\n%s\n%s\n%s\n%x", method, path, stamp, nonce, seq, hash)
	return hex.EncodeToString(m.Sum(nil))
}
func signHTTP(r *http.Request, key, body []byte, seq uint64) error {
	nonce, e := randomHex(16)
	if e != nil {
		return e
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	sq := strconv.FormatUint(seq, 10)
	r.Header.Set("X-Request-Time", stamp)
	r.Header.Set("X-Request-ID", nonce)
	r.Header.Set("X-Request-Sequence", sq)
	r.Header.Set("Authorization", "Bearer "+httpMAC(key, r.Method, r.URL.EscapedPath(), stamp, nonce, sq, body))
	return nil
}

type httpSession struct {
	conn    net.Conn
	write   sync.Mutex
	next    uint64
	reading atomic.Bool
	last    atomic.Int64
	born    time.Time
	once    sync.Once
}

func (s *httpSession) close() { s.once.Do(func() { s.conn.Close() }) }

type httpHub struct {
	key           []byte
	path, backend string
	limit         int
	mu            sync.Mutex
	sessions      map[string]*httpSession
	seen          map[string]time.Time
	dial          func(context.Context) (net.Conn, error)
}

func newHTTPHub(o options, key []byte) *httpHub {
	h := &httpHub{key: key, path: o.httpPath, backend: o.httpBackend, limit: o.maxSessions, sessions: make(map[string]*httpSession), seen: make(map[string]time.Time)}
	h.dial = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", h.backend)
	}
	return h
}
func (h *httpHub) authorized(r *http.Request, b []byte) bool {
	stamp, nonce, sq := r.Header.Get("X-Request-Time"), r.Header.Get("X-Request-ID"), r.Header.Get("X-Request-Sequence")
	t, e := strconv.ParseInt(stamp, 10, 64)
	if e != nil || t < time.Now().Unix()-30 || t > time.Now().Unix()+30 {
		return false
	}
	nb, e := hex.DecodeString(nonce)
	if e != nil || len(nb) != 16 {
		return false
	}
	if _, e = strconv.ParseUint(sq, 10, 64); e != nil {
		return false
	}
	got, e := hex.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	want, _ := hex.DecodeString(httpMAC(h.key, r.Method, r.URL.EscapedPath(), stamp, nonce, sq, b))
	return e == nil && hmac.Equal(got, want)
}
func (h *httpHub) remove(id string, s *httpSession) {
	h.mu.Lock()
	if h.sessions[id] == s {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
	s.close()
}
func (h *httpHub) cleanup(all bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for id, s := range h.sessions {
		if all || now.Sub(time.Unix(0, s.last.Load())) > httpIdle || now.Sub(s.born) > 2*time.Hour {
			s.close()
			delete(h.sessions, id)
		}
	}
	for n, t := range h.seen {
		if now.Sub(t) > 65*time.Second {
			delete(h.seen, n)
		}
	}
}
func quiet404(w http.ResponseWriter) { http.NotFound(w, &http.Request{}) }
func (h *httpHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ReadTimeout and connection cap bound slow readers; no proxy-provided identity trusted.
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Get("Authorization")) > 128 {
		quiet404(w)
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, h.path)
	if suffix == r.URL.Path || (suffix != "" && !strings.HasPrefix(suffix, "/")) {
		quiet404(w)
		return
	}
	if r.Method != "POST" && r.Method != "GET" && r.Method != "DELETE" {
		quiet404(w)
		return
	}
	max := int64(httpChunk)
	if r.Method != "POST" || suffix == "" {
		max = 0
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if e != nil || !h.authorized(r, b) {
		quiet404(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if suffix == "" {
		if r.Method != "POST" || r.Header.Get("X-Request-Sequence") != "0" {
			quiet404(w)
			return
		}
		h.mu.Lock()
		nonce := r.Header.Get("X-Request-ID")
		if _, ok := h.seen[nonce]; ok {
			h.mu.Unlock()
			quiet404(w)
			return
		}
		if len(h.sessions) >= h.limit || len(h.seen) >= 4096 {
			h.mu.Unlock()
			http.Error(w, "Unavailable", 503)
			return
		}
		h.seen[nonce] = time.Now()
		id, e := randomHex(32)
		if e != nil {
			h.mu.Unlock()
			http.Error(w, "Unavailable", 503)
			return
		}
		placeholder := &httpSession{conn: &closedConn{}, born: time.Now()}
		placeholder.last.Store(time.Now().UnixNano())
		h.sessions[id] = placeholder
		h.mu.Unlock()
		conn, e := h.dial(r.Context())
		if e != nil {
			h.remove(id, placeholder)
			http.Error(w, "Unavailable", 503)
			return
		}
		s := &httpSession{conn: conn, born: time.Now()}
		s.last.Store(time.Now().UnixNano())
		h.mu.Lock()
		if h.sessions[id] != placeholder {
			h.mu.Unlock()
			conn.Close()
			http.Error(w, "Unavailable", 503)
			return
		}
		h.sessions[id] = s
		h.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, id)
		return
	}
	id := strings.TrimPrefix(suffix, "/")
	if len(id) != 64 {
		quiet404(w)
		return
	}
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		quiet404(w)
		return
	}
	if r.Method == "DELETE" {
		h.remove(id, s)
		w.WriteHeader(204)
		return
	}
	if r.Method == "POST" {
		if len(b) == 0 || !s.write.TryLock() {
			http.Error(w, "Conflict", 409)
			return
		}
		defer s.write.Unlock()
		seq, e := strconv.ParseUint(r.Header.Get("X-Request-Sequence"), 10, 64)
		if e != nil || seq != s.next {
			http.Error(w, "Conflict", 409)
			return
		}
		s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if e = writeFull(s.conn, b); e != nil {
			h.remove(id, s)
			http.Error(w, "Unavailable", 503)
			return
		}
		s.next++
		s.last.Store(time.Now().UnixNano())
		w.WriteHeader(204)
		return
	}
	if !s.reading.CompareAndSwap(false, true) {
		http.Error(w, "Conflict", 409)
		return
	}
	defer h.remove(id, s)
	stop := context.AfterFunc(r.Context(), func() { s.close() })
	defer stop()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	w.WriteHeader(200)
	if e = rc.Flush(); e != nil {
		return
	}
	buf := make([]byte, 32*1024)
	for {
		s.conn.SetReadDeadline(time.Now().Add(httpIdle))
		n, err := s.conn.Read(buf)
		if n > 0 {
			rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, e = w.Write(buf[:n]); e != nil {
				return
			}
			if e = rc.Flush(); e != nil {
				return
			}
			s.last.Store(time.Now().UnixNano())
		}
		if err != nil {
			return
		}
	}
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

=type closedConn struct{ net.Conn }

func (*closedConn) Close() error { return nil }

type cappedListener struct {
	net.Listener
	slots chan struct{}
}
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *cappedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &countedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func runHTTPServer(o options) error {
	key, e := httpSecret(o.httpKey)
	if e != nil {
		return e
	}
	h := newHTTPHub(o, key)
	ln, e := net.Listen("tcp", o.httpListen)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				h.cleanup(true)
				srv.Close()
				return
			case <-ticker.C:
				h.cleanup(false)
			}
		}
	}()
	log.Printf("event=http_server_start experimental=true max_sessions=%d max_connections=64 max_post_bytes=%d", o.maxSessions, httpChunk)
	e = srv.Serve(&cappedListener{Listener: ln, slots: make(chan struct{}, 64)})
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func httpClient(o options, roots *x509.CertPool) (*http.Client, *http.Transport) {
	tr := &http.Transport{ForceAttemptHTTP2: false, DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 8192,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, _, e := connectCDN(ctx, o, roots)
			return c, e
		}}
=	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr
}
func carrierRequest(ctx context.Context, client *http.Client, o options, key []byte, method, id string, b []byte, seq uint64) (*http.Response, error) {
	path := o.httpPath
	if id != "" {
		path += "/" + id
	}
	var body io.Reader
	if len(b) > 0 {
		body = bytes.NewReader(b)
	}
	r, e := http.NewRequestWithContext(ctx, method, "https://"+o.name+path, body)
	if e != nil {
		return nil, e
	}
	r.GetBody = nil // never replay automatically
	r.Header.Set("User-Agent", browserUA(o.fingerprint))
	r.Header.Set("Accept", "*/*")
	if len(b) > 0 {
		r.Header.Set("Content-Type", "application/octet-stream")
	}
	if e = signHTTP(r, key, b, seq); e != nil {
		return nil, e
	}
	return client.Do(r)
}
func proxyHTTP(parent context.Context, local net.Conn, o options, roots *x509.CertPool, session string) {
	defer local.Close()
	key, e := httpSecret(o.httpKey)
	if e != nil {
		log.Print("event=http_key_error")
		return
	}
	client, tr := httpClient(o, roots)
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { local.Close() })
	defer stop()
	createCtx, done := context.WithTimeout(ctx, 10*time.Second)
	resp, e := carrierRequest(createCtx, client, o, key, "POST", "", nil, 0)
	if e != nil {
		done()
		return
	}
	idBytes, e := io.ReadAll(io.LimitReader(resp.Body, 65))
	resp.Body.Close()
	done()
	if e != nil || resp.StatusCode != 201 || len(idBytes) != 64 {
		return
	}
	id := string(idBytes)
	if _, e = hex.DecodeString(id); e != nil {
		return
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if r, e := carrierRequest(cleanup, client, o, key, "DELETE", id, nil, 0); e == nil {
			r.Body.Close()
		}
	}()
	resp, e = carrierRequest(ctx, client, o, key, "GET", id, nil, 0)
	if e != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	local.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if e = writeFull(local, []byte("UTLSOK1\n")); e != nil {
		return
	}
	local.SetWriteDeadline(time.Time{})
	log.Printf("session=%s event=http_ready experimental=true", session)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			n, e := resp.Body.Read(buf)
			if n > 0 {
				local.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if writeFull(local, buf[:n]) != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	buf := make([]byte, httpChunk)
	var seq uint64
	for {
		local.SetReadDeadline(time.Now().Add(httpIdle))
		n, err := local.Read(buf)
		if n > 0 {
			reqCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			r, e := carrierRequest(reqCtx, client, o, key, "POST", id, buf[:n], seq)
			if e == nil {
				_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
				r.Body.Close()
				if r.StatusCode != 204 {
					e = errors.New("upload rejected")
				}
			}
			stop()
			if e != nil {
				break
			}
			seq++
		}
		if err != nil {
			break
		}
	}
	cancel()
	resp.Body.Close()
	<-finished
	log.Printf("session=%s event=http_closed posts=%d", session, seq)
}
