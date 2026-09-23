package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Azumi67/Pacetun/cdn/adapter/transportpolicy"
	utls "github.com/refraction-networking/utls"
)

func helloID(profile string) utls.ClientHelloID {
	if profile == "chrome120" {
		return utls.HelloChrome_120
	}
	return utls.HelloFirefox_120
}

func rootPool(ca string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA bundle has no usable certificates")
	}
	return roots, nil
}

func setHTTP11(c *utls.UConn) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	found := false
	for _, ext := range c.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = []string{"http/1.1"}
			found = true
		}
	}
	if !found {
		return errors.New("selected uTLS profile lacks ALPN extension")
	}
	return c.BuildHandshakeState()
}

var cdnSelector = transportpolicy.NewSelector()

type connectTimings struct {
	DNS, TCP, TLS time.Duration
	Attempts      int
	IP            string
	Phase         string
}

func connectCDN(ctx context.Context, o options, roots *x509.CertPool) (*utls.UConn, connectTimings, error) {
	var m connectTimings
	m.Phase = "dns_tcp"
	raw, timings, err := cdnSelector.Dial(ctx, o.remote, o.timeout)
	m.DNS, m.TCP, m.Attempts, m.IP = timings.DNS, timings.TCP, timings.Attempts, timings.SelectedIP
	if err != nil {
		return nil, m, fmt.Errorf("CDN TCP connection: %w", err)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopCancel()
	cfg := &utls.Config{
		ServerName: o.name, RootCAs: roots,
		MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, InsecureSkipVerify: false,
	}
	conn := utls.UClient(raw, cfg, helloID(o.fingerprint))
	m.Phase = "tls_hello"
	if err := setHTTP11(conn); err != nil {
		_ = conn.Close()
		return nil, m, fmt.Errorf("uTLS hello: %w", err)
	}
	m.Phase = "tls_handshake"
	_ = raw.SetDeadline(time.Now().Add(o.timeout))
	tlsStart := time.Now()
	err = conn.Handshake()
	m.TLS = time.Since(tlsStart)
	if err != nil {
		cdnSelector.RecordTLS(m.IP, m.TLS, false)
		_ = conn.Close()
		return nil, m, fmt.Errorf("verified TLS handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	negotiated := conn.ConnectionState().NegotiatedProtocol
	if negotiated != "http/1.1" && negotiated != "" {
		cdnSelector.RecordTLS(m.IP, m.TLS, false)
		_ = conn.Close()
		return nil, m, fmt.Errorf("CDN negotiated unsupported ALPN %q", negotiated)
	}
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		cdnSelector.RecordTLS(m.IP, m.TLS, false)
		_ = conn.Close()
		return nil, m, errors.New("TLS certificate chain not verified")
	}
	cdnSelector.RecordTLS(m.IP, m.TLS, true)
	m.Phase = "ready"
	return conn, m, nil
}

func classifyConnectError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout"
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "DNS"), strings.Contains(text, "no IPv4"):
		return "dns"
	case strings.Contains(text, "TCP"):
		return "tcp"
	case strings.Contains(text, "certificate"), strings.Contains(text, "x509"):
		return "certificate"
	case strings.Contains(text, "ALPN"), strings.Contains(text, "hello"):
		return "protocol"
	default:
		return "tls_or_io"
	}
}

func classifyStreamError(err error) string {
	if err == nil || errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return "closed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "io_error"
}

func proxy(ctx context.Context, local net.Conn, o options, roots *x509.CertPool, session string) {
	started := time.Now()
	defer local.Close()
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			_ = local.Close()
			cancel()
		}
	}()
	tlsStarted := time.Now()
	tlsConn, timings, err := connectCDN(dialCtx, o, roots)
	if err != nil {
		log.Printf("session=%s event=connect_failed phase=%s elapsed_ms=%d dns_ms=%d tcp_ms=%d tls_ms=%d endpoint_attempts=%d reason=%s", session, timings.Phase, time.Since(tlsStarted).Milliseconds(), timings.DNS.Milliseconds(), timings.TCP.Milliseconds(), timings.TLS.Milliseconds(), timings.Attempts, classifyConnectError(err))
		return
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	peer := "redacted"
	if o.logPeer {
		peer = tlsConn.RemoteAddr().String()
	}
	log.Printf("session=%s event=tls_ready peer=%s version=0x%04x alpn=%q cert_verified=%t fingerprint=%s dns_ms=%d tcp_ms=%d tls_ms=%d total_ms=%d endpoint_attempts=%d", session,
		peer, state.Version, state.NegotiatedProtocol, len(state.VerifiedChains) > 0, o.fingerprint, timings.DNS.Milliseconds(), timings.TCP.Milliseconds(), timings.TLS.Milliseconds(), time.Since(tlsStarted).Milliseconds(), timings.Attempts)
	if err := startupRequests(dialCtx, tlsConn, o); err != nil {
		log.Printf("session=%s event=startup_failed reason=protocol_or_budget", session)
		return
	}
	_ = local.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(local, "UTLSOK1\n"); err != nil {
		return
	}
	_ = local.SetWriteDeadline(time.Time{})
	var wg sync.WaitGroup
	var once sync.Once
	shutdown := func() { once.Do(func() { _ = tlsConn.Close(); _ = local.Close() }) }
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-cancelDone:
		}
	}()
	var up, down int64
	var upReason, downReason string
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		up, err = io.CopyBuffer(tlsConn, local, make([]byte, 32*1024))
		upReason = classifyStreamError(err)
		shutdown()
	}()
	go func() {
		defer wg.Done()
		var err error
		down, err = io.CopyBuffer(local, tlsConn, make([]byte, 32*1024))
		downReason = classifyStreamError(err)
		shutdown()
	}()
	wg.Wait()
	close(cancelDone)
	log.Printf("session=%s event=closed duration_ms=%d uplink_bytes=%d downlink_bytes=%d up_result=%s down_result=%s", session, time.Since(started).Milliseconds(), up, down, upReason, downReason)
}

func listen(o options) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(o.socket), 0700); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(o.socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("socket path occupied by non-socket file")
		}
		conn, dialErr := net.DialTimeout("unix", o.socket, 300*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("another adapter is already listening")
		}
		if err := os.Remove(o.socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", o.socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(o.socket, 0600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

const bridgeVersion = "6.0.0-alpha1-utls1.8.2"

func newRunID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pid%d", os.Getpid())
	}
	return fmt.Sprintf("%x", b[:])
}

func main() {
	var version, check bool
	flag.BoolVar(&check, "check", false, "validate options and key, then exit without listening")
	flag.BoolVar(&version, "version", false, "print bridge version and exit")
	var o options
	flag.StringVar(&o.socket, "socket", "/run/pacetun-utls/bridge.sock", "root-owned Unix socket")
	flag.StringVar(&o.remote, "remote", "", "CDN domain and port, e.g. example.org:443")
	flag.StringVar(&o.name, "server-name", "", "CDN TLS SNI and verified certificate hostname")
	flag.StringVar(&o.ca, "ca", "/etc/ssl/certs/ca-certificates.crt", "trusted PEM CA bundle")
	flag.StringVar(&o.fingerprint, "fingerprint", "firefox120", "firefox120 or chrome120")
	flag.DurationVar(&o.timeout, "timeout", 20*time.Second, "TCP and TLS establishment timeout")
	flag.IntVar(&o.maxSessions, "max-sessions", 6, "maximum simultaneous authenticated or pending sessions (1-128)")
	flag.BoolVar(&o.logPeer, "log-peer", false, "opt in to logging the selected CDN edge IP")
	flag.StringVar(&o.family, "family", "auto", "auto, ipv4 or ipv6; does not change TLS identity")
	flag.StringVar(&o.bootstrap, "bootstrap-ips", "", "optional comma-separated CDN IPs used if DNS fails")
	flag.StringVar(&o.carrier, "carrier", "websocket", "websocket, http-client or http-server (HTTP experimental)")
	flag.StringVar(&o.startupPaths, "startup-paths", "", "experimental: up to two comma-separated same-origin GET paths; 32 KiB/3s/60s limits")
	flag.StringVar(&o.httpListen, "http-listen", "127.0.0.1:19444", "HTTP server local Nginx upstream")
	flag.StringVar(&o.httpBackend, "http-backend", "127.0.0.1:19443", "fixed local PaceTun WebSocket backend")
	flag.StringVar(&o.httpPath, "http-path", "/assets/transfer/v1", "HTTP carrier path (match both peers)")
	flag.StringVar(&o.httpKey, "http-key", "", "separate 32-byte hex authentication key file for HTTP carrier")
	flag.Parse()
	if version {
		fmt.Printf("pacetun-utls-bridge %s\n", bridgeVersion)
		return
	}
	if err := validate(o); err != nil {
		log.Fatal(err)
	}
	if o.carrier == "http-client" || o.carrier == "http-server" {
		if _, err := httpSecret(o.httpKey); err != nil {
			log.Fatal(err)
		}
	}
	if check {
		fmt.Println("bridge configuration OK")
		return
	}
	if o.carrier == "http-server" {
		if err := runHTTPServer(o); err != nil {
			log.Fatal(err)
		}
		return
	}
	cdnSelector = transportpolicy.NewSelectorWithPolicy(o.family, o.bootstrap)
	roots, err := rootPool(o.ca)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := listen(o)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close(); _ = os.Remove(o.socket) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	runID := newRunID()
	log.Printf("event=bridge_start run=%s profile=%s cert_verification=required max_sessions=%d edge_selection=%s alpn=http/1.1", runID, o.fingerprint, o.maxSessions, o.family)
	slots := make(chan struct{}, o.maxSessions)
	var nextSession uint64
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Print("event=accept_failed reason=io_error")
			continue
		}
		select {
		case slots <- struct{}{}:
			session := fmt.Sprintf("%s-%d", runID, atomic.AddUint64(&nextSession, 1))
			go func() {
				defer func() { <-slots }()
				if o.carrier == "http-client" {
					proxyHTTP(ctx, c, o, roots, session)
				} else {
					proxy(ctx, c, o, roots, session)
				}
			}()
		default:
			log.Print("event=connection_rejected reason=max_sessions")
			_ = c.Close()
		}
	}
}
