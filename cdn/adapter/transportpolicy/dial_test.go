package transportpolicy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type mockConn struct{ net.Conn }

func (c *mockConn) Close() error { return nil }
func TestIPv4UniqueAndBounded(t *testing.T) {
	ips := []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.1")}}
	for n := 2; n < 20; n++ {
		ips = append(ips, net.IPAddr{IP: net.IPv4(192, 0, 2, byte(n))})
	}
	out := ipv4Candidates(ips)
	if len(out) != maxEdges || out[0] != "192.0.2.1" {
		t.Fatalf("bad candidate list: %v", out)
	}
}
func TestFallbackAndCooldown(t *testing.T) {
	s := NewSelector()
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}}, nil
	}
	attempts := []string{}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		if strings.Contains(address, "192.0.2.1") {
			return nil, errors.New("refused")
		}
		return &mockConn{}, nil
	}
	s.rotate = 1
	_, metrics, err := s.dial(context.Background(), "cdn.test:443", 2*time.Second, lookup, dial)
	if err != nil || metrics.Attempts != 2 || metrics.SelectedIP != "192.0.2.2" {
		t.Fatalf("fallback: %+v %v %v", metrics, err, attempts)
	}
	attempts = nil
	_, metrics, err = s.dial(context.Background(), "cdn.test:443", 2*time.Second, lookup, dial)
	if err != nil || metrics.Attempts != 1 || metrics.SelectedIP != "192.0.2.2" {
		t.Fatalf("cooldown not preferred: %+v %v %v", metrics, err, attempts)
	}
}
func TestDNSFailClosed(t *testing.T) {
	s := NewSelector()
	lookup := func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("lookup failed") }
	dial := func(context.Context, string, string) (net.Conn, error) { t.Fatal("dial must not run"); return nil, nil }
	_, _, err := s.dial(context.Background(), "cdn.test:443", time.Second, lookup, dial)
	if err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("expected DNS failure: %v", err)
	}
}
func TestNoIPv6AndValidPorts(t *testing.T) {
	if len(ipv4Candidates([]net.IPAddr{{IP: net.ParseIP("2001:db8::1")}})) != 0 {
		t.Fatal("IPv6 accepted on tcp4 bridge")
	}
	for _, p := range []string{"x:0", "x:65536", "x:bad"} {
		if ParsePort(p) {
			t.Fatalf("accepted %s", p)
		}
	}
	if !ParsePort("cdn.test:443") {
		t.Fatal("rejected valid port")
	}
}
func TestCancelledDoesNotDial(t *testing.T) {
	s := NewSelector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial after cancellation")
		return nil, nil
	}
	_, _, err := s.dial(ctx, "cdn.test:443", time.Second, lookup, dial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestTLSFailureCooldownSurvivesTCPSuccess(t *testing.T) {
	s := NewSelector()
	bad, good := "192.0.2.1", "192.0.2.2"
	s.RecordTLS(bad, 90*time.Millisecond, false)
	s.record(bad, 10*time.Millisecond, true, time.Now())
	ranked := s.order([]string{bad, good}, time.Now())
	if ranked[0] != good {
		t.Fatalf("TLS failure ignored after TCP success: %v", ranked)
	}
	s.RecordTLS(bad, 50*time.Millisecond, true)
	s.mu.Lock()
	h := s.edges[bad]
	s.mu.Unlock()
	if !h.tlsFailedUntil.IsZero() || h.tlsLatency != 50*time.Millisecond {
		t.Fatalf("successful TLS not recorded: %+v", h)
	}
}
