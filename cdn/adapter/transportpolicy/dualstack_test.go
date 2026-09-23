package transportpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDualStackFallbackAndTLSHealth(t *testing.T) {
	s := NewSelectorWithPolicy("auto", "")
	s.rotate = 1
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, nil
	}
	var networks []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		networks = append(networks, network)
		if network == "tcp6" {
			return nil, errors.New("unreachable")
		}
		return &mockConn{}, nil
	}
	_, m, err := s.dial(context.Background(), "cdn.test:443", time.Second, lookup, dial)
	if err != nil || m.Attempts != 2 || len(networks) != 2 || networks[0] != "tcp6" || networks[1] != "tcp4" {
		t.Fatalf("fallback: %+v %v %v", m, err, networks)
	}
	s.RecordTLS("2001:db8::1", time.Millisecond, false)
	if !s.edges["2001:db8::1"].tlsFailedUntil.After(time.Now()) {
		t.Fatal("IPv6 TLS cooldown lost")
	}
}
func TestIPv6OnlyAndBootstrap(t *testing.T) {
	s := NewSelectorWithPolicy("ipv6", "192.0.2.1,2001:db8::2")
	lookup := func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("DNS blocked") }
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp6" || address != "[2001:db8::2]:443" {
			t.Fatalf("wrong endpoint %s %s", network, address)
		}
		return &mockConn{}, nil
	}
	_, m, err := s.dial(context.Background(), "cdn.test:443", time.Second, lookup, dial)
	if err != nil || m.SelectedIP != "2001:db8::2" {
		t.Fatalf("bootstrap %+v %v", m, err)
	}
}
func TestDNSCacheBoundedAndCancellation(t *testing.T) {
	s := NewSelectorWithPolicy("auto", "")
	calls := 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return &mockConn{}, nil }
	for i := 0; i < 3; i++ {
		_, _, e := s.dial(context.Background(), "cdn.test:443", time.Second, lookup, dial)
		if e != nil {
			t.Fatal(e)
		}
	}
	if calls != 1 {
		t.Fatalf("DNS cache calls %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, e := s.dial(ctx, "cdn.test:443", time.Second, lookup, func(context.Context, string, string) (net.Conn, error) { t.Fatal("dial after cancel"); return nil, nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestCandidateFamiliesBounded(t *testing.T) {
	var ips []net.IPAddr
	for i := 0; i < 20; i++ {
		ips = append(ips, net.IPAddr{IP: net.ParseIP("2001:db8::" + string(rune('a'+i%6)))})
	}
	ips = append(ips, net.IPAddr{IP: net.ParseIP("192.0.2.1")})
	out := candidatesFor(ips, "auto")
	if len(out) > 8 || len(out) < 2 || out[1] != "192.0.2.1" {
		t.Fatal(out)
	}
}
