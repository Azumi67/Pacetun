package transportpolicy

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxEdges        = 8
	perEdgeTimeout  = 4 * time.Second
	failureCooldown = 20 * time.Second
)

type Metrics struct {
	DNS        time.Duration
	TCP        time.Duration
	Attempts   int
	SelectedIP string
}

type health struct {
	failedUntil    time.Time
	tlsFailedUntil time.Time
	latency        time.Duration
	tlsLatency     time.Duration
}

type Selector struct {
	mu        sync.Mutex
	edges     map[string]health
	rotate    uint64
	family    string
	bootstrap []net.IPAddr
	cache     map[string]dnsEntry
}

type dnsEntry struct {
	ips     []net.IPAddr
	expires time.Time
}

func NewSelector() *Selector { return NewSelectorWithPolicy("ipv4", "") }
func NewSelectorWithPolicy(family, bootstrap string) *Selector {
	if family == "" {
		family = "auto"
	}
	s := &Selector{edges: make(map[string]health), family: family, cache: make(map[string]dnsEntry)}
	for _, p := range strings.Split(bootstrap, ",") {
		if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil {
			s.bootstrap = append(s.bootstrap, net.IPAddr{IP: ip})
		}
	}
	return s
}
func (s *Selector) resolve(ctx context.Context, host string, lookup lookupFunc) ([]net.IPAddr, error) {
	s.mu.Lock()
	cached, ok := s.cache[host]
	s.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.ips, nil
	}
	dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := lookup(dnsCtx, host)
	if err != nil || len(ips) == 0 {
		if len(s.bootstrap) > 0 {
			return append([]net.IPAddr(nil), s.bootstrap...), nil
		}
		if err == nil {
			err = errors.New("empty DNS answer")
		}
		return nil, err
	}
	s.mu.Lock()
	if len(s.cache) >= 16 {
		s.cache = make(map[string]dnsEntry)
	}
	s.cache[host] = dnsEntry{append([]net.IPAddr(nil), ips...), time.Now().Add(60 * time.Second)}
	s.mu.Unlock()
	return ips, nil
}
func candidatesFor(ips []net.IPAddr, family string) []string {
	seen := make(map[string]bool)
	var v4, v6 []string
	for _, a := range ips {
		if a.IP == nil || a.Zone != "" {
			continue
		}
		is4 := a.IP.To4() != nil
		if (family == "ipv4" && !is4) || (family == "ipv6" && is4) {
			continue
		}
		ip := a.IP.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if is4 {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	var out []string
	for i := 0; len(out) < maxEdges && (i < len(v4) || i < len(v6)); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if len(out) < maxEdges && i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

type lookupFunc func(context.Context, string) ([]net.IPAddr, error)
type dialFunc func(context.Context, string, string) (net.Conn, error)

func ipv4Candidates(ips []net.IPAddr) []string {
	seen := make(map[string]bool)
	var out []string
	for _, addr := range ips {
		ip := addr.IP.To4()
		if ip == nil {
			continue
		}
		text := ip.String()
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	if len(out) > maxEdges {
		out = out[:maxEdges]
	}
	return out
}

func (s *Selector) order(edges []string, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotate++
	offset := int(s.rotate % uint64(len(edges)))
	out := append([]string(nil), edges...)
	positions := make(map[string]int, len(edges))
	for i, ip := range edges {
		positions[ip] = (i - offset + len(edges)) % len(edges)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := s.edges[out[i]], s.edges[out[j]]
		af, bf := now.Before(a.failedUntil) || now.Before(a.tlsFailedUntil), now.Before(b.failedUntil) || now.Before(b.tlsFailedUntil)
		if af != bf {
			return !af
		}
		bucket := func(h health) int {
			if h.tlsLatency > 0 {
				n := int(h.tlsLatency / (50 * time.Millisecond))
				if n > 10 {
					return 10
				}
				return n
			}
			if h.latency <= 0 {
				return 3
			}
			n := int(h.latency / (50 * time.Millisecond))
			if n > 10 {
				return 10
			}
			return n
		}
		x, y := bucket(a), bucket(b)
		if x != y {
			return x < y
		}
		return positions[out[i]] < positions[out[j]]
	})
	return out
}

func (s *Selector) record(ip string, latency time.Duration, ok bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.edges) > 64 {
		s.edges = make(map[string]health)
	}
	old := s.edges[ip]
	if ok {
		old.failedUntil = time.Time{} 
		if old.latency == 0 {
			old.latency = latency
		} else {
			old.latency = (3*old.latency + latency) / 4
		}
	} else {
		old.failedUntil = now.Add(failureCooldown)
	}
	s.edges[ip] = old
}

func (s *Selector) RecordTLS(ip string, latency time.Duration, verified bool) {
	if net.ParseIP(ip) == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.edges) > 64 {
		s.edges = make(map[string]health)
	}
	h := s.edges[ip]
	if !verified {
		h.tlsFailedUntil = time.Now().Add(failureCooldown)
	} else {
		h.tlsFailedUntil = time.Time{}
		if h.tlsLatency == 0 {
			h.tlsLatency = latency
		} else {
			h.tlsLatency = (3*h.tlsLatency + latency) / 4
		}
	}
	s.edges[ip] = h
}

func (s *Selector) Dial(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, Metrics, error) {
	resolver := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	return s.dial(ctx, endpoint, timeout, resolver, dialer.DialContext)
}

func (s *Selector) dial(ctx context.Context, endpoint string, timeout time.Duration, lookup lookupFunc, dial dialFunc) (net.Conn, Metrics, error) {
	var m Metrics
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, m, errors.New("invalid CDN endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	var ips []net.IPAddr
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []net.IPAddr{{IP: parsed}}
	} else {
		ips, err = s.resolve(ctx, host, lookup)
	}
	m.DNS = time.Since(started)
	if err != nil {
		return nil, m, errors.New("CDN DNS lookup failed")
	}
	candidates := candidatesFor(ips, s.family)
	if len(candidates) == 0 {
		return nil, m, errors.New("CDN has no endpoint for selected address family")
	}
	ordered := s.order(candidates, time.Now())
	var lastErr error
	for index, ip := range ordered {
		if ctx.Err() != nil {
			break
		}
		deadline, _ := ctx.Deadline()
		edgeBudget := time.Until(deadline) / time.Duration(len(ordered)-index)
		if edgeBudget > perEdgeTimeout {
			edgeBudget = perEdgeTimeout
		}
		if edgeBudget <= 0 {
			break
		}
		attemptCtx, stop := context.WithTimeout(ctx, edgeBudget)
		start := time.Now()
		m.Attempts++
		network := "tcp6"
		if net.ParseIP(ip).To4() != nil {
			network = "tcp4"
		}
		conn, dialErr := dial(attemptCtx, network, net.JoinHostPort(ip, port))
		stop()
		elapsed := time.Since(start)
		m.TCP += elapsed
		if dialErr == nil && conn != nil {
			s.record(ip, elapsed, true, time.Now())
			m.SelectedIP = ip
			return conn, m, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		s.record(ip, elapsed, false, time.Now())
		lastErr = dialErr
	}
	if ctx.Err() != nil {
		return nil, m, ctx.Err()
	}
	if lastErr != nil {
		return nil, m, errors.New("all resolved CDN TCP endpoints failed")
	}
	return nil, m, errors.New("CDN TCP dial unavailable")
}

func ParsePort(endpoint string) bool {
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
