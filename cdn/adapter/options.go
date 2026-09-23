package main

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type options struct {
	startupPaths string
	carrier      string
	httpListen   string
	httpBackend  string
	httpPath     string
	httpKey      string
	socket       string
	remote       string
	name         string
	ca           string
	fingerprint  string
	timeout      time.Duration
	maxSessions  int
	family       string
	bootstrap    string
	logPeer      bool 
}

func validHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) < 1 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func validate(o options) error {
	if !validStartupPaths(o.startupPaths) {
		return errors.New("startup paths: at most two same-origin absolute paths")
	}
	if o.carrier != "" && o.carrier != "websocket" && o.carrier != "http-client" && o.carrier != "http-server" {
		return errors.New("invalid carrier")
	}
	if o.carrier == "http-client" || o.carrier == "http-server" {
		if !validHTTPPath(o.httpPath) || o.httpKey == "" {
			return errors.New("HTTP carrier requires --http-path and --http-key")
		}
		if o.maxSessions < 1 || o.maxSessions > 16 {
			return errors.New("HTTP carrier max-sessions must be 1..16")
		}
		if o.startupPaths != "" {
			return errors.New("startup requests currently require websocket carrier")
		}
	}
	if o.carrier == "http-server" {
		if !loopbackAddress(o.httpListen) || !loopbackAddress(o.httpBackend) {
			return errors.New("HTTP server listen/backend must use numeric loopback addresses")
		}
		return nil
	}
	if o.family != "" && o.family != "auto" && o.family != "ipv4" && o.family != "ipv6" {
		return errors.New("--family must be auto, ipv4 or ipv6")
	}
	if o.bootstrap != "" {
		parts := strings.Split(o.bootstrap, ",")
		if len(parts) > 8 {
			return errors.New("at most 8 bootstrap IP addresses")
		}
		for _, part := range parts {
			if net.ParseIP(strings.TrimSpace(part)) == nil {
				return errors.New("--bootstrap-ips requires numeric IP addresses")
			}
		}
	}

	if !filepath.IsAbs(o.socket) || len(o.socket) >= 100 || strings.ContainsRune(o.socket, '\x00') {
		return errors.New("--socket must be a short absolute Unix socket path")
	}
	host, port, err := net.SplitHostPort(o.remote)
	if err != nil || !validHost(host) {
		return errors.New("--remote must be host:port or [IPv6]:port (without URL syntax)")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("--remote port must be numeric and between 1 and 65535")
	}
	if !validHost(o.name) {
		return errors.New("invalid --server-name")
	}
	if o.ca == "" {
		return errors.New("--ca certificate bundle is required")
	}
	if o.fingerprint != "firefox120" && o.fingerprint != "chrome120" {
		return errors.New("--fingerprint must be firefox120 or chrome120")
	}
	if o.timeout < time.Second || o.timeout > 120*time.Second {
		return errors.New("--timeout must be between 1s and 120s")
	}
	if o.maxSessions < 1 || o.maxSessions > 128 {
		return errors.New("--max-sessions must be between 1 and 128")
	}
	return nil
}
