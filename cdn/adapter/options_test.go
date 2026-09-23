package main

import (
	"testing"
	"time"
)

func TestAddressAndLimitValidation(t *testing.T) {
	good := options{socket: "/run/pacetun-utls/bridge.sock", remote: "ws-edge.example.test:443", name: "ws-edge.example.test", ca: "/etc/ssl/certs/ca-certificates.crt", fingerprint: "firefox120", timeout: 20 * time.Second, maxSessions: 16}
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	badRemote := []string{"http://example.test", "example.test:http", "example.test:0", "example.test:65536", "example.test:443/path", "foo@bar:443", "-bad.test:443", "example.test:443?x=1", "example.test:-1", "example.test:9999999999999999999"}
	for _, value := range badRemote {
		check := good
		check.remote = value
		if validate(check) == nil {
			t.Errorf("accepted invalid remote %q", value)
		}
	}
	for _, value := range []string{"example.test:443", "127.0.0.1:443", "[::1]:443"} {
		check := good
		check.remote = value
		if err := validate(check); err != nil {
			t.Errorf("rejected valid remote %q: %v", value, err)
		}
	}
	for _, value := range []int{-1, 0, 129} {
		check := good
		check.maxSessions = value
		if validate(check) == nil {
			t.Errorf("accepted invalid max-sessions %d", value)
		}
	}
	check := good
	check.name = "http://example.test"
	if validate(check) == nil {
		t.Fatal("URL syntax accepted as TLS SNI")
	}
	check = good
	check.fingerprint = "random"
	if validate(check) == nil {
		t.Fatal("unsupported fingerprint accepted")
	}
	check = good
	check.timeout = time.Millisecond
	if validate(check) == nil {
		t.Fatal("unbounded timeout accepted")
	}
}
