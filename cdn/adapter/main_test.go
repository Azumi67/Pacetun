package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOptionsFailClosed(t *testing.T) {
	good := options{socket: "/run/pacetun-utls/bridge.sock", remote: "example.test:443", name: "example.test", ca: "/etc/ssl/certs/ca-certificates.crt", fingerprint: "firefox120", timeout: 20 * time.Second, maxSessions: 16}
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.socket = "relative.sock"
	if validate(bad) == nil {
		t.Fatal("relative unix socket accepted")
	}
	bad = good
	bad.fingerprint = "random"
	if validate(bad) == nil {
		t.Fatal("arbitrary unvalidated profile accepted")
	}
	bad = good
	bad.ca = ""
	if validate(bad) == nil {
		t.Fatal("empty CA bundle accepted")
	}
	bad = good
	bad.remote = "http://example.test"
	if validate(bad) == nil {
		t.Fatal("non host:port remote accepted")
	}
}

func TestVerifiedTLSAndHostname(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "PaceTun test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "good.test"}, DNSNames: []string{"good.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	roots, err := rootPool(caFile)
	if err != nil {
		t.Fatal(err)
	}
	opts := options{socket: "/tmp/test.sock", remote: listener.Addr().String(), name: "good.test", ca: caFile, fingerprint: "firefox120", timeout: 3 * time.Second}
	conn, metrics, err := connectCDN(context.Background(), opts, roots)
	if err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "http/1.1" {
		t.Fatalf("unexpected ALPN %q", proto)
	}
	if metrics.Phase != "ready" || metrics.Attempts < 1 || metrics.TLS <= 0 {
		t.Fatalf("invalid phase timing: %+v", metrics)
	}
	conn.Close()
	opts.name = "wrong.test"
	_, _, err = connectCDN(context.Background(), opts, roots)
	if err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Logf("hostname rejection: %v", err)
	}
	badRoots := x509.NewCertPool()
	opts.name = "good.test"
	_, _, err = connectCDN(context.Background(), opts, badRoots)
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestServerRejectsNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.sock")
	if err := os.WriteFile(path, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := listen(options{socket: path})
	if err == nil {
		t.Fatal("overwrote non-socket file")
	}
}
