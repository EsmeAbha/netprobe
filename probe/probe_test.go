package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hi")) }

func tlsServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(ok))
	t.Cleanup(srv.Close)
	return srv, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func TestHTTPSuccessRecordsPhases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(ok))
	defer srv.Close()
	r := Probe(context.Background(), srv.URL, Options{})
	if !r.OK || r.Status != 200 {
		t.Fatalf("want OK 200, got %+v", r)
	}
	for _, p := range []string{"connect", "ttfb", "total"} {
		if _, found := r.Phases[p]; !found {
			t.Errorf("missing phase %s in %v", p, r.Phases)
		}
	}
}

func TestHTTPSTrustedCertificate(t *testing.T) {
	srv, pool := tlsServer(t)
	r := Probe(context.Background(), srv.URL, Options{RootCAs: pool})
	if !r.OK || r.TLSVersion == "" || r.CertDaysLeft <= 0 || r.Phases["tls"] == 0 {
		t.Fatalf("want OK with TLS details, got %+v", r)
	}
}

func TestHTTPSUntrustedCertificateFailsInTLSPhase(t *testing.T) {
	srv, _ := tlsServer(t)
	r := Probe(context.Background(), srv.URL, Options{})
	if r.OK || r.FailedPhase != "tls" || !strings.Contains(r.Error, "unknown authority") {
		t.Fatalf("want TLS unknown-authority failure, got phase=%q err=%q", r.FailedPhase, r.Error)
	}
	r = Probe(context.Background(), srv.URL, Options{Insecure: true})
	if !r.OK || r.CertNotAfter.IsZero() {
		t.Fatalf("insecure mode should succeed and still report the cert: %+v", r)
	}
}

func TestUnexpectedStatusFailsInHTTPPhase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	r := Probe(context.Background(), srv.URL, Options{})
	if r.OK || r.FailedPhase != "http" || r.Status != 503 {
		t.Fatalf("want http-phase failure with 503, got %+v", r)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	r := Probe(context.Background(), srv.URL, Options{Timeout: 200 * time.Millisecond})
	if r.OK || !strings.HasPrefix(r.Error, "timeout") {
		t.Fatalf("want timeout, got %+v", r)
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestTCPRefusedAndOpen(t *testing.T) {
	r := Probe(context.Background(), "tcp://"+freePort(t), Options{Timeout: 2 * time.Second})
	if r.OK || r.FailedPhase != "connect" {
		t.Fatalf("want connect failure, got %+v", r)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	r = Probe(context.Background(), "tcp://"+l.Addr().String(), Options{})
	if !r.OK || r.RemoteAddr == "" {
		t.Fatalf("want open port OK, got %+v", r)
	}
}

func TestTLSOnlyTarget(t *testing.T) {
	srv, pool := tlsServer(t)
	r := Probe(context.Background(), "tls://"+srv.Listener.Addr().String(), Options{RootCAs: pool})
	if !r.OK || r.Phases["tls"] == 0 || r.Status != 0 {
		t.Fatalf("want TLS handshake only, got %+v", r)
	}
}

func TestDNS(t *testing.T) {
	if r := Probe(context.Background(), "dns://localhost", Options{}); !r.OK || len(r.Addrs) == 0 {
		t.Fatalf("localhost should resolve: %+v", r)
	}
	r := Probe(context.Background(), "dns://no-such-host.invalid", Options{Timeout: 5 * time.Second})
	if r.OK || r.FailedPhase != "dns" {
		t.Fatalf("want DNS failure, got %+v", r)
	}
}

func TestExpiringCertificateWarns(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expiring.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()

	r := Probe(context.Background(), srv.URL, Options{RootCAs: pool})
	if !r.OK || !strings.Contains(r.Warning, "expires in") || r.CertSubject != "expiring.test" {
		t.Fatalf("want OK with expiry warning, got %+v", r)
	}
}

func TestInvalidTarget(t *testing.T) {
	if r := Probe(context.Background(), "example.com", Options{}); r.OK || r.FailedPhase != "parse" {
		t.Fatalf("want parse failure, got %+v", r)
	}
}
