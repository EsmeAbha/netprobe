// Package probe measures where time goes in a network request: DNS lookup, TCP connect,
// TLS handshake and time to first byte, and reports TLS certificate expiry.
//
// Target forms:
//
//	https://host/path, http://host/path   full HTTP request, phase timings, status, certificate
//	tls://host:port                       DNS + TCP + TLS handshake only (any TLS service, e.g. SMTPS, Postgres)
//	tcp://host:port                       DNS + TCP connect (is the port reachable?)
//	dns://host                            DNS resolution only
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// Phases are reported in this order.
var PhaseOrder = []string{"dns", "connect", "tls", "ttfb", "total"}

type Options struct {
	Timeout        time.Duration
	Insecure       bool           // skip certificate verification (still reports the certificate)
	RootCAs        *x509.CertPool // nil = system roots
	CertWarnDays   float64        // warn when a certificate expires sooner than this
	ExpectStatus   func(int) bool // nil = 2xx/3xx
	FollowRedirect bool
}

type Result struct {
	Target       string                   `json:"target"`
	Kind         string                   `json:"kind"`
	OK           bool                     `json:"ok"`
	Error        string                   `json:"error,omitempty"`
	FailedPhase  string                   `json:"failed_phase,omitempty"`
	Warning      string                   `json:"warning,omitempty"`
	Phases       map[string]time.Duration `json:"phases_ns"`
	Addrs        []string                 `json:"addrs,omitempty"`
	RemoteAddr   string                   `json:"remote_addr,omitempty"`
	Status       int                      `json:"status,omitempty"`
	Proto        string                   `json:"proto,omitempty"`
	TLSVersion   string                   `json:"tls_version,omitempty"`
	CertSubject  string                   `json:"cert_subject,omitempty"`
	CertNotAfter time.Time                `json:"cert_not_after,omitempty"`
	CertDaysLeft float64                  `json:"cert_days_left,omitempty"`
}

// Probe runs one check. It never panics on network errors; failures are reported in the Result.
func Probe(ctx context.Context, target string, opt Options) Result {
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.CertWarnDays == 0 {
		opt.CertWarnDays = 14
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	r := Result{Target: target, Phases: map[string]time.Duration{}}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		r.Kind, r.Error, r.FailedPhase = "invalid", fmt.Sprintf("cannot parse target %q (want scheme://host)", target), "parse"
		return r
	}
	r.Kind = u.Scheme
	start := time.Now()
	switch u.Scheme {
	case "http", "https":
		probeHTTP(ctx, u, opt, &r)
	case "tls":
		probeConn(ctx, u.Host, true, opt, &r)
	case "tcp":
		probeConn(ctx, u.Host, false, opt, &r)
	case "dns":
		probeDNS(ctx, u.Hostname(), &r)
	default:
		r.Error, r.FailedPhase = "unsupported scheme "+u.Scheme, "parse"
	}
	r.Phases["total"] = time.Since(start)
	r.OK = r.Error == ""
	if r.OK && !r.CertNotAfter.IsZero() && r.CertDaysLeft < opt.CertWarnDays {
		r.Warning = fmt.Sprintf("certificate expires in %.1f days", r.CertDaysLeft)
	}
	return r
}

func probeDNS(ctx context.Context, host string, r *Result) []net.IPAddr {
	t := time.Now()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	r.Phases["dns"] = time.Since(t)
	if err != nil {
		r.Error, r.FailedPhase = explain(err), "dns"
		return nil
	}
	for _, a := range addrs {
		r.Addrs = append(r.Addrs, a.String())
	}
	return addrs
}

func probeConn(ctx context.Context, hostport string, withTLS bool, opt Options, r *Result) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		r.Error, r.FailedPhase = "target needs host:port", "parse"
		return
	}
	addrs := probeDNS(ctx, host, r)
	if r.Error != "" {
		return
	}
	var d net.Dialer
	t := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0].String(), port))
	r.Phases["connect"] = time.Since(t)
	if err != nil {
		r.Error, r.FailedPhase = explain(err), "connect"
		return
	}
	defer conn.Close()
	r.RemoteAddr = conn.RemoteAddr().String()
	if !withTLS {
		return
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: opt.Insecure, RootCAs: opt.RootCAs})
	t = time.Now()
	err = tc.HandshakeContext(ctx)
	r.Phases["tls"] = time.Since(t)
	if err != nil {
		r.Error, r.FailedPhase = explain(err), "tls"
		return
	}
	recordTLS(tc.ConnectionState(), r)
}

func probeHTTP(ctx context.Context, u *url.URL, opt Options, r *Result) {
	var dnsStart, connStart, tlsStart, reqStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:      func(httptrace.DNSDoneInfo) { r.Phases["dns"] = time.Since(dnsStart) },
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		// a phase is only recorded when it succeeds, so failedPhase can tell where things broke
		ConnectDone: func(_, addr string, err error) {
			if err == nil {
				r.Phases["connect"] = time.Since(connStart)
				r.RemoteAddr = addr
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				r.Phases["tls"] = time.Since(tlsStart)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { reqStart = time.Now() },
		GotFirstResponseByte: func() {
			if !reqStart.IsZero() {
				r.Phases["ttfb"] = time.Since(reqStart)
			}
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true, // measure a fresh connection every time
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: opt.Insecure, RootCAs: opt.RootCAs},
			Proxy:             http.ProxyFromEnvironment,
		},
	}
	if !opt.FollowRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "netprobe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		r.Error = explain(err)
		r.FailedPhase = failedPhase(r.Phases, u.Scheme == "https")
		return
	}
	defer resp.Body.Close()
	r.Status, r.Proto = resp.StatusCode, resp.Proto
	if resp.TLS != nil {
		recordTLS(*resp.TLS, r)
	}
	ok := opt.ExpectStatus
	if ok == nil {
		ok = func(s int) bool { return s >= 200 && s < 400 }
	}
	if !ok(resp.StatusCode) {
		r.Error, r.FailedPhase = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode), "http"
	}
}

func recordTLS(cs tls.ConnectionState, r *Result) {
	r.TLSVersion = tls.VersionName(cs.Version)
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		r.CertSubject = c.Subject.CommonName
		if r.CertSubject == "" && len(c.DNSNames) > 0 {
			r.CertSubject = c.DNSNames[0]
		}
		r.CertNotAfter = c.NotAfter
		r.CertDaysLeft = time.Until(c.NotAfter).Hours() / 24
	}
}

// failedPhase infers which phase an HTTP error happened in from the phases that completed.
func failedPhase(p map[string]time.Duration, https bool) string {
	switch {
	case p["dns"] == 0 && p["connect"] == 0:
		return "dns"
	case p["connect"] == 0:
		return "connect"
	case https && p["tls"] == 0:
		return "tls"
	default:
		return "http"
	}
}

// explain turns Go network errors into the words an on-call engineer would use.
func explain(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "i/o timeout"):
		return "timeout: " + msg
	case errors.As(err, &dnsErr):
		if dnsErr.IsNotFound {
			return "DNS: no such host (NXDOMAIN): " + dnsErr.Name
		}
		return "DNS lookup failed: " + msg
	case errors.As(err, &hostErr):
		return "TLS: certificate is not valid for this hostname: " + msg
	case errors.As(err, &unknownCA):
		return "TLS: certificate signed by unknown authority (self-signed or missing intermediate)"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "TLS: certificate expired or not yet valid"
		}
		return "TLS: invalid certificate: " + msg
	case errors.As(err, &certErr):
		return "TLS: certificate verification failed: " + msg
	case strings.Contains(msg, "connection refused"):
		return "connection refused: nothing listening on that port (or a firewall rejects it)"
	case strings.Contains(msg, "connection reset"):
		return "connection reset by peer"
	}
	return msg
}
