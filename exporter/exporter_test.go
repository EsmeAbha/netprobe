package exporter

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EsmeAbha/netprobe/probe"
)

func TestMetricsOutput(t *testing.T) {
	e := New([]string{"https://ok.test", `https://bad"quote.test`}, probe.Options{})
	e.Probe = func(_ context.Context, target string, _ probe.Options) probe.Result {
		if strings.Contains(target, "bad") {
			return probe.Result{Target: target, Kind: "https", FailedPhase: "tls", Phases: map[string]time.Duration{"total": time.Second}}
		}
		return probe.Result{Target: target, Kind: "https", OK: true, Status: 200, CertSubject: "ok.test",
			CertNotAfter: time.Now().Add(240 * time.Hour), CertDaysLeft: 10,
			Phases: map[string]time.Duration{"dns": 5 * time.Millisecond, "total": 50 * time.Millisecond}}
	}
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	out := string(body)
	for _, want := range []string{
		`netprobe_up{target="https://ok.test",kind="https",failed_phase=""} 1`,
		`netprobe_up{target="https://bad\"quote.test",kind="https",failed_phase="tls"} 0`,
		`netprobe_phase_seconds{target="https://ok.test",phase="dns"} 0.005`,
		`netprobe_http_status_code{target="https://ok.test"} 200`,
		`netprobe_tls_cert_expiry_days{target="https://ok.test",subject="ok.test"} 10`,
		"# TYPE netprobe_up gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	New(nil, probe.Options{}).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
}
