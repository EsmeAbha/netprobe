// Package exporter serves probe results in the Prometheus text format, blackbox-exporter style:
// every scrape runs the probes, so results are never staler than the scrape interval.
package exporter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/EsmeAbha/netprobe/probe"
)

type Exporter struct {
	Targets []string
	Options probe.Options
	// Probe is swappable for tests.
	Probe func(context.Context, string, probe.Options) probe.Result
}

func New(targets []string, opt probe.Options) *Exporter {
	return &Exporter{Targets: targets, Options: opt, Probe: probe.Probe}
}

func (e *Exporter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Write(w, e.run(r.Context()))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}

func (e *Exporter) run(ctx context.Context) []probe.Result {
	results := make([]probe.Result, len(e.Targets))
	var wg sync.WaitGroup
	for i, t := range e.Targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			results[i] = e.Probe(ctx, t, e.Options)
		}(i, t)
	}
	wg.Wait()
	return results
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// Write renders results as Prometheus metrics.
func Write(w io.Writer, results []probe.Result) {
	sort.Slice(results, func(i, j int) bool { return results[i].Target < results[j].Target })
	fmt.Fprintln(w, "# HELP netprobe_up 1 if the probe succeeded.")
	fmt.Fprintln(w, "# TYPE netprobe_up gauge")
	for _, r := range results {
		up := 0
		if r.OK {
			up = 1
		}
		fmt.Fprintf(w, "netprobe_up{target=\"%s\",kind=\"%s\",failed_phase=\"%s\"} %d\n", esc(r.Target), r.Kind, r.FailedPhase, up)
	}
	fmt.Fprintln(w, "# HELP netprobe_phase_seconds Duration of each phase of the probe.")
	fmt.Fprintln(w, "# TYPE netprobe_phase_seconds gauge")
	for _, r := range results {
		for _, p := range probe.PhaseOrder {
			if d, ok := r.Phases[p]; ok {
				fmt.Fprintf(w, "netprobe_phase_seconds{target=\"%s\",phase=\"%s\"} %g\n", esc(r.Target), p, d.Seconds())
			}
		}
	}
	fmt.Fprintln(w, "# HELP netprobe_http_status_code HTTP status of the response.")
	fmt.Fprintln(w, "# TYPE netprobe_http_status_code gauge")
	for _, r := range results {
		if r.Status != 0 {
			fmt.Fprintf(w, "netprobe_http_status_code{target=\"%s\"} %d\n", esc(r.Target), r.Status)
		}
	}
	fmt.Fprintln(w, "# HELP netprobe_tls_cert_expiry_days Days until the leaf certificate expires.")
	fmt.Fprintln(w, "# TYPE netprobe_tls_cert_expiry_days gauge")
	for _, r := range results {
		if !r.CertNotAfter.IsZero() {
			fmt.Fprintf(w, "netprobe_tls_cert_expiry_days{target=\"%s\",subject=\"%s\"} %g\n", esc(r.Target), esc(r.CertSubject), r.CertDaysLeft)
		}
	}
}
