// netprobe: find out where a request is slow or failing (DNS, TCP, TLS, server) and watch certificates.
//
//	netprobe check https://example.com tcp://db.internal:5432 dns://api.example.com
//	netprobe check -json -f targets.txt
//	netprobe serve -listen :9115 -f targets.txt      # Prometheus exporter
//
// check exits 1 if any target fails, so it works in cron jobs and CI.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/EsmeAbha/netprobe/exporter"
	"github.com/EsmeAbha/netprobe/probe"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(check(os.Args[2:], os.Stdout))
	case "serve":
		os.Exit(serve(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: netprobe check [flags] TARGET...   |   netprobe serve [flags] TARGET...")
	fmt.Fprintln(os.Stderr, "targets: https://host/path  http://...  tls://host:port  tcp://host:port  dns://host")
}

type common struct {
	timeout  time.Duration
	insecure bool
	warnDays float64
	file     string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-target timeout")
	fs.BoolVar(&c.insecure, "insecure", false, "skip TLS verification (certificate is still reported)")
	fs.Float64Var(&c.warnDays, "cert-warn-days", 14, "warn when a certificate expires within this many days")
	fs.StringVar(&c.file, "f", "", "file with one target per line (# comments allowed)")
}

func (c *common) targets(args []string) ([]string, error) {
	targets := append([]string{}, args...)
	if c.file != "" {
		f, err := os.Open(c.file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
			if line != "" {
				targets = append(targets, line)
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets given")
	}
	return targets, nil
}

// parse accepts flags before or after targets (Go's flag package stops at the first non-flag).
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func (c *common) options() probe.Options {
	return probe.Options{Timeout: c.timeout, Insecure: c.insecure, CertWarnDays: c.warnDays}
}

func check(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	var c common
	c.register(fs)
	asJSON := fs.Bool("json", false, "print JSON instead of a table")
	positional, err := parse(fs, args)
	if err != nil {
		return 2
	}
	targets, err := c.targets(positional)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	results := make([]probe.Result, len(targets))
	done := make(chan struct{})
	for i, t := range targets {
		go func(i int, t string) {
			results[i] = probe.Probe(context.Background(), t, c.options())
			done <- struct{}{}
		}(i, t)
	}
	for range targets {
		<-done
	}

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		printTable(out, results)
	}
	for _, r := range results {
		if !r.OK {
			return 1
		}
	}
	return 0
}

func ms(d time.Duration, ok bool) string {
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(d.Microseconds())/1000)
}

func printTable(out io.Writer, results []probe.Result) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tRESULT\tDNS ms\tCONNECT ms\tTLS ms\tTTFB ms\tTOTAL ms\tSTATUS\tCERT DAYS\tDETAIL")
	for _, r := range results {
		res := "OK"
		detail := r.RemoteAddr
		if !r.OK {
			res, detail = "FAIL("+r.FailedPhase+")", r.Error
		} else if r.Warning != "" {
			res, detail = "WARN", r.Warning
		}
		status, cert := "-", "-"
		if r.Status != 0 {
			status = fmt.Sprint(r.Status)
		}
		if !r.CertNotAfter.IsZero() {
			cert = fmt.Sprintf("%.0f", r.CertDaysLeft)
		}
		p := func(n string) string { d, ok := r.Phases[n]; return ms(d, ok) }
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Target, res, p("dns"), p("connect"), p("tls"),
			p("ttfb"), p("total"), status, cert, detail)
	}
	tw.Flush()
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var c common
	c.register(fs)
	listen := fs.String("listen", ":9115", "address for /metrics and /healthz")
	positional, err := parse(fs, args)
	if err != nil {
		return 2
	}
	targets, err := c.targets(positional)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	srv := &http.Server{Addr: *listen, Handler: exporter.New(targets, c.options()).Handler(),
		ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown) // finish in-flight scrapes, then exit
	}()
	log.Printf("netprobe exporter on %s probing %d targets", *listen, len(targets))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Print(err)
		return 1
	}
	return 0
}
