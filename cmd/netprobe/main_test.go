package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckExitCodes(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer down.Close()

	var out bytes.Buffer
	if code := check([]string{up.URL}, &out); code != 0 {
		t.Fatalf("healthy target: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "TOTAL ms") || !strings.Contains(out.String(), "OK") {
		t.Fatalf("table missing columns:\n%s", out.String())
	}
	out.Reset()
	if code := check([]string{up.URL, down.URL}, &out); code != 1 {
		t.Fatalf("one failing target should exit 1, got %d", code)
	}
	if code := check([]string{}, &out); code != 2 {
		t.Fatalf("no targets should exit 2, got %d", code)
	}
}

func TestTargetsFileAndJSON(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()
	f := filepath.Join(t.TempDir(), "targets.txt")
	os.WriteFile(f, []byte("# comment\n"+up.URL+"  # inline comment\n\n"), 0o644)
	var out bytes.Buffer
	if code := check([]string{"-json", "-f", f}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), `"ok": true`) {
		t.Fatalf("want JSON result, got %s", out.String())
	}
}

func TestFlagsAfterTargets(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()
	var out bytes.Buffer
	if code := check([]string{up.URL, "-timeout", "2s", "-json"}, &out); code != 0 || !strings.Contains(out.String(), `"ok": true`) {
		t.Fatalf("flags after targets should work: exit %d\n%s", code, out.String())
	}
}
