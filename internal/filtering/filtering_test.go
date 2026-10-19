// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package filtering

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, ppd string) (*Engine, queue.Printer, queue.Job, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("production filters intentionally refuse root")
	}
	dir := t.TempDir()
	catalog, err := drivers.Open(filepath.Join(dir, "ppds"))
	if err != nil {
		t.Fatal(err)
	}
	var a bytes.Buffer
	gz := gzip.NewWriter(&a)
	tarw := tar.NewWriter(gz)
	tarw.WriteHeader(&tar.Header{Name: "test.ppd", Size: int64(len(ppd)), Mode: 0600})
	tarw.Write([]byte(ppd))
	tarw.Close()
	gz.Close()
	if err = catalog.Import(&a); err != nil {
		t.Fatal(err)
	}
	profile := catalog.Search("", "")[0]
	e, err := New(filepath.Join(dir, "prepared"), catalog, DefaultOutputLimit)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input.pdf")
	os.WriteFile(input, testutil.PDF(), 0600)
	p := queue.Printer{ID: "test", PPDID: profile.ID, Formats: []string{"application/postscript"}}
	j := queue.Job{ID: "test-job", Owner: "local-admin", Title: "original title", Format: "application/pdf"}
	return e, p, j, input
}
func fake(t *testing.T, e *Engine, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cupsfilter")
	script := "#!/bin/sh\nif [ \"$1\" = \"--list-filters\" ]; then printf 'render\\nppd-driver\\n'; exit 0; fi\n" + body + "\n"
	if err := os.WriteFile(p, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	e.program = p
}
func TestPreparationOutputAndNoSecrets(t *testing.T) {
	e, p, j, input := fixture(t, testutil.PPD+"*cupsFilter2: \"application/pdf application/vnd.hp-pcl 0 driver\"\n")
	t.Setenv("GOPRINT_TOKEN", "not-for-filters")
	t.Setenv("CUPS_SERVER", "not-for-filters")
	fake(t, e, `[ -z "$GOPRINT_TOKEN" ] && [ -z "$CUPS_SERVER" ] || exit 9
ppd=''
while [ "$#" -gt 0 ]; do if [ "$1" = '-p' ]; then ppd="$2"; shift; fi; shift; done
[ -f "$ppd" ] || exit 8
printf 'RENDERED-PCL'`)
	r, err := e.Prepare(context.Background(), p, j, input)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	b, _ := os.ReadFile(r.Path)
	if string(b) != "RENDERED-PCL" || r.Format != "application/vnd.hp-pcl" || r.Size != 12 {
		t.Fatalf("result: %+v %q", r, b)
	}
	original, _ := os.ReadFile(input)
	if !bytes.Equal(original, testutil.PDF()) {
		t.Fatal("input changed")
	}
	dir := filepath.Dir(r.Path)
	r.Cleanup()
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("temporary files retained")
	}
}
func TestFailedPartialOutputIsDiscarded(t *testing.T) {
	e, p, j, input := fixture(t, testutil.PPD)
	fake(t, e, "printf partial; exit 7")
	r, err := e.Prepare(context.Background(), p, j, input)
	if err == nil || r.Path != "" {
		t.Fatalf("unsafe fallback: %+v %v", r, err)
	}
	files, _ := os.ReadDir(e.dir)
	if len(files) != 0 {
		t.Fatal("partial result retained")
	}
}
func TestOutputLimitStopsDriver(t *testing.T) {
	e, p, j, input := fixture(t, testutil.PPD)
	e.limit = 16
	fake(t, e, "while :; do printf '0123456789abcdef0123456789abcdef'; done")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := e.Prepare(ctx, p, j, input)
	if err == nil || !strings.Contains(err.Error(), "лимит") {
		t.Fatal(err)
	}
}
func TestDeadlineKillsDescendants(t *testing.T) {
	e, p, j, input := fixture(t, testutil.PPD)
	trace := filepath.Join(t.TempDir(), "heartbeat")
	fake(t, e, "(while :; do printf x >> '"+trace+"'; sleep .02; done) &\nwait")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.Prepare(ctx, p, j, input); done <- err }()
	for {
		if _, err := os.Stat(trace); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("filter stopped before child started: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		if ctx.Err() != nil {
			t.Fatal("driver never started")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filter process group did not stop")
	}
	a, err := os.Stat(trace)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	b, _ := os.Stat(trace)
	if a.Size() != b.Size() {
		t.Fatal("driver child survived cancellation")
	}
}
func TestPPDIntegrityAndRawCannotBypass(t *testing.T) {
	e, p, j, input := fixture(t, testutil.PPD)
	fake(t, e, "printf rendered")
	j.Format = "application/octet-stream"
	if _, err := e.Prepare(context.Background(), p, j, input); err == nil {
		t.Fatal("RAW bypassed selected PPD")
	}
	j.Format = "application/pdf"
	os.WriteFile(filepath.Join(e.catalogDirForTest(), p.PPDID+".ppd"), []byte("tampered"), 0600)
	if _, err := e.Prepare(context.Background(), p, j, input); err == nil {
		t.Fatal("tampered PPD accepted")
	}
}
func (e *Engine) catalogDirForTest() string { return filepath.Join(filepath.Dir(e.dir), "ppds") }
func TestNoPPDPreservesDirectPrinting(t *testing.T) {
	dir := t.TempDir()
	e, _ := New(dir, nil, 100)
	input := filepath.Join(dir, "document")
	os.WriteFile(input, []byte("RAW"), 0600)
	r, err := e.Prepare(context.Background(), queue.Printer{}, queue.Job{Format: "application/octet-stream"}, input)
	if err != nil || r.Path != input || r.Format != "application/octet-stream" || r.Size != 3 {
		t.Fatalf("result: %+v %v", r, err)
	}
}
func TestSystemCUPSActuallyAppliesPPD(t *testing.T) {
	if _, err := Executable(); err != nil {
		if os.Getenv("GOPRINT_REQUIRE_CUPS_TEST") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	e, p, j, input := fixture(t, testutil.PPD)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := e.Prepare(ctx, p, j, input)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	b, _ := os.ReadFile(r.Path)
	if !bytes.Contains(b, []byte("%!PS")) || !bytes.Contains(b, []byte("GOPRINT_PPD_APPLIED")) {
		t.Fatalf("PPD was not applied; output begins: %q", b[:min(len(b), 300)])
	}
	if r.Format != "application/postscript" || len(r.Chain) == 0 {
		t.Fatalf("result: %+v", r)
	}
}

func TestPersonalOptionsReachActualFilterArguments(t *testing.T) {
	ppd := testutil.PPD + "*DefaultPageSize: A4\n*PageSize A4/A4: \"\"\n*PageSize A3/A3: \"\"\n*DefaultDuplex: None\n*Duplex None: \"\"\n*Duplex DuplexNoTumble: \"\"\n*DefaultColorModel: RGB\n*ColorModel RGB: \"\"\n*ColorModel Gray: \"\"\n"
	e, p, j, input := fixture(t, ppd)
	j.Options = queue.PrintOptions{Media: "iso_a3_297x420mm", Sides: "two-sided-long-edge", Color: "monochrome"}
	fake(t, e, `paper=0; duplex=0; color=0
while [ "$#" -gt 0 ]; do
 case "$1" in PageSize=A3) paper=1;; Duplex=DuplexNoTumble) duplex=1;; ColorModel=Gray) color=1;; esac
 shift
done
[ "$paper$duplex$color" = 111 ] || exit 9
printf 'configured-output'`)
	r, err := e.Prepare(context.Background(), p, j, input)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	b, _ := os.ReadFile(r.Path)
	if string(b) != "configured-output" {
		t.Fatal(string(b))
	}
}
