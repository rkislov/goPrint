// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package printing

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/filtering"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/testutil"
)

func setup(t *testing.T, uri, ppd string) (*Pipeline, queue.Printer, queue.Job) {
	t.Helper()
	if _, err := filtering.Executable(); err != nil {
		if os.Getenv("GOPRINT_REQUIRE_CUPS_TEST") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("filters refuse root")
	}
	dir := t.TempDir()
	store, err := queue.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	catalog, err := drivers.Open(filepath.Join(dir, "ppds"))
	if err != nil {
		t.Fatal(err)
	}
	var a bytes.Buffer
	gz := gzip.NewWriter(&a)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "profile.ppd", Size: int64(len(ppd)), Mode: 0600})
	tw.Write([]byte(ppd))
	tw.Close()
	gz.Close()
	if err = catalog.Import(&a); err != nil {
		t.Fatal(err)
	}
	p, err := store.AddPrinter(context.Background(), queue.Printer{Name: "test", URI: uri, PPDID: catalog.Search("", "")[0].ID, Formats: []string{"application/postscript"}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := store.Submit(context.Background(), p.ID, "admin", "original.pdf", "application/pdf", bytes.NewReader(testutil.PDF()))
	if err != nil {
		t.Fatal(err)
	}
	j, err = store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := filtering.New(filepath.Join(dir, "prepared"), catalog, filtering.DefaultOutputLimit)
	if err != nil {
		t.Fatal(err)
	}
	return &Pipeline{Store: store, Filters: engine}, p, j
}
func TestPreparedPSAndUpdatedMimeAndLengthReachIPP(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if int64(len(data)) != r.ContentLength {
			t.Error("prepared Content-Length mismatch")
		}
		var request goipp.Message
		if err = request.Decode(bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		header, _ := request.EncodeBytes()
		body := data[len(header):]
		if !bytes.Contains(body, []byte("%!PS")) || !bytes.Contains(body, []byte("GOPRINT_PPD_APPLIED")) {
			t.Error("unfiltered bytes reached printer")
		}
		format := ""
		for _, a := range request.Operation {
			if a.Name == "document-format" {
				format = string(a.Values[0].V.(goipp.String))
			}
		}
		if format != "application/postscript" {
			t.Errorf("wrong wire MIME: %s", format)
		}
		received.Add(1)
		response := goipp.NewResponse(goipp.DefaultVersion, goipp.StatusOk, request.RequestID)
		w.Header().Set("Content-Type", "application/ipp")
		response.Encode(w)
	}))
	defer srv.Close()
	pipeline, p, j := setup(t, strings.Replace(srv.URL, "http://", "ipp://", 1)+"/ipp/print", testutil.PPD)
	r := pipeline.Deliver(context.Background(), p, j, pipeline.Store.Document(j.ID))
	if r.State != "submitted" || received.Load() != 1 {
		t.Fatalf("result: %+v", r)
	}
	original, _ := os.ReadFile(pipeline.Store.Document(j.ID))
	if !bytes.Equal(original, testutil.PDF()) {
		t.Fatal("source spool changed")
	}
	events, _ := pipeline.Store.Events(context.Background(), j.ID)
	if !strings.Contains(events[len(events)-1].Detail, "PPD filters applied") {
		t.Fatal("filter application not audited")
	}
}
func TestMissingDriverNeverContactsPrinter(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	ppd := testutil.PPD + "*cupsFilter: \"application/vnd.cups-raster 0 goprint-driver-that-is-not-installed\"\n"
	pipeline, p, j := setup(t, strings.Replace(srv.URL, "http://", "ipp://", 1)+"/ipp/print", ppd)
	r := pipeline.Deliver(context.Background(), p, j, pipeline.Store.Document(j.ID))
	if r.State != "failed" || received.Load() != 0 {
		t.Fatalf("unfiltered fallback: %+v, requests: %d", r, received.Load())
	}
}
