// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"encoding/json"
	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDiagnosticsAccessIPPAndThrottle(t *testing.T) {
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	var calls atomic.Int32
	ipp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var m goipp.Message
		if e := m.Decode(r.Body); e != nil {
			t.Error(e)
			return
		}
		if m.Code != goipp.Code(goipp.OpGetPrinterAttributes) {
			t.Errorf("printing operation %d", m.Code)
		}
		goipp.NewResponse(goipp.DefaultVersion, goipp.StatusOk, m.RequestID).Encode(w)
	}))
	defer ipp.Close()
	p, _ := q.AddPrinter(context.Background(), queue.Printer{Name: "IPP", URI: strings.Replace(ipp.URL, "http://", "ipp://", 1) + "/ipp/print", Formats: []string{"application/pdf"}})
	token := strings.Repeat("a", 32)
	s := &Server{Store: q, Token: token, Domain: emailDomain{}}
	h := s.Handler()
	user := domainCookie(t, h, "alice@example.org")
	for _, path := range []string{"/api/diagnostics", "/api/diagnostics/printer?id=" + p.ID} {
		method := "GET"
		if strings.Contains(path, "printer") {
			method = "POST"
		}
		r := httptest.NewRequest(method, path, nil)
		r.AddCookie(user)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized network request")
	}
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("/api/diagnostics/printer?id=" + p.ID)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var report diagnostics.Report
	if e = json.Unmarshal(w.Body.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if report.Status != "warning" || calls.Load() != 1 {
		t.Fatal(report, calls.Load())
	}
	if w = request("/api/diagnostics/printer?id=" + p.ID); w.Code != 429 {
		t.Fatal("no throttle", w.Code)
	}
	if calls.Load() != 1 {
		t.Fatal("throttled network call")
	}
	jobs, _ := q.JobsFor(context.Background(), "", true)
	if len(jobs) != 0 {
		t.Fatal("diagnostic created job")
	}
	if w = request("/api/diagnostics/ldap"); w.Code != 200 || !strings.Contains(w.Body.String(), "ldap_unconfigured") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("/api/diagnostics/ldap?id=bypass"); w.Code != 429 {
		t.Fatal("query bypassed LDAP throttle", w.Code)
	}
	if w = request("/api/diagnostics/sso"); w.Code != 200 || !strings.Contains(w.Body.String(), "sso_unconfigured") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestScannerDiagnosticsNeverStartsScan(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/eSCL/ScannerCapabilities" {
			t.Errorf("unexpected scan request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`<scan:ScannerCapabilities xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03"/>`))
	}))
	defer srv.Close()
	r := diagnoseScanner(context.Background(), srv.URL+"/eSCL")
	if r.Status != "warning" || calls.Load() != 1 {
		t.Fatal(r)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>Not a scanner</html>`)) }))
	defer bad.Close()
	r = diagnoseScanner(context.Background(), bad.URL)
	if r.Status != "error" || r.Steps[0].Code != "scanner_xml" {
		t.Fatal(r)
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS request reached scanner") }))
	defer secure.Close()
	r = diagnoseScanner(context.Background(), secure.URL)
	if r.Status != "error" || r.Steps[0].Code != "scanner_connect_tls_ca" {
		t.Fatal(r)
	}
}
func TestDiagnosticTargetsExcludeScannerCredentials(t *testing.T) {
	dir := t.TempDir()
	q, _ := queue.Open(dir)
	defer q.Close()
	sc, e := scanning.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer sc.Close()
	v, e := sc.Add(context.Background(), "Scanner", "http://192.0.2.1/eSCL")
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("a", 32)
	h := (&Server{Store: q, Scans: sc, Token: token}).Handler()
	r := httptest.NewRequest("GET", "/api/diagnostics", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), v.DeviceToken) || strings.Contains(w.Body.String(), "192.0.2.1") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestSocketDiagnosticNoData(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan int, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- -1
			return
		}
		defer c.Close()
		b := make([]byte, 1)
		n, _ := c.Read(b)
		done <- n
	}()
	q, _ := queue.Open(t.TempDir())
	defer q.Close()
	p, _ := q.AddPrinter(context.Background(), queue.Printer{Name: "Socket", URI: "socket://" + ln.Addr().String(), Formats: []string{"application/pdf"}})
	token := strings.Repeat("a", 32)
	h := (&Server{Store: q, Token: token}).Handler()
	r := httptest.NewRequest("POST", "/api/diagnostics/printer?id="+p.ID, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || <-done != 0 {
		t.Fatal("diagnostic wrote print bytes", w.Code)
	}
}
