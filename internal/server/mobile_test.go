// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/goPrint/internal/personal"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	qrcode "github.com/skip2/go-qrcode"
)

func TestMobileQRPermissionsAndOwnQueue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	sc, e := scanning.Open(filepath.Join(dir, "scans"))
	if e != nil {
		t.Fatal(e)
	}
	defer sc.Close()
	per, e := personal.New(dir, q)
	if e != nil {
		t.Fatal(e)
	}
	mfp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.Header().Set("Location", "/eSCL/ScanJobs/1")
			w.WriteHeader(201)
		case "GET":
			w.Write([]byte("%PDF-1.7\ntest\n%%EOF"))
		default:
			w.WriteHeader(204)
		}
	}))
	defer mfp.Close()
	scanner, e := sc.Add(ctx, "MFP", mfp.URL+"/eSCL")
	if e != nil {
		t.Fatal(e)
	}
	p, e := q.AddPrinter(ctx, queue.Printer{Name: "Office MFP", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = q.SetAccess(ctx, p.ID, queue.PrinterAccess{Users: []string{"alice@example.org"}}); e != nil {
		t.Fatal(e)
	}
	s := &Server{Store: q, Scans: sc, Personal: per, Token: strings.Repeat("a", 32), Domain: emailDomain{}, PublicURL: "https://print.example.org"}
	h := s.Handler()
	alice := domainCookie(t, h, "alice@example.org")
	bob := domainCookie(t, h, "bob@example.org")
	admin := domainCookie(t, h, "admin@example.org")
	req := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if strings.HasPrefix(path, "/api/jobs?") {
			r.Header.Set("Content-Type", "application/pdf")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := req("GET", "/device/"+p.ID, "", nil); w.Code != 303 || w.Header().Get("Location") != "/login?next="+url.QueryEscape("/device/"+p.ID) {
		t.Fatal(w.Code, w.Header())
	}
	if w := req("GET", "/api/me/devices/"+p.ID, "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, cookie := range []*http.Cookie{alice, bob} {
		if w := req("GET", "/api/printers/"+p.ID+"/qr.png", "", cookie); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := req("GET", "/api/me/devices/"+p.ID, "", bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := req("GET", "/api/me/devices/"+p.ID, "", alice); w.Code != 200 || !strings.Contains(w.Body.String(), `"can_print":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	w := req("GET", "/api/printers/"+p.ID+"/qr.png", "", admin)
	expected, _ := qrcode.Encode(s.PublicURL+"/device/"+p.ID, qrcode.Medium, 768)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), expected) {
		t.Fatal("QR payload or PNG mismatch", w.Code)
	}
	for _, origin := range []string{"", "http://127.0.0.1:8631", "https://localhost", "https://127.0.0.1"} {
		s.PublicURL = origin
		if w := req("GET", "/api/printers/"+p.ID+"/qr.png", "", admin); w.Code != 409 {
			t.Fatal(origin, w.Code)
		}
	}
	s.PublicURL = "https://print.example.org"
	scanBody := `{"scanner_id":"` + scanner.ID + `","source":"Platen","format":"application/pdf","resolution":300}`
	if w := req("POST", "/api/scans", scanBody, alice); w.Code != 404 {
		t.Fatal("unbound scanner allowed", w.Code)
	}
	config := `{"scanner_id":"` + scanner.ID + `","scan_with_print":true,"scan_access":{"users":[]}}`
	if w := req("PUT", "/api/printers/"+p.ID+"/mobile", config, alice); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := req("PUT", "/api/printers/"+p.ID+"/mobile", config, admin); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("GET", "/api/scanners", "", alice); w.Code != 200 || !strings.Contains(w.Body.String(), scanner.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("GET", "/api/scanners", "", bob); w.Code != 200 || strings.Contains(w.Body.String(), scanner.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("POST", "/api/scans", scanBody, bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	w = req("POST", "/api/scans", scanBody, alice)
	var scan scanning.Job
	json.Unmarshal(w.Body.Bytes(), &scan)
	if w.Code != 200 || scan.Owner != "alice@example.org" {
		t.Fatal(w.Code, w.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := sc.Job(ctx, scan.ID)
		if j.State == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := req("GET", "/api/scans/"+scan.ID+"/document", "", alice); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("GET", "/api/scans/"+scan.ID+"/document", "", bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	// Scan-only access does not grant printing or let a QR release another owner's jobs.
	config = `{"scanner_id":"` + scanner.ID + `","scan_access":{"users":["bob@example.org"]}}`
	if w := req("PUT", "/api/printers/"+p.ID+"/mobile", config, admin); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := req("GET", "/api/me/devices/"+p.ID, "", bob); w.Code != 200 || !strings.Contains(w.Body.String(), `"can_print":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("POST", "/api/scans", scanBody, alice); w.Code != 404 {
		t.Fatal("revoked scan access", w.Code)
	}
	for _, v := range []struct{ user, pin string }{{"alice@example.org", "12345678"}, {"bob@example.org", "87654321"}} {
		if _, e = per.Configure(ctx, v.user, true, v.pin); e != nil {
			t.Fatal(e)
		}
	}
	// Give Bob printing temporarily to create his held job, then revoke it again.
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{Public: true})
	a := req("POST", "/api/jobs?printer="+p.ID+"&title=alice.pdf", "%PDF-1.4", alice)
	var aj queue.Job
	json.Unmarshal(a.Body.Bytes(), &aj)
	b := req("POST", "/api/jobs?printer="+p.ID+"&title=bob.pdf", "%PDF-1.4", bob)
	var bj queue.Job
	json.Unmarshal(b.Body.Bytes(), &bj)
	if a.Code != 201 || b.Code != 201 {
		t.Fatal(a.Code, b.Code)
	}
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{Users: []string{"alice@example.org"}})
	if w := req("POST", "/api/me/release", `{"pin":"87654321","printer":"`+p.ID+`"}`, bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := req("POST", "/api/me/release", `{"pin":"87654321","printer":"`+p.ID+`"}`, alice); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := req("POST", "/api/me/release", `{"pin":"12345678","printer":"`+p.ID+`"}`, alice); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := q.Job(ctx, bj.ID)
	if after.State != "held-release" {
		t.Fatal("Bob's job released", after)
	}
	after, _ = q.Job(ctx, aj.ID)
	if after.State != "queued" {
		t.Fatal("Alice's job not released", after)
	}
}
