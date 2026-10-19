// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDomain struct{}

func (fakeDomain) Authenticate(_ context.Context, u, p string) (auth.Identity, error) {
	if p != "domain-password" {
		return auth.Identity{}, auth.ErrCredentials
	}
	return auth.Identity{User: strings.ToLower(u), Admin: u == "admin@example.org"}, nil
}
func domainCookie(t *testing.T, h http.Handler, user string) *http.Cookie {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": "domain-password"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/session", strings.NewReader(string(b))))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}
func TestDomainOwnershipAndAdminBoundary(t *testing.T) {
	store, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scans, err := scanning.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer scans.Close()
	s := &Server{Store: store, Scans: scans, Token: strings.Repeat("a", 32), Domain: fakeDomain{}}
	h := s.Handler()
	alice := domainCookie(t, h, "alice@example.org")
	bob := domainCookie(t, h, "bob@example.org")
	admin := domainCookie(t, h, "admin@example.org")
	p, err := store.AddPrinter(context.Background(), queue.Printer{Name: "test", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/pdf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/jobs?printer="+p.ID+"&title=alice.pdf", "%PDF-1.4", alice)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var j queue.Job
	json.Unmarshal(w.Body.Bytes(), &j)
	if j.Owner != "alice@example.org" {
		t.Fatal(j.Owner)
	}
	for _, path := range []string{"/api/jobs/" + j.ID, "/api/jobs/" + j.ID + "/events"} {
		if w = request("GET", path, "", bob); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	if w = request("POST", "/api/jobs/"+j.ID+"/cancel", "", bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/api/siem", "/api/watermark", "/api/drivers", "/api/filters"} {
		if w = request("GET", path, "", alice); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	if w = request("GET", "/api/jobs", "", bob); w.Code != 200 || strings.Contains(w.Body.String(), "alice.pdf") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("GET", "/api/jobs/"+j.ID, "", admin); w.Code != 200 {
		t.Fatal(w.Code)
	}
	scanner, err := scans.Add(context.Background(), "mfp", "http://127.0.0.1/eSCL")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scans.Receive(context.Background(), scanner.ID, "private.pdf", strings.NewReader("%PDF-1.4"))
	if err != nil {
		t.Fatal(err)
	}
	if w = request("GET", "/api/scans/"+scan.ID+"/document", "", alice); w.Code != 404 {
		t.Fatal("inbox leak", w.Code)
	}
	if w = request("GET", "/api/scans", "", alice); strings.Contains(w.Body.String(), "private.pdf") {
		t.Fatal("inbox listing leak")
	}
	// Role and username cannot be edited in a signed session.
	payload, _ := json.Marshal(session{User: "bob@example.org", Admin: true, Expires: 9999999999})
	bob.Value = base64.RawURLEncoding.EncodeToString(payload) + ".invalid"
	if w = request("GET", "/api/jobs", "", bob); w.Code != 401 {
		t.Fatal("forged role accepted")
	}
}
func TestProvisioningQuotesNamesAndDoesNotBypassQueue(t *testing.T) {
	st, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.AddPrinter(context.Background(), queue.Printer{Name: "test '; $(touch /tmp/bad)\n", URI: "socket://192.0.2.1:9100", Formats: []string{"application/pdf"}})
	s := &Server{Store: st, Token: strings.Repeat("x", 32), PublicURL: "https://print.example.org:8631"}
	h := s.Handler()
	for _, platform := range []string{"linux.sh", "windows.ps1"} {
		r := httptest.NewRequest("GET", "/api/clients/"+p.ID+"/"+platform, nil)
		r.Header.Set("Authorization", "Bearer "+s.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		b := w.Body.String()
		if strings.Contains(b, s.Token) || strings.Contains(b, p.URI) || !strings.Contains(b, "/ipp/printers/"+p.ID) {
			t.Fatal("unsafe provisioner", b)
		}
	}
	for _, u := range []string{"http://print.example.org", "https://user:pass@print.example.org", "https://print.example.org/path", "https://print.example.org?x=x"} {
		if ValidatePublicURL(u) == nil {
			t.Fatal("unsafe origin", u)
		}
	}
}
