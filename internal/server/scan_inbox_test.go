// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scaninbox"
	"github.com/rkislov/goPrint/internal/scanning"
	"github.com/rkislov/goPrint/internal/testutil"
)

func TestScanInboxAdminConfigurationAndWebDAVOwnership(t *testing.T) {
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
	in, e := scaninbox.New(dir, q, sc, func(_ context.Context, user string) (string, error) { return user, nil }, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	token := strings.Repeat("a", 32)
	s := &Server{Store: q, Scans: sc, Inboxes: in, Token: token, Domain: emailDomain{}, PublicURL: "https://print.example.org"}
	h := s.Handler()
	alice := domainCookie(t, h, "alice@example.org")
	bob := domainCookie(t, h, "bob@example.org")
	request := func(method, path, body string, cookie *http.Cookie, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if admin {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/scan-inboxes", "/api/scan-inboxes/ftp"} {
		if w := request("GET", path, "", alice, false); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	w := request("POST", "/api/scan-inboxes", `{"name":"Office Bob","owner":"bob@example.org","enabled":true,"webdav":true,"ftps":true,"max_mib":20}`, nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var d scaninbox.Destination
	if e = json.Unmarshal(w.Body.Bytes(), &d); e != nil || d.Token == "" {
		t.Fatal(e, w.Body.String())
	}
	upload := func(password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/inbox/"+d.ID+"/alice@example.org.pdf", bytes.NewReader(testutil.PDF()))
		r.SetBasicAuth(d.ID, password)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w = upload(d.Token); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	jobs, _ := sc.JobsFor(ctx, "bob@example.org", false)
	if len(jobs) != 1 || jobs[0].Owner != "bob@example.org" {
		t.Fatal(jobs)
	}
	if w = request("GET", "/api/scans/"+jobs[0].ID+"/document", "", alice, false); w.Code != 404 {
		t.Fatal("Alice read Bob scan", w.Code)
	}
	if w = request("GET", "/api/scans/"+jobs[0].ID+"/document", "", bob, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request("GET", "/api/scan-inboxes", "", nil, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), d.Token) || strings.Contains(w.Body.String(), "token_hash") {
		t.Fatal("credential leak", w.Code, w.Body.String())
	}
	w = request("POST", "/api/scan-inboxes/"+d.ID+"/password", "", nil, true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = upload(d.Token); w.Code != 401 {
		t.Fatal("revoked credential still works", w.Code)
	}
	// An ordinary user cannot bind the MFP to another owner or enable a listener.
	for _, path := range []string{"/api/scan-inboxes/" + d.ID, "/api/scan-inboxes/ftp"} {
		if w = request("PUT", path, `{}`, alice, false); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}
