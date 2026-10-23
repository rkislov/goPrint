// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSMBAdminOnlyAndSecretRedaction(t *testing.T) {
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	smb, e := backend.NewSMB(dir, q)
	if e != nil {
		t.Fatal(e)
	}
	p, e := q.AddPrinter(context.Background(), queue.Printer{Name: "SMB", URI: "smb://server/office", Formats: []string{"application/pdf"}})
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("a", 32)
	h := (&Server{Store: q, Token: token, SMB: smb, Domain: emailDomain{}}).Handler()
	user := domainCookie(t, h, "alice@example.org")
	for _, method := range []string{"GET", "PUT"} {
		r := httptest.NewRequest(method, "/api/printers/"+p.ID+"/smb", nil)
		r.AddCookie(user)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("user %s: %d", method, w.Code)
		}
	}
	r := httptest.NewRequest("PUT", "/api/printers/"+p.ID+"/smb", strings.NewReader(`{"enabled":true,"domain":"LAB","username":"service","password":"secret-value"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-value") {
		t.Fatalf("admin: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/api/printers/"+p.ID+"/smb", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-value") || !strings.Contains(w.Body.String(), `"password_set":true`) {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
}
