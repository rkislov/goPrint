package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rkislov/goPrint/internal/queue"
)

func TestAPIAuthenticationAndOwnership(t *testing.T) {
	s, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	token := strings.Repeat("t", 32)
	h := (&Server{Store: s, Token: token}).Handler()
	p, err := s.AddPrinter(context.Background(), queue.Printer{Name: "test", URI: "socket://localhost:9100", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/pdf")
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/jobs", "", false); w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	w := request("POST", "/api/jobs?printer="+p.ID+"&owner=DOMAIN%5Cadmin&title=test", "%PDF-test", true)
	if w.Code != 201 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var j queue.Job
	if err = json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j.Owner != "local-admin" {
		t.Fatalf("untrusted owner accepted: %s", j.Owner)
	}
	if w = request("POST", "/api/jobs/"+j.ID+"/cancel", "", true); w.Code != 200 {
		t.Fatalf("cancel: %d", w.Code)
	}
	if w = request("POST", "/api/jobs/"+j.ID+"/cancel", "", true); w.Code != 409 {
		t.Fatalf("repeat cancel: %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", "http://attacker.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross origin: %d", w.Code)
	}
}
