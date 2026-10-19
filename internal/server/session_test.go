// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/scanning"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionLoginReloadAndLogout(t *testing.T) {
	s := &Server{Token: strings.Repeat("secret", 8)}
	h := s.Handler()
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/print", "", nil); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/session", `{"token":"wrong"}`, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	b, _ := json.Marshal(map[string]string{"token": s.Token})
	w := request("POST", "/api/session", string(b), nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	if w = request("GET", "/print", "", cookies[0]); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("GET", "/api/session", "", cookies[0]); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = request("DELETE", "/api/session", "", cookies[0])
	if w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	cookies[0].Value += "tampered"
	if w = request("GET", "/api/session", "", cookies[0]); w.Code != 401 {
		t.Fatal("tampered cookie accepted")
	}
}
func TestDeviceInboxIsWriteOnlyAndScoped(t *testing.T) {
	svc, err := scanning.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	device, err := svc.Add(context.Background(), "MFP", "http://localhost/eSCL")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Token: strings.Repeat("a", 32), Scans: svc}).Handler()
	for _, method := range []string{"PUT", "GET"} {
		r := httptest.NewRequest(method, "/inbox/"+device.ID+"/scan.pdf", strings.NewReader("%PDF-1.7\ntest"))
		r.SetBasicAuth(device.ID, device.DeviceToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 201
		if method == "GET" {
			want = 405
		}
		if w.Code != want {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "/api/scans", nil)
	r.SetBasicAuth(device.ID, device.DeviceToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("device has administrator access")
	}
	jobs, _ := svc.Jobs(context.Background())
	if len(jobs) != 1 || jobs[0].State != "completed" {
		t.Fatalf("inbox: %+v", jobs)
	}
}
