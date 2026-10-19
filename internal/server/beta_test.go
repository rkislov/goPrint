// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/personal"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type emailDomain struct{ fakeDomain }

func (emailDomain) ResolveMail(_ context.Context, mail string) (auth.Identity, error) {
	if mail == "alice@corp.example" {
		return auth.Identity{User: "alice@example.org"}, nil
	}
	if mail == "bob@corp.example" {
		return auth.Identity{User: "bob@example.org"}, nil
	}
	return auth.Identity{}, auth.ErrCredentials
}
func TestBetaACLFollowMeTerminalAndEmailIdentity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	per, e := personal.New(dir, q)
	if e != nil {
		t.Fatal(e)
	}
	s := &Server{Store: q, Personal: per, Token: strings.Repeat("a", 32), Domain: emailDomain{}, PublicURL: "https://print.example.org"}
	h := s.Handler()
	alice := domainCookie(t, h, "alice@example.org")
	bob := domainCookie(t, h, "bob@example.org")
	admin := domainCookie(t, h, "admin@example.org")
	p, e := q.AddPrinter(ctx, queue.Printer{Name: "Private", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	if e != nil {
		t.Fatal(e)
	}
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{Users: []string{"alice@example.org"}})
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("Content-Type", "application/pdf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/printers", "", bob); w.Code != 200 || strings.Contains(w.Body.String(), "Private") {
		t.Fatal(w.Code, w.Body.String())
	}

	if w := request("GET", "/api/printers/"+p.ID+"/preferences", "", bob); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/api/clients/"+p.ID+"/linux.sh", "", bob); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := request("PUT", "/api/printers/"+p.ID+"/preferences", `{"media":"iso_a4_210x297mm","sides":"one-sided","color":"color"}`, alice); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("PUT", "/api/printers/"+p.ID+"/preferences", `{"media":"arbitrary-command","sides":"one-sided","color":"color"}`, alice); w.Code != 400 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/api/smtp", "/api/antivirus", "/api/domain/sso", "/api/email-print"} {
		if w := request("GET", path, "", alice); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	if w := request("PUT", "/api/domain/keytab", "secret", alice); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("PUT", "/api/me/follow-me", `{"follow_me":true,"pin":"12345678"}`, alice); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := request("POST", "/api/jobs?printer="+p.ID+"&title=held.pdf", "%PDF-1.4", alice)
	var j queue.Job
	json.Unmarshal(w.Body.Bytes(), &j)
	if w.Code != 201 || j.State != "held-release" {
		t.Fatal(w.Code, j, w.Body.String())
	}
	if _, e = q.Claim(ctx); e == nil {
		t.Fatal("held job was delivered")
	}
	if w = request("POST", "/api/me/release", `{"pin":"12345678","printer":"`+p.ID+`"}`, bob); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = request("POST", "/api/printers/"+p.ID+"/terminal", "", admin)
	var terminal map[string]string
	json.Unmarshal(w.Body.Bytes(), &terminal)
	if w.Code != 200 || terminal["token"] == "" {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/terminal/"+p.ID+"/release", strings.NewReader(`{"pin":"12345678"}`))
	r.TLS = &tls.ConnectionState{}
	r.SetBasicAuth(p.ID, terminal["token"])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"released":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	got, _ := q.Job(ctx, j.ID)
	if got.State != "queued" || got.Options.FollowMe {
		t.Fatal(got)
	}
	w = request("PUT", "/api/email-print", `{"enabled":true,"printer":"`+p.ID+`","rotate":true}`, admin)
	var gateway map[string]any
	json.Unmarshal(w.Body.Bytes(), &gateway)
	token, _ := gateway["token"].(string)
	if w.Code != 200 || token == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	raw := "From: bob@corp.example\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=mail.pdf\r\n\r\n%PDF-1.4"
	email := func(sender, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/mail/incoming", strings.NewReader(raw))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-GoPrint-Authenticated-Sender", sender)
		r.Header.Set("X-GoPrint-Message-ID", "test-message-0001")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w = email("alice@corp.example", token)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result emailResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Jobs) != 1 {
		t.Fatal(result)
	}
	got, _ = q.Job(ctx, result.Jobs[0])
	if got.Owner != "alice@example.org" || got.State != "held-release" {
		t.Fatal("From header spoofed identity", got)
	}
	if w = email("alice@corp.example", token); w.Code != 200 {
		t.Fatal(w.Code)
	}
	all, _ := q.Jobs(ctx)
	if len(all) != 2 {
		t.Fatal("retry duplicated attachment", len(all))
	}
	if w = email("bob@corp.example", token); w.Code != 404 {
		t.Fatal("email bypassed ACL", w.Code)
	}
	if w = email("alice@corp.example", "wrong"); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

type mockNegotiator struct{}

func (mockNegotiator) AuthenticateToken(_ context.Context, token string) (auth.Identity, string, error) {
	if token != "valid" {
		return auth.Identity{}, "", auth.ErrNegotiation
	}
	return auth.Identity{User: "alice@example.org"}, "mutual-response", nil
}
func TestSSOHandshakeDoesNotDowngrade(t *testing.T) {
	q, e := queue.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	s := &Server{Store: q, Domain: fakeDomain{}, SSO: mockNegotiator{}, Token: strings.Repeat("a", 32)}
	h := s.Handler()
	request := func(authorization string, tlsEnabled bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/session/negotiate", nil)
		if tlsEnabled {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, value := range []string{"", "Basic YWxpY2U6cGFzc3dvcmQ=", "Negotiate invalid"} {
		w := request(value, true)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Negotiate" {
			t.Fatal(w.Code, w.Header())
		}
	}
	if w := request("Negotiate valid", false); w.Code != 401 {
		t.Fatal("SSO accepted HTTP")
	}
	w := request("Negotiate valid", true)
	if w.Code != 200 || w.Header().Get("WWW-Authenticate") != "Negotiate mutual-response" || len(w.Result().Cookies()) != 1 {
		t.Fatal(w.Code, w.Header())
	}
}
