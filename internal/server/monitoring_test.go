// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/monitoring"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMonitoringAdministratorOnlyAndSecretRedaction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	monitor, e := monitoring.New(dir, q, nil)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := q.AddPrinter(ctx, queue.Printer{Name: "Private", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
	token := strings.Repeat("a", 32)
	s := &Server{Store: q, Token: token, Monitoring: monitor, Domain: emailDomain{}}
	h := s.Handler()
	user := domainCookie(t, h, "alice@example.org")
	request := func(method, path, body string, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if admin {
			r.Header.Set("Authorization", "Bearer "+token)
		} else {
			r.AddCookie(user)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, v := range []struct{ method, path, body string }{{"GET", "/api/monitoring", ""}, {"GET", "/api/monitoring/policy", ""}, {"PUT", "/api/monitoring/policy", "{}"}, {"PUT", "/api/printers/" + p.ID + "/monitoring", "{}"}, {"POST", "/api/printers/" + p.ID + "/monitoring/poll", ""}, {"POST", "/api/printers/" + p.ID + "/monitoring/ack", "{}"}} {
		if w := request(v.method, v.path, v.body, false); w.Code != 403 {
			t.Fatal(v, w.Code, w.Body.String())
		}
	}
	c := monitoring.Defaults()
	c.Enabled = true
	c.Method = "snmp"
	c.Version = "2c"
	c.Community = "private-read-community"
	b, _ := json.Marshal(c)
	w := request("PUT", "/api/printers/"+p.ID+"/monitoring", string(b), true)
	if w.Code != 200 || strings.Contains(w.Body.String(), c.Community) {
		t.Fatal(w.Code, w.Body.String())
	}
	monitor.Probe = func(context.Context, queue.Printer, monitoring.Config) (monitoring.Reading, error) {
		n := 4
		return monitoring.Reading{Supplies: []monitoring.Supply{{ID: "black", Name: "Black", Percent: &n}}}, nil
	}
	w = request("POST", "/api/printers/"+p.ID+"/monitoring/poll", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "critical") || strings.Contains(w.Body.String(), c.Community) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request("GET", "/api/monitoring", "", true)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), c.Community) {
		t.Fatal(w.Code, w.Body.String())
	}
}
