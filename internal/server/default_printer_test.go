// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/queue"
)

type printDefaultDomain struct{ fakeDomain }

func (d printDefaultDomain) Authenticate(ctx context.Context, u, p string) (auth.Identity, error) {
	id, err := d.fakeDomain.Authenticate(ctx, u, p)
	if id.User == "alice@example.org" {
		id.Groups = []string{"CN=Staff,OU=Groups,DC=example,DC=org", "CN=Office,OU=Groups,DC=example,DC=org"}
	}
	return id, err
}

func TestDefaultPrinterPriorityAndAccess(t *testing.T) {
	ctx := context.Background()
	q, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	token := strings.Repeat("x", 32)
	h := (&Server{Store: q, Domain: printDefaultDomain{}, Token: token}).Handler()
	alice := domainCookie(t, h, "alice@example.org")
	bob := domainCookie(t, h, "bob@example.org")
	add := func(name string, public bool) string {
		t.Helper()
		p, err := q.AddPrinter(ctx, queue.Printer{Name: name, URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
		if err != nil {
			t.Fatal(err)
		}
		if err = q.SetAccess(ctx, p.ID, queue.PrinterAccess{Public: public}); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	staff, office, assigned, personal, restricted := add("Staff", true), add("Office", true), add("Assigned", true), add("Personal", true), add("Restricted", false)
	request := func(method, path string, input any, cookie *http.Cookie, admin bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(input)
		r := httptest.NewRequest(method, path, strings.NewReader(string(b)))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if admin {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, status, w.Body.String())
		}
		return w
	}
	const rulesPath = "/api/print-default-rules"
	const personalPath = "/api/me/default-printer"
	rules := []defaultPrinterRule{
		{Kind: "group", Subject: "cn=office,ou=Groups,dc=example,dc=org", Printer: office},
		{Kind: "group", Subject: "CN=Staff,OU=Groups,DC=example,DC=org", Printer: staff},
		{Kind: "user", Subject: "ALICE@example.org", Printer: assigned},
	}
	request("GET", personalPath, nil, nil, false, 401)
	request("GET", rulesPath, nil, alice, false, 403)
	request("PUT", rulesPath, rules, alice, false, 403)
	request("PUT", rulesPath, rules, nil, true, 200)
	request("PUT", rulesPath, []defaultPrinterRule{{Kind: "group", Subject: "not a DN", Printer: staff}}, nil, true, 400)
	request("PUT", rulesPath, []defaultPrinterRule{{Kind: "user", Subject: "alice@example.org", Printer: "missing"}}, nil, true, 404)
	assertDefault := func(cookie *http.Cookie, printer, source string) {
		t.Helper()
		var v defaultPrinterView
		w := request("GET", personalPath, nil, cookie, false, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Printer != printer || v.Source != source {
			t.Fatalf("want %s/%s: %s (%v)", printer, source, w.Body, err)
		}
	}
	assertDefault(alice, assigned, "user")
	assertDefault(bob, "", "none")
	request("PUT", personalPath, map[string]string{"printer_id": restricted}, alice, false, 404)
	request("PUT", personalPath, map[string]string{"printer_id": personal}, alice, false, 200)
	assertDefault(alice, personal, "personal")
	assertDefault(bob, "", "none")

	for _, p := range []string{personal, assigned, office, staff} {
		if err := q.SetAccess(ctx, p, queue.PrinterAccess{}); err != nil {
			t.Fatal(err)
		}
		switch p {
		case personal:
			assertDefault(alice, assigned, "user")
		case assigned:
			assertDefault(alice, office, "group")
		case office:
			assertDefault(alice, staff, "group")
		case staff:
			assertDefault(alice, "", "none")
		}
	}
	if err := q.SetAccess(ctx, assigned, queue.PrinterAccess{Public: true}); err != nil {
		t.Fatal(err)
	}
	request("PUT", personalPath, map[string]string{"printer_id": ""}, alice, false, 200)
	if err := q.SetAccess(ctx, personal, queue.PrinterAccess{Public: true}); err != nil {
		t.Fatal(err)
	}
	assertDefault(alice, assigned, "user")
	request("PUT", rulesPath, []defaultPrinterRule{}, nil, true, 200)
	assertDefault(alice, "", "none")
}
