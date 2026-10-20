// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/personal"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/sambaprint"
)

type sambaDomain struct {
	fakeDomain
	user   string
	denied bool
}

func (d *sambaDomain) ResolveUser(_ context.Context, user string) (auth.Identity, error) {
	if d.denied {
		return auth.Identity{}, auth.ErrCredentials
	}
	return auth.Identity{User: user, Admin: true, Groups: []string{"CN=Staff,DC=example,DC=org"}}, nil
}
func TestSambaLocalPeerOwnershipACLPoliciesAndReceipts(t *testing.T) {
	if os.Getuid() <= 0 {
		t.Skip("test requires an unprivileged Unix peer")
	}
	dir, e := os.MkdirTemp("", "gp-samba-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	ctx := context.Background()
	q, e := queue.Open(filepath.Join(dir, "data"))
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	per, e := personal.New(filepath.Join(dir, "data"), q)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = per.Configure(ctx, "alice@example.org", true, "12345678"); e != nil {
		t.Fatal(e)
	}
	catalog, e := drivers.Open(filepath.Join(dir, "catalog"))
	if e != nil {
		t.Fatal(e)
	}
	ppd := `*PPD-Adobe: "4.3"
*ModelName: "Samba Test"
*DefaultPageSize: A4
*PageSize A4: ""
*DefaultDuplex: None
*Duplex None: ""
*Duplex DuplexNoTumble: ""
*DefaultColorModel: RGB
*ColorModel RGB: ""
*ColorModel Gray: ""
`
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "test.ppd", Mode: 0600, Size: int64(len(ppd))})
	tw.Write([]byte(ppd))
	tw.Close()
	gz.Close()
	if e = catalog.Import(&archive); e != nil {
		t.Fatal(e)
	}
	profile := catalog.Search("Samba Test", "")[0]
	p, e := q.AddPrinter(ctx, queue.Printer{Name: "Office", PPDID: profile.ID, URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	if e != nil {
		t.Fatal(e)
	}
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{Users: []string{"alice@example.org"}})
	q.SetPreferences(ctx, "alice@example.org", p.ID, queue.PrintOptions{Media: "iso_a4_210x297mm", Sides: "two-sided-long-edge", Color: "monochrome"})
	d := &sambaDomain{}
	s := &Server{Catalog: catalog, Store: q, Personal: per, Domain: d, Token: strings.Repeat("a", 32)}
	uid := strconv.Itoa(os.Getuid())
	users := map[string]string{uid: "alice@example.org"}
	listener, e := sambaprint.Listen(sambaprint.Config{Socket: filepath.Join(dir, "submit.sock")})
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: s.SambaHandler(users), ConnContext: sambaprint.ConnContext}
	go srv.Serve(listener)
	defer srv.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	req := func(id, content string) (int, []byte) {
		r, _ := http.NewRequest("POST", "http://unix/submit?printer="+p.ID+"&title=samba.pdf&owner=bob@example.org", strings.NewReader(content))
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("X-GoPrint-Spool-ID", id)
		r.Header.Set("X-GoPrint-User", "bob@example.org")
		r.Header.Set("Authorization", "Bearer "+s.Token)
		rsp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer rsp.Body.Close()
		b, _ := io.ReadAll(rsp.Body)
		return rsp.StatusCode, b
	}
	// No network caller or administrator token can supply kernel credentials.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/submit", nil)
	r.Header.Set("Authorization", "Bearer "+s.Token)
	s.SambaHandler(users).ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	id := strings.Repeat("1", 64)
	code, body := req(id, "%PDF-1.7\n%%EOF")
	if code != 201 {
		t.Fatal(code, string(body))
	}
	var receipt sambaReceipt
	json.Unmarshal(body, &receipt)
	j, e := q.Job(ctx, receipt.JobID)
	if e != nil || j.Owner != "alice@example.org" || j.State != "held-release" {
		t.Fatal(j, e)
	}
	options := j.Options
	if e != nil || options.Sides != "two-sided-long-edge" || options.Color != "monochrome" {
		t.Fatal(options, e)
	}
	code, _ = req(id, "%PDF-1.7\n%%EOF")
	if code != 200 {
		t.Fatal("replay", code)
	}
	all, _ := q.JobsFor(ctx, "alice@example.org", false)
	if len(all) != 1 {
		t.Fatal("duplicate created", len(all))
	}
	// Recheck current LDAP state and ACL even for a known receipt.
	d.denied = true
	code, _ = req(id, "%PDF-")
	if code != 403 {
		t.Fatal(code)
	}
	d.denied = false
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{})
	code, _ = req(id, "%PDF-")
	if code != 404 {
		t.Fatal("bridge inherited domain admin privileges", code)
	}
	q.SetAccess(ctx, p.ID, queue.PrinterAccess{Groups: []string{"CN=staff,DC=example,DC=org"}})
	code, _ = req(id, "%PDF-")
	if code != 200 {
		t.Fatal("group ACL", code)
	}
	// A UID reassignment must not reuse the prior domain user's receipt.
	users[uid] = "bob@example.org"
	code, body = req(id, "%PDF-1.7\n%%EOF")
	if code != 201 {
		t.Fatal(code, string(body))
	}
	json.Unmarshal(body, &receipt)
	j, _ = q.Job(ctx, receipt.JobID)
	if j.Owner != "bob@example.org" || j.State != "queued" {
		t.Fatal(j)
	}
	users[uid] = "alice@example.org"
	unknown := strings.Repeat("2", 64)
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", os.Getuid(), "alice@example.org", p.ID, unknown)))
	q.SetSetting(ctx, "samba-job:"+hex.EncodeToString(hash[:]), sambaReceipt{State: "processing"})
	code, _ = req(unknown, "%PDF-")
	if code != 409 {
		t.Fatal(code)
	}
	code, _ = req("invalid", "%PDF-")
	if code != 400 {
		t.Fatal(code)
	}
	delete(users, uid)
	code, _ = req(strings.Repeat("3", 64), "%PDF-")
	if code != 403 {
		t.Fatal(code)
	}
}
