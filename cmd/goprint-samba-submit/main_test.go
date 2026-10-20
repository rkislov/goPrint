// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubmitRetainsSpoolUntilConfirmedAndDoesNotUseAdminToken(t *testing.T) {
	dir, e := os.MkdirTemp("", "gp-cli-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	status := 409
	body := `uncertain`
	seenID := ""
	calls := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "" {
			t.Error("admin token leaked")
		}
		id := r.Header.Get("X-GoPrint-Spool-ID")
		if len(id) != 64 {
			t.Error("missing receipt ID")
		}
		if seenID != "" && seenID != id {
			t.Error("unstable retry ID")
		}
		seenID = id
		b, _ := io.ReadAll(r.Body)
		if string(b) != "%PDF-1.7\n%%EOF" {
			t.Error("changed payload")
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	server.Listener = ln
	server.Start()
	defer server.Close()
	t.Setenv("GOPRINT_TOKEN", strings.Repeat("secret", 12))
	doc := filepath.Join(dir, "smbprn.001")
	os.WriteFile(doc, []byte("%PDF-1.7\n%%EOF"), 0600)
	args := []string{"-socket", sock, "-printer", "test-id", "-spool-dir", dir, doc}
	if e := run(args); e == nil {
		t.Fatal("ambiguous response accepted")
	}
	if _, e := os.Stat(doc); e != nil {
		t.Fatal("spool removed after error")
	}
	status = 200
	body = `{"state":"accepted","job_id":"0123456789abcdef0123456789abcdef"}`
	if e := run(args); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(doc); !os.IsNotExist(e) {
		t.Fatal("confirmed spool not removed")
	}
	os.WriteFile(doc, []byte("EMF test payload"), 0600)
	if e := run(args); e == nil {
		t.Fatal("EMF silently treated as PDF")
	}
	if calls != 2 {
		t.Fatal("unsupported data sent")
	}
	link := filepath.Join(dir, "symlink")
	os.Symlink(doc, link)
	args[len(args)-1] = link
	if e := run(args); e == nil {
		t.Fatal("symlink accepted")
	}
}
