// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/queue"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSMBCredentialsAndDelivery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, err := queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	s, err := NewSMB(dir, q)
	if err != nil {
		t.Fatal(err)
	}
	p, err := q.AddPrinter(ctx, queue.Printer{Name: "SMB", URI: "smb://server/office", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := q.Submit(ctx, p.ID, "alice@example.org", "evil;!touch hacked", "application/pdf", bytes.NewReader([]byte("%PDF-test")))
	if err != nil {
		t.Fatal(err)
	}
	c := SMBConfig{Enabled: true, Domain: "LAB", Username: "service", Password: "sensitive-value"}
	out, err := s.Configure(ctx, p.ID, c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), c.Password) || !out.PasswordSet {
		t.Fatal("secret leaked")
	}
	var stored smbStored
	q.Setting(ctx, "smb:"+p.ID, &stored)
	b, _ = json.Marshal(stored)
	if bytes.Contains(b, []byte(c.Password)) {
		t.Fatal("plaintext in storage")
	}
	out.Username = "other"
	if _, err = s.Configure(ctx, p.ID, out); err == nil {
		t.Fatal("reused password across accounts")
	}
	c.Password = "bad\nusername = root"
	if _, err = s.Configure(ctx, p.ID, c); err == nil {
		t.Fatal("credential injection")
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	t.Setenv("GOPRINT_TOKEN", "must-not-leak")
	executable := filepath.Join(bin, "smbclient")
	script := `#!/bin/sh
[ "$GOPRINT_TOKEN" = "" ] || exit 7
[ -f auth ] && [ -f document.prn ] || exit 8
case "$*" in *'print document.prn'*) %s;; esac
exit 0
`
	for _, tc := range []struct{ command, want string }{{":", "submitted"}, {"echo NT_STATUS_ACCESS_DENIED", "unknown"}, {"exit 1", "unknown"}} {
		os.WriteFile(executable, []byte(strings.Replace(script, "%s", tc.command, 1)), 0700)
		result := s.Deliver(ctx, p, j, document(t))
		if result.State != tc.want {
			t.Fatalf("%s: %+v", tc.command, result)
		}
	}
	os.WriteFile(executable, []byte("#!/bin/sh\nexit 1\n"), 0700)
	if r := s.Deliver(ctx, p, j, document(t)); r.State != "failed" {
		t.Fatal(r)
	}
	// Copying encrypted credentials to a different printer cannot decrypt them.
	q.SetSetting(ctx, "smb:other", stored)
	p.ID = "other"
	if r := s.Deliver(ctx, p, j, document(t)); r.State != "failed" || !strings.Contains(r.Detail, "decrypt") {
		t.Fatal(r)
	}
}
