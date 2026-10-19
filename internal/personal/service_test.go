// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package personal

import (
	"context"
	"github.com/rkislov/goPrint/internal/queue"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPINRotationUniqueAndRestart(t *testing.T) {
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	s, e := New(dir, q)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e = s.Configure(ctx, "alice", true, "1234"); e == nil {
		t.Fatal("short code accepted")
	}
	if _, e = s.Configure(ctx, "alice", true, "12345678"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Configure(ctx, "bob", true, "12345678"); e == nil {
		t.Fatal("duplicate code accepted")
	}
	if u, e := s.AuthenticateCode(ctx, "12345678"); e != nil || u != "alice" {
		t.Fatal(u, e)
	}
	if _, e = s.Configure(ctx, "alice", true, "87654321"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthenticateCode(ctx, "12345678"); e == nil {
		t.Fatal("old code accepted")
	}
	s, e = New(dir, q)
	if e != nil {
		t.Fatal(e)
	}
	if u, e := s.AuthenticateCode(ctx, "87654321"); e != nil || u != "alice" {
		t.Fatal(u, e)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "queue.db-wal"))
	if strings.Contains(string(b), "87654321") {
		t.Fatal("plaintext code persisted")
	}
}
