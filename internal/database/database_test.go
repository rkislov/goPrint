// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRewrite(t *testing.T) {
	q := `SELECT '?', 'a''?b', ? FROM jobs WHERE id=?`
	want := `SELECT '?', 'a''?b', $1 FROM jobs WHERE id=$2`
	if got := rewrite(q, true); got != want {
		t.Fatal(got)
	}
	if rewrite(q, false) != q {
		t.Fatal("SQLite SQL changed")
	}
}
func TestDSNFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dsn")
	os.WriteFile(p, []byte("postgres://example"), 0644)
	if _, e := ReadDSN(p); e == nil {
		t.Fatal("accepted public credential file")
	}
	os.Chmod(p, 0600)
	if s, e := ReadDSN(p); e != nil || s != "postgres://example" {
		t.Fatal(s, e)
	}
}
func TestRejectRemoteUnverified(t *testing.T) {
	for _, mode := range []string{"disable", "require", "prefer", "verify-ca"} {
		if db, e := Open("", "postgres://user:secret@example.invalid/db?sslmode="+mode, "goprint_queue"); e == nil {
			db.Close()
			t.Fatal("accepted", mode)
		}
	}
}
