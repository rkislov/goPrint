// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package sambaprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigAndSocketBoundaries(t *testing.T) {
	dir, e := os.MkdirTemp("", "gp-config-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "gateway.json")
	for _, content := range []string{`{"socket":"/run/goprint/s.sock","users":{"0":"root@example.org"}}`, `{"socket":"relative","users":{"1000":"a@example.org"}}`, `{"socket":"/run/goprint/s.sock","users":{"01000":"a@example.org"}}`, `{"socket":"/run/goprint/s.sock","users":{"1000":"a@example.org"},"unknown":true}`} {
		os.WriteFile(p, []byte(content), 0600)
		if _, e = Load(p); e == nil {
			t.Fatal(content)
		}
	}
	os.WriteFile(p, []byte(`{"socket":"`+filepath.Join(dir, "s.sock")+`","users":{"1000":"alice@example.org"}}`), 0600)
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	ln, e := Listen(c)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	st, _ := os.Stat(c.Socket)
	if st.Mode().Perm() != 0660 {
		t.Fatal(st.Mode())
	}
	if _, e = Listen(c); e == nil {
		t.Fatal("active socket replaced")
	}
	os.Chmod(p, 0666)
	if _, e = Load(p); e == nil {
		t.Fatal("writable config accepted")
	}
	os.Chmod(dir, 0777)
	if _, e = Listen(Config{Socket: filepath.Join(dir, "other.sock")}); e == nil {
		t.Fatal("untrusted socket directory accepted")
	}
}
