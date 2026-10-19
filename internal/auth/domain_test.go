// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"strings"
	"testing"
)

func TestSecureConfigurationAndPrincipal(t *testing.T) {
	c := Config{URL: "ldaps://dc.example.org:636", Domain: "example.org", NetBIOS: "EXAMPLE", BaseDN: "DC=example,DC=org", AllowedGroupDN: "CN=GoPrint,DC=example,DC=org"}
	d, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"Alice", `EXAMPLE\Alice`, "Alice@EXAMPLE.ORG"} {
		p, err := d.Principal(u)
		if err != nil || p != "alice@example.org" {
			t.Fatal(u, p, err)
		}
	}
	for _, u := range []string{"alice@other.org", `OTHER\alice`, "*)(objectClass=*)", "a\x00b", strings.Repeat("a", 129)} {
		if _, err := d.Principal(u); err == nil {
			t.Fatal(u)
		}
	}
	if _, err := d.Authenticate(context.Background(), "alice", ""); err == nil {
		t.Fatal("empty password")
	}
	for _, u := range []string{"http://dc.example.org", "ldaps://user:pass@dc.example.org", "ldaps://dc.example.org/path"} {
		x := c
		x.URL = u
		if _, err := New(x); err == nil {
			t.Fatal(u)
		}
	}
	x := c
	x.AllowedGroupDN = ""
	if _, err := New(x); err == nil {
		t.Fatal("missing allowed group")
	}
}
