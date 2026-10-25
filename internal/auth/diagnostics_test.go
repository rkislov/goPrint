// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLDAPDiagnosticsBindTrustAndGroups(t *testing.T) {
	for _, tc := range []struct {
		name, code                string
		trusted, correct, missing bool
	}{{"ready", "ldap_user_scope", true, true, false}, {"bad password", "ldap_bind_credentials", true, false, false}, {"bad trust", "ldap_tls_tls_ca", false, true, false}, {"missing group", "ldap_allowed_group", true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			certServer := httptest.NewTLSServer(nil)
			cert := certServer.TLS.Certificates[0]
			certServer.Close()
			ln, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := ln.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				for {
					p, e := ber.ReadPacket(c)
					if e != nil {
						return
					}
					id := p.Children[0].Value.(int64)
					op := p.Children[1]
					switch op.Tag {
					case 0:
						code := int64(0)
						if op.Children[2].Data.String() != "sensitive-value" {
							code = 49
						}
						c.Write(ldapPacket(id, ldapResult(1, code)).Bytes())
					case 3:
						dn := op.Children[0].Value.(string)
						if !tc.missing || !strings.HasPrefix(dn, "CN=Allowed") {
							entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
							entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
							entry.AppendChild(ber.NewSequence(""))
							c.Write(ldapPacket(id, entry).Bytes())
						}
						c.Write(ldapPacket(id, ldapResult(5, 0)).Bytes())
					default:
						return
					}
				}
			}()
			dir := t.TempDir()
			password := "sensitive-value"
			if !tc.correct {
				password = "wrong"
			}
			pw := filepath.Join(dir, "password")
			os.WriteFile(pw, []byte(password), 0600)
			cfg := Config{URL: "ldaps://" + ln.Addr().String(), Domain: "example.org", BaseDN: "DC=example,DC=org", AllowedGroupDN: "CN=Allowed,DC=example,DC=org", DirectoryBindDN: "CN=Service,DC=example,DC=org", DirectoryPasswordFile: pw}
			if tc.trusted {
				ca := filepath.Join(dir, "ca.pem")
				os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600)
				cfg.CAFile = ca
			}
			d, e := New(cfg)
			if e != nil {
				t.Fatal(e)
			}
			r := d.Diagnose(context.Background())
			<-done
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), password) {
				t.Fatal("secret leaked")
			}
			found := false
			for _, s := range r.Steps {
				if s.Code == tc.code {
					found = true
				}
			}
			if !found {
				t.Fatal(r)
			}
		})
	}
}
