// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdministratorKeytabUploadAndAtomicRejection(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "ldap-password")
	os.WriteFile(password, []byte("test-directory-password"), 0600)
	path := filepath.Join(dir, "domain", "http.keytab")
	domain, e := auth.New(auth.Config{URL: "ldaps://dc.example.org:636", Domain: "example.org", BaseDN: "DC=example,DC=org", AllowedGroupDN: "CN=Allowed,DC=example,DC=org", DirectoryBindDN: "CN=svc,DC=example,DC=org", DirectoryPasswordFile: password, Kerberos: &auth.KerberosConfig{Realm: "EXAMPLE.ORG", ServicePrincipal: "HTTP/print.example.org", KeytabFile: path}})
	if e != nil {
		t.Fatal(e)
	}
	k, e := auth.NewKerberos(domain, &x509.Certificate{DNSNames: []string{"print.example.org"}, Raw: []byte("certificate")})
	if e != nil {
		t.Fatal(e)
	}
	q, e := queue.Open(filepath.Join(dir, "data"))
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	s := &Server{Store: q, Domain: domain, SSO: k, Token: strings.Repeat("a", 32)}
	h := s.Handler()
	kt := keytab.New()
	if e = kt.AddEntry("HTTP/print.example.org", "EXAMPLE.ORG", "test-key", time.Now(), 1, 18); e != nil {
		t.Fatal(e)
	}
	valid, e := kt.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	upload := func(data []byte, secure bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/api/domain/keytab", bytes.NewReader(data))
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+s.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := upload(valid, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := upload(valid, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before, _ := os.ReadFile(path)
	for _, bad := range [][]byte{nil, {5}, []byte("not-a-keytab")} {
		if w := upload(bad, true); w.Code != 400 {
			t.Fatal(w.Code)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("failed upload replaced active keytab")
		}
	}
	if _, _, ready := k.Status(); !ready {
		t.Fatal("valid upload not activated")
	}
}
