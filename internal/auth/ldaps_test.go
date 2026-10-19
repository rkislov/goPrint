// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A wire-level LDAPS fixture verifies bind, group checks, and certificate validation.
func TestLDAPSBindGroupsAndTrust(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveLDAP(conn)
		}
	}()
	defer func() { listener.Close(); <-done }()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600)
	config := Config{URL: "ldaps://" + listener.Addr().String(), Domain: "example.org", BaseDN: "DC=example,DC=org", AllowedGroupDN: "CN=Allowed,DC=example,DC=org", AdminGroupDN: "CN=Admins,DC=example,DC=org", CAFile: ca}
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Authenticate(context.Background(), "alice", "correct-password")
	if err != nil || id.User != "alice@example.org" || !id.Admin {
		t.Fatal(id, err)
	}
	if _, err = d.Authenticate(context.Background(), "alice", "wrong"); err == nil {
		t.Fatal("invalid password accepted")
	}
	config.CAFile = ""
	untrusted, _ := New(config)
	if _, err = untrusted.Authenticate(context.Background(), "alice", "correct-password"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
func ldapPacket(id int64, op *ber.Packet) *ber.Packet {
	p := ber.NewSequence("")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	p.AppendChild(op)
	return p
}
func ldapResult(tag ber.Tag, code int64) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return p
}
func serveLDAP(c net.Conn) {
	defer c.Close()
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case 0:
			code := int64(49)
			if len(op.Children) == 3 && op.Children[1].Value == "alice@example.org" && op.Children[2].Data.String() == "correct-password" {
				code = 0
			}
			c.Write(ldapPacket(id, ldapResult(1, code)).Bytes())
		case 3:
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "CN=Alice,DC=example,DC=org", ""))
			attrs := ber.NewSequence("")
			a := ber.NewSequence("")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "userPrincipalName", ""))
			values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "alice@example.org", ""))
			a.AppendChild(values)
			attrs.AppendChild(a)
			entry.AppendChild(attrs)
			c.Write(ldapPacket(id, entry).Bytes())
			c.Write(ldapPacket(id, ldapResult(5, 0)).Bytes())
		default:
			return
		}
	}
}
