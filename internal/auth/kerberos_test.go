// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKerberosTicketsMutualReplayAndKeytab(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Domain: "example.org", Kerberos: &KerberosConfig{Realm: "EXAMPLE.ORG", ServicePrincipal: "HTTP/print.example.org", KeytabFile: filepath.Join(dir, "domain", "http.keytab"), DirectoryBindDN: "CN=svc,DC=example,DC=org", DirectoryPasswordFile: "unused"}}
	d := &Domain{Config: cfg}
	cert := &x509.Certificate{DNSNames: []string{"print.example.org"}, Raw: []byte("test certificate"), SignatureAlgorithm: x509.SHA256WithRSA}
	k, e := NewKerberos(d, cert)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, ready := k.Status(); ready {
		t.Fatal("missing keytab marked ready")
	}
	kt := keytab.New()
	if e = kt.AddEntry(cfg.Kerberos.ServicePrincipal, "EXAMPLE.ORG", "test-service-password", time.Now(), 1, 18); e != nil {
		t.Fatal(e)
	}
	b, e := kt.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	if e = k.InstallKeytab(b); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(cfg.Kerberos.KeytabFile)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	if e = k.InstallKeytab([]byte("invalid")); e == nil {
		t.Fatal("invalid keytab accepted")
	}
	k.resolve = func(context.Context, string, string) (Identity, error) {
		return Identity{User: "alice@example.org", Groups: []string{"CN=Allowed,DC=example,DC=org"}}, nil
	}
	issue := func(binding []byte, offset time.Duration, spn string) (string, types.EncryptionKey, types.Authenticator) {
		t.Helper()
		when := time.Now().UTC()
		cname := types.PrincipalName{NameType: 1, NameString: []string{"alice"}}
		sname := types.PrincipalName{NameType: 2, NameString: []string{"HTTP", "print.example.org"}}
		ticket, key, e := messages.NewTicket(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), kt, 18, 1, when, when.Add(-time.Minute), when.Add(time.Hour), when.Add(time.Hour))
		if e != nil {
			t.Fatal(e)
		}
		a, e := types.NewAuthenticator("EXAMPLE.ORG", cname)
		if e != nil {
			t.Fatal(e)
		}
		a.CTime = a.CTime.Add(offset)
		checksum := make([]byte, 24)
		binary.LittleEndian.PutUint32(checksum, 16)
		copy(checksum[4:20], binding)
		a.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		req, e := messages.NewAPReq(ticket, key, a)
		if e != nil {
			t.Fatal(e)
		}
		if spn != "" {
			req.Ticket.SName.NameString[1] = spn
		}
		ap, e := req.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		oid, _ := asn1.Marshal(gssapi.OIDKRB5.OID())
		mech := asn1tools.AddASNAppTag(append(append(oid, 1, 0), ap...), 0)
		neg := spnego.SPNEGOToken{Init: true, NegTokenInit: spnego.NegTokenInit{MechTypes: []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, MechTokenBytes: mech}}
		raw, e := neg.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(raw), key, a
	}
	token, key, a := issue(k.binding[:], 0, "")
	id, reply, e := k.AuthenticateToken(context.Background(), token)
	if e != nil || id.User != "alice@example.org" || reply == "" {
		t.Fatal(id, e)
	}
	raw, _ := base64.StdEncoding.DecodeString(reply)
	var response spnego.SPNEGOToken
	if e = response.Unmarshal(raw); e != nil {
		t.Fatal(e)
	}
	var mech spnego.KRB5Token
	if e = mech.Unmarshal(response.NegTokenResp.ResponseToken); e != nil {
		t.Fatal(e)
	}
	plain, e := crypto.DecryptEncPart(mech.APRep.EncPart, key, keyusage.AP_REP_ENCPART)
	if e != nil {
		t.Fatal(e)
	}
	var enc messages.EncAPRepPart
	if e = enc.Unmarshal(plain); e != nil || !enc.CTime.Equal(a.CTime.Truncate(time.Second)) || enc.Cusec != a.Cusec {
		t.Fatal("mutual authentication timestamp mismatch", e)
	}
	if _, _, e = k.AuthenticateToken(context.Background(), token); e == nil {
		t.Fatal("replay accepted")
	}
	for _, tc := range []struct {
		binding []byte
		offset  time.Duration
		spn     string
	}{{[]byte("wrong-binding-xx"), 0, ""}, {k.binding[:], -10 * time.Minute, ""}, {k.binding[:], 0, "other.example.org"}} {
		token, _, _ = issue(tc.binding, tc.offset, tc.spn)
		if _, _, e = k.AuthenticateToken(context.Background(), token); e == nil {
			t.Fatal("invalid ticket accepted", tc)
		}
	}
	cfg.Kerberos.RequireChannelBinding = true
	zero := make([]byte, 16)
	token, _, _ = issue(zero, 0, "")
	if _, _, e = k.AuthenticateToken(context.Background(), token); e == nil {
		t.Fatal("missing required CBT accepted")
	}
}
