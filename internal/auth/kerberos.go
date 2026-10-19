// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type KerberosConfig struct {
	Realm                 string `json:"realm"`
	ServicePrincipal      string `json:"service_principal"`
	KeytabFile            string `json:"keytab_file"`
	DirectoryBindDN       string `json:"directory_bind_dn"`
	DirectoryPasswordFile string `json:"directory_password_file"`
	RequireChannelBinding bool   `json:"require_channel_binding,omitempty"`
}
type Negotiator interface {
	AuthenticateToken(context.Context, string) (Identity, string, error)
}
type kerberosClaims struct {
	id      Identity
	expires time.Time
}
type Kerberos struct {
	installMu sync.Mutex
	resolve   func(context.Context, string, string) (Identity, error)
	keyMu     sync.RWMutex
	domain    *Domain
	kt        *keytab.Keytab
	binding   [16]byte
	mu        sync.Mutex
	claims    map[string]kerberosClaims
}

// Serializing verification makes gokrb5's replay-cache read/add atomic for this acceptor.
var verifyMu sync.Mutex
var ErrNegotiation = errors.New("Kerberos authentication rejected")

func privateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Kerberos secret files must be regular files with mode 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("invalid Kerberos secret file size")
	}
	return b, nil
}
func validateKerberosConfig(c Config) error {
	k := c.Kerberos
	bindDN, passwordFile := k.DirectoryBindDN, k.DirectoryPasswordFile
	if bindDN == "" {
		bindDN = c.DirectoryBindDN
	}
	if passwordFile == "" {
		passwordFile = c.DirectoryPasswordFile
	}
	if k.Realm == "" || k.Realm != strings.ToUpper(c.Domain) || k.ServicePrincipal != "HTTP/"+strings.ToLower(strings.TrimPrefix(k.ServicePrincipal, "HTTP/")) || !strings.HasPrefix(k.ServicePrincipal, "HTTP/") || strings.ContainsAny(strings.TrimPrefix(k.ServicePrincipal, "HTTP/"), "/:@ \r\n") || !strings.Contains(strings.TrimPrefix(k.ServicePrincipal, "HTTP/"), ".") || k.KeytabFile == "" || bindDN == "" || passwordFile == "" {
		return errors.New("Kerberos requires matching uppercase realm, HTTP/FQDN SPN, keytab, directory bind DN and password file")
	}
	return nil
}
func NewKerberos(d *Domain, certificate *x509.Certificate) (*Kerberos, error) {
	if d == nil || d.Config.Kerberos == nil || certificate == nil {
		return nil, errors.New("Kerberos requires configured domain and HTTPS certificate")
	}
	if err := validateKerberosConfig(d.Config); err != nil {
		return nil, err
	}
	k := d.Config.Kerberos
	if err := certificate.VerifyHostname(strings.TrimPrefix(k.ServicePrincipal, "HTTP/")); err != nil {
		return nil, err
	}
	result := &Kerberos{domain: d, binding: channelBinding(certificate), claims: map[string]kerberosClaims{}}
	b, err := privateFile(k.KeytabFile, 1<<20)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	kt, err := result.parseKeytab(b)
	if err != nil {
		return nil, err
	}
	result.kt = kt
	return result, nil
}
func (k *Kerberos) parseKeytab(b []byte) (*keytab.Keytab, error) {
	kt := new(keytab.Keytab)
	if len(b) > 1<<20 {
		return nil, errors.New("keytab too large")
	}
	if err := kt.Unmarshal(b); err != nil {
		return nil, errors.New("invalid keytab")
	}
	cfg := k.domain.Config.Kerberos
	for _, entry := range kt.Entries {
		if entry.Principal.Realm == cfg.Realm && strings.Join(entry.Principal.Components, "/") == cfg.ServicePrincipal && strongEnctype(entry.Key.KeyType) {
			return kt, nil
		}
	}
	return nil, errors.New("keytab contains no AES key for configured HTTP SPN and realm")
}
func (k *Kerberos) Status() (string, string, bool) {
	k.keyMu.RLock()
	defer k.keyMu.RUnlock()
	c := k.domain.Config.Kerberos
	return c.Realm, c.ServicePrincipal, k.kt != nil
}
func (k *Kerberos) InstallKeytab(b []byte) error {
	k.installMu.Lock()
	defer k.installMu.Unlock()
	kt, err := k.parseKeytab(b)
	if err != nil {
		return err
	}
	path := k.domain.Config.Kerberos.KeytabFile
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".keytab-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = df.Sync()
	df.Close()
	if err != nil {
		return err
	}
	k.keyMu.Lock()
	k.kt = kt
	k.keyMu.Unlock()
	return nil
}

func strongEnctype(n int32) bool { return n == 17 || n == 18 || n == 19 || n == 20 }
func (k *Kerberos) AuthenticateToken(ctx context.Context, encoded string) (Identity, string, error) {
	if len(encoded) > 128<<10 {
		return Identity{}, "", ErrNegotiation
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Identity{}, "", ErrNegotiation
	}
	var token spnego.SPNEGOToken
	var mech []byte
	if err = token.Unmarshal(raw); err != nil {
		return Identity{}, "", ErrNegotiation
	}
	if token.Init {
		mech = token.NegTokenInit.MechTokenBytes
	} else {
		mech = token.NegTokenResp.ResponseToken
	}
	if len(mech) == 0 {
		reply := spnego.NegTokenResp{NegState: asn1.Enumerated(spnego.NegStateAcceptIncomplete), SupportedMech: gssapi.OIDKRB5.OID()}
		b, e := reply.Marshal()
		if e != nil {
			return Identity{}, "", ErrNegotiation
		}
		return Identity{}, base64.StdEncoding.EncodeToString(b), ErrNegotiation
	}
	var krb spnego.KRB5Token
	if err = krb.Unmarshal(mech); err != nil || !krb.IsAPReq() {
		return Identity{}, "", ErrNegotiation
	}
	req := &krb.APReq
	cfg := k.domain.Config.Kerberos
	if req.Ticket.Realm != cfg.Realm || req.Ticket.SName.PrincipalNameString() != cfg.ServicePrincipal || !strongEnctype(req.Ticket.EncPart.EType) {
		return Identity{}, "", ErrNegotiation
	}
	k.keyMu.RLock()
	kt := k.kt
	k.keyMu.RUnlock()
	if kt == nil {
		return Identity{}, "", ErrNegotiation
	}
	verifyMu.Lock()
	ok, _, err := service.VerifyAPREQ(req, service.NewSettings(kt, service.DecodePAC(false), service.MaxClockSkew(2*time.Minute)))
	verifyMu.Unlock()
	if err != nil || !ok || req.Authenticator.CRealm != cfg.Realm || len(req.Authenticator.CName.NameString) != 1 || !strongEnctype(req.Ticket.DecryptedEncPart.Key.KeyType) {
		return Identity{}, "", ErrNegotiation
	}
	checksum := req.Authenticator.Cksum
	if checksum.CksumType != chksumtype.GSSAPI || len(checksum.Checksum) < 24 || binary.LittleEndian.Uint32(checksum.Checksum[:4]) != 16 {
		return Identity{}, "", ErrNegotiation
	}
	supplied := checksum.Checksum[4:20]
	zero := make([]byte, 16)
	if subtle.ConstantTimeCompare(supplied, zero) != 1 || cfg.RequireChannelBinding {
		if subtle.ConstantTimeCompare(supplied, k.binding[:]) != 1 {
			return Identity{}, "", ErrNegotiation
		}
	}
	if binary.LittleEndian.Uint32(checksum.Checksum[20:24])&1 != 0 {
		return Identity{}, "", ErrNegotiation
	} // No credential delegation.
	user := req.Authenticator.CName.NameString[0]
	key := user + "@" + cfg.Realm
	k.mu.Lock()
	cached, present := k.claims[key]
	k.mu.Unlock()
	var id Identity
	if present && time.Now().Before(cached.expires) {
		id = cached.id
	} else {
		if k.resolve != nil {
			id, err = k.resolve(ctx, user, cfg.Realm)
		} else {
			id, err = k.domain.ResolveKerberos(ctx, user, cfg.Realm)
		}
		if err != nil {
			return Identity{}, "", ErrCredentials
		}
		k.mu.Lock()
		for name, v := range k.claims {
			if time.Now().After(v.expires) {
				delete(k.claims, name)
			}
		}
		if len(k.claims) < 2048 {
			k.claims[key] = kerberosClaims{id, time.Now().Add(30 * time.Second)}
		}
		k.mu.Unlock()
	}
	reply, err := mutualReply(*req)
	if err != nil {
		return Identity{}, "", ErrNegotiation
	}
	return id, base64.StdEncoding.EncodeToString(reply), nil
}
func mutualReply(req messages.APReq) ([]byte, error) {
	enc := messages.EncAPRepPart{CTime: req.Authenticator.CTime, Cusec: req.Authenticator.Cusec}
	b, err := asn1.Marshal(enc)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, 27)
	encrypted, err := crypto.GetEncryptedData(b, req.Ticket.DecryptedEncPart.Key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}
	reply := messages.APRep{PVNO: 5, MsgType: 15, EncPart: encrypted}
	b, err = asn1.Marshal(reply)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, 15)
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	mech := asn1tools.AddASNAppTag(append(append(oid, 2, 0), b...), 0)
	response := spnego.NegTokenResp{NegState: asn1.Enumerated(spnego.NegStateAcceptCompleted), SupportedMech: gssapi.OIDKRB5.OID(), ResponseToken: mech}
	return response.Marshal()
}
func channelBinding(cert *x509.Certificate) [16]byte {
	var hash []byte
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		h := sha512.Sum384(cert.Raw)
		hash = h[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		h := sha512.Sum512(cert.Raw)
		hash = h[:]
	default:
		h := sha256.Sum256(cert.Raw)
		hash = h[:]
	}
	data := append([]byte("tls-server-end-point:"), hash...)
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(data)))
	b = append(b, data...)
	return md5.Sum(b) // RFC 4121 channel-binding hash, not password hashing.
}
