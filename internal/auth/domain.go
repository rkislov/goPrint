// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type Identity struct {
	User   string   `json:"user"`
	Admin  bool     `json:"admin"`
	Groups []string `json:"groups,omitempty"`
}
type Authenticator interface {
	Authenticate(context.Context, string, string) (Identity, error)
}
type Config struct {
	DirectoryBindDN       string          `json:"directory_bind_dn,omitempty"`
	DirectoryPasswordFile string          `json:"directory_password_file,omitempty"`
	URL                   string          `json:"url"`
	Domain                string          `json:"domain"`
	NetBIOS               string          `json:"netbios,omitempty"`
	BaseDN                string          `json:"base_dn"`
	AllowedGroupDN        string          `json:"allowed_group_dn"`
	AdminGroupDN          string          `json:"admin_group_dn,omitempty"`
	CAFile                string          `json:"ca_file,omitempty"`
	Kerberos              *KerberosConfig `json:"kerberos,omitempty"`
}
type Domain struct {
	Config            Config
	tls               *tls.Config
	directoryPassword string
}

var ErrCredentials = errors.New("неверное имя, пароль или нет доступа к GoPrint")

func Load(path string) (*Domain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c Config
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("expected one domain config object")
	}
	return New(c)
}
func New(c Config) (*Domain, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return nil, errors.New("domain URL must be ldaps://host:636 or ldap://host:389 (mandatory StartTLS)")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9-]+$`).MatchString(c.Domain) {
		return nil, errors.New("domain DNS name required")
	}
	for _, dn := range []string{c.BaseDN, c.AllowedGroupDN} {
		if dn == "" {
			return nil, errors.New("base_dn and allowed_group_dn required")
		}
		if _, err := ldap.ParseDN(dn); err != nil {
			return nil, fmt.Errorf("invalid DN: %w", err)
		}
	}
	if c.AdminGroupDN != "" {
		if _, err := ldap.ParseDN(c.AdminGroupDN); err != nil {
			return nil, err
		}
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.CAFile != "" {
		b, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificate")
		}
		tc.RootCAs = roots
	}
	d := &Domain{Config: c, tls: tc}
	if c.Kerberos != nil {
		if err := validateKerberosConfig(c); err != nil {
			return nil, err
		}
		if c.DirectoryBindDN == "" {
			c.DirectoryBindDN = c.Kerberos.DirectoryBindDN
		}
		if c.DirectoryPasswordFile == "" {
			c.DirectoryPasswordFile = c.Kerberos.DirectoryPasswordFile
		}
	}
	if c.DirectoryBindDN != "" || c.DirectoryPasswordFile != "" {
		if _, err := ldap.ParseDN(c.DirectoryBindDN); err != nil {
			return nil, errors.New("invalid directory bind DN")
		}
		password, err := privateFile(c.DirectoryPasswordFile, 4096)
		if err != nil {
			return nil, err
		}
		d.directoryPassword = strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
		if d.directoryPassword == "" {
			return nil, errors.New("empty directory service password")
		}
	}
	d.Config = c

	return d, nil
}
func (d *Domain) Principal(user string) (string, error) {
	user = strings.TrimSpace(user)
	if strings.Contains(user, `\`) {
		parts := strings.Split(user, `\`)
		if len(parts) != 2 || d.Config.NetBIOS == "" || !strings.EqualFold(parts[0], d.Config.NetBIOS) {
			return "", ErrCredentials
		}
		user = parts[1]
	}
	if !strings.Contains(user, "@") {
		user += "@" + d.Config.Domain
	}
	p := strings.Split(user, "@")
	if len(p) != 2 || !strings.EqualFold(p[1], d.Config.Domain) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(p[0]) {
		return "", ErrCredentials
	}
	return strings.ToLower(user), nil
}
func (d *Domain) Authenticate(ctx context.Context, user, password string) (Identity, error) {
	principal, err := d.Principal(user)
	if err != nil || password == "" || len(password) > 4096 {
		return Identity{}, ErrCredentials
	}
	conn, err := d.connect(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()
	if err = conn.Bind(principal, password); err != nil {
		return Identity{}, ErrCredentials
	}
	return d.resolve(ctx, conn, "(userPrincipalName="+ldap.EscapeFilter(principal)+")", principal)
}
func (d *Domain) connect(ctx context.Context) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(d.Config.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}), ldap.DialWithTLSConfig(d.tls.Clone()))
	if err != nil {
		return nil, errors.New("контроллер домена недоступен или сертификат не прошёл проверку")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	_ = stop
	conn.SetTimeout(8 * time.Second)
	if strings.HasPrefix(d.Config.URL, "ldap://") {
		if err = conn.StartTLS(d.tls.Clone()); err != nil {
			conn.Close()
			return nil, errors.New("StartTLS домена не установлен")
		}
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return conn, nil
}
func (d *Domain) resolve(ctx context.Context, conn *ldap.Conn, selector, expected string) (Identity, error) {
	filter := "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))" + selector + "(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(d.Config.AllowedGroupDN) + "))"
	result, err := conn.Search(ldap.NewSearchRequest(d.Config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 8, false, filter, []string{"userPrincipalName"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return Identity{}, ErrCredentials
	}
	canonical, err := d.Principal(result.Entries[0].GetAttributeValue("userPrincipalName"))
	if err != nil || expected != "" && canonical != expected {
		return Identity{}, ErrCredentials
	}
	id := Identity{User: canonical, Groups: []string{d.Config.AllowedGroupDN}}
	if d.Config.AdminGroupDN != "" {
		r, err := conn.Search(ldap.NewSearchRequest(result.Entries[0].DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(memberOf:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(d.Config.AdminGroupDN)+")", []string{"1.1"}, nil))
		if err != nil {
			return Identity{}, ErrCredentials
		}
		id.Admin = len(r.Entries) == 1
	}
	groups, err := conn.Search(ldap.NewSearchRequest(d.Config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1024, 8, false, "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(result.Entries[0].DN)+"))", []string{"1.1"}, nil))
	if err != nil {
		return Identity{}, ErrCredentials
	}
	for _, entry := range groups.Entries {
		id.Groups = append(id.Groups, entry.DN)
	}
	return id, nil
}
func (d *Domain) ResolveKerberos(ctx context.Context, user, realm string) (Identity, error) {
	if d.Config.Kerberos == nil || realm != d.Config.Kerberos.Realm {
		return Identity{}, ErrCredentials
	}
	principal, err := d.Principal(user)
	if err != nil {
		return Identity{}, err
	}
	name := strings.Split(principal, "@")[0]
	conn, err := d.connect(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()
	if err = conn.Bind(d.Config.DirectoryBindDN, d.directoryPassword); err != nil {
		return Identity{}, ErrCredentials
	}
	return d.resolve(ctx, conn, "(sAMAccountName="+ldap.EscapeFilter(name)+")", "")
}

// ResolveMail is called only after a trusted gateway authenticates the envelope sender.
func (d *Domain) ResolveMail(ctx context.Context, address string) (Identity, error) {
	if len(address) > 254 || !strings.Contains(address, "@") || strings.ContainsAny(address, "\r\n\x00") {
		return Identity{}, ErrCredentials
	}
	return d.directoryIdentity(ctx, "(mail="+ldap.EscapeFilter(address)+")")
}
func (d *Domain) ResolveUser(ctx context.Context, user string) (Identity, error) {
	p, e := d.Principal(user)
	if e != nil {
		return Identity{}, e
	}
	return d.directoryIdentity(ctx, "(userPrincipalName="+ldap.EscapeFilter(p)+")")
}
func (d *Domain) directoryIdentity(ctx context.Context, selector string) (Identity, error) {
	if d.Config.DirectoryBindDN == "" || d.directoryPassword == "" {
		return Identity{}, ErrCredentials
	}
	conn, e := d.connect(ctx)
	if e != nil {
		return Identity{}, e
	}
	defer conn.Close()
	if e = conn.Bind(d.Config.DirectoryBindDN, d.directoryPassword); e != nil {
		return Identity{}, ErrCredentials
	}
	return d.resolve(ctx, conn, selector, "")
}
