// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package auth

import (
	"context"
	"crypto/tls"
	"github.com/go-ldap/ldap/v3"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"net"
	"net/url"
	"time"
)

// Diagnose binds only the saved service account, never a guessed user password.
func (d *Domain) Diagnose(ctx context.Context) diagnostics.Report {
	r := diagnostics.New()
	u, _ := url.Parse(d.Config.URL)
	port := u.Port()
	if port == "" {
		if u.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		r.Error("ldap_connect", err)
		return r
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	r.Add("ldap_tcp", "ok", "TCP-соединение с контроллером установлено.", "")
	connRaw := raw
	if u.Scheme == "ldaps" {
		secure := tls.Client(raw, d.tls.Clone())
		if err = secure.HandshakeContext(ctx); err != nil {
			r.Error("ldap_tls", err)
			return r
		}
		connRaw = secure
	}
	conn := ldap.NewConn(connRaw, u.Scheme == "ldaps")
	conn.Start()
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)
	if u.Scheme == "ldap" {
		if err = conn.StartTLS(d.tls.Clone()); err != nil {
			r.Error("ldap_starttls", err)
			return r
		}
	}
	r.Add("ldap_tls", "ok", "Защищённое LDAP-соединение установлено; сертификат проверен.", "")
	if d.Config.DirectoryBindDN == "" || d.directoryPassword == "" {
		r.Add("ldap_bind_unconfigured", "warning", "Служебная учётная запись LDAP не настроена.", "Вход по паролю может работать без неё. Для SSO, email и Samba настройте directory_bind_dn и directory_password_file; чтение каталога не проверено.")
		return r
	}
	if err = conn.Bind(d.Config.DirectoryBindDN, d.directoryPassword); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			r.Add("ldap_bind_credentials", "error", "Контроллер отклонил служебные учётные данные.", "Проверьте DN и пароль, блокировку, срок действия и состояние служебной записи.")
		} else {
			r.Error("ldap_bind", err)
		}
		return r
	}
	r.Add("ldap_bind", "ok", "Служебный LDAP bind выполнен.", "")
	for _, v := range []struct{ dn, code, name string }{{d.Config.BaseDN, "ldap_base", "База поиска"}, {d.Config.AllowedGroupDN, "ldap_allowed_group", "Разрешённая группа"}, {d.Config.AdminGroupDN, "ldap_admin_group", "Группа администраторов"}} {
		if v.dn == "" {
			continue
		}
		filter := "(objectClass=*)"
		if v.code != "ldap_base" {
			filter = "(objectClass=group)"
		}
		out, e := conn.Search(ldap.NewSearchRequest(v.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 4, false, filter, []string{"1.1"}, nil))
		if e != nil || len(out.Entries) != 1 {
			r.Add(v.code, "error", v.name+": объект не найден или недоступен для чтения.", "Проверьте полный DN и права чтения служебной записи.")
			return r
		}
		r.Add(v.code, "ok", v.name+": объект доступен.", "")
	}
	r.Add("ldap_user_scope", "warning", "Вход конкретного пользователя и вложенные группы не проверялись.", "Выполните контрольный вход разрешённым и запрещённым пользователями.")
	return r
}
