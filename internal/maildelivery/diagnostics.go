// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"context"
	"crypto/tls"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"net"
	"net/smtp"
	"strconv"
	"time"
)

// Diagnose intentionally stops before MAIL, RCPT and DATA: no email is sent.
func (s *Service) Diagnose(ctx context.Context) diagnostics.Report {
	r := diagnostics.New()
	var v stored
	if e := s.Store.Setting(ctx, "smtp", &v); e != nil {
		r.Add("smtp_config", "error", "Не удалось прочитать настройки SMTP.", "Проверьте доступность БД.")
		return r
	}
	c := v.Config
	if !c.Enabled {
		r.Add("smtp_disabled", "warning", "SMTP выключен.", "Настройте и включите сервер в разделе «Почта», затем повторите проверку.")
		return r
	}
	if c.Host == "" || c.Port < 1 || c.Port > 65535 || c.Mode != "tls" && c.Mode != "starttls" {
		r.Add("smtp_config", "error", "Неполная конфигурация SMTP.", "Задайте сервер, порт и TLS/STARTTLS.")
		return r
	}
	password, e := s.open(v.Ciphertext)
	if e != nil {
		r.Add("smtp_secret", "error", "Не удалось расшифровать пароль SMTP.", "Восстановите smtp.key из резервной копии или сохраните пароль заново.")
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if e != nil {
		r.Error("smtp_connect", e)
		return r
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	r.Add("smtp_tcp", "ok", "TCP-соединение с SMTP установлено.", "")
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
	if s.TLSConfig != nil {
		tc = s.TLSConfig.Clone()
		tc.ServerName = c.Host
	}
	conn := raw
	if c.Mode == "tls" {
		secure := tls.Client(raw, tc)
		if e = secure.HandshakeContext(ctx); e != nil {
			r.Error("smtp_tls", e)
			return r
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, c.Host)
	if e != nil {
		r.Error("smtp_greeting", e)
		return r
	}
	defer client.Close()
	if c.Mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			r.Add("smtp_starttls_missing", "error", "SMTP-сервер не предлагает STARTTLS.", "Проверьте порт и режим; для неявного TLS выберите TLS.")
			return r
		}
		if e = client.StartTLS(tc); e != nil {
			r.Error("smtp_starttls", e)
			return r
		}
	}
	r.Add("smtp_tls", "ok", "TLS установлен; сертификат проверен.", "")
	if c.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			r.Add("smtp_auth_missing", "error", "Сервер не предлагает SMTP AUTH после TLS.", "Проверьте порт и политику аутентификации SMTP.")
			return r
		}
		if e = client.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); e != nil {
			r.Add("smtp_auth", "error", "SMTP-аутентификация отклонена или прервана.", "Проверьте служебную запись, пароль и разрешение AUTH PLAIN после TLS.")
			return r
		}
		r.Add("smtp_auth", "ok", "SMTP-аутентификация выполнена.", "")
	} else {
		r.Add("smtp_auth_skipped", "warning", "SMTP AUTH не настроен; доступ по IP не проверен.", "Если используется релей по IP, проверьте разрешения отдельно.")
	}
	r.Add("smtp_delivery_unchecked", "warning", "Письмо не отправлялось; права на отправителя и получателя не проверены.", "Проверка не выполняет MAIL, RCPT и DATA. Доставку документа проверьте отдельным разрешённым сценарием.")
	return r
}
