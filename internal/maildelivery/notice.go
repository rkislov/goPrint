// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

// SendNotice sends a plain notification without document attachments. It applies
// the same TLS and recipient-domain policy as scan delivery. Unknown means the
// DATA acknowledgement was lost; callers must not immediately retry it.
func (s *Service) SendNotice(ctx context.Context, to, subject, body string) (string, error) {
	var cfg stored
	if e := s.Store.Setting(ctx, "smtp", &cfg); e != nil {
		return "failed", e
	}
	c := cfg.Config
	if !c.Enabled || !s.allowed(c, Rule{Recipient: to, MaxMiB: 1, Formats: []string{"application/pdf"}}) {
		return "failed", errors.New("SMTP disabled or recipient domain not allowed")
	}
	if len(body) > 64<<10 || len(subject) > 1024 || strings.ContainsAny(subject, "\r\n\x00") {
		return "failed", errors.New("invalid notification")
	}
	password, e := s.open(cfg.Ciphertext)
	if e != nil {
		return "failed", e
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
	if s.TLSConfig != nil {
		tlsCfg = s.TLSConfig.Clone()
		tlsCfg.ServerName = c.Host
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if e != nil {
		return "failed", e
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	conn := raw
	if c.Mode == "tls" {
		secure := tls.Client(raw, tlsCfg)
		if e = secure.HandshakeContext(ctx); e != nil {
			return "failed", e
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, c.Host)
	if e != nil {
		return "failed", e
	}
	defer client.Close()
	if c.Mode == "starttls" {
		if e = client.StartTLS(tlsCfg); e != nil {
			return "failed", e
		}
	} else if c.Mode != "tls" {
		return "failed", errors.New("SMTP TLS required")
	}
	if c.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); e != nil {
			return "failed", e
		}
	}
	if e = client.Mail(c.From); e != nil {
		return "failed", e
	}
	if e = client.Rcpt(to); e != nil {
		return "failed", e
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@goprint>\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", c.From, to, mime.QEncoding.Encode("UTF-8", subject), queue.ID(), time.Now().UTC().Format(time.RFC1123Z))
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	for len(encoded) > 0 {
		n := min(76, len(encoded))
		msg += encoded[:n] + "\r\n"
		encoded = encoded[n:]
	}
	writer, e := client.Data()
	if e != nil {
		return "failed", e
	}
	if _, e = writer.Write([]byte(msg)); e != nil {
		return "unknown", e
	}
	if e = writer.Close(); e != nil {
		return "unknown", e
	}
	return "sent", nil
}
