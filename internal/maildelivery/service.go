// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Mode        string   `json:"mode"`
	From        string   `json:"from"`
	Username    string   `json:"username"`
	Password    string   `json:"password,omitempty"`
	PasswordSet bool     `json:"password_set"`
	Domains     []string `json:"allowed_domains"`
	MaxMiB      int      `json:"max_mib"`
}
type stored struct {
	Config     Config `json:"config"`
	Ciphertext []byte `json:"ciphertext"`
}
type Rule struct {
	Enabled   bool     `json:"enabled"`
	Recipient string   `json:"recipient"`
	Formats   []string `json:"formats"`
	MaxMiB    int      `json:"max_mib"`
	Since     string   `json:"since,omitempty"`
}
type Service struct {
	Store     *queue.Store
	Scans     *scanning.Service
	key       []byte
	TLSConfig *tls.Config
}

func New(dir string, q *queue.Store, s *scanning.Service) (*Service, error) {
	p := filepath.Join(dir, "smtp.key")
	key, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, e = f.Write(key)
		if e == nil {
			e = f.Sync()
		}
		f.Close()
	}
	if e != nil || len(key) != 32 {
		return nil, errors.New("invalid SMTP encryption key")
	}
	st, e := os.Stat(p)
	if e != nil || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("SMTP key requires private permissions")
	}
	return &Service{Store: q, Scans: s, key: key}, nil
}
func (s *Service) seal(b []byte) ([]byte, error) {
	c, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, b, nil), nil
}
func (s *Service) open(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	c, e := aes.NewCipher(s.key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(c)
	if e != nil || len(b) < g.NonceSize() {
		return "", errors.New("invalid encrypted SMTP credential")
	}
	plain, e := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	return string(plain), e
}
func address(v string) bool {
	a, e := mail.ParseAddress(v)
	return e == nil && a.Address == v && !strings.ContainsAny(v, "\r\n\x00")
}
func (s *Service) Config(ctx context.Context) (Config, error) {
	var v stored
	e := s.Store.Setting(ctx, "smtp", &v)
	c := v.Config
	c.Password = ""
	c.PasswordSet = len(v.Ciphertext) > 0
	if c.Mode == "" {
		c.Mode = "starttls"
		c.Port = 587
		c.MaxMiB = 20
	}
	return c, e
}
func (s *Service) Configure(ctx context.Context, c Config) (Config, error) {
	if c.Mode != "tls" && c.Mode != "starttls" {
		return c, errors.New("выберите TLS или STARTTLS")
	}
	if c.Port < 1 || c.Port > 65535 || c.MaxMiB < 1 || c.MaxMiB > 20 {
		return c, errors.New("порт 1–65535, размер 1–20 МиБ")
	}
	if c.Enabled && (!address(c.From) || len(c.Domains) == 0 || c.Host == "") {
		return c, errors.New("нужны SMTP-сервер, адрес отправителя и разрешённые домены")
	}
	if strings.ContainsAny(c.Host, "/ \r\n\x00") || strings.ContainsAny(c.Username, "\r\n\x00") {
		return c, errors.New("неверный SMTP-сервер или пользователь")
	}
	for i, d := range c.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.ContainsAny(d, "@/ *\r\n\x00") || !strings.Contains(d, ".") {
			return c, errors.New("нужны точные домены получателей без масок")
		}
		c.Domains[i] = d
	}
	var old stored
	if e := s.Store.Setting(ctx, "smtp", &old); e != nil {
		return c, e
	}
	if len(c.Password) > 4096 {
		return c, errors.New("слишком длинный пароль")
	}
	if c.Password != "" {
		b, e := s.seal([]byte(c.Password))
		if e != nil {
			return c, e
		}
		old.Ciphertext = b
	}
	c.Password = ""
	c.PasswordSet = len(old.Ciphertext) > 0
	old.Config = c
	return c, s.Store.SetSetting(ctx, "smtp", old)
}
func (s *Service) Rule(ctx context.Context, user string) (Rule, error) {
	var r Rule
	e := s.Store.Setting(ctx, "scan-rule:"+user, &r)
	if r.MaxMiB == 0 {
		r.MaxMiB = 10
		r.Formats = []string{"application/pdf"}
	}
	return r, e
}
func (s *Service) allowed(c Config, r Rule) bool {
	if !address(r.Recipient) || r.MaxMiB < 1 || r.MaxMiB > c.MaxMiB || len(r.Formats) == 0 {
		return false
	}
	_, domain, _ := strings.Cut(r.Recipient, "@")
	found := false
	for _, d := range c.Domains {
		if strings.EqualFold(d, domain) {
			found = true
		}
	}
	for _, f := range r.Formats {
		if f != "application/pdf" && f != "image/jpeg" && f != "image/png" && f != "application/zip" {
			return false
		}
	}
	return found
}
func (s *Service) SetRule(ctx context.Context, user string, r Rule) (Rule, error) {
	c, e := s.Config(ctx)
	if e != nil {
		return r, e
	}
	if r.Enabled && !s.allowed(c, r) {
		return r, errors.New("проверьте адрес, разрешённый домен, форматы и размер не выше лимита SMTP")
	}
	r.Since = time.Now().UTC().Format(time.RFC3339Nano)
	return r, s.Store.SetSetting(ctx, "scan-rule:"+user, r)
}
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Service) Tick(ctx context.Context) {
	c, e := s.Config(ctx)
	if e != nil || !c.Enabled {
		return
	}
	jobs, e := s.Scans.Undelivered(ctx)
	if e != nil {
		return
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		r, e := s.Rule(ctx, j.Owner)
		if e != nil {
			return
		}
		d := scanning.Delivery{ID: j.ID, State: "skipped", Detail: "scan does not match an enabled delivery rule"}
		match := false
		for _, f := range r.Formats {
			if f == j.Format {
				match = true
			}
		}
		created, _ := time.Parse(time.RFC3339Nano, j.CreatedAt)
		since, _ := time.Parse(time.RFC3339Nano, r.Since)
		if !r.Enabled || !s.allowed(c, r) || !match || j.Size > int64(r.MaxMiB)<<20 || created.Before(since) {
			s.Scans.SaveMail(ctx, d)
			continue
		}
		d.Target = r.Recipient
		d.State = "sending"
		d.Detail = "SMTP delivery started"
		if e = s.Scans.SaveMail(ctx, d); e != nil {
			return
		}
		state, e := s.send(ctx, c, j, r.Recipient)
		d.State = state
		d.Detail = ""
		if e != nil {
			d.Detail = "SMTP delivery failed; check mail server and recipient"
		}
		if e = s.Scans.SaveMail(context.WithoutCancel(ctx), d); e != nil {
			return
		}
	}
}
func (s *Service) send(ctx context.Context, c Config, j scanning.Job, to string) (state string, err error) {
	state = "failed"
	var cfg stored
	if err = s.Store.Setting(ctx, "smtp", &cfg); err != nil {
		return
	}
	if !cfg.Config.Enabled || cfg.Config.Host != c.Host || cfg.Config.Port != c.Port || cfg.Config.Mode != c.Mode || cfg.Config.Username != c.Username || !s.allowed(cfg.Config, Rule{Recipient: to, MaxMiB: 1, Formats: []string{j.Format}}) {
		return state, errors.New("SMTP policy changed before delivery")
	}
	password, e := s.open(cfg.Ciphertext)
	if e != nil {
		return state, e
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
		return state, e
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
			return state, e
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, c.Host)
	if e != nil {
		return state, e
	}
	defer client.Close()
	if c.Mode == "starttls" {
		if e = client.StartTLS(tlsCfg); e != nil {
			return state, e
		}
	}
	if c.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); e != nil {
			return state, e
		}
	}
	if e = client.Mail(c.From); e != nil {
		return state, e
	}
	if e = client.Rcpt(to); e != nil {
		return state, e
	}
	if e = s.Scans.CheckDocument(ctx, s.Scans.Path(j.ID)); e != nil {
		return state, e
	}
	file, e := os.Open(s.Scans.Path(j.ID))
	if e != nil {
		return state, e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, int64(c.MaxMiB)<<20+1))
	if e != nil || len(b) > c.MaxMiB<<20 {
		return state, errors.New("scan exceeds SMTP attachment limit")
	}
	ext := map[string]string{"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png", "application/zip": "zip"}[j.Format]
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@goprint>\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\nContent-Disposition: attachment; filename=\"scan.%s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n", c.From, to, mime.QEncoding.Encode("UTF-8", "Сканированный документ"), j.ID, j.Format, ext)
	encoded := base64.StdEncoding.EncodeToString(b)
	for len(encoded) > 0 {
		n := 76
		if n > len(encoded) {
			n = len(encoded)
		}
		msg.WriteString(encoded[:n] + "\r\n")
		encoded = encoded[n:]
	}
	writer, e := client.Data()
	if e != nil {
		return state, e
	}
	state = "unknown"
	if _, e = writer.Write(msg.Bytes()); e != nil {
		return state, e
	}
	if e = writer.Close(); e != nil {
		return state, e
	}
	return "sent", nil
}
