// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package monitoring polls read-only printer telemetry and persists alert state.
package monitoring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

type Config struct {
	Enabled        bool   `json:"enabled"`
	Method         string `json:"method"`
	IPPURI         string `json:"ipp_uri"`
	Interval       int    `json:"interval_seconds"`
	Port           int    `json:"snmp_port"`
	Version        string `json:"snmp_version"`
	Username       string `json:"snmp_username"`
	Community      string `json:"community,omitempty"`
	AuthPassword   string `json:"auth_password,omitempty"`
	PrivPassword   string `json:"priv_password,omitempty"`
	CredentialsSet bool   `json:"credentials_set"`
	Warning        int    `json:"warning_percent"`
	Critical       int    `json:"critical_percent"`
}
type savedConfig struct {
	Config  Config `json:"config"`
	Secrets []byte `json:"secrets"`
}
type Policy struct {
	Email         bool     `json:"email"`
	Recipients    []string `json:"recipients"`
	ReminderHours int      `json:"reminder_hours"`
	Recovery      bool     `json:"recovery"`
}
type Alert struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity"`
	Active       bool              `json:"active"`
	Acknowledged bool              `json:"acknowledged"`
	FirstSeen    time.Time         `json:"first_seen"`
	ChangedAt    time.Time         `json:"changed_at"`
	LastAttempt  time.Time         `json:"last_attempt"`
	Delivery     map[string]string `json:"delivery"`
	SentSeverity string            `json:"sent_severity"`
}
type Snapshot struct {
	PrinterID   string    `json:"printer_id"`
	PrinterName string    `json:"printer_name"`
	Config      Config    `json:"config"`
	Reading     Reading   `json:"reading"`
	CheckedAt   time.Time `json:"checked_at"`
	LastSuccess time.Time `json:"last_success"`
	Error       string    `json:"error,omitempty"`
	Failures    int       `json:"failures"`
	Alerts      []Alert   `json:"alerts"`
}
type Notifier interface {
	SendNotice(context.Context, string, string, string) (string, error)
}
type Service struct {
	Store *queue.Store
	Mail  Notifier
	key   []byte
	locks sync.Map
	Probe func(context.Context, queue.Printer, Config) (Reading, error)
}

func New(dir string, q *queue.Store, mail Notifier) (*Service, error) {
	path := filepath.Join(dir, "monitoring.key")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		b = make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			return nil, e
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e != nil {
		return nil, e
	}
	st, e := os.Stat(path)
	if e != nil || len(b) != 32 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("monitoring key requires 32 bytes and private permissions")
	}
	return &Service{Store: q, Mail: mail, key: b, Probe: Probe}, nil
}
func (s *Service) lock(id string) func() {
	m, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
func Defaults() Config {
	return Config{Method: "ipp", Interval: 300, Port: 161, Version: "3", Warning: 20, Critical: 5}
}
func (s *Service) config(ctx context.Context, id string) (Config, error) {
	v := savedConfig{Config: Defaults()}
	if e := s.Store.Setting(ctx, "monitor-config:"+id, &v); e != nil {
		return Config{}, e
	}
	c := v.Config
	c.CredentialsSet = len(v.Secrets) > 0
	if len(v.Secrets) > 0 {
		g, e := s.aead()
		if e != nil {
			return c, e
		}
		if len(v.Secrets) < g.NonceSize() {
			return c, errors.New("invalid monitoring credential")
		}
		b, e := g.Open(nil, v.Secrets[:g.NonceSize()], v.Secrets[g.NonceSize():], []byte(id))
		if e != nil {
			return c, e
		}
		var sec struct{ Community, Auth, Priv string }
		if e = json.Unmarshal(b, &sec); e != nil {
			return c, e
		}
		c.Community = sec.Community
		c.AuthPassword = sec.Auth
		c.PrivPassword = sec.Priv
	}
	c.CredentialsSet = c.Community != "" || c.AuthPassword != ""
	return c, nil
}
func public(c Config) Config { c.Community = ""; c.AuthPassword = ""; c.PrivPassword = ""; return c }
func (s *Service) aead() (cipher.AEAD, error) {
	b, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func (s *Service) Configure(ctx context.Context, id string, c Config) (Config, error) {
	defer s.lock(id)()
	if _, e := s.Store.Printer(ctx, id); e != nil {
		return Config{}, e
	}
	old, e := s.config(ctx, id)
	if e != nil {
		return Config{}, e
	}
	if c.Community == "" {
		c.Community = old.Community
	}
	if c.AuthPassword == "" {
		c.AuthPassword = old.AuthPassword
	}
	if c.PrivPassword == "" {
		c.PrivPassword = old.PrivPassword
	}
	if c.Method != "ipp" && c.Method != "snmp" {
		return Config{}, errors.New("метод: ipp или snmp")
	}
	if c.Interval < 60 || c.Interval > 3600 || c.Port < 1 || c.Port > 65535 || c.Critical < 0 || c.Warning > 50 || c.Critical >= c.Warning {
		return Config{}, errors.New("интервал 60–3600 секунд, порт 1–65535, пороги 0 ≤ критический < предупреждение ≤ 50")
	}
	if c.IPPURI != "" {
		u, e := url.Parse(c.IPPURI)
		if e != nil || u.User != nil || u.Hostname() == "" || u.Fragment != "" || (u.Scheme != "ipp" && u.Scheme != "ipps") {
			return Config{}, errors.New("нужен IPP/IPPS URL без пароля")
		}
	}
	if c.Version != "2c" && c.Version != "3" {
		return Config{}, errors.New("SNMP: 2c или 3")
	}
	if len(c.Community) > 255 || len(c.Username) > 255 || len(c.AuthPassword) > 255 || len(c.PrivPassword) > 255 {
		return Config{}, errors.New("слишком длинные учётные данные SNMP")
	}
	if c.Enabled && c.Method == "snmp" && (c.Version == "2c" && c.Community == "" || c.Version == "3" && (c.Username == "" || len(c.AuthPassword) < 8 || len(c.PrivPassword) < 8)) {
		return Config{}, errors.New("SNMPv2c: community; SNMPv3: имя и пароли SHA-256/AES от 8 символов")
	}
	b, _ := json.Marshal(struct{ Community, Auth, Priv string }{c.Community, c.AuthPassword, c.PrivPassword})
	g, e := s.aead()
	if e != nil {
		return Config{}, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return Config{}, e
	}
	enc := g.Seal(n, n, b, []byte(id))
	c.CredentialsSet = c.Community != "" || c.AuthPassword != ""
	v := savedConfig{public(c), enc}
	if e = s.Store.SetSetting(ctx, "monitor-config:"+id, v); e != nil {
		return Config{}, e
	}
	// A new source must not inherit old readings or alert identities.
	if old.Method != c.Method || old.IPPURI != c.IPPURI || old.Port != c.Port || old.Version != c.Version {
		if e = s.Store.SetSetting(ctx, "monitor-snapshot:"+id, Snapshot{}); e != nil {
			return Config{}, e
		}
	}
	return public(c), nil
}
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	p := Policy{ReminderHours: 24, Recovery: true, Recipients: []string{}}
	e := s.Store.Setting(ctx, "monitor-policy", &p)
	return p, e
}
func (s *Service) SetPolicy(ctx context.Context, p Policy) (Policy, error) {
	if p.ReminderHours < 1 || p.ReminderHours > 720 || len(p.Recipients) > 20 || p.Email && len(p.Recipients) == 0 {
		return p, errors.New("нужны получатели и интервал напоминания 1–720 часов")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, v := range p.Recipients {
		v = strings.TrimSpace(v)
		a, e := mail.ParseAddress(v)
		if e != nil || a.Address != v || strings.ContainsAny(v, "\r\n\x00") {
			return p, errors.New("неверный адрес администратора")
		}
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	p.Recipients = out
	return p, s.Store.SetSetting(ctx, "monitor-policy", p)
}
func (s *Service) Snapshot(ctx context.Context, p queue.Printer) (Snapshot, error) {
	c, e := s.config(ctx, p.ID)
	if e != nil {
		return Snapshot{}, e
	}
	var v Snapshot
	e = s.Store.Setting(ctx, "monitor-snapshot:"+p.ID, &v)
	v.PrinterID = p.ID
	v.PrinterName = p.Name
	v.Config = public(c)
	if v.Alerts == nil {
		v.Alerts = []Alert{}
	}
	return v, e
}
func (s *Service) All(ctx context.Context) ([]Snapshot, error) {
	ps, e := s.Store.Printers(ctx)
	if e != nil {
		return nil, e
	}
	out := []Snapshot{}
	for _, p := range ps {
		v, e := s.Snapshot(ctx, p)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Service) Poll(ctx context.Context, p queue.Printer, manual bool) (Snapshot, error) {
	defer s.lock(p.ID)()
	v, e := s.Snapshot(ctx, p)
	if e != nil {
		return v, e
	}
	c, e := s.config(ctx, p.ID)
	if e != nil {
		return v, e
	}
	age := time.Since(v.CheckedAt)
	if !c.Enabled || age < 15*time.Second || !manual && age < time.Duration(c.Interval)*time.Second {
		return v, nil
	}
	now := time.Now().UTC()
	reading, err := s.Probe(ctx, p, c)
	v.CheckedAt = now
	if ctx.Err() != nil {
		return v, ctx.Err()
	}
	if err != nil {
		v.Error = "Устройство не ответило: проверьте сеть, протокол, сертификат и учётные данные."
		v.Failures++
		if v.Failures >= 3 {
			updateAlert(&v, "offline", "Нет связи с принтером", "warning", now)
		}
	} else {
		v.Reading = reading
		v.LastSuccess = now
		v.Error = ""
		v.Failures = 0
		resolve(&v, "offline", now)
		for _, supply := range reading.Supplies {
			id := "supply:" + supply.ID
			if supply.Percent == nil {
				continue
			}
			remaining := *supply.Percent
			if supply.Filled {
				remaining = 100 - remaining
			}
			severity := ""
			if remaining <= c.Critical {
				severity = "critical"
			} else if remaining <= c.Warning {
				severity = "warning"
			}
			title := fmt.Sprintf("%s: %d%%", supply.Name, *supply.Percent)
			if supply.Filled {
				title += " (заполнение)"
			}
			if severity != "" {
				updateAlert(&v, id, title, severity, now)
			} else if remaining > c.Warning+3 {
				for i := range v.Alerts {
					if v.Alerts[i].ID == id {
						v.Alerts[i].Title = title
					}
				}
				resolve(&v, id, now)
			}
		}
		// Missing supply rows are unknown, never evidence of a replacement.
	}
	if e = s.Store.SetSetting(ctx, "monitor-snapshot:"+p.ID, v); e != nil {
		return v, e
	}
	policy, e := s.Policy(ctx)
	if e != nil {
		return v, e
	}
	if policy.Email && s.Mail != nil {
		if e = s.notify(ctx, p, &v, policy, now); e != nil {
			return v, e
		}
	}
	return v, nil
}
func updateAlert(v *Snapshot, id, title, severity string, now time.Time) {
	for i := range v.Alerts {
		a := &v.Alerts[i]
		if a.ID == id {
			a.Title = title
			if !a.Active || a.Severity != severity {
				a.Active = true
				a.Severity = severity
				a.ChangedAt = now
				a.Acknowledged = false
				a.Delivery = nil
				a.LastAttempt = time.Time{}
			}
			return
		}
	}
	v.Alerts = append(v.Alerts, Alert{ID: id, Title: title, Severity: severity, Active: true, FirstSeen: now, ChangedAt: now})
}
func resolve(v *Snapshot, id string, now time.Time) {
	for i := range v.Alerts {
		a := &v.Alerts[i]
		if a.ID == id && a.Active {
			a.Active = false
			a.ChangedAt = now
			a.Delivery = nil
			a.LastAttempt = time.Time{}
		}
	}
}
func (s *Service) notify(ctx context.Context, p queue.Printer, v *Snapshot, policy Policy, now time.Time) error {
	deliveryCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	attempts := 0
	for i := range v.Alerts {
		a := &v.Alerts[i]
		severity := a.Severity
		if !a.Active {
			severity = "recovered"
			if !policy.Recovery || a.SentSeverity == "" {
				continue
			}
		} else if a.Acknowledged {
			continue
		}
		if a.SentSeverity == severity && !a.LastAttempt.IsZero() {
			if !a.Active || now.Sub(a.LastAttempt) < time.Duration(policy.ReminderHours)*time.Hour {
				continue
			}
			a.Delivery = nil
		}
		if a.Delivery == nil {
			a.Delivery = map[string]string{}
		}
		for _, to := range policy.Recipients {
			if a.Delivery[to] != "" {
				continue
			}
			if attempts >= 8 || deliveryCtx.Err() != nil {
				return nil
			}
			attempts++
			a.Delivery[to] = "sending"
			a.LastAttempt = now
			// Persist before sending. Unknown SMTP results are not automatically retried.
			if e := s.Store.SetSetting(ctx, "monitor-snapshot:"+p.ID, v); e != nil {
				return e
			}
			label := "Предупреждение"
			if severity == "critical" {
				label = "Критический уровень"
			}
			if severity == "recovered" {
				label = "Восстановлено"
			}
			body := fmt.Sprintf("Принтер: %s\nСобытие: %s\nПоказатель: %s\nВремя UTC: %s\n\nПоказания получены от устройства. Откройте GoPrint → Настройки → Мониторинг.\n", p.Name, label, a.Title, v.CheckedAt.Format(time.RFC3339))
			state, e := s.Mail.SendNotice(deliveryCtx, to, "GoPrint: "+label+" — "+p.Name, body)
			if e != nil && state == "" {
				state = "failed"
			}
			if state == "" {
				state = "unknown"
			}
			a.Delivery[to] = state
			if e = s.Store.SetSetting(ctx, "monitor-snapshot:"+p.ID, v); e != nil {
				return e
			}
		}
		a.SentSeverity = severity
		if e := s.Store.SetSetting(ctx, "monitor-snapshot:"+p.ID, v); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Acknowledge(ctx context.Context, p queue.Printer, id string) (Snapshot, error) {
	defer s.lock(p.ID)()
	v, e := s.Snapshot(ctx, p)
	if e != nil {
		return v, e
	}
	for i := range v.Alerts {
		if v.Alerts[i].ID == id {
			v.Alerts[i].Acknowledged = true
			return v, s.Store.SetSetting(ctx, "monitor-snapshot:"+p.ID, v)
		}
	}
	return v, queue.ErrNotFound
}
func (s *Service) Run(ctx context.Context) {
	s.Tick(ctx)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}
func (s *Service) Tick(ctx context.Context) {
	ps, e := s.Store.Printers(ctx)
	if e != nil {
		return
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, p := range ps {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-sem }(); _, _ = s.Poll(ctx, p, false) }()
	}
	wg.Wait()
}
