// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package audit exports committed print events using RFC 5424 and octet counting.
package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
}
type Status struct {
	LastEvent int64  `json:"last_event"`
	LastSent  string `json:"last_sent,omitempty"`
	Error     string `json:"error,omitempty"`
}
type Exporter struct {
	store  *queue.Store
	mu     sync.Mutex
	status Status
}

func New(s *queue.Store) *Exporter {
	var cursor int64
	_ = s.Setting(context.Background(), "siem_cursor", &cursor)
	return &Exporter{store: s, status: Status{LastEvent: cursor}}
}
func Validate(c Config) error {
	if !c.Enabled && c.Endpoint == "" {
		return nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Hostname() == "" || u.Port() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "tcp" && u.Scheme != "tls") {
		return errors.New("укажите tcp://host:port или tls://host:port без пароля и пути")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("некорректный адрес SIEM")
	}
	return nil
}
func (e *Exporter) Status() Status { e.mu.Lock(); defer e.mu.Unlock(); return e.status }
func (e *Exporter) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := e.Once(ctx); err != nil {
			e.mu.Lock()
			e.status.Error = err.Error()
			e.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (e *Exporter) Once(ctx context.Context) error {
	var config Config
	if err := e.store.Setting(ctx, "siem", &config); err != nil {
		return err
	}
	if !config.Enabled {
		return nil
	}
	var cursor int64
	if err := e.store.Setting(ctx, "siem_cursor", &cursor); err != nil {
		return err
	}
	events, err := e.store.AuditEvents(ctx, cursor)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if err = Validate(config); err != nil {
		return err
	}
	u, _ := url.Parse(config.Endpoint)
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	if u.Scheme == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}).DialContext(sendCtx, "tcp", u.Host)
	} else {
		conn, err = dialer.DialContext(sendCtx, "tcp", u.Host)
	}
	if err != nil {
		return errors.New("не удалось подключиться к SIEM; события остаются в локальном журнале")
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	for _, event := range events {
		msg := Message(event)
		frame := fmt.Sprintf("%d %s", len(msg), msg)
		if _, err = io.Copy(conn, strings.NewReader(frame)); err != nil {
			return errors.New("отправка в SIEM прервана; событие будет повторено")
		}
		if err = e.store.SetSetting(ctx, "siem_cursor", event.ID); err != nil {
			return err
		}
		e.mu.Lock()
		e.status = Status{LastEvent: event.ID, LastSent: time.Now().UTC().Format(time.RFC3339)}
		e.mu.Unlock()
	}
	return nil
}
func Message(event queue.AuditEvent) string {
	b, _ := json.Marshal(event)
	stamp := event.At
	if t, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
		stamp = t.UTC().Format("2006-01-02T15:04:05.000000Z")
	} else {
		stamp = time.Now().UTC().Format(time.RFC3339)
	}
	return "<134>1 " + stamp + " - goprint - print - " + string(b)
}
