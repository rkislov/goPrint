// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSyslogFramingAndDurableCursor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	p, err := s.AddPrinter(ctx, queue.Printer{Name: "Office", URI: "socket://localhost:9100", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Submit(ctx, p.ID, "DOMAIN\\user", "private-title", "application/pdf", strings.NewReader("%PDF-test"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSetting(ctx, "siem", Config{Enabled: true, Endpoint: "tcp://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	e := New(s)
	if err = e.Once(ctx); err == nil {
		t.Fatal("failed connection not reported")
	}
	var cursor int64
	s.Setting(ctx, "siem_cursor", &cursor)
	if cursor != 0 {
		t.Fatal("failed delivery advanced cursor")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	message := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		prefix, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(prefix))
		b := make([]byte, n)
		io.ReadFull(r, b)
		message <- string(b)
	}()
	s.SetSetting(ctx, "siem", Config{Enabled: true, Endpoint: "tcp://" + ln.Addr().String()})
	if err = e.Once(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-message:
		if !strings.HasPrefix(msg, "<134>1 ") || strings.Contains(msg, "private-title") {
			t.Fatalf("bad payload: %s", msg)
		}
		var event queue.AuditEvent
		if err = json.Unmarshal([]byte(msg[strings.Index(msg, "{"):]), &event); err != nil || event.JobID != j.ID || event.ID != 1 {
			t.Fatalf("bad event: %+v %v", event, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message")
	}
	s.Close()
	s, err = queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e = New(s)
	if e.Status().LastEvent != 1 {
		t.Fatal("cursor did not survive restart")
	}
	ln.Close()
	if err = e.Once(ctx); err != nil {
		t.Fatalf("already sent event replayed: %v", err)
	}
}
