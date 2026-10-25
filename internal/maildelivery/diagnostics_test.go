// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPDiagnosticsTLSAuthAndNoMail(t *testing.T) {
	for _, tc := range []struct {
		name, mode, code string
		trusted, reject  bool
	}{{"authenticated", "tls", "smtp_delivery_unchecked", true, false}, {"untrusted", "tls", "smtp_tls_tls_ca", false, false}, {"auth rejected", "tls", "smtp_auth", true, true}, {"missing starttls", "starttls", "smtp_starttls_missing", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			q, e := queue.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer q.Close()
			s, e := New(dir, q, nil)
			if e != nil {
				t.Fatal(e)
			}
			fixture := httptest.NewTLSServer(nil)
			cert := fixture.TLS.Certificates[0]
			fixture.Close()
			roots := x509.NewCertPool()
			parsed, _ := x509.ParseCertificate(cert.Certificate[0])
			roots.AddCert(parsed)
			if tc.trusted {
				s.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			}
			var ln net.Listener
			if tc.mode == "tls" {
				ln, e = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			} else {
				ln, e = net.Listen("tcp", "127.0.0.1:0")
			}
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			done := make(chan struct{})
			commands := make(chan string, 16)
			go func() {
				defer close(done)
				c, e := ln.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprint(c, "220 fixture\r\n")
				b := bufio.NewReader(c)
				for {
					line, e := b.ReadString('\n')
					if e != nil {
						return
					}
					commands <- line
					switch {
					case strings.HasPrefix(line, "EHLO"):
						fmt.Fprint(c, "250-test\r\n250 AUTH PLAIN\r\n")
					case strings.HasPrefix(line, "AUTH"):
						if tc.reject {
							fmt.Fprint(c, "535 sensitive-value\r\n")
						} else {
							fmt.Fprint(c, "235 authenticated\r\n")
						}
					default:
						return
					}
				}
			}()
			host, port, _ := net.SplitHostPort(ln.Addr().String())
			n, _ := strconv.Atoi(port)
			_, e = s.Configure(context.Background(), Config{Enabled: true, Host: host, Port: n, Mode: tc.mode, From: "print@example.org", Username: "service", Password: "sensitive-value", Domains: []string{"example.org"}, MaxMiB: 1})
			if e != nil {
				t.Fatal(e)
			}
			result := s.Diagnose(context.Background())
			<-done
			close(commands)
			for cmd := range commands {
				if strings.HasPrefix(cmd, "MAIL") || strings.HasPrefix(cmd, "RCPT") || strings.HasPrefix(cmd, "DATA") {
					t.Fatal("email operation", cmd)
				}
			}
			b, _ := json.Marshal(result)
			if strings.Contains(string(b), "sensitive-value") {
				t.Fatal("secret leaked")
			}
			found := false
			for _, step := range result.Steps {
				if step.Code == tc.code {
					found = true
				}
			}
			if !found {
				t.Fatal(result)
			}
		})
	}
}
