// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSMTPEncryptedRuleAndUncertainAck(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprint(drop), func(t *testing.T) {
			dir := t.TempDir()
			q, e := queue.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer q.Close()
			sc, e := scanning.Open(filepath.Join(dir, "scans"))
			if e != nil {
				t.Fatal(e)
			}
			defer sc.Close()
			svc, e := New(dir, q, sc)
			if e != nil {
				t.Fatal(e)
			}
			fixture := httptest.NewTLSServer(nil)
			cert := fixture.TLS.Certificates[0]
			fixture.Close()
			root := x509.NewCertPool()
			parsed, _ := x509.ParseCertificate(cert.Certificate[0])
			root.AddCert(parsed)
			svc.TLSConfig = &tls.Config{RootCAs: root, MinVersion: tls.VersionTLS12}
			listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			var accepted atomic.Int32
			go func() {
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						r := bufio.NewReader(c)
						fmt.Fprint(c, "220 test SMTP\r\n")
						for {
							line, e := r.ReadString('\n')
							if e != nil {
								return
							}
							switch {
							case strings.HasPrefix(line, "EHLO"):
								fmt.Fprint(c, "250-test\r\n250 AUTH PLAIN\r\n")
							case strings.HasPrefix(line, "AUTH"):
								fmt.Fprint(c, "235 OK\r\n")
							case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
								fmt.Fprint(c, "250 OK\r\n")
							case strings.HasPrefix(line, "DATA"):
								fmt.Fprint(c, "354 Send\r\n")
								var body strings.Builder
								for {
									l, e := r.ReadString('\n')
									if e != nil {
										return
									}
									if l == ".\r\n" {
										break
									}
									body.WriteString(l)
								}
								if !strings.Contains(body.String(), "Content-Transfer-Encoding: base64") || !strings.Contains(body.String(), "JVBERi") {
									t.Error("attachment missing")
								}
								accepted.Add(1)
								if drop {
									return
								}
								fmt.Fprint(c, "250 queued\r\n")
							default:
								return
							}
						}
					}()
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			var n int
			fmt.Sscan(port, &n)
			ctx := context.Background()
			cfg := Config{Enabled: true, Host: host, Port: n, Mode: "tls", From: "scan@example.test", Username: "smtp-user", Password: "top-secret", Domains: []string{"example.test"}, MaxMiB: 20}
			view, e := svc.Configure(ctx, cfg)
			if e != nil || view.Password != "" || !view.PasswordSet {
				t.Fatal(view, e)
			}
			var storedValue stored
			q.Setting(ctx, "smtp", &storedValue)
			if strings.Contains(string(storedValue.Ciphertext), "top-secret") || storedValue.Config.Password != "" {
				t.Fatal("plaintext SMTP credential persisted")
			}
			if _, e = svc.SetRule(ctx, "local-admin", Rule{Enabled: true, Recipient: "alice@evil.test", Formats: []string{"application/pdf"}, MaxMiB: 10}); e == nil {
				t.Fatal("foreign recipient domain accepted")
			}
			if _, e = svc.SetRule(ctx, "local-admin", Rule{Enabled: true, Recipient: "alice@example.test", Formats: []string{"application/pdf"}, MaxMiB: 10}); e != nil {
				t.Fatal(e)
			}
			scanner, e := sc.Add(ctx, "test", "http://127.0.0.1/eSCL")
			if e != nil {
				t.Fatal(e)
			}
			time.Sleep(time.Millisecond)
			job, e := sc.Receive(ctx, scanner.ID, "test.pdf", strings.NewReader("%PDF-1.4 test"))
			if e != nil {
				t.Fatal(e)
			}
			svc.Tick(ctx)
			status, e := sc.MailStatus(ctx, job.ID)
			want := "sent"
			if drop {
				want = "unknown"
			}
			if e != nil || status.State != want {
				t.Fatal(status, e)
			}
			svc.Tick(ctx)
			if accepted.Load() != 1 {
				t.Fatal("duplicate automatic email", accepted.Load())
			}
			key, _ := os.ReadFile(filepath.Join(dir, "smtp.key"))
			if len(key) != 32 {
				t.Fatal("missing durable encryption key")
			}
		})
	}
}
