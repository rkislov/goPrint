// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package maildelivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

func TestNoticeTLSPlainMessageAndLostAcknowledgement(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprint(drop), func(t *testing.T) {
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
			s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
			listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			messages := make(chan string, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				fmt.Fprint(conn, "220 test\r\n")
				for {
					line, e := r.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						fmt.Fprint(conn, "250 OK\r\n")
					case strings.HasPrefix(line, "DATA"):
						fmt.Fprint(conn, "354 send\r\n")
						var b strings.Builder
						for {
							line, e = r.ReadString('\n')
							if e != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							b.WriteString(line)
						}
						messages <- b.String()
						if drop {
							return
						}
						fmt.Fprint(conn, "250 queued\r\n")
					default:
						return
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			n, _ := strconv.Atoi(port)
			_, e = s.Configure(context.Background(), Config{Enabled: true, Host: host, Port: n, Mode: "tls", From: "goprint@example.test", Domains: []string{"example.test"}, MaxMiB: 1})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.SendNotice(context.Background(), "admin@other.test", "test", "test"); e == nil {
				t.Fatal("recipient policy bypass")
			}
			state, e := s.SendNotice(context.Background(), "admin@example.test", "Заканчивается тонер", "Принтер: Office\nОстаток: 4%")
			if drop {
				if state != "unknown" || e == nil {
					t.Fatal(state, e)
				}
			} else if state != "sent" || e != nil {
				t.Fatal(state, e)
			}
			select {
			case text := <-messages:
				msg, e := mail.ReadMessage(strings.NewReader(text))
				if e != nil || !strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") || msg.Header.Get("Content-Disposition") != "" {
					t.Fatal(text, e)
				}
				encoded, _ := io.ReadAll(msg.Body)
				b, e := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(encoded), "\r", ""), "\n", ""))
				if e != nil || !strings.Contains(string(b), "Остаток: 4%") {
					t.Fatal(string(b), e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no SMTP message")
			}
		})
	}
}
