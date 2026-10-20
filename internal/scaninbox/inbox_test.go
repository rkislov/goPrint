// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scaninbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"github.com/rkislov/goPrint/internal/testutil"
)

func fixture(t *testing.T) (*Service, *scanning.Service) {
	t.Helper()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { q.Close() })
	sc, e := scanning.Open(filepath.Join(dir, "scans"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { sc.Close() })
	s, e := New(dir, q, sc, func(_ context.Context, user string) (string, error) {
		if user == "alice@example.org" || user == "bob@example.org" || user == "local-admin" {
			return user, nil
		}
		return "", errors.New("disabled user")
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s, sc
}
func destination(t *testing.T, s *Service) Destination {
	t.Helper()
	d, e := s.Save(context.Background(), "", Destination{Name: "Office", Owner: "alice@example.org", Enabled: true, WebDAV: true, FTP: true, FTPS: true, MaxMiB: 1}, false)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestBoundOwnerRotationDisableLimitAndValidation(t *testing.T) {
	s, sc := fixture(t)
	ctx := context.Background()
	d := destination(t, s)
	token := d.Token
	j, e := s.Receive(ctx, d.ID, token, "webdav", "bob@example.org.pdf", bytes.NewReader(testutil.PDF()))
	if e != nil || j.Owner != "alice@example.org" {
		t.Fatal(j, e)
	}
	users, _ := sc.JobsFor(ctx, "bob@example.org", false)
	if len(users) != 0 {
		t.Fatal("scan leaked to Bob")
	}
	alice, _ := sc.JobsFor(ctx, "alice@example.org", false)
	if len(alice) != 1 {
		t.Fatal(alice)
	}
	all, _ := s.List(ctx)
	if all[0].Token != "" || all[0].Hash != "" {
		t.Fatal("credential leak")
	}
	if _, e = s.Receive(ctx, d.ID, token, "webdav", "bad.pdf", strings.NewReader("%PDF-1.4\ntruncated")); e == nil {
		t.Fatal("truncated PDF accepted")
	}
	if _, e = s.Receive(ctx, d.ID, token, "webdav", "large.pdf", bytes.NewReader(bytes.Repeat([]byte{'x'}, (1<<20)+1))); e == nil {
		t.Fatal("size limit ignored")
	}
	d.Owner = "bob@example.org"
	d, e = s.Save(ctx, d.ID, d, false)
	if e != nil || d.Token == "" || d.Token == token {
		t.Fatal(d, e)
	}
	if _, e = s.Authenticate(ctx, d.ID, token, "webdav"); e == nil {
		t.Fatal("old token survived owner change")
	}
	token = d.Token
	d.Enabled = false
	if _, e = s.Save(ctx, d.ID, d, false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, d.ID, token, "ftp"); e == nil {
		t.Fatal("disabled destination accepted")
	}
	jobs, _ := sc.Jobs(ctx)
	if len(jobs) != 1 {
		t.Fatal("rejected files published", jobs)
	}
}

type wire struct {
	conn net.Conn
	r    *textproto.Reader
	t    *testing.T
}

func (w *wire) command(code int, format string, args ...any) string {
	w.t.Helper()
	if _, e := fmt.Fprintf(w.conn, format+"\r\n", args...); e != nil {
		w.t.Fatal(e)
	}
	_, msg, e := w.r.ReadResponse(code)
	if e != nil {
		w.t.Fatal(format, msg, e)
	}
	return msg
}
func TestFTPAndFTPSUploadIsolationAndTemporaryRename(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			s, sc := fixture(t)
			d := destination(t, s)
			certServer := httptest.NewTLSServer(nil)
			cert := certServer.TLS.Certificates[0]
			certServer.Close()
			roots := x509.NewCertPool()
			parsed, _ := x509.ParseCertificate(cert.Certificate[0])
			roots.AddCert(parsed)
			s.TLSConfig = func() (*tls.Config, error) {
				return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
			}
			c := DefaultFTP()
			c.Enabled = true
			c.Listen = "127.0.0.1:0"
			c.PassiveMin = 0
			c.AllowPlain = !secure
			runtime, e := s.start(c)
			if e != nil {
				t.Fatal(e)
			}
			defer runtime.close()
			if secure {
				clear, e := net.DialTimeout("tcp", runtime.server.Addr(), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				clear.SetDeadline(time.Now().Add(3 * time.Second))
				pr := textproto.NewReader(bufio.NewReader(clear))
				if _, _, e = pr.ReadResponse(220); e != nil {
					t.Fatal(e)
				}
				fmt.Fprintf(clear, "USER %s\r\n", d.ID)
				if _, _, e = pr.ReadResponse(421); e != nil {
					t.Fatal("FTPS accepted clear login", e)
				}
				clear.Close()
			}
			conn, e := net.DialTimeout("tcp", runtime.server.Addr(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			w := &wire{conn: conn, r: textproto.NewReader(bufio.NewReader(conn)), t: t}
			if _, _, e = w.r.ReadResponse(220); e != nil {
				t.Fatal(e)
			}
			if secure {
				w.command(234, "AUTH TLS")
				tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
				if e = tlsConn.Handshake(); e != nil {
					t.Fatal(e)
				}
				w.conn = tlsConn
				w.r = textproto.NewReader(bufio.NewReader(tlsConn))
				w.command(200, "PBSZ 0")
				w.command(200, "PROT P")
			}
			w.command(331, "USER %s", d.ID)
			w.command(230, "PASS %s", d.Token)
			w.command(200, "TYPE I")
			if secure {
				w.command(200, "PROT C")
				w.command(550, "STOR unprotected.pdf")
				w.command(200, "PROT P")
			}
			upload := func(name string, body []byte) {
				t.Helper()
				msg := w.command(229, "EPSV")
				start := strings.Index(msg, "|||")
				end := strings.Index(msg[start+3:], "|")
				if start < 0 || end < 0 {
					t.Fatal(msg)
				}
				port := msg[start+3 : start+3+end]
				data, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				data.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(w.conn, "STOR %s\r\n", name)
				if _, _, e = w.r.ReadResponse(150); e != nil {
					t.Fatal(e)
				}
				if secure {
					tc := tls.Client(data, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
					if e = tc.Handshake(); e != nil {
						t.Fatal(e)
					}
					data = tc
				}
				if _, e = data.Write(body); e != nil {
					t.Fatal(e)
				}
				data.Close()
				if _, _, e = w.r.ReadResponse(226); e != nil {
					t.Fatal(e)
				}
			}
			upload("scan.tmp", testutil.PDF())
			jobs, _ := sc.Jobs(context.Background())
			if len(jobs) != 0 {
				t.Fatal("temporary scan published before RNTO")
			}
			w.command(350, "RNFR scan.tmp")
			w.command(250, "RNTO scan.pdf")
			jobs, _ = sc.Jobs(context.Background())
			if len(jobs) != 1 || jobs[0].Owner != "alice@example.org" {
				t.Fatal(jobs)
			}
			upload("second.pdf", testutil.PDF())
			jobs, _ = sc.Jobs(context.Background())
			if len(jobs) != 2 {
				t.Fatal(jobs)
			}
			if !secure {
				msg := w.command(229, "EPSV")
				start := strings.Index(msg, "|||")
				tail := msg[start+3:]
				end := strings.Index(tail, "|")
				data, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", tail[:end]), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				fmt.Fprint(w.conn, "STOR broken.pdf\r\n")
				if _, _, e = w.r.ReadResponse(150); e != nil {
					t.Fatal(e)
				}
				data.Write(testutil.PDF()[:40])
				data.(*net.TCPConn).SetLinger(0)
				data.Close()
				code, _, e := w.r.ReadResponse(-1)
				if e != nil || code < 400 {
					t.Fatal("interrupted transfer acknowledged", code, e)
				}
				jobs, _ = sc.Jobs(context.Background())
				if len(jobs) != 2 {
					t.Fatal("partial file published", jobs)
				}
			}
			msg := w.command(229, "EPSV")
			start := strings.Index(msg, "|||")
			tail := msg[start+3:]
			end := strings.Index(tail, "|")
			data, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", tail[:end]), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			data.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprint(w.conn, "STOR oversized.pdf\r\n")
			if _, _, e = w.r.ReadResponse(150); e != nil {
				t.Fatal(e)
			}
			if secure {
				tc := tls.Client(data, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
				if e = tc.Handshake(); e != nil {
					t.Fatal(e)
				}
				data = tc
			}
			_, _ = data.Write(bytes.Repeat([]byte{'x'}, (1<<20)+32768))
			data.Close()
			code, _, e := w.r.ReadResponse(-1)
			if e != nil || code < 400 {
				t.Fatal("oversized upload acknowledged", code, e)
			}
			jobs, _ = sc.Jobs(context.Background())
			if len(jobs) != 2 {
				t.Fatal("oversized upload published", jobs)
			}
			w.command(550, "RETR scan.pdf")
			w.command(550, "APPE scan.pdf")
			w.command(421, "PORT 127,0,0,1,1,1")
		})
	}
}

type rejectScan struct{}

func (rejectScan) Check(context.Context, string) error { return errors.New("antivirus unavailable") }
func TestAntivirusFailureAndMidstreamRevocationDoNotPublish(t *testing.T) {
	s, sc := fixture(t)
	d := destination(t, s)
	ctx := context.Background()
	sc.Validator = rejectScan{}
	if _, e := s.Receive(ctx, d.ID, d.Token, "webdav", "infected.pdf", bytes.NewReader(testutil.PDF())); e == nil {
		t.Fatal("antivirus bypassed")
	}
	sc.Validator = nil
	reader := &revokingReader{Reader: bytes.NewReader(testutil.PDF()), revoke: func() { s.Rotate(ctx, d.ID) }}
	if _, e := s.Receive(ctx, d.ID, d.Token, "webdav", "revoked.pdf", reader); e == nil {
		t.Fatal("revoked during streaming accepted")
	}
	jobs, _ := sc.Jobs(ctx)
	if len(jobs) != 0 {
		t.Fatal(jobs)
	}
}

type revokingReader struct {
	*bytes.Reader
	revoke func()
}

func (r *revokingReader) Read(p []byte) (int, error) {
	if r.revoke != nil {
		r.revoke()
		r.revoke = nil
	}
	return r.Reader.Read(p)
}
func TestFTPConfigurationRequiresExplicitPlaintextNetworks(t *testing.T) {
	c := DefaultFTP()
	c.Enabled = true
	c.AllowPlain = true
	if validateFTP(c) == nil {
		t.Fatal("plaintext without allowlist accepted")
	}
	c.Networks = []string{"192.0.2.0/24"}
	if e := validateFTP(c); e != nil {
		t.Fatal(e)
	}
	s, _ := fixture(t)
	c.AllowPlain = false
	if _, e := s.SetFTP(context.Background(), c); e == nil {
		t.Fatal("FTPS without certificate accepted")
	}
}

func TestFTPListenerConfigurationPersistsAndStops(t *testing.T) {
	s, _ := fixture(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	c := DefaultFTP()
	c.Enabled = true
	c.AllowPlain = true
	c.Networks = []string{"127.0.0.0/8"}
	c.Listen = address
	c.PassiveMin = 40000
	c.PassiveMax = 40015
	if strings.HasSuffix(address, ":40000") {
		c.PassiveMin = 41000
		c.PassiveMax = 41015
	}
	status, e := s.SetFTP(context.Background(), c)
	if e != nil || !status.Listening {
		t.Fatal(status, e)
	}
	s.Close()
	restored, e := New(filepath.Dir(s.dir), s.Store, s.Scans, s.ResolveOwner, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if !restored.FTPStatus().Listening {
		t.Fatal("listener config was not restored")
	}
	c.Enabled = false
	status, e = restored.SetFTP(context.Background(), c)
	if e != nil || status.Listening {
		t.Fatal(status, e)
	}
	if conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("disabled listener still accepts")
	}
}
