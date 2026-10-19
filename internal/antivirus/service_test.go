// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package antivirus

import (
	"bufio"
	"context"
	"encoding/binary"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClamStreamingAndFailClosed(t *testing.T) {
	q, e := queue.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	av := New(q)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				command, _ := r.ReadString(0)
				if command == "zPING\x00" {
					io.WriteString(c, "PONG\x00")
					return
				}
				if command != "zINSTREAM\x00" {
					return
				}
				var b [4]byte
				var data []byte
				for {
					if _, e := io.ReadFull(r, b[:]); e != nil {
						return
					}
					n := binary.BigEndian.Uint32(b[:])
					if n == 0 {
						break
					}
					if n > 32<<10 {
						return
					}
					v := make([]byte, n)
					if _, e = io.ReadFull(r, v); e != nil {
						return
					}
					data = append(data, v...)
				}
				answer := "stream: OK\x00"
				if strings.Contains(string(data), "EICAR") {
					answer = "stream: Eicar-Test-Signature FOUND\x00"
				}
				io.WriteString(c, answer)
			}()
		}
	}()
	ctx := context.Background()
	cfg := Config{Enabled: true, Engine: "clamav", Endpoint: "tcp://" + listener.Addr().String()}
	if _, e = av.Configure(ctx, cfg); e != nil {
		t.Fatal(e)
	}
	if e = av.Test(ctx); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "document")
	os.WriteFile(path, []byte("clean"), 0600)
	if e = av.Check(ctx, path); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, []byte("EICAR"), 0600)
	if e = av.Check(ctx, path); e == nil {
		t.Fatal("infected document accepted")
	}
	listener.Close()
	os.WriteFile(path, []byte("clean"), 0600)
	if e = av.Check(ctx, path); e == nil {
		t.Fatal("unavailable scanner allowed document")
	}
}
func TestICAPCleanBlockedAndMalformed(t *testing.T) {
	for _, response := range []string{"ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n", "ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n", "garbage\r\n\r\n"} {
		t.Run(response[:7], func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			go func() {
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, e := r.ReadString('\n')
					if e != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				for {
					line, e := r.ReadString('\n')
					if e != nil {
						return
					}
					if line == "0\r\n" {
						r.ReadString('\n')
						break
					}
				}
				io.WriteString(c, response)
			}()
			c, e := net.Dial("tcp", l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			u, _ := url.Parse("icap://" + l.Addr().String() + "/scan")
			e = icap(c, u, strings.NewReader("test"), 4)
			if (e == nil) != strings.Contains(response, "204") {
				t.Fatal(e)
			}
		})
	}
}
