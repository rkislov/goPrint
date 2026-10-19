// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package antivirus

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled  bool   `json:"enabled"`
	Engine   string `json:"engine"`
	Endpoint string `json:"endpoint"`
}
type Service struct {
	Store *queue.Store
	slots chan struct{}
}

func New(q *queue.Store) *Service { return &Service{Store: q, slots: make(chan struct{}, 2)} }
func (s *Service) Config(ctx context.Context) (Config, error) {
	var c Config
	e := s.Store.Setting(ctx, "antivirus", &c)
	return c, e
}
func validate(c Config) error {
	if !c.Enabled && c.Endpoint == "" {
		return nil
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid antivirus endpoint")
	}
	switch c.Engine {
	case "clamav":
		if u.Scheme == "unix" && u.Path != "" && u.Host == "" {
			return nil
		}
		if u.Scheme != "tcp" || u.Hostname() == "" || u.Port() == "" || u.Path != "" {
			return errors.New("ClamAV: unix:///path/clamd.sock or tcp://host:3310")
		}
	case "icap":
		if (u.Scheme != "icap" && u.Scheme != "icaps") || u.Hostname() == "" || u.Path == "" || u.Path == "/" {
			return errors.New("ICAP: icap(s)://host:1344/service")
		}
	default:
		return errors.New("choose ClamAV or ICAP")
	}
	return nil
}
func (s *Service) Configure(ctx context.Context, c Config) (Config, error) {
	if e := validate(c); e != nil {
		return c, e
	}
	return c, s.Store.SetSetting(ctx, "antivirus", c)
}
func connect(ctx context.Context, u *url.URL) (net.Conn, error) {
	network, address := "tcp", u.Host
	if u.Scheme == "unix" {
		network, address = "unix", u.Path
	} else if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "1344")
	}
	c, e := (&net.Dialer{}).DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	if u.Scheme == "icaps" {
		secure := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()})
		if e = secure.HandshakeContext(ctx); e != nil {
			c.Close()
			return nil, e
		}
		return secure, nil
	}
	return c, nil
}
func (s *Service) Check(ctx context.Context, path string) error {
	cfg, e := s.Config(ctx)
	if e != nil {
		return errors.New("antivirus policy unavailable; document blocked")
	}
	if !cfg.Enabled {
		return nil
	}
	if e = validate(cfg); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return errors.New("antivirus timeout; document blocked")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > queue.MaxDocumentSize || !st.Mode().IsRegular() {
		return errors.New("antivirus document size/type rejected")
	}
	u, _ := url.Parse(cfg.Endpoint)
	c, e := connect(ctx, u)
	if e != nil {
		return errors.New("antivirus unavailable; document blocked")
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if cfg.Engine == "clamav" {
		e = clam(c, f)
	} else {
		e = icap(c, u, f, st.Size())
	}
	if e != nil {
		return fmt.Errorf("antivirus blocked document: %w", e)
	}
	return nil
}
func clam(c net.Conn, r io.Reader) error {
	if _, e := io.WriteString(c, "zINSTREAM\x00"); e != nil {
		return errors.New("ClamAV connection failed")
	}
	b := make([]byte, 32<<10)
	var size [4]byte
	for {
		n, readErr := r.Read(b)
		var e error
		if n > 0 {
			binary.BigEndian.PutUint32(size[:], uint32(n))
			if _, e = c.Write(size[:]); e != nil {
				return errors.New("ClamAV transfer failed")
			}
			if _, e = c.Write(b[:n]); e != nil {
				return errors.New("ClamAV transfer failed")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	if _, e := c.Write(size[:]); e != nil {
		return errors.New("ClamAV transfer failed")
	}
	response, e := bufio.NewReader(io.LimitReader(c, 4096)).ReadString(0)
	if e != nil {
		return errors.New("ClamAV response incomplete")
	}
	answer := strings.TrimSuffix(response, "\x00")
	if answer == "stream: OK" {
		return nil
	}
	if strings.HasSuffix(answer, " FOUND") {
		return errors.New("malware detected")
	}
	return errors.New("ClamAV did not confirm a clean document")
}
func icap(c net.Conn, u *url.URL, r io.Reader, size int64) error {
	h := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", size)
	endpoint := *u
	endpoint.Scheme = "icap"
	if _, e := fmt.Fprintf(c, "RESPMOD %s ICAP/1.0\r\nHost: %s\r\nAllow: 204\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s", endpoint.String(), u.Host, len(h), h); e != nil {
		return errors.New("ICAP connection failed")
	}
	b := make([]byte, 32<<10)
	for {
		n, readErr := r.Read(b)
		var e error
		if n > 0 {
			if _, e = fmt.Fprintf(c, "%x\r\n", n); e != nil {
				return errors.New("ICAP transfer failed")
			}
			if _, e = c.Write(b[:n]); e != nil {
				return errors.New("ICAP transfer failed")
			}
			if _, e = io.WriteString(c, "\r\n"); e != nil {
				return errors.New("ICAP transfer failed")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if _, e := io.WriteString(c, "0\r\n\r\n"); e != nil {
		return errors.New("ICAP transfer failed")
	}
	reader := textproto.NewReader(bufio.NewReader(io.LimitReader(c, 16<<10)))
	for i := 0; i < 2; i++ {
		line, e := reader.ReadLine()
		if e != nil {
			return errors.New("ICAP response incomplete")
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || parts[0] != "ICAP/1.0" {
			return errors.New("invalid ICAP response")
		}
		status, e := strconv.Atoi(parts[1])
		if e != nil {
			return errors.New("invalid ICAP status")
		}
		if _, e = reader.ReadMIMEHeader(); e != nil {
			return errors.New("invalid ICAP headers")
		}
		if status == 100 {
			continue
		}
		if status == 204 {
			return nil
		}
		if status == 200 {
			return errors.New("ICAP returned a blocking or modified response")
		}
		return errors.New("ICAP did not confirm a clean document")
	}
	return errors.New("ICAP response incomplete")
}
func (s *Service) Test(ctx context.Context) error {
	cfg, e := s.Config(ctx)
	if e != nil {
		return e
	}
	if e = validate(cfg); e != nil {
		return e
	}
	if cfg.Endpoint == "" {
		return errors.New("configure antivirus endpoint")
	}
	u, _ := url.Parse(cfg.Endpoint)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, e := connect(ctx, u)
	if e != nil {
		return errors.New("antivirus connection failed")
	}
	defer c.Close()
	if cfg.Engine == "clamav" {
		if _, e = io.WriteString(c, "zPING\x00"); e != nil {
			return e
		}
		b, e := bufio.NewReader(io.LimitReader(c, 64)).ReadString(0)
		if e != nil || b != "PONG\x00" {
			return errors.New("ClamAV PING failed")
		}
		return nil
	}
	if _, e = fmt.Fprintf(c, "OPTIONS %s ICAP/1.0\r\nHost: %s\r\n\r\n", cfg.Endpoint, u.Host); e != nil {
		return e
	}
	line, e := bufio.NewReader(io.LimitReader(c, 4096)).ReadString('\n')
	if e != nil || !strings.HasPrefix(line, "ICAP/1.0 200 ") {
		return errors.New("ICAP OPTIONS failed")
	}
	return nil
}
