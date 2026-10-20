// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scaninbox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

type FTPConfig struct {
	Enabled    bool     `json:"enabled"`
	Listen     string   `json:"listen"`
	PublicIP   string   `json:"passive_public_ip"`
	PassiveMin int      `json:"passive_min"`
	PassiveMax int      `json:"passive_max"`
	AllowPlain bool     `json:"allow_plain_ftp"`
	Networks   []string `json:"allowed_networks"`
}
type FTPStatus struct {
	Config       FTPConfig `json:"config"`
	Listening    bool      `json:"listening"`
	Address      string    `json:"address,omitempty"`
	TLSAvailable bool      `json:"tls_available"`
	Error        string    `json:"error,omitempty"`
}

func DefaultFTP() FTPConfig {
	return FTPConfig{Listen: "127.0.0.1:2121", PassiveMin: 50000, PassiveMax: 50031, Networks: []string{}}
}
func validateFTP(c FTPConfig) error {
	host, port, e := net.SplitHostPort(c.Listen)
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || net.ParseIP(host) == nil || n < 1 || n > 65535 {
		return errors.New("нужен IP:порт FTP, например 0.0.0.0:2121")
	}
	if c.PassiveMin < 1024 || c.PassiveMax > 65535 || c.PassiveMax < c.PassiveMin || c.PassiveMax-c.PassiveMin > 255 || n >= c.PassiveMin && n <= c.PassiveMax {
		return errors.New("пассивный диапазон: 1024–65535, до 256 портов, без управляющего порта")
	}
	if c.PublicIP != "" && (net.ParseIP(c.PublicIP) == nil || net.ParseIP(c.PublicIP).To4() == nil) {
		return errors.New("для PASV нужен IPv4 сервера; для IPv6 используйте EPSV")
	}
	if len(c.Networks) > 32 || c.AllowPlain && len(c.Networks) == 0 {
		return errors.New("для обычного FTP явно укажите разрешённые CIDR-подсети")
	}
	for _, s := range c.Networks {
		if _, _, e := net.ParseCIDR(s); e != nil {
			return errors.New("неверная CIDR-подсеть")
		}
	}
	return nil
}
func (s *Service) FTPStatus() FTPStatus {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	return s.status()
}
func (s *Service) status() FTPStatus {
	v := FTPStatus{Config: s.ftpConfig, Error: s.ftpError}
	if s.runtime != nil {
		v.Listening = true
		v.Address = s.runtime.server.Addr()
	}
	if s.TLSConfig != nil {
		c, e := s.TLSConfig()
		v.TLSAvailable = e == nil && c != nil && len(c.Certificates) > 0
	}
	return v
}
func (s *Service) SetFTP(ctx context.Context, c FTPConfig) (FTPStatus, error) {
	if e := validateFTP(c); e != nil {
		return FTPStatus{}, e
	}
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if c.Enabled && !c.AllowPlain {
		if s.TLSConfig == nil {
			return FTPStatus{}, errors.New("настройте TLS-сертификат GoPrint для FTPS")
		}
		if _, e := s.TLSConfig(); e != nil {
			return FTPStatus{}, errors.New("TLS-сертификат FTPS недоступен")
		}
	}
	old := s.ftpConfig
	if s.runtime != nil {
		s.runtime.close()
		s.runtime = nil
	}
	var r *ftpRuntime
	var e error
	if c.Enabled {
		r, e = s.start(c)
	}
	if e == nil {
		e = s.Store.SetSetting(ctx, "scan-ftp", c)
	}
	if e != nil {
		if r != nil {
			r.close()
		}
		if old.Enabled {
			s.runtime, _ = s.start(old)
		}
		return s.status(), errors.New("не удалось применить FTP: проверьте свободные порты и TLS")
	}
	s.ftpConfig = c
	s.runtime = r
	s.ftpError = ""
	return s.status(), nil
}
func (s *Service) Close() {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.runtime != nil {
		s.runtime.close()
		s.runtime = nil
	}
}

type ftpClient struct {
	cc ftpserver.ClientContext
	fs *uploadFS
}
type attempt struct {
	start time.Time
	count int
}
type ftpRuntime struct {
	listener net.Listener
	conns    map[*trackedConn]bool
	owner    *Service
	cfg      FTPConfig
	server   *ftpserver.FtpServer
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	clients  map[uint32]*ftpClient
	attempts map[string]attempt
	closing  bool
	wg       sync.WaitGroup
	done     chan struct{}
}

func (s *Service) start(c FTPConfig) (*ftpRuntime, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &ftpRuntime{owner: s, cfg: c, ctx: ctx, cancel: cancel, clients: map[uint32]*ftpClient{}, attempts: map[string]attempt{}, done: make(chan struct{})}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		cancel()
		return nil, e
	}
	r.conns = map[*trackedConn]bool{}
	r.listener = &trackedListener{Listener: listener, runtime: r}
	r.server = ftpserver.NewFtpServer(r)
	if e := r.server.Listen(); e != nil {
		r.listener.Close()
		cancel()
		return nil, e
	}
	go func() { defer close(r.done); _ = r.server.Serve() }()
	return r, nil
}
func (r *ftpRuntime) close() {
	r.mu.Lock()
	r.closing = true
	conns := []*trackedConn{}
	for conn := range r.conns {
		conns = append(conns, conn)
	}
	r.mu.Unlock()
	r.cancel()
	_ = r.server.Stop()
	for _, conn := range conns {
		_ = conn.Close()
	}
	<-r.done
	r.wg.Wait()
}
func (r *ftpRuntime) GetSettings() (*ftpserver.Settings, error) {
	mode := ftpserver.MandatoryEncryption
	if r.cfg.AllowPlain {
		mode = ftpserver.ClearOrEncrypted
	}
	v := &ftpserver.Settings{Listener: r.listener, ListenAddr: r.cfg.Listen, PublicHost: r.cfg.PublicIP, Banner: "GoPrint scan inbox", IdleTimeout: 120, ConnectionTimeout: 30, TLSRequired: mode, DisableActiveMode: true, DisableSite: true, DisableMFMT: true, DisableSTAT: true, DisableASCIIConversion: true, DefaultTransferType: ftpserver.TransferTypeBinary, PasvConnectionsCheck: ftpserver.IPMatchRequired}
	if r.cfg.PassiveMin > 0 {
		v.PassiveTransferPortRange = &ftpserver.PortRange{Start: r.cfg.PassiveMin, End: r.cfg.PassiveMax}
	}
	return v, nil
}
func (r *ftpRuntime) GetTLSConfig() (*tls.Config, error) {
	if r.owner.TLSConfig == nil {
		return nil, errors.New("TLS unavailable")
	}
	c, e := r.owner.TLSConfig()
	if e != nil || c == nil {
		return nil, errors.New("TLS unavailable")
	}
	c = c.Clone()
	c.MinVersion = tls.VersionTLS12
	return c, nil
}
func (r *ftpRuntime) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || len(r.clients) >= 32 {
		return "", errors.New("connection limit")
	}
	ip := peerIP(cc.RemoteAddr())
	allowed := len(r.cfg.Networks) == 0
	for _, v := range r.cfg.Networks {
		_, network, _ := net.ParseCIDR(v)
		if network != nil && network.Contains(ip) {
			allowed = true
		}
	}
	if !allowed {
		return "", errors.New("network not allowed")
	}
	r.clients[cc.ID()] = &ftpClient{cc: cc}
	r.wg.Add(1)
	return "GoPrint scan inbox", nil
}
func (r *ftpRuntime) ClientDisconnected(cc ftpserver.ClientContext) {
	r.mu.Lock()
	c := r.clients[cc.ID()]
	delete(r.clients, cc.ID())
	r.mu.Unlock()
	if c != nil {
		if c.fs != nil {
			c.fs.cleanup()
		}
		r.wg.Done()
	}
}
func (r *ftpRuntime) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	protocol := "ftp"
	if cc.HasTLSForControl() {
		protocol = "ftps"
		if e := cc.SetTLSRequirement(ftpserver.MandatoryEncryption); e != nil {
			return nil, e
		}
	} else if !r.cfg.AllowPlain {
		return nil, ErrCredentials
	}
	ip := peerIP(cc.RemoteAddr()).String()
	r.mu.Lock()
	a, exists := r.attempts[ip]
	if len(r.attempts) >= 1024 && !exists {
		for key, value := range r.attempts {
			if time.Since(value.start) > time.Minute {
				delete(r.attempts, key)
			}
		}
		if len(r.attempts) >= 1024 {
			r.mu.Unlock()
			return nil, ErrCredentials
		}
	}
	if time.Since(a.start) > time.Minute {
		a = attempt{start: time.Now()}
	}
	a.count++
	r.attempts[ip] = a
	tooMany := a.count > 20
	client := r.clients[cc.ID()]
	r.mu.Unlock()
	if tooMany || client == nil {
		return nil, ErrCredentials
	}
	if _, e := r.owner.Authenticate(r.ctx, user, pass, protocol); e != nil {
		return nil, ErrCredentials
	}
	fs := &uploadFS{Fs: afero.NewReadOnlyFs(afero.NewMemMapFs()), runtime: r, cc: cc, id: user, token: pass, protocol: protocol}
	r.mu.Lock()
	if r.closing || r.clients[cc.ID()] != client {
		r.mu.Unlock()
		return nil, ErrCredentials
	}
	old := client.fs
	client.fs = fs
	r.mu.Unlock()
	if old != nil {
		old.cleanup()
	}
	return fs, nil
}

// uploadFS exposes only an empty virtual root. It never exposes the spool or a
// path chosen by a remote client; RETR, append, resume and filesystem mutation
// are denied. A completed temporary upload can be committed with RNTO.
type uploadFS struct {
	afero.Fs
	runtime             *ftpRuntime
	cc                  ftpserver.ClientContext
	id, token, protocol string
	mu                  sync.Mutex
	staged              *upload
	closed              bool
}

func cleanName(name string) (string, error) {
	if strings.ContainsAny(name, "\\\r\n\x00") || len(name) > 256 || strings.Contains(name, "/../") || name == ".." {
		return "", os.ErrPermission
	}
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." || strings.Contains(name, "/") || name == ".." {
		return "", os.ErrPermission
	}
	return name, nil
}
func (f *uploadFS) GetHandle(name string, flags int, offset int64) (ftpserver.FileTransfer, error) {
	if flags&os.O_WRONLY == 0 || flags&os.O_APPEND != 0 || offset != 0 {
		return nil, os.ErrPermission
	}
	title, e := cleanName(name)
	if e != nil {
		return nil, e
	}
	if f.protocol == "ftps" && !f.cc.HasTLSForTransfers() {
		return nil, errors.New("PROT P required")
	}
	d, e := f.runtime.owner.Authenticate(f.runtime.ctx, f.id, f.token, f.protocol)
	if e != nil {
		return nil, e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.staged != nil {
		return nil, errors.New("one pending upload per connection")
	}
	select {
	case f.runtime.owner.slots <- struct{}{}:
	default:
		return nil, errors.New("upload capacity reached")
	}
	file, e := os.CreateTemp(f.runtime.owner.dir, ".ftp-")
	if e != nil {
		<-f.runtime.owner.slots
		return nil, e
	}
	u := &upload{File: file, fs: f, title: title, limit: int64(d.MaxMiB) << 20}
	f.staged = u
	return u, nil
}
func (f *uploadFS) Rename(oldname, newname string) error {
	old, e := cleanName(oldname)
	if e != nil {
		return e
	}
	name, e := cleanName(newname)
	if e != nil || temporary(name) {
		return os.ErrPermission
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.staged == nil || !f.staged.complete || f.staged.title != old {
		return os.ErrNotExist
	}
	u := f.staged
	u.title = name
	return u.commitLocked()
}
func (f *uploadFS) Remove(name string) error {
	title, e := cleanName(name)
	if e != nil {
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.staged == nil || !f.staged.complete || f.staged.title != title {
		return os.ErrNotExist
	}
	f.staged.discardLocked()
	return nil
}
func (f *uploadFS) RemoveAll(string) error { return os.ErrPermission }
func (f *uploadFS) Mkdir(name string, _ os.FileMode) error {
	if path.Clean(name) == "/" || path.Clean(name) == "." {
		return nil
	}
	return os.ErrPermission
}
func (f *uploadFS) MkdirAll(name string, p os.FileMode) error { return f.Mkdir(name, p) }
func (f *uploadFS) cleanup() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if f.staged != nil {
		f.staged.failed = true
		f.staged.discardLocked()
	}
}
func temporary(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".part") || strings.HasSuffix(name, ".partial")
}

type upload struct {
	*os.File
	fs                         *uploadFS
	title                      string
	size, limit                int64
	failed, complete, released bool
}

func (u *upload) Read([]byte) (int, error)       { return 0, os.ErrPermission }
func (u *upload) Seek(int64, int) (int64, error) { return 0, os.ErrPermission }
func (u *upload) Write(p []byte) (int, error) {
	u.fs.mu.Lock()
	defer u.fs.mu.Unlock()
	if u.failed || u.complete || u.fs.closed {
		return 0, os.ErrPermission
	}
	if u.size+int64(len(p)) > u.limit {
		u.failed = true
		return 0, errors.New("document size limit")
	}
	n, e := u.File.Write(p)
	u.size += int64(n)
	if e != nil {
		u.failed = true
	}
	return n, e
}
func (u *upload) TransferError(error) { u.fs.mu.Lock(); defer u.fs.mu.Unlock(); u.failed = true }
func (u *upload) Close() error {
	u.fs.mu.Lock()
	defer u.fs.mu.Unlock()
	if u.complete || u.released {
		return nil
	}
	if u.failed || u.fs.closed {
		u.discardLocked()
		return errors.New("upload interrupted")
	}
	if e := u.File.Sync(); e != nil {
		u.discardLocked()
		return e
	}
	if e := u.File.Close(); e != nil {
		u.discardLocked()
		return e
	}
	u.complete = true
	if temporary(u.title) {
		return nil
	}
	return u.commitLocked()
}
func (u *upload) discardLocked() {
	if u.released {
		return
	}
	u.released = true
	_ = u.File.Close()
	_ = os.Remove(u.File.Name())
	u.fs.staged = nil
	<-u.fs.runtime.owner.slots
}
func (u *upload) commitLocked() error {
	defer u.discardLocked()
	file, e := os.Open(u.File.Name())
	if e != nil {
		return e
	}
	defer file.Close()
	_, e = u.fs.runtime.owner.Receive(u.fs.runtime.ctx, u.fs.id, u.fs.token, u.fs.protocol, u.title, file)
	if e != nil {
		return fmt.Errorf("scan rejected: check recipient, size, format and antivirus")
	}
	return nil
}

func (f *uploadFS) Stat(name string) (os.FileInfo, error) {
	if name == "/" || name == "." {
		return f.Fs.Stat("/")
	}
	title, e := cleanName(name)
	if e != nil {
		return nil, os.ErrNotExist
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.staged == nil || f.staged.title != title || !f.staged.complete {
		return nil, os.ErrNotExist
	}
	info, e := os.Stat(f.staged.File.Name())
	if e != nil {
		return nil, e
	}
	return namedInfo{FileInfo: info, title: title}, nil
}

type namedInfo struct {
	os.FileInfo
	title string
}

func (i namedInfo) Name() string { return i.title }

type trackedListener struct {
	net.Listener
	runtime *ftpRuntime
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	t := &trackedConn{Conn: c, runtime: l.runtime}
	l.runtime.mu.Lock()
	if l.runtime.closing {
		l.runtime.mu.Unlock()
		c.Close()
		return nil, net.ErrClosed
	}
	l.runtime.conns[t] = true
	l.runtime.mu.Unlock()
	return t, nil
}

type trackedConn struct {
	net.Conn
	runtime *ftpRuntime
	once    sync.Once
}

func (c *trackedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.runtime.mu.Lock(); delete(c.runtime.conns, c); c.runtime.mu.Unlock() })
	return e
}
