// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scaninbox

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
)

var ErrCredentials = errors.New("invalid scan destination credentials")

type Destination struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ScannerID    string `json:"scanner_id"`
	Owner        string `json:"owner"`
	Enabled      bool   `json:"enabled"`
	WebDAV       bool   `json:"webdav"`
	FTP          bool   `json:"ftp"`
	FTPS         bool   `json:"ftps"`
	MaxMiB       int    `json:"max_mib"`
	Token        string `json:"password,omitempty"`
	Hash         string `json:"token_hash,omitempty"`
	LastReceived string `json:"last_received,omitempty"`
	LastProtocol string `json:"last_protocol,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}
type Service struct {
	Store        *queue.Store
	Scans        *scanning.Service
	ResolveOwner func(context.Context, string) (string, error)
	TLSConfig    func() (*tls.Config, error)
	dir          string
	mu           sync.Mutex
	runtimeMu    sync.Mutex
	runtime      *ftpRuntime
	ftpConfig    FTPConfig
	ftpError     string
	slots        chan struct{}
}

func New(dir string, q *queue.Store, sc *scanning.Service, resolve func(context.Context, string) (string, error), tlsConfig func() (*tls.Config, error)) (*Service, error) {
	dir = filepath.Join(dir, "scan-incoming")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	// No externally supplied path is ever used for staged files.
	paths, _ := filepath.Glob(filepath.Join(dir, ".ftp-*"))
	for _, p := range paths {
		if e := os.Remove(p); e != nil {
			return nil, e
		}
	}
	s := &Service{Store: q, Scans: sc, ResolveOwner: resolve, TLSConfig: tlsConfig, dir: dir, slots: make(chan struct{}, 8)}
	c := DefaultFTP()
	if e := q.Setting(context.Background(), "scan-ftp", &c); e != nil {
		return nil, e
	}
	s.ftpConfig = c
	if c.Enabled {
		if e := validateFTP(c); e != nil {
			s.ftpError = e.Error()
		} else {
			r, e := s.start(c)
			if e != nil {
				s.ftpError = "Не удалось запустить FTP: проверьте адрес, порты и TLS"
			} else {
				s.runtime = r
			}
		}
	}
	return s, nil
}
func (s *Service) List(ctx context.Context) ([]Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := []Destination{}
	e := s.Store.Setting(ctx, "scan-inboxes", &v)
	for i := range v {
		v[i].Hash = ""
		v[i].Token = ""
	}
	return v, e
}
func (s *Service) find(ctx context.Context, id string) (Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := []Destination{}
	if e := s.Store.Setting(ctx, "scan-inboxes", &v); e != nil {
		return Destination{}, e
	}
	for _, d := range v {
		if d.ID == id {
			return d, nil
		}
	}
	return Destination{}, queue.ErrNotFound
}
func validOwner(v string) bool {
	if v == "local-admin" {
		return true
	}
	a, b, ok := strings.Cut(v, "@")
	return ok && a != "" && b != "" && strings.Contains(b, ".") && !strings.ContainsAny(v, " /\\\r\n\x00") && len(v) <= 254
}
func (s *Service) Save(ctx context.Context, id string, d Destination, rotate bool) (Destination, error) {
	d.Name = strings.TrimSpace(d.Name)
	d.Owner = strings.ToLower(strings.TrimSpace(d.Owner))
	if d.Name == "" || len(d.Name) > 128 || strings.ContainsAny(d.Name, "\r\n\x00") || !validOwner(d.Owner) || d.MaxMiB < 1 || d.MaxMiB > 100 {
		return Destination{}, errors.New("нужны название, UPN пользователя или local-admin и размер 1–100 МиБ")
	}
	if !d.WebDAV && !d.FTP && !d.FTPS {
		return Destination{}, errors.New("выберите хотя бы один протокол")
	}
	// Scanner identity is fixed after creation. Ownership changes rotate credentials.
	s.mu.Lock()
	defer s.mu.Unlock()
	all := []Destination{}
	if e := s.Store.Setting(ctx, "scan-inboxes", &all); e != nil {
		return Destination{}, e
	}
	index := -1
	if id != "" {
		for i, old := range all {
			if old.ID == id {
				index = i
				d.ID = id
				d.ScannerID = old.ScannerID
				d.Hash = old.Hash
				d.LastReceived = old.LastReceived
				d.LastProtocol = old.LastProtocol
				d.LastError = old.LastError
				if d.Owner != old.Owner {
					rotate = true
				}
				break
			}
		}
		if index < 0 {
			return Destination{}, queue.ErrNotFound
		}
	} else {
		if len(all) >= 1000 {
			return Destination{}, errors.New("лимит 1000 назначений")
		}
		if d.ScannerID == "" {
			device, e := s.Scans.AddReceiver(ctx, d.Name)
			if e != nil {
				return Destination{}, e
			}
			d.ScannerID = device.ID
		} else if _, e := s.Scans.Get(ctx, d.ScannerID); e != nil {
			return Destination{}, e
		}
		d.ID = queue.ID()
		rotate = true
	}
	d.Token = ""
	token := ""
	if rotate {
		token = queue.ID() + queue.ID()
		sum := sha256.Sum256([]byte(token))
		d.Hash = hex.EncodeToString(sum[:])
	}
	if index < 0 {
		all = append(all, d)
	} else {
		all[index] = d
	}
	if e := s.Store.SetSetting(ctx, "scan-inboxes", all); e != nil {
		return Destination{}, e
	}
	d.Hash = ""
	d.Token = token
	return d, nil
}
func (s *Service) Authenticate(ctx context.Context, id, token, protocol string) (Destination, error) {
	d, e := s.find(ctx, id)
	if e != nil || !d.Enabled || len(token) != 64 {
		return Destination{}, ErrCredentials
	}
	allowed := protocol == "webdav" && d.WebDAV || protocol == "ftp" && d.FTP || protocol == "ftps" && d.FTPS
	sum := sha256.Sum256([]byte(token))
	if !allowed || subtle.ConstantTimeCompare([]byte(d.Hash), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return Destination{}, ErrCredentials
	}
	d.Hash = ""
	d.Token = ""
	return d, nil
}
func (s *Service) Receive(ctx context.Context, id, token, protocol, title string, r io.Reader) (scanning.Job, error) {
	if protocol == "webdav" {
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			return scanning.Job{}, errors.New("scan upload capacity reached")
		}
	}
	d, e := s.Authenticate(ctx, id, token, protocol)
	if e != nil {
		return scanning.Job{}, e
	}
	owner := d.Owner
	if s.ResolveOwner != nil {
		owner, e = s.ResolveOwner(ctx, owner)
	} else if owner != "local-admin" {
		e = errors.New("domain directory unavailable")
	}
	if e != nil {
		s.record(ctx, id, protocol, false)
		return scanning.Job{}, errors.New("получатель недоступен в домене")
	}
	locked := false
	check := func(ctx context.Context) error {
		// Serialize the final authorization and durable publication with revocation.
		// Configuration remains editable while bytes and antivirus checks run.
		s.mu.Lock()
		locked = true
		var all []Destination
		if e := s.Store.Setting(ctx, "scan-inboxes", &all); e != nil {
			return e
		}
		valid := false
		hash := sha256.Sum256([]byte(token))
		for _, current := range all {
			if current.ID == id && current.Enabled && current.Owner == d.Owner {
				allowed := protocol == "webdav" && current.WebDAV || protocol == "ftp" && current.FTP || protocol == "ftps" && current.FTPS
				valid = allowed && subtle.ConstantTimeCompare([]byte(current.Hash), []byte(hex.EncodeToString(hash[:]))) == 1
			}
		}
		if !valid {
			return ErrCredentials
		}
		if s.ResolveOwner != nil {
			current, e := s.ResolveOwner(ctx, d.Owner)
			if e != nil || current != owner {
				return ErrCredentials
			}
		}
		return nil
	}
	limited := &limitReader{Reader: r, left: int64(d.MaxMiB) << 20}
	j, e := s.Scans.ReceiveFor(ctx, d.ScannerID, title, owner, limited, check)
	if locked {
		s.mu.Unlock()
	}
	s.record(ctx, id, protocol, e == nil)
	return j, e
}

type limitReader struct {
	io.Reader
	left int64
}

func (r *limitReader) Read(p []byte) (int, error) {
	if r.left < 0 {
		return 0, queue.ErrTooLarge
	}
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, e := r.Reader.Read(p)
	r.left -= int64(n)
	if r.left < 0 {
		return n, queue.ErrTooLarge
	}
	return n, e
}
func (s *Service) record(ctx context.Context, id, protocol string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Destination
	if s.Store.Setting(ctx, "scan-inboxes", &all) != nil {
		return
	}
	for i := range all {
		if all[i].ID == id {
			if success {
				all[i].LastReceived = time.Now().UTC().Format(time.RFC3339Nano)
				all[i].LastProtocol = protocol
				all[i].LastError = ""
			} else {
				all[i].LastError = "Документ отклонён: проверьте получателя, формат, размер и антивирус"
			}
		}
	}
	_ = s.Store.SetSetting(ctx, "scan-inboxes", all)
}
func peerIP(addr net.Addr) net.IP {
	host, _, e := net.SplitHostPort(addr.String())
	if e != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (s *Service) Lookup(ctx context.Context, id string) (Destination, error) {
	d, e := s.find(ctx, id)
	d.Hash = ""
	d.Token = ""
	return d, e
}
func (s *Service) Rotate(ctx context.Context, id string) (Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Destination
	if e := s.Store.Setting(ctx, "scan-inboxes", &all); e != nil {
		return Destination{}, e
	}
	for i := range all {
		if all[i].ID == id {
			token := queue.ID() + queue.ID()
			hash := sha256.Sum256([]byte(token))
			all[i].Hash = hex.EncodeToString(hash[:])
			if e := s.Store.SetSetting(ctx, "scan-inboxes", all); e != nil {
				return Destination{}, e
			}
			d := all[i]
			d.Hash = ""
			d.Token = token
			return d, nil
		}
	}
	return Destination{}, queue.ErrNotFound
}
