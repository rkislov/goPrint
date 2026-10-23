// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package backend

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

type SMBConfig struct {
	Enabled     bool   `json:"enabled"`
	Domain      string `json:"domain"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	PasswordSet bool   `json:"password_set"`
}
type smbStored struct {
	Config SMBConfig `json:"config"`
	Secret []byte    `json:"secret"`
}
type SMBService struct {
	store *queue.Store
	key   []byte
	mu    sync.Mutex
}

func NewSMB(dir string, store *queue.Store) (*SMBService, error) {
	path := filepath.Join(dir, "smb.key")
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
	}
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || len(key) != 32 {
		return nil, errors.New("SMB key must be a private regular 32-byte file")
	}
	return &SMBService{store: store, key: key}, nil
}
func (s *SMBService) aead() cipher.AEAD {
	b, _ := aes.NewCipher(s.key)
	a, _ := cipher.NewGCM(b)
	return a
}
func (s *SMBService) Config(ctx context.Context, id string) (SMBConfig, error) {
	var v smbStored
	err := s.store.Setting(ctx, "smb:"+id, &v)
	v.Config.Password = ""
	v.Config.PasswordSet = len(v.Secret) > 0
	return v.Config, err
}
func (s *SMBService) Configure(ctx context.Context, id string, c SMBConfig) (SMBConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range []string{c.Domain, c.Username, c.Password} {
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") || v != strings.TrimSpace(v) {
			return SMBConfig{}, errors.New("SMB fields cannot contain newlines or leading/trailing whitespace")
		}
	}
	if strings.ContainsAny(c.Username, "\\/%") || strings.ContainsAny(c.Domain, "\\/%") {
		return SMBConfig{}, errors.New("specify domain and username separately")
	}
	var old smbStored
	if err := s.store.Setting(ctx, "smb:"+id, &old); err != nil {
		return SMBConfig{}, err
	}
	secret := old.Secret
	if c.Domain != old.Config.Domain || c.Username != old.Config.Username {
		secret = nil
	}
	if c.Password != "" {
		a := s.aead()
		n := make([]byte, a.NonceSize())
		if _, err := rand.Read(n); err != nil {
			return SMBConfig{}, err
		}
		secret = a.Seal(n, n, []byte(c.Password), []byte(id))
	}
	c.Password = ""
	c.PasswordSet = len(secret) > 0
	if c.Enabled && (c.Username == "" || !c.PasswordSet) {
		return SMBConfig{}, errors.New("SMB username and password are required")
	}
	if err := s.store.SetSetting(ctx, "smb:"+id, smbStored{c, secret}); err != nil {
		return SMBConfig{}, err
	}
	return c, nil
}

// SMB runs without a shell. Only fixed, server-generated filenames enter the
// smbclient command language; document titles and user names never do.
func (s *SMBService) Deliver(ctx context.Context, p queue.Printer, j queue.Job, path string) Result {
	fail := func(detail string) Result { return Result{State: "failed", Detail: detail} }
	if err := Validate(p); err != nil {
		return fail("invalid SMB printer configuration")
	}
	u, _ := url.Parse(p.URI)
	if u.Scheme != "smb" {
		return fail("invalid SMB scheme")
	}
	var v smbStored
	if err := s.store.Setting(ctx, "smb:"+p.ID, &v); err != nil {
		return fail("cannot read SMB configuration")
	}
	if !v.Config.Enabled || len(v.Secret) == 0 {
		return fail("SMB credentials are not configured or delivery is disabled")
	}
	a := s.aead()
	if len(v.Secret) < a.NonceSize() {
		return fail("invalid SMB credential")
	}
	password, err := a.Open(nil, v.Secret[:a.NonceSize()], v.Secret[a.NonceSize():], []byte(p.ID))
	if err != nil {
		return fail("cannot decrypt SMB credential")
	}
	executable, err := exec.LookPath("smbclient")
	if err != nil {
		return fail("smbclient is not installed on the GoPrint server")
	}
	dir, err := os.MkdirTemp("", "goprint-smb-")
	if err != nil {
		return fail("cannot prepare SMB transfer")
	}
	defer os.RemoveAll(dir)
	auth := []byte("username = " + v.Config.Username + "\ndomain = " + v.Config.Domain + "\npassword = " + string(password) + "\n")
	if err = os.WriteFile(filepath.Join(dir, "auth"), auth, 0600); err != nil {
		return fail("cannot prepare SMB credential file")
	}
	input, err := os.Open(path)
	if err != nil {
		return fail("cannot open prepared document")
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(dir, "document.prn"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail("cannot prepare SMB document")
	}
	_, err = io.Copy(output, input)
	ce := output.Close()
	if err != nil || ce != nil {
		return fail("cannot prepare SMB document")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	run := func(command string) error {
		cmd := exec.CommandContext(ctx, executable, "//"+u.Host+u.Path, "-A", "auth", "--use-kerberos=off", "--client-protection=encrypt", "--option=client min protocol=SMB3_00", "--option=client max protocol=SMB3", "--option=client ntlmv2 auth=yes", "-t", "20", "-c", command)
		cmd.Dir = dir
		cmd.Env = []string{"LANG=C", "LC_ALL=C", "HOME=" + dir, "TMPDIR=" + dir}
		// Discard backend output: it may contain credentials or server-provided text.
		var output limitedSMBOutput
		cmd.Stdout = &output
		cmd.Stderr = &output
		err := cmd.Run()
		if err == nil && (bytes.Contains(output.data, []byte("NT_STATUS_")) || bytes.Contains(output.data, []byte("Error")) || bytes.Contains(output.data, []byte("failed"))) {
			return errors.New("SMB command failed")
		}
		return err
	}
	// A failed login/protocol preflight cannot have submitted a print job.
	if err = run("quit"); err != nil {
		return fail("SMB connection/authentication failed; require SMB3 encryption and verify credentials")
	}
	if err = s.store.RecordEvent(ctx, j.ID, "SMB delivery starting; encrypted SMB3; remote service account; physical printing unconfirmed"); err != nil {
		return fail("cannot audit SMB delivery; document not sent")
	}
	if err = run("print document.prn"); err != nil {
		return Result{State: "unknown", Detail: "SMB delivery result is uncertain; check the remote queue before resubmitting"}
	}
	return Result{State: "submitted", Detail: "SMB server acknowledged transfer; remote processing and physical printing are not confirmed"}
}

// Keep diagnostics bounded and private; never persist remote output.
type limitedSMBOutput struct{ data []byte }

func (b *limitedSMBOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data) < 65536 {
		left := 65536 - len(b.data)
		if len(p) > left {
			p = p[:left]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
