// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package personal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"github.com/rkislov/goPrint/internal/queue"
	"golang.org/x/crypto/argon2"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type Config struct {
	FollowMe      bool `json:"follow_me"`
	PINConfigured bool `json:"pin_configured"`
}
type record struct {
	Enabled bool   `json:"enabled"`
	Salt    []byte `json:"salt"`
	Hash    []byte `json:"hash"`
	Lookup  string `json:"lookup"`
}
type Service struct {
	store *queue.Store
	key   []byte
	mu    sync.Mutex
}

func New(dir string, store *queue.Store) (*Service, error) {
	path := filepath.Join(dir, "followme.key")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
	}
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid Follow Me key")
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Follow Me key requires private permissions")
	}
	return &Service{store: store, key: b}, nil
}
func (s *Service) lookup(pin string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(pin))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) Config(ctx context.Context, user string) (Config, error) {
	var r record
	err := s.store.Setting(ctx, "pin:"+user, &r)
	return Config{r.Enabled, len(r.Hash) > 0}, err
}
func (s *Service) Configure(ctx context.Context, user string, enabled bool, pin string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var old record
	if err := s.store.Setting(ctx, "pin:"+user, &old); err != nil {
		return Config{}, err
	}
	r := old
	r.Enabled = enabled
	if pin != "" {
		if !regexp.MustCompile(`^[0-9]{8,12}$`).MatchString(pin) {
			return Config{}, errors.New("код должен содержать от 8 до 12 цифр")
		}
		lookup := s.lookup(pin)
		var existing string
		if err := s.store.Setting(ctx, "pin-index:"+lookup, &existing); err != nil {
			return Config{}, err
		}
		if existing != "" && existing != user {
			return Config{}, errors.New("этот код уже занят; выберите другой")
		}
		r.Salt = make([]byte, 16)
		if _, err := rand.Read(r.Salt); err != nil {
			return Config{}, err
		}
		r.Hash = argon2.IDKey([]byte(pin), r.Salt, 1, 32*1024, 2, 32)
		r.Lookup = lookup
	}
	if enabled && len(r.Hash) == 0 {
		return Config{}, errors.New("сначала задайте личный код Follow Me")
	}
	// One SQLite transaction publishes both the PIN index and hashed verifier.
	updates := map[string]any{"pin:" + user: r}
	if r.Lookup != "" {
		updates["pin-index:"+r.Lookup] = user
	}
	if old.Lookup != "" && old.Lookup != r.Lookup {
		updates["pin-index:"+old.Lookup] = ""
	}
	if err := s.store.SettingsAtomic(ctx, updates); err != nil {
		return Config{}, err
	}
	return Config{r.Enabled, len(r.Hash) > 0}, nil
}
func (s *Service) AuthenticateCode(ctx context.Context, pin string) (string, error) {
	if !regexp.MustCompile(`^[0-9]{8,12}$`).MatchString(pin) {
		return "", errors.New("неверный код")
	}
	var user string
	if err := s.store.Setting(ctx, "pin-index:"+s.lookup(pin), &user); err != nil || user == "" {
		return "", errors.New("неверный код")
	}
	var r record
	if err := s.store.Setting(ctx, "pin:"+user, &r); err != nil || len(r.Salt) != 16 || len(r.Hash) != 32 {
		return "", errors.New("неверный код")
	}
	actual := argon2.IDKey([]byte(pin), r.Salt, 1, 32*1024, 2, 32)
	if subtle.ConstantTimeCompare(actual, r.Hash) != 1 {
		return "", errors.New("неверный код")
	}
	return user, nil
}
