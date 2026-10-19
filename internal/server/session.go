// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/auth"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cookieName = "goprint_session"

func (s *Server) signed(payload string) string {
	m := hmac.New(sha256.New, []byte(s.Token))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

type session struct {
	User    string `json:"user"`
	Admin   bool   `json:"admin"`
	Expires int64  `json:"expires"`
}
type identityKey struct{}

func (s *Server) identity(r *http.Request) (auth.Identity, bool) {
	if id, ok := r.Context().Value(identityKey{}).(auth.Identity); ok {
		return id, true
	}
	if s.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) == 1 {
		return auth.Identity{User: "local-admin", Admin: true}, true
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return auth.Identity{}, false
	}
	payload, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok || !hmac.Equal([]byte(signature), []byte(s.signed(payload))) {
		return auth.Identity{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return auth.Identity{}, false
	}
	var v session
	if json.Unmarshal(b, &v) != nil || v.User == "" || v.Expires <= time.Now().Unix() || v.Expires > time.Now().Add(8*time.Hour+time.Minute).Unix() {
		return auth.Identity{}, false
	}
	return auth.Identity{User: v.User, Admin: v.Admin}, true
}
func (s *Server) authorized(r *http.Request) bool { _, ok := s.identity(r); return ok }
func (s *Server) authCredentials(ctx context.Context, user, password string) (auth.Identity, error) {
	if user == "local-admin" && s.Token != "" && subtle.ConstantTimeCompare([]byte(password), []byte(s.Token)) == 1 {
		return auth.Identity{User: "local-admin", Admin: true}, nil
	}
	if s.Domain == nil {
		return auth.Identity{}, auth.ErrCredentials
	}
	return s.Domain.Authenticate(ctx, user, password)
}

type attempt struct {
	start time.Time
	count int
}
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]attempt
}

func (l *loginLimiter) allow(r *http.Request) bool {
	key, _, _ := net.SplitHostPort(r.RemoteAddr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]attempt{}
	}
	now := time.Now()
	for k, v := range l.entries {
		if now.Sub(v.start) > time.Minute {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= 4096 {
		return false
	}
	v := l.entries[key]
	if v.start.IsZero() {
		v.start = now
	}
	v.count++
	l.entries[key] = v
	return v.count <= 20
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(r) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "слишком много попыток входа", 429)
		return
	}
	var input struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	var id auth.Identity
	var err error
	if input.Token != "" {
		id, err = s.authCredentials(r.Context(), "local-admin", input.Token)
	} else {
		id, err = s.authCredentials(r.Context(), input.Username, input.Password)
	}
	if err != nil {
		http.Error(w, "Неверные данные входа или доступ к GoPrint не разрешён", 401)
		return
	}
	expires := time.Now().Add(8 * time.Hour)
	b, _ := json.Marshal(session{User: id.User, Admin: id.Admin, Expires: expires.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: payload + "." + s.signed(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, Expires: expires, MaxAge: 8 * 60 * 60})
	respond(w, id, nil)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: -1})
	respond(w, map[string]bool{"ok": true}, nil)
}

type cachedCredential struct {
	identity auth.Identity
	expires  time.Time
}
type credentialCache struct {
	mu      sync.Mutex
	entries map[string]cachedCredential
}

func (s *Server) cachedCredentials(r *http.Request, user, password string) (auth.Identity, error) {
	key := s.signed(user + "\x00" + password)
	now := time.Now()
	c := &s.credentials
	c.mu.Lock()
	if cached, ok := c.entries[key]; ok && now.Before(cached.expires) {
		c.mu.Unlock()
		return cached.identity, nil
	}
	c.mu.Unlock()
	if !s.limiter.allow(r) {
		return auth.Identity{}, auth.ErrCredentials
	}
	id, err := s.authCredentials(r.Context(), user, password)
	if err != nil {
		return id, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]cachedCredential{}
	}
	for k, v := range c.entries {
		if now.After(v.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < 2048 {
		c.entries[key] = cachedCredential{id, now.Add(30 * time.Second)}
	}
	return id, nil
}
