// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "goprint_session"

func (s *Server) signed(payload string) string {
	m := hmac.New(sha256.New, []byte(s.Token))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *Server) authorized(r *http.Request) bool {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) == 1 {
		return true
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	payload, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return false
	}
	expires, err := strconv.ParseInt(payload, 10, 64)
	if err != nil || expires <= time.Now().Unix() || expires > time.Now().Add(8*time.Hour+time.Minute).Unix() {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(s.signed(payload)))
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &input) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(input.Token), []byte(s.Token)) != 1 {
		http.Error(w, "Неверный токен администратора", http.StatusUnauthorized)
		return
	}
	expires := time.Now().Add(8 * time.Hour)
	payload := strconv.FormatInt(expires.Unix(), 10)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: payload + "." + s.signed(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, Expires: expires, MaxAge: 8 * 60 * 60})
	respond(w, map[string]string{"user": "Администратор"}, nil)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: -1})
	respond(w, map[string]bool{"ok": true}, nil)
}
