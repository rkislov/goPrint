// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"encoding/base64"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/auth"
	"net/http"
	"strings"
	"time"
)

type identitySnapshot struct {
	Identity auth.Identity `json:"identity"`
	Expires  int64         `json:"expires"`
}

func (s *Server) sessionFor(w http.ResponseWriter, r *http.Request, id auth.Identity) bool {
	expires := time.Now().Add(8 * time.Hour)
	if id.User != "local-admin" && s.Store != nil {
		if err := s.Store.SetSetting(r.Context(), "identity:"+id.User, identitySnapshot{id, expires.Unix()}); err != nil {
			http.Error(w, "cannot persist domain identity", 500)
			return false
		}
	}
	b, _ := json.Marshal(session{User: id.User, Admin: id.Admin, Expires: expires.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: payload + "." + s.signed(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, Expires: expires, MaxAge: 8 * 60 * 60})
	return true
}
func (s *Server) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Negotiate")
	if s.SSO == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="GoPrint", charset="UTF-8"`)
	}
}
func (s *Server) negotiate(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	if s.SSO == nil || r.TLS == nil {
		return auth.Identity{}, false
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Negotiate") {
		return auth.Identity{}, false
	}
	id, reply, err := s.SSO.AuthenticateToken(r.Context(), token)
	if reply != "" {
		w.Header().Set("WWW-Authenticate", "Negotiate "+reply)
	}
	if err != nil {
		return auth.Identity{}, false
	}
	return id, true
}
func (s *Server) loginSSO(w http.ResponseWriter, r *http.Request) {
	id, ok := s.negotiate(w, r)
	if !ok {
		if w.Header().Get("WWW-Authenticate") == "" {
			s.challenge(w)
		}
		http.Error(w, "Windows Kerberos authentication required", 401)
		return
	}
	if s.sessionFor(w, r, id) {
		respond(w, map[string]any{"user": id.User, "admin": id.Admin}, nil)
	}
}
