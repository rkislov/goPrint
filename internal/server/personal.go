// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/maildelivery"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"time"
)

func (s *Server) holdOptions(ctx context.Context, user string, o queue.PrintOptions) (queue.PrintOptions, error) {
	if s.Personal == nil {
		return o, nil
	}
	c, e := s.Personal.Config(ctx, user)
	o.FollowMe = c.FollowMe
	return o, e
}
func (s *Server) personalRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/me/follow-me", func(w http.ResponseWriter, r *http.Request) {
		if s.Personal == nil {
			http.Error(w, "personal service unavailable", 503)
			return
		}
		id, _ := s.identity(r)
		c, e := s.Personal.Config(r.Context(), id.User)
		respond(w, c, e)
	})
	api.HandleFunc("PUT /api/me/follow-me", func(w http.ResponseWriter, r *http.Request) {
		if s.Personal == nil {
			http.Error(w, "personal service unavailable", 503)
			return
		}
		if !s.limiter.allow(r) {
			http.Error(w, "too many attempts", 429)
			return
		}
		var c struct {
			Enabled bool   `json:"follow_me"`
			PIN     string `json:"pin"`
		}
		if !decode(w, r, &c) {
			return
		}
		id, _ := s.identity(r)
		v, e := s.Personal.Configure(r.Context(), id.User, c.Enabled, c.PIN)
		respond(w, v, e)
	})
	api.HandleFunc("POST /api/me/release", func(w http.ResponseWriter, r *http.Request) {
		if s.Personal == nil {
			http.Error(w, "personal service unavailable", 503)
			return
		}
		if !s.limiter.allow(r) {
			http.Error(w, "too many attempts", 429)
			return
		}
		var b struct {
			PIN     string `json:"pin"`
			Printer string `json:"printer"`
		}
		if !decode(w, r, &b) {
			return
		}
		id, _ := s.identity(r)
		owner, e := s.Personal.AuthenticateCode(r.Context(), b.PIN)
		if e != nil || owner != id.User {
			http.Error(w, "неверный код", 403)
			return
		}
		s.releaseOwner(w, r, owner, b.Printer)
	})
	api.HandleFunc("POST /api/printers/{id}/terminal", func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.Store.Printer(r.Context(), r.PathValue("id")); e != nil {
			http.NotFound(w, r)
			return
		}
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			http.Error(w, "random source unavailable", 500)
			return
		}
		token := hex.EncodeToString(b)
		h := sha256.Sum256([]byte(token))
		e := s.Store.SetSetting(r.Context(), "terminal:"+r.PathValue("id"), hex.EncodeToString(h[:]))
		respond(w, map[string]string{"token": token, "username": r.PathValue("id"), "url": s.baseURL(r) + "/terminal/" + r.PathValue("id") + "/release"}, e)
	})
	api.HandleFunc("GET /api/me/scan-delivery", func(w http.ResponseWriter, r *http.Request) {
		if s.Mail == nil {
			http.Error(w, "mail service unavailable", 503)
			return
		}
		id, _ := s.identity(r)
		c, e := s.Mail.Rule(r.Context(), id.User)
		respond(w, c, e)
	})
	api.HandleFunc("PUT /api/me/scan-delivery", func(w http.ResponseWriter, r *http.Request) {
		if s.Mail == nil {
			http.Error(w, "mail service unavailable", 503)
			return
		}
		var c maildelivery.Rule
		if !decode(w, r, &c) {
			return
		}
		id, _ := s.identity(r)
		v, e := s.Mail.SetRule(r.Context(), id.User, c)
		respond(w, v, e)
	})
	api.HandleFunc("GET /api/smtp", func(w http.ResponseWriter, r *http.Request) {
		if s.Mail == nil {
			http.Error(w, "mail service unavailable", 503)
			return
		}
		c, e := s.Mail.Config(r.Context())
		respond(w, c, e)
	})
	api.HandleFunc("PUT /api/smtp", func(w http.ResponseWriter, r *http.Request) {
		if s.Mail == nil {
			http.Error(w, "mail service unavailable", 503)
			return
		}
		var c maildelivery.Config
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Mail.Configure(r.Context(), c)
		respond(w, v, e)
	})
	api.HandleFunc("GET /api/scans/{id}/delivery", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.NotFound(w, r)
			return
		}
		j, e := s.Scans.Job(r.Context(), r.PathValue("id"))
		id, _ := s.identity(r)
		if e != nil || !id.Admin && j.Owner != id.User {
			http.NotFound(w, r)
			return
		}
		v, e := s.Scans.MailStatus(r.Context(), j.ID)
		respond(w, v, e)
	})
}
func (s *Server) releaseOwner(w http.ResponseWriter, r *http.Request, owner, pid string) {
	p, ok := s.permittedPrinter(w, r, pid)
	if !ok {
		return
	}
	jobs, e := s.Store.HeldFor(r.Context(), owner)
	if e != nil {
		respond(w, nil, e)
		return
	}
	c, e := s.capabilities(p)
	if e != nil {
		respond(w, nil, e)
		return
	}
	count := 0
	for _, j := range jobs {
		if !queue.Accepts(p, j.Format) {
			continue
		}
		o, e := c.Resolve(queue.PrintOptions{}, j.Options)
		if e != nil {
			continue
		}
		if e = s.Store.ReleaseHeld(r.Context(), j.ID, pid, owner, o); e == nil {
			count++
		} else if !errors.Is(e, queue.ErrConflict) {
			respond(w, nil, e)
			return
		}
	}
	respond(w, map[string]int{"released": count}, nil)
}
func (s *Server) terminalRelease(w http.ResponseWriter, r *http.Request) {
	if s.Personal == nil || r.TLS == nil {
		http.Error(w, "HTTPS and configured personal service required", 403)
		return
	}
	if !s.limiter.allow(r) {
		http.Error(w, "too many attempts", 429)
		return
	}
	pid := r.PathValue("id")
	user, password, ok := r.BasicAuth()
	var expected string
	e := s.Store.Setting(r.Context(), "terminal:"+pid, &expected)
	h := sha256.Sum256([]byte(password))
	if !ok || user != pid || e != nil || expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(hex.EncodeToString(h[:]))) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="GoPrint terminal"`)
		http.Error(w, "terminal authentication required", 401)
		return
	}
	var b struct {
		PIN string `json:"pin"`
	}
	if !decode(w, r, &b) {
		return
	}
	owner, e := s.Personal.AuthenticateCode(r.Context(), b.PIN)
	if e != nil {
		http.Error(w, "неверный код", 403)
		return
	}
	var identity auth.Identity
	if owner == "local-admin" {
		identity = auth.Identity{User: owner, Admin: true}
	} else if d, ok := s.Domain.(*auth.Domain); ok {
		identity, e = d.ResolveUser(r.Context(), owner)
		if e != nil {
			http.Error(w, "domain authorization unavailable; use browser release", 403)
			return
		}
	} else {
		var snap identitySnapshot
		e = s.Store.Setting(r.Context(), "identity:"+owner, &snap)
		if e != nil || snap.Expires < time.Now().Unix() {
			http.Error(w, "sign in again before terminal release", 403)
			return
		}
		identity = snap.Identity
	}
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, identity))
	s.releaseOwner(w, r, owner, pid)
}
