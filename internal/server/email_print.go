// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/emailprint"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"net/http"
	"net/mail"
	"strings"
)

type emailConfig struct {
	Enabled  bool   `json:"enabled"`
	Printer  string `json:"printer"`
	TokenSet bool   `json:"token_set"`
	Rotate   bool   `json:"rotate,omitempty"`
	hash     string
}
type emailStored struct {
	Enabled bool   `json:"enabled"`
	Printer string `json:"printer"`
	Hash    string `json:"hash"`
}
type emailResult struct {
	State string   `json:"state"`
	Jobs  []string `json:"jobs"`
}

func (s *Server) emailRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/email-print", func(w http.ResponseWriter, r *http.Request) {
		var c emailStored
		e := s.Store.Setting(r.Context(), "email-print", &c)
		respond(w, emailConfig{Enabled: c.Enabled, Printer: c.Printer, TokenSet: c.Hash != ""}, e)
	})
	api.HandleFunc("PUT /api/email-print", func(w http.ResponseWriter, r *http.Request) {
		var c emailConfig
		if !decode(w, r, &c) {
			return
		}
		var old emailStored
		if e := s.Store.Setting(r.Context(), "email-print", &old); e != nil {
			respond(w, nil, e)
			return
		}
		if c.Enabled {
			if _, e := s.Store.Printer(r.Context(), c.Printer); e != nil {
				http.Error(w, "выберите принтер", 400)
				return
			}
			if _, ok := s.Domain.(interface {
				ResolveMail(context.Context, string) (auth.Identity, error)
			}); !ok {
				http.Error(w, "нужен настроенный домен со служебным LDAP bind", 409)
				return
			}
		}
		token := ""
		if c.Rotate {
			b := make([]byte, 32)
			if _, e := rand.Read(b); e != nil {
				http.Error(w, "random source unavailable", 500)
				return
			}
			token = hex.EncodeToString(b)
			h := sha256.Sum256([]byte(token))
			old.Hash = hex.EncodeToString(h[:])
		}
		if c.Enabled && old.Hash == "" {
			http.Error(w, "сначала создайте ключ почтового шлюза", 400)
			return
		}
		old.Enabled = c.Enabled
		old.Printer = c.Printer
		respond(w, map[string]any{"configured": true, "token": token}, s.Store.SetSetting(r.Context(), "email-print", old))
	})
}
func (s *Server) incomingEmail(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "HTTPS required", 403)
		return
	}
	var c emailStored
	if e := s.Store.Setting(r.Context(), "email-print", &c); e != nil || !c.Enabled {
		http.Error(w, "email printing unavailable", 503)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	h := sha256.Sum256([]byte(token))
	if c.Hash == "" || subtle.ConstantTimeCompare([]byte(c.Hash), []byte(hex.EncodeToString(h[:]))) != 1 {
		http.Error(w, "gateway authentication required", 401)
		return
	}
	if !s.limiter.allow(r) {
		http.Error(w, "gateway rate limit exceeded", 429)
		return
	}
	s.emailMu.Lock()
	defer s.emailMu.Unlock()
	sender := r.Header.Get("X-GoPrint-Authenticated-Sender")
	address, e := mail.ParseAddress(sender)
	if e != nil || address.Address != sender || strings.ContainsAny(sender, "\r\n\x00") {
		http.Error(w, "authenticated envelope sender required", 400)
		return
	}
	messageID := r.Header.Get("X-GoPrint-Message-ID")
	if len(messageID) < 8 || len(messageID) > 254 || strings.ContainsAny(messageID, "\r\n\x00") {
		http.Error(w, "stable gateway message ID required", 400)
		return
	}
	resolver, ok := s.Domain.(interface {
		ResolveMail(context.Context, string) (auth.Identity, error)
	})
	if !ok {
		http.Error(w, "directory lookup unavailable", 503)
		return
	}
	id, e := resolver.ResolveMail(r.Context(), sender)
	if e != nil {
		http.Error(w, "sender has no authorized domain account", 403)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
	p, ok := s.permittedPrinter(w, r, c.Printer)
	if !ok {
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 30<<20))
	if e != nil {
		http.Error(w, "message must be at most 30 MiB", 413)
		return
	}
	attachments, e := emailprint.Parse(bytes.NewReader(raw))
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	for _, a := range attachments {
		if !queue.Accepts(p, a.Format) {
			http.Error(w, "printer does not accept attachment format", 415)
			return
		}
	}
	options, e := s.effectiveOptions(r, p, queue.PrintOptions{})
	if e == nil {
		options, e = s.holdOptions(r.Context(), id.User, options)
	}
	if e != nil {
		respond(w, nil, e)
		return
	}
	// A durable marker is written before the first submission. An interrupted batch is
	// never replayed automatically, even if the gateway retries after a lost response.
	keyhash := sha256.Sum256([]byte(strings.ToLower(sender) + "\x00" + messageID))
	key := "email-msg:" + hex.EncodeToString(keyhash[:])
	var result emailResult
	if e = s.Store.Setting(r.Context(), key, &result); e != nil {
		respond(w, nil, e)
		return
	}
	if result.State != "" {
		if result.State != "accepted" {
			w.WriteHeader(409)
		}
		respond(w, result, nil)
		return
	}
	result = emailResult{State: "processing", Jobs: []string{}}
	if e = s.Store.SetSetting(r.Context(), key, result); e != nil {
		respond(w, nil, e)
		return
	}
	for _, a := range attachments {
		j, e := s.Store.SubmitOptions(r.Context(), p.ID, id.User, a.Name, a.Format, bytes.NewReader(a.Data), options)
		if e != nil {
			http.Error(w, "submission interrupted; administrator must inspect queue before retrying", 500)
			return
		}
		result.Jobs = append(result.Jobs, j.ID)
		if e = s.Store.SetSetting(r.Context(), key, result); e != nil {
			http.Error(w, "cannot persist email receipt; inspect queue", 500)
			return
		}
	}
	result.State = "accepted"
	respond(w, result, s.Store.SetSetting(r.Context(), key, result))
}
