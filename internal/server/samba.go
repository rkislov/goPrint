// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/sambaprint"
)

type sambaReceipt struct {
	State string `json:"state"`
	JobID string `json:"job_id"`
}

// SambaHandler is served ONLY on the peer-authenticated Unix socket, never the TCP API.
func (s *Server) SambaHandler(users map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "POST" || r.URL.Path != "/submit" {
			http.NotFound(w, r)
			return
		}
		uid, ok := sambaprint.UID(r.Context())
		if !ok {
			http.Error(w, "local non-root peer credentials required", 403)
			return
		}
		upn, ok := users[strconv.FormatUint(uint64(uid), 10)]
		if !ok {
			http.Error(w, "Unix UID is not mapped to a domain account", 403)
			return
		}
		r.RemoteAddr = net.JoinHostPort(strconv.FormatUint(uint64(uid), 10), "0")
		if !s.limiter.allow(r) {
			http.Error(w, "submission rate limit exceeded", 429)
			return
		}
		resolver, ok := s.Domain.(interface {
			ResolveUser(context.Context, string) (auth.Identity, error)
		})
		if !ok {
			http.Error(w, "directory lookup unavailable", 503)
			return
		}
		id, e := resolver.ResolveUser(r.Context(), upn)
		if e != nil || !strings.EqualFold(id.User, upn) {
			http.Error(w, "domain account is not authorized", 403)
			return
		}
		// The bridge grants printing as this user, never administrator API authority.
		id.Admin = false
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
		if _, ok := s.permittedPrinter(w, r, r.URL.Query().Get("printer")); !ok {
			return
		}
		receipt := r.Header.Get("X-GoPrint-Spool-ID")
		b, e := hex.DecodeString(receipt)
		if e != nil || len(b) != 32 {
			http.Error(w, "stable 64-hex spool ID required", 400)
			return
		}

		h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", uid, strings.ToLower(id.User), r.URL.Query().Get("printer"), strings.ToLower(receipt))))
		key := "samba-job:" + hex.EncodeToString(h[:])
		s.sambaMu.Lock()
		defer s.sambaMu.Unlock()
		var prev sambaReceipt
		if e = s.Store.Setting(r.Context(), key, &prev); e != nil {
			respond(w, nil, e)
			return
		}
		if prev.State == "accepted" {
			respond(w, prev, nil)
			return
		}
		if prev.State != "" {
			http.Error(w, "submission result uncertain; inspect GoPrint queue before retrying", 409)
			return
		}
		// Write before submitting: after a crash or lost acknowledgement, never blindly duplicate a job.
		if e = s.Store.SetSetting(r.Context(), key, sambaReceipt{State: "processing"}); e != nil {
			respond(w, nil, e)
			return
		}
		j, ok := s.acceptPrint(w, r)
		if !ok {
			return
		}
		result := sambaReceipt{State: "accepted", JobID: j.ID}
		if e = s.Store.SetSetting(r.Context(), key, result); e != nil {
			http.Error(w, "receipt persistence failed; inspect queue", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		respond(w, result, nil)
	})
}
