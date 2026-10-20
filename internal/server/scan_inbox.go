// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/scaninbox"
	"net/http"
	"strings"
)

func (s *Server) scanInboxRoutes(api *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, ok := s.identity(r)
			if !ok || !id.Admin {
				http.Error(w, "administrator access required", 403)
				return
			}
			if s.Inboxes == nil {
				http.Error(w, "scan inbox unavailable", 503)
				return
			}
			fn(w, r)
		}
	}
	api.HandleFunc("GET /api/scan-inboxes", wrap(func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Inboxes.List(r.Context())
		base := s.PublicURL
		if base == "" {
			base = requestOrigin(r)
		}
		respond(w, map[string]any{"destinations": v, "ftp": s.Inboxes.FTPStatus(), "webdav_base": strings.TrimRight(base, "/") + "/inbox/", "domain_configured": s.Domain != nil}, e)
	}))
	save := wrap(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name      string `json:"name"`
			ScannerID string `json:"scanner_id"`
			Owner     string `json:"owner"`
			Enabled   bool   `json:"enabled"`
			WebDAV    bool   `json:"webdav"`
			FTP       bool   `json:"ftp"`
			FTPS      bool   `json:"ftps"`
			MaxMiB    int    `json:"max_mib"`
		}
		if !decode(w, r, &v) {
			return
		}
		d, e := s.Inboxes.Save(r.Context(), r.PathValue("id"), scaninbox.Destination{Name: v.Name, ScannerID: v.ScannerID, Owner: v.Owner, Enabled: v.Enabled, WebDAV: v.WebDAV, FTP: v.FTP, FTPS: v.FTPS, MaxMiB: v.MaxMiB}, false)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		respond(w, d, nil)
	})
	api.HandleFunc("POST /api/scan-inboxes", save)
	api.HandleFunc("PUT /api/scan-inboxes/{id}", save)
	api.HandleFunc("POST /api/scan-inboxes/{id}/password", wrap(func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Inboxes.Rotate(r.Context(), r.PathValue("id"))
		respond(w, v, e)
	}))
	api.HandleFunc("PUT /api/scan-inboxes/ftp", wrap(func(w http.ResponseWriter, r *http.Request) {
		var c scaninbox.FTPConfig
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Inboxes.SetFTP(r.Context(), c)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		respond(w, v, nil)
	}))
}
