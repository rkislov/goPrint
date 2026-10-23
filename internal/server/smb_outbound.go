// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/backend"
	"net/http"
	"strings"
)

func (s *Server) smbRoutes(api *http.ServeMux) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.permittedPrinter(w, r, r.PathValue("id"))
		if !ok {
			return
		}
		if !strings.HasPrefix(p.URI, "smb://") {
			http.Error(w, "not an SMB printer", 409)
			return
		}
		if s.SMB == nil {
			http.Error(w, "SMB service unavailable", 503)
			return
		}
		if r.Method == "GET" {
			c, err := s.SMB.Config(r.Context(), p.ID)
			respond(w, c, err)
			return
		}
		var c backend.SMBConfig
		if !decode(w, r, &c) {
			return
		}
		out, err := s.SMB.Configure(r.Context(), p.ID, c)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		respond(w, out, nil)
	}
	api.HandleFunc("GET /api/printers/{id}/smb", handler)
	api.HandleFunc("PUT /api/printers/{id}/smb", handler)
}
