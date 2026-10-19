// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/audit"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/watermark"
	"net/http"
)

func (s *Server) policyRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/siem", func(w http.ResponseWriter, r *http.Request) {
		var c audit.Config
		err := s.Store.Setting(r.Context(), "siem", &c)
		status := audit.Status{}
		if s.Audit != nil {
			status = s.Audit.Status()
		}
		respond(w, map[string]any{"config": c, "status": status}, err)
	})
	api.HandleFunc("PUT /api/siem", func(w http.ResponseWriter, r *http.Request) {
		var c audit.Config
		if !decode(w, r, &c) {
			return
		}
		if err := audit.Validate(c); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		err := s.Store.SetSetting(r.Context(), "siem", c)
		respond(w, c, err)
	})
	api.HandleFunc("GET /api/watermark", func(w http.ResponseWriter, r *http.Request) {
		c := watermark.Default()
		err := s.Store.Setting(r.Context(), "watermark", &c)
		respond(w, c, err)
	})
	api.HandleFunc("PUT /api/watermark", func(w http.ResponseWriter, r *http.Request) {
		var c watermark.Config
		if !decode(w, r, &c) {
			return
		}
		if err := watermark.Validate(c); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		c.Version = queue.ID()
		err := s.Store.SetSetting(r.Context(), "watermark", c)
		respond(w, c, err)
	})
}
