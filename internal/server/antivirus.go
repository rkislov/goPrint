// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/antivirus"
	"net/http"
)

func (s *Server) antivirusRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/antivirus", func(w http.ResponseWriter, r *http.Request) {
		if s.Antivirus == nil {
			http.Error(w, "antivirus service unavailable", 503)
			return
		}
		v, e := s.Antivirus.Config(r.Context())
		respond(w, v, e)
	})
	api.HandleFunc("PUT /api/antivirus", func(w http.ResponseWriter, r *http.Request) {
		if s.Antivirus == nil {
			http.Error(w, "antivirus service unavailable", 503)
			return
		}
		var c antivirus.Config
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Antivirus.Configure(r.Context(), c)
		respond(w, v, e)
	})
	api.HandleFunc("POST /api/antivirus/test", func(w http.ResponseWriter, r *http.Request) {
		if s.Antivirus == nil {
			http.Error(w, "antivirus service unavailable", 503)
			return
		}
		e := s.Antivirus.Test(r.Context())
		respond(w, map[string]bool{"connected": e == nil}, e)
	})
}
