// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/auth"
	"io"
	"net/http"
)

func (s *Server) ssoRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/domain/sso", func(w http.ResponseWriter, r *http.Request) {
		v := map[string]any{"configured": false, "ready": false}
		if k, ok := s.SSO.(*auth.Kerberos); ok {
			realm, spn, ready := k.Status()
			v["configured"] = true
			v["realm"] = realm
			v["spn"] = spn
			v["ready"] = ready
		}
		respond(w, v, nil)
	})
	api.HandleFunc("PUT /api/domain/keytab", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS required for keytab upload", 403)
			return
		}
		k, ok := s.SSO.(*auth.Kerberos)
		if !ok {
			http.Error(w, "сначала настройте Kerberos в конфигурации домена и перезапустите службу", 409)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if e != nil {
			http.Error(w, "keytab must be at most 1 MiB", 413)
			return
		}
		if e = k.InstallKeytab(b); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		respond(w, map[string]bool{"ready": true}, nil)
	})
}
