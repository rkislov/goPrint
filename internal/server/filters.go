// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"github.com/rkislov/goPrint/internal/drivers"
	"net/http"
)

func (s *Server) filterRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/filters", func(w http.ResponseWriter, r *http.Request) {
		status := "Менеджер пакетов не настроен"
		if s.Filters != nil {
			status = s.Filters.Status()
		}
		respond(w, map[string]any{"filters": drivers.InstalledFilters(), "status": status}, nil)
	})
	api.HandleFunc("POST /api/filters/download", func(w http.ResponseWriter, r *http.Request) {
		if s.Filters == nil {
			http.Error(w, "manager unavailable", 503)
			return
		}
		ctx := s.Background
		if ctx == nil {
			ctx = context.Background()
		}
		message, err := s.Filters.Download(ctx)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		respond(w, map[string]string{"message": message}, nil)
	})
}
