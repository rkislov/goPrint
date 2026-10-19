// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/monitoring"
	"net/http"
)

func (s *Server) monitoringRoutes(api *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, ok := s.identity(r)
			if !ok || !id.Admin {
				http.Error(w, "administrator access required", 403)
				return
			}
			if s.Monitoring == nil {
				http.Error(w, "monitoring unavailable", 503)
				return
			}
			fn(w, r)
		}
	}
	api.HandleFunc("GET /api/monitoring", wrap(func(w http.ResponseWriter, r *http.Request) { v, e := s.Monitoring.All(r.Context()); respond(w, v, e) }))
	api.HandleFunc("GET /api/monitoring/policy", wrap(func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Monitoring.Policy(r.Context())
		respond(w, v, e)
	}))
	api.HandleFunc("PUT /api/monitoring/policy", wrap(func(w http.ResponseWriter, r *http.Request) {
		var c monitoring.Policy
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Monitoring.SetPolicy(r.Context(), c)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		respond(w, v, nil)
	}))
	api.HandleFunc("PUT /api/printers/{id}/monitoring", wrap(func(w http.ResponseWriter, r *http.Request) {
		var c monitoring.Config
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Monitoring.Configure(r.Context(), r.PathValue("id"), c)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		respond(w, v, nil)
	}))
	api.HandleFunc("POST /api/printers/{id}/monitoring/poll", wrap(func(w http.ResponseWriter, r *http.Request) {
		p, e := s.Store.Printer(r.Context(), r.PathValue("id"))
		if e != nil {
			respond(w, nil, e)
			return
		}
		v, e := s.Monitoring.Poll(r.Context(), p, true)
		respond(w, v, e)
	}))
	api.HandleFunc("POST /api/printers/{id}/monitoring/ack", wrap(func(w http.ResponseWriter, r *http.Request) {
		p, e := s.Store.Printer(r.Context(), r.PathValue("id"))
		if e != nil {
			respond(w, nil, e)
			return
		}
		var c struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &c) {
			return
		}
		v, e := s.Monitoring.Acknowledge(r.Context(), p, c.ID)
		respond(w, v, e)
	}))
}
