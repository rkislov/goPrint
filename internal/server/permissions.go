// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"strings"
)

func (s *Server) permitAPI(r *http.Request) bool {
	id, ok := s.identity(r)
	if !ok {
		return false
	}
	if id.Admin {
		return true
	}
	path := r.URL.Path
	if path == "/api/session" || strings.HasPrefix(path, "/api/me/") {
		return true
	}
	if r.Method == "GET" && (path == "/api/printers" || strings.HasPrefix(path, "/api/printers/") && strings.HasSuffix(path, "/preferences") || path == "/api/jobs" || strings.HasPrefix(path, "/api/jobs/") || path == "/api/scanners" || path == "/api/scans" || strings.HasPrefix(path, "/api/scans/") || strings.HasPrefix(path, "/api/clients/")) {
		return true
	}
	if r.Method == "PUT" && strings.HasPrefix(path, "/api/printers/") && strings.HasSuffix(path, "/preferences") {
		return true
	}
	return r.Method == "POST" && (path == "/api/jobs" || path == "/api/scans" || strings.HasPrefix(path, "/api/jobs/") && strings.HasSuffix(path, "/cancel"))
}
func (s *Server) ownJob(w http.ResponseWriter, r *http.Request, id string) bool {
	j, err := s.Store.Job(r.Context(), id)
	identity, _ := s.identity(r)
	if err != nil || !identity.Admin && j.Owner != identity.User {
		http.Error(w, "job not found", 404)
		return false
	}
	return true
}
func (s *Server) visibleJobs(r *http.Request) ([]queue.Job, error) {
	identity, _ := s.identity(r)
	return s.Store.JobsFor(r.Context(), identity.User, identity.Admin)
}
