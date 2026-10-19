// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
)

func (s *Server) scanRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/scanners", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.Error(w, "scanning unavailable", 503)
			return
		}
		v, err := s.Scans.List(r.Context())
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/scanners", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.Error(w, "scanning unavailable", 503)
			return
		}
		var input struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		if !decode(w, r, &input) {
			return
		}
		v, err := s.Scans.Add(r.Context(), input.Name, input.URI)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		respond(w, v, nil)
	})
	api.HandleFunc("GET /api/scans", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.Error(w, "scanning unavailable", 503)
			return
		}
		v, err := s.Scans.Jobs(r.Context())
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/scans", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.Error(w, "scanning unavailable", 503)
			return
		}
		var o scanning.Options
		if !decode(w, r, &o) {
			return
		}
		v, err := s.Scans.Start(r.Context(), o)
		if err != nil {
			if errors.Is(err, queue.ErrConflict) || errors.Is(err, queue.ErrNotFound) {
				respond(w, nil, err)
			} else {
				http.Error(w, err.Error(), 400)
			}
			return
		}
		respond(w, v, nil)
	})
	api.HandleFunc("GET /api/scans/{id}/document", func(w http.ResponseWriter, r *http.Request) {
		if s.Scans == nil {
			http.Error(w, "scanning unavailable", 503)
			return
		}
		j, err := s.Scans.Job(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, nil, err)
			return
		}
		if j.State != "completed" {
			respond(w, nil, queue.ErrConflict)
			return
		}
		ext := map[string]string{"application/pdf": ".pdf", "image/jpeg": ".jpg", "image/png": ".png", "application/zip": ".zip"}[j.Format]
		w.Header().Set("Content-Type", j.Format)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s%s"`, j.ID, ext))
		http.ServeFile(w, r, s.Scans.Path(j.ID))
	})
}
func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	if s.Scans == nil {
		http.Error(w, "scanning unavailable", 503)
		return
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Allow", "OPTIONS, PROPFIND, MKCOL, PUT")
		w.Header().Set("DAV", "1")
		w.WriteHeader(204)
		return
	}
	id := r.PathValue("scanner")
	user, token, ok := r.BasicAuth()
	if !ok || user != id || !s.Scans.Authenticate(r.Context(), id, token) {
		w.Header().Set("WWW-Authenticate", `Basic realm="GoPrint scan inbox"`)
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("DAV", "1")
	switch r.Method {
	case "MKCOL":
		w.WriteHeader(http.StatusCreated)
	case "PROPFIND":
		if depth := r.Header.Get("Depth"); depth != "" && depth != "0" && depth != "1" {
			http.Error(w, "Depth must be 0 or 1", 403)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(207)
		fmt.Fprintf(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/inbox/%s/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:displayname>GoPrint Inbox</d:displayname></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, xmlEscape(id))
	case "PUT":
		title := path.Base(r.PathValue("file"))
		if title == "." || title == "/" || strings.TrimSpace(title) == "" {
			http.Error(w, "file name required", 400)
			return
		}
		if r.ContentLength > queue.MaxDocumentSize {
			http.Error(w, "document exceeds size limit", 413)
			return
		}
		j, err := s.Scans.Receive(r.Context(), id, title, r.Body)
		if err != nil {
			if errors.Is(err, queue.ErrTooLarge) {
				respond(w, nil, err)
			} else {
				http.Error(w, "could not accept PDF/JPEG/PNG document", 400)
			}
			return
		}
		w.Header().Set("Location", "/api/scans/"+j.ID+"/document")
		w.WriteHeader(http.StatusCreated)
	default:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, MKCOL, PUT")
		http.Error(w, "method not allowed", 405)
	}
}
func xmlEscape(v string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(v))
	return b.String()
}
