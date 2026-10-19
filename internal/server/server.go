// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// Package server exposes the local administrator API and a small web console.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/rkislov/goPrint/internal/antivirus"
	"github.com/rkislov/goPrint/internal/audit"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/maildelivery"
	"github.com/rkislov/goPrint/internal/personal"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"github.com/rkislov/goPrint/internal/watermark"
)

type Server struct {
	Antivirus   *antivirus.Service
	emailMu     sync.Mutex
	Personal    *personal.Service
	Mail        *maildelivery.Service
	PublicURL   string
	Domain      auth.Authenticator
	SSO         auth.Negotiator
	limiter     loginLimiter
	credentials credentialCache
	Store       *queue.Store
	Token       string
	Catalog     *drivers.Catalog
	Filters     *drivers.FilterManager
	Audit       *audit.Exporter
	Scans       *scanning.Service
	Background  context.Context
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(web, "web")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		target := "/login"
		if s.authorized(r) {
			target = "/print"
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
	page := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" && !s.authorized(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		b, _ := web.ReadFile("web/index.html")
		w.Write(b)
	}
	mux.HandleFunc("GET /login", page)
	mux.HandleFunc("GET /print", page)
	mux.HandleFunc("GET /settings", page)
	mux.HandleFunc("GET /scan", page)
	mux.HandleFunc("GET /watermarks", page)
	mux.HandleFunc("GET /clients", page)
	mux.HandleFunc("GET /printers", page)
	mux.HandleFunc("GET /profile", page)
	mux.HandleFunc("GET /mail", page)
	mux.HandleFunc("GET /security", page)
	mux.HandleFunc("GET /protection", page)
	mux.HandleFunc("POST /terminal/{id}/release", s.terminalRelease)
	mux.HandleFunc("POST /mail/incoming", s.incomingEmail)
	mux.HandleFunc("/inbox/{scanner}/{file...}", s.inbox)
	mux.HandleFunc("/inbox/{scanner}", s.inbox)
	mux.HandleFunc("POST /api/session", s.login)
	mux.HandleFunc("POST /api/session/negotiate", s.loginSSO)
	mux.HandleFunc("POST /ipp/printers/{id}", s.ipp)
	mux.HandleFunc("POST /ipp/printers/{id}/jobs/{job}", s.ipp)
	mux.HandleFunc("GET /api/auth/options", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]bool{"domain": s.Domain != nil, "sso": s.SSO != nil}, nil)
	})
	api := http.NewServeMux()
	s.scanRoutes(api)
	s.filterRoutes(api)
	s.policyRoutes(api)
	s.clientRoutes(api)
	s.printerRoutes(api)
	s.personalRoutes(api)
	s.ssoRoutes(api)
	s.emailRoutes(api)
	s.antivirusRoutes(api)
	api.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		id, _ := s.identity(r)
		respond(w, id, nil)
	})
	api.HandleFunc("DELETE /api/session", s.logout)
	api.HandleFunc("GET /api/drivers", func(w http.ResponseWriter, r *http.Request) {
		if s.Catalog == nil {
			http.Error(w, "catalog unavailable", 503)
			return
		}
		respond(w, map[string]any{"profiles": s.Catalog.Search(r.URL.Query().Get("q"), r.URL.Query().Get("manufacturer")), "manufacturers": s.Catalog.Manufacturers(), "status": s.Catalog.Status(), "katusha": s.Catalog.KatushaStatus()}, nil)
	})
	api.HandleFunc("GET /api/drivers/katusha/packages/{name}", func(w http.ResponseWriter, r *http.Request) {
		if s.Catalog == nil {
			http.NotFound(w, r)
			return
		}
		p, err := s.Catalog.KatushaPackage(r.PathValue("name"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
		http.ServeFile(w, r, p)
	})
	api.HandleFunc("POST /api/drivers/sync", func(w http.ResponseWriter, r *http.Request) {
		if s.Catalog == nil {
			http.Error(w, "catalog unavailable", 503)
			return
		}
		ctx := s.Background
		if ctx == nil {
			ctx = context.Background()
		}
		started := s.Catalog.StartSync(ctx)
		s.Catalog.StartKatushaSync(ctx)
		respond(w, map[string]bool{"started": started}, nil)
	})
	api.HandleFunc("GET /api/printers", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.visiblePrinters(r)
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/printers", s.addPrinter)
	api.HandleFunc("PUT /api/printers/{id}/paused", s.pause)
	api.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, r *http.Request) { v, err := s.visibleJobs(r); respond(w, v, err) })
	api.HandleFunc("GET /api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !s.ownJob(w, r, r.PathValue("id")) {
			return
		}
		v, err := s.Store.Job(r.Context(), r.PathValue("id"))
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/jobs", s.submit)
	api.HandleFunc("POST /api/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !s.ownJob(w, r, r.PathValue("id")) {
			return
		}
		err := s.Store.CancelIPP(r.Context(), r.PathValue("id"))
		respond(w, map[string]string{"state": "canceled"}, err)
	})
	api.HandleFunc("GET /api/jobs/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.ownJob(w, r, r.PathValue("id")) {
			return
		}
		v, err := s.Store.Events(r.Context(), r.PathValue("id"))
		respond(w, v, err)
	})
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !s.permitAPI(r) {
			http.Error(w, "administrator access required", 403)
			return
		}
		api.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		// Block browser requests from other origins, including requests through DNS rebinding.
		if origin := r.Header.Get("Origin"); origin != "" && origin != requestOrigin(r) {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		message := "internal server error"
		switch {
		case errors.Is(err, queue.ErrNotFound):
			status = 404
			message = err.Error()
		case errors.Is(err, queue.ErrConflict):
			status = 409
			message = err.Error()
		case errors.Is(err, queue.ErrTooLarge):
			status = 413
			message = err.Error()
		}
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "expected one JSON object", 400)
		return false
	}
	return true
}
func (s *Server) addPrinter(w http.ResponseWriter, r *http.Request) {
	var p queue.Printer
	if !decode(w, r, &p) {
		return
	}
	if err := backend.Validate(p); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if p.PPDID != "" {
		if s.Catalog == nil {
			http.Error(w, "catalog unavailable", 503)
			return
		}
		if _, ok := s.Catalog.Find(p.PPDID); !ok {
			http.Error(w, "PPD profile not found", 400)
			return
		}
	}
	v, err := s.Store.AddPrinter(r.Context(), p)
	respond(w, v, err)
}
func (s *Server) pause(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Paused bool `json:"paused"`
	}
	if !decode(w, r, &p) {
		return
	}
	err := s.Store.Pause(r.Context(), r.PathValue("id"), p.Paused)
	respond(w, p, err)
}
func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	format, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "valid Content-Type required", 400)
		return
	}
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Untitled"
	}
	if len(title) > 255 || strings.ContainsAny(title, "\r\n\x00") {
		http.Error(w, "invalid title", 400)
		return
	}
	policy := watermark.Default()
	if err := s.Store.Setting(r.Context(), "watermark", &policy); err != nil {
		respond(w, nil, err)
		return
	}
	if policy.Enabled && format != "application/pdf" {
		http.Error(w, "Обязательный watermark поддерживает только PDF", 415)
		return
	}
	p, ok := s.permittedPrinter(w, r, r.URL.Query().Get("printer"))
	if !ok {
		return
	}
	if !queue.Accepts(p, format) {
		http.Error(w, "document format not accepted by printer", 415)
		return
	}
	if r.ContentLength > queue.MaxDocumentSize {
		http.Error(w, "document exceeds size limit", 413)
		return
	}
	// LimitReader in Store also protects chunked requests without Content-Length.
	identity, _ := s.identity(r)
	options, err := s.effectiveOptions(r, p, queue.PrintOptions{Media: r.URL.Query().Get("media"), Sides: r.URL.Query().Get("sides"), Color: r.URL.Query().Get("color")})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	options, err = s.holdOptions(r.Context(), identity.User, options)
	if err != nil {
		respond(w, nil, err)
		return
	}
	j, err := s.Store.SubmitOptions(r.Context(), p.ID, identity.User, title, format, r.Body, options)
	if err != nil {
		if errors.Is(err, queue.ErrTooLarge) {
			respond(w, nil, err)
		} else {
			http.Error(w, "document could not be accepted", 400)
		}
		return
	}
	w.Header().Set("Location", "/api/jobs/"+j.ID)
	w.Header().Set("Content-Length", strconv.Itoa(len(mustJSON(j))))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(mustJSON(j))
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

//go:embed web/*
var web embed.FS

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
