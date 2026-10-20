// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	qrcode "github.com/skip2/go-qrcode"
)

// QR links identify a device; they never carry credentials or grant access.
type mobileDevice struct {
	ScannerID     string              `json:"scanner_id"`
	ScanWithPrint bool                `json:"scan_with_print"`
	ScanAccess    queue.PrinterAccess `json:"scan_access"`
}

func (s *Server) mobileConfig(ctx context.Context, pid string) (mobileDevice, error) {
	var c mobileDevice
	err := s.Store.Setting(ctx, "mobile-device:"+pid, &c)
	return c, err
}
func (s *Server) allowedDeviceScan(r *http.Request, p queue.Printer, c mobileDevice) bool {
	id, ok := s.identity(r)
	return ok && (id.Admin || c.ScanWithPrint && s.allowedPrinter(r, p) || s.allowedAccess(r, c.ScanAccess))
}
func (s *Server) allowedScanner(r *http.Request, sid string) bool {
	id, ok := s.identity(r)
	if !ok {
		return false
	}
	if id.Admin {
		return true
	}
	ps, err := s.Store.Printers(r.Context())
	if err != nil {
		return false
	}
	for _, p := range ps {
		c, err := s.mobileConfig(r.Context(), p.ID)
		if err == nil && c.ScannerID == sid && s.allowedDeviceScan(r, p, c) {
			return true
		}
	}
	return false
}
func (s *Server) mobileRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/printers/{id}/mobile", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.Store.Printer(r.Context(), r.PathValue("id")); err != nil {
			http.NotFound(w, r)
			return
		}
		c, err := s.mobileConfig(r.Context(), r.PathValue("id"))
		respond(w, c, err)
	})
	api.HandleFunc("PUT /api/printers/{id}/mobile", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.Store.Printer(r.Context(), r.PathValue("id")); err != nil {
			http.NotFound(w, r)
			return
		}
		var c mobileDevice
		if !decode(w, r, &c) {
			return
		}
		if err := validateAccess(c.ScanAccess); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if c.ScannerID != "" {
			if s.Scans == nil {
				http.Error(w, "scanning unavailable", 503)
				return
			}
			v, err := s.Scans.Get(r.Context(), c.ScannerID)
			if err != nil || v.URI == "" {
				http.Error(w, "нужен сканер eSCL / AirScan", 400)
				return
			}
		}
		respond(w, c, s.Store.SetSetting(r.Context(), "mobile-device:"+r.PathValue("id"), c))
	})
	api.HandleFunc("GET /api/printers/{id}/qr.png", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.Store.Printer(r.Context(), r.PathValue("id")); err != nil {
			http.NotFound(w, r)
			return
		}
		// Never derive a printed, persistent login URL from an untrusted Host header.
		u, err := url.Parse(s.PublicURL)
		if err != nil || ValidatePublicURL(s.PublicURL) != nil || u.Scheme != "https" || u.Hostname() == "" || strings.EqualFold(u.Hostname(), "localhost") || net.ParseIP(u.Hostname()).IsLoopback() {
			http.Error(w, "Для QR задайте public-url: HTTPS-адрес GoPrint, доступный с телефона", 409)
			return
		}
		b, err := qrcode.Encode(s.PublicURL+"/device/"+url.PathEscape(r.PathValue("id")), qrcode.Medium, 768)
		if err != nil {
			http.Error(w, "could not encode QR", 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", `inline; filename="GoPrint-QR.png"`)
		w.Write(b)
	})
	api.HandleFunc("GET /api/me/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Store.Printer(r.Context(), r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		c, err := s.mobileConfig(r.Context(), p.ID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		canPrint := s.allowedPrinter(r, p)
		var scanner *scanning.Scanner
		if s.Scans != nil && c.ScannerID != "" && s.allowedDeviceScan(r, p, c) {
			if v, e := s.Scans.Get(r.Context(), c.ScannerID); e == nil && v.URI != "" {
				scanner = &v
			}
		}
		if !canPrint && scanner == nil {
			http.NotFound(w, r)
			return
		}
		respond(w, map[string]any{"id": p.ID, "name": p.Name, "can_print": canPrint, "paused": p.Paused, "scanner": scanner}, nil)
	})
}
