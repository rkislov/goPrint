// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"errors"
	"github.com/go-ldap/ldap/v3"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
	"strings"
)

func (s *Server) allowedPrinter(r *http.Request, p queue.Printer) bool {
	id, ok := s.identity(r)
	if ok && id.Admin {
		return true
	}
	access, err := s.Store.Access(r.Context(), p.ID)
	if err != nil {
		return false
	}
	if !ok {
		return false
	}
	if access.Public {
		return true
	}
	return s.allowedAccess(r, access)
}

func (s *Server) allowedAccess(r *http.Request, access queue.PrinterAccess) bool {
	id, ok := s.identity(r)
	if !ok {
		return false
	}
	if id.Admin || access.Public {
		return true
	}
	for _, u := range access.Users {
		if strings.EqualFold(u, id.User) {
			return true
		}
	}
	for _, rule := range access.Groups {
		a, err := ldap.ParseDN(rule)
		if err != nil {
			continue
		}
		for _, g := range id.Groups {
			b, err := ldap.ParseDN(g)
			if err == nil && a.EqualFold(b) {
				return true
			}
		}
	}
	return false
}
func (s *Server) permittedPrinter(w http.ResponseWriter, r *http.Request, id string) (queue.Printer, bool) {
	p, err := s.Store.Printer(r.Context(), id)
	if err != nil || !s.allowedPrinter(r, p) {
		http.Error(w, "printer not found", 404)
		return p, false
	}
	return p, true
}
func (s *Server) visiblePrinters(r *http.Request) ([]queue.Printer, error) {
	all, err := s.Store.Printers(r.Context())
	if err != nil {
		return nil, err
	}
	out := []queue.Printer{}
	for _, p := range all {
		if s.allowedPrinter(r, p) {
			out = append(out, p)
		}
	}
	return out, nil
}
func (s *Server) capabilities(p queue.Printer) (drivers.Capabilities, error) {
	if p.PPDID == "" {
		return drivers.DirectCapabilities(), nil
	}
	if s.Catalog == nil {
		return drivers.Capabilities{}, errors.New("каталог PPD недоступен")
	}
	b, err := s.Catalog.PPD(p.PPDID)
	if err != nil {
		return drivers.Capabilities{}, err
	}
	return drivers.CapabilitiesFor(b)
}
func (s *Server) effectiveOptions(r *http.Request, p queue.Printer, over queue.PrintOptions) (queue.PrintOptions, error) {
	id, _ := s.identity(r)
	base, err := s.Store.Preferences(r.Context(), id.User, p.ID)
	if err != nil {
		return over, err
	}
	c, err := s.capabilities(p)
	if err != nil {
		if base == (queue.PrintOptions{}) && over == (queue.PrintOptions{}) {
			return queue.PrintOptions{}, nil
		}
		return over, err
	}
	return c.Resolve(base, over)
}
func validateAccess(p queue.PrinterAccess) error {
	if len(p.Users) > 100 || len(p.Groups) > 100 {
		return errors.New("слишком много правил доступа")
	}
	for _, u := range p.Users {
		if len(u) > 254 || !strings.Contains(u, "@") || strings.ContainsAny(u, "\r\n\x00") {
			return errors.New("нужен UPN пользователя")
		}
	}
	for _, g := range p.Groups {
		if len(g) > 2048 {
			return errors.New("слишком длинный DN группы")
		}
		if _, err := ldap.ParseDN(g); err != nil {
			return errors.New("нужен полный DN группы")
		}
	}
	return nil
}
func (s *Server) printerRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/printers/{id}/access", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.permittedPrinter(w, r, r.PathValue("id")); !ok {
			return
		}
		p, err := s.Store.Access(r.Context(), r.PathValue("id"))
		respond(w, p, err)
	})
	api.HandleFunc("PUT /api/printers/{id}/access", func(w http.ResponseWriter, r *http.Request) {
		var p queue.PrinterAccess
		if !decode(w, r, &p) {
			return
		}
		if err := validateAccess(p); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		respond(w, p, s.Store.SetAccess(r.Context(), r.PathValue("id"), p))
	})
	api.HandleFunc("GET /api/printers/{id}/preferences", func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.permittedPrinter(w, r, r.PathValue("id"))
		if !ok {
			return
		}
		c, err := s.capabilities(p)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		options, err := s.effectiveOptions(r, p, queue.PrintOptions{})
		respond(w, map[string]any{"capabilities": c, "options": options}, err)
	})
	api.HandleFunc("PUT /api/printers/{id}/preferences", func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.permittedPrinter(w, r, r.PathValue("id"))
		if !ok {
			return
		}
		var o queue.PrintOptions
		if !decode(w, r, &o) {
			return
		}
		c, err := s.capabilities(p)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		o, err = c.Resolve(queue.PrintOptions{}, o)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		id, _ := s.identity(r)
		respond(w, o, s.Store.SetPreferences(r.Context(), id.User, p.ID, o))
	})
}
