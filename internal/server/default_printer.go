// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rkislov/goPrint/internal/queue"
)

const defaultPrinterRulesKey = "print_default_rules"

type defaultPrinterRule struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Printer string `json:"printer_id"`
}

type defaultPrinterView struct {
	Printer  string `json:"printer_id"`
	Source   string `json:"source"`
	Personal string `json:"personal_id"`
}

func (s *Server) printDefault(r *http.Request) (defaultPrinterView, error) {
	ctx := r.Context()
	id, _ := s.identity(r)
	result := defaultPrinterView{Source: "none"}
	if err := s.Store.Setting(ctx, "print_default:"+id.User, &result.Personal); err != nil {
		return result, err
	}
	available := func(candidate string) (bool, error) {
		if candidate == "" {
			return false, nil
		}
		p, err := s.Store.Printer(ctx, candidate)
		if errors.Is(err, queue.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return s.allowedPrinter(r, p), nil
	}
	if ok, err := available(result.Personal); err != nil || ok {
		if ok {
			result.Printer, result.Source = result.Personal, "personal"
		}
		return result, err
	}
	var rules []defaultPrinterRule
	if err := s.Store.Setting(ctx, defaultPrinterRulesKey, &rules); err != nil {
		return result, err
	}
	for _, kind := range []string{"user", "group"} {
		for _, rule := range rules {
			if rule.Kind != kind {
				continue
			}
			match := kind == "user" && strings.EqualFold(rule.Subject, id.User)
			if kind == "group" {
				dn, err := ldap.ParseDN(rule.Subject)
				if err != nil {
					continue
				}
				for _, group := range id.Groups {
					member, err := ldap.ParseDN(group)
					if err == nil && dn.EqualFold(member) {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
			ok, err := available(rule.Printer)
			if err != nil {
				return result, err
			}
			if ok {
				result.Printer, result.Source = rule.Printer, kind
				return result, nil
			}
		}
	}
	return result, nil
}

func (s *Server) defaultPrinterRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/me/default-printer", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.printDefault(r)
		respond(w, v, err)
	})
	api.HandleFunc("PUT /api/me/default-printer", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Printer *string `json:"printer_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Printer == nil {
			http.Error(w, "Укажите printer_id", 400)
			return
		}
		if *input.Printer != "" {
			if _, ok := s.permittedPrinter(w, r, *input.Printer); !ok {
				return
			}
		}
		id, _ := s.identity(r)
		if err := s.Store.SetSetting(r.Context(), "print_default:"+id.User, *input.Printer); err != nil {
			respond(w, nil, err)
			return
		}
		v, err := s.printDefault(r)
		respond(w, v, err)
	})
	api.HandleFunc("GET /api/print-default-rules", func(w http.ResponseWriter, r *http.Request) {
		rules := []defaultPrinterRule{}
		err := s.Store.Setting(r.Context(), defaultPrinterRulesKey, &rules)
		respond(w, rules, err)
	})
	api.HandleFunc("PUT /api/print-default-rules", func(w http.ResponseWriter, r *http.Request) {
		var rules []defaultPrinterRule
		if !decode(w, r, &rules) {
			return
		}
		if rules == nil || len(rules) > 100 {
			http.Error(w, "Передайте список из не более чем 100 назначений", 400)
			return
		}
		users := map[string]bool{}
		var groups []*ldap.DN
		for i := range rules {
			rule := &rules[i]
			rule.Subject = strings.TrimSpace(rule.Subject)
			if rule.Subject == "" || len(rule.Subject) > 1024 || strings.ContainsAny(rule.Subject, "\r\n\x00") {
				http.Error(w, "Укажите пользователя или полный DN группы", 400)
				return
			}
			switch rule.Kind {
			case "user":
				key := strings.ToLower(rule.Subject)
				if users[key] {
					http.Error(w, "Пользователь указан дважды", 400)
					return
				}
				users[key] = true
			case "group":
				dn, err := ldap.ParseDN(rule.Subject)
				if err != nil || len(dn.RDNs) == 0 {
					http.Error(w, "Укажите полный DN группы", 400)
					return
				}
				for _, prev := range groups {
					if prev.EqualFold(dn) {
						http.Error(w, "Группа указана дважды", 400)
						return
					}
				}
				groups = append(groups, dn)
			default:
				http.Error(w, "Выберите пользователя или группу", 400)
				return
			}
			if _, err := s.Store.Printer(r.Context(), rule.Printer); err != nil {
				respond(w, nil, err)
				return
			}
		}
		respond(w, rules, s.Store.SetSetting(r.Context(), defaultPrinterRulesKey, rules))
	})
}
