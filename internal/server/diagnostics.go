// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"github.com/rkislov/goPrint/internal/monitoring"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type diagnosticGate struct {
	mu   sync.Mutex
	busy bool
	last map[string]time.Time
}

func (g *diagnosticGate) enter(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.busy || now.Sub(g.last[key]) < 10*time.Second {
		return false
	}
	if g.last == nil {
		g.last = map[string]time.Time{}
	}
	for k, v := range g.last {
		if now.Sub(v) > time.Minute {
			delete(g.last, k)
		}
	}
	if len(g.last) >= 1024 {
		return false
	}
	g.last[key] = now
	g.busy = true
	return true
}
func (g *diagnosticGate) leave() { g.mu.Lock(); defer g.mu.Unlock(); g.busy = false }
func (s *Server) diagnosticRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.identity(r)
		if !ok || !id.Admin {
			http.Error(w, "administrator access required", 403)
			return
		}
		p, e := s.Store.Printers(r.Context())
		if e != nil {
			respond(w, nil, e)
			return
		}
		targets := []map[string]string{}
		for _, p := range p {
			targets = append(targets, map[string]string{"id": p.ID, "name": p.Name, "kind": "printer"})
		}
		if s.Scans != nil {
			ss, e := s.Scans.List(r.Context())
			if e != nil {
				respond(w, nil, e)
				return
			}
			for _, v := range ss {
				if v.URI != "" {
					targets = append(targets, map[string]string{"id": v.ID, "name": v.Name, "kind": "scanner"})
				}
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, map[string]any{"targets": targets}, nil)
	})
	api.HandleFunc("POST /api/diagnostics/{kind}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.identity(r)
		if !ok || !id.Admin {
			http.Error(w, "administrator access required", 403)
			return
		}
		kind := r.PathValue("kind")
		if kind != "ldap" && kind != "sso" && kind != "smtp" && kind != "printer" && kind != "scanner" {
			http.NotFound(w, r)
			return
		}
		target := r.URL.Query().Get("id")
		if kind != "printer" && kind != "scanner" {
			target = ""
		}
		if len(target) > 128 {
			http.Error(w, "invalid device id", 400)
			return
		}
		if (kind == "printer" || kind == "scanner") && target == "" {
			http.Error(w, "device id required", 400)
			return
		}
		if !s.diagGate.enter(kind + ":" + target) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "Диагностика уже выполняется или запущена слишком часто. Подождите 10 секунд.", 429)
			return
		}
		defer s.diagGate.leave()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		result := diagnostics.New()
		switch kind {
		case "ldap":
			if d, ok := s.Domain.(*auth.Domain); ok {
				result = d.Diagnose(ctx)
			} else {
				result.Add("ldap_unconfigured", "warning", "Домен LDAP не настроен.", "Настройте domain-config и перезапустите службу.")
			}
		case "sso":
			if k, ok := s.SSO.(*auth.Kerberos); ok {
				_, spn, ready := k.Status()
				u, e := url.Parse(s.PublicURL)
				if e != nil || u.Scheme != "https" || "HTTP/"+u.Hostname() != spn {
					result.Add("sso_origin", "error", "HTTPS public-url не соответствует HTTP SPN.", "Проверьте public-url и service_principal в конфигурации домена.")
				} else {
					result.Add("sso_config", "ok", "HTTPS public-url соответствует загруженной конфигурации HTTP SPN.", "")
				}
				if ready {
					result.Add("sso_keytab", "ok", "Keytab загружен; AES-ключ для настроенного SPN найден.", "")
				} else {
					result.Add("sso_keytab_missing", "error", "Keytab не установлен.", "Создайте keytab и загрузите его в разделе «Домен и SSO».")
				}
				result.Add("sso_ticket_unchecked", "warning", "Билет Windows, регистрация SPN в AD и синхронизация времени не проверены.", "Выполните вход с доменного Windows-клиента. Готовность keytab не подтверждает сквозной SSO.")
			} else {
				result.Add("sso_unconfigured", "warning", "Kerberos SSO не настроен.", "Настройте HTTPS, public-url и Kerberos в domain-config, затем перезапустите службу.")
			}
		case "smtp":
			if s.Mail != nil {
				result = s.Mail.Diagnose(ctx)
			} else {
				result.Add("smtp_unavailable", "error", "Сервис SMTP недоступен.", "Проверьте запуск службы и конфигурацию.")
			}
		case "printer":
			p, e := s.Store.Printer(ctx, target)
			if e != nil {
				http.NotFound(w, r)
				return
			}
			switch {
			case strings.HasPrefix(p.URI, "smb://"):
				if s.SMB != nil {
					result = s.SMB.Diagnose(ctx, p)
				} else {
					result.Add("smb_unavailable", "error", "SMB-сервис недоступен.", "Проверьте запуск GoPrint.")
				}
			case strings.HasPrefix(p.URI, "socket://"):
				u, _ := url.Parse(p.URI)
				conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
				if e != nil {
					result.Error("printer_tcp", e)
				} else {
					conn.Close()
					result.Add("printer_tcp", "ok", "TCP-порт принтера доступен; данные не отправлялись.", "")
					result.Add("printer_print_unchecked", "warning", "Готовность принтера и физическая печать не проверены.", "TCP-соединение не подтверждает поддержку формата документа.")
				}
			default:
				_, e := monitoring.Probe(ctx, p, monitoring.Defaults())
				if e != nil {
					result.Error("printer_ipp", e)
				} else {
					result.Add("printer_ipp", "ok", "Принтер ответил на IPP Get-Printer-Attributes.", "")
					result.Add("printer_print_unchecked", "warning", "Приём задания и выход бумаги не проверены.", "Диагностика не отправляет Print-Job.")
				}
			}
			if s.Monitoring != nil {
				m := s.Monitoring.Diagnose(ctx, p)
				for _, v := range m.Steps {
					result.Add(v.Code, v.Status, v.Message, v.Hint)
				}
			}
		case "scanner":
			if s.Scans == nil {
				http.NotFound(w, r)
				return
			}
			v, e := s.Scans.Get(ctx, target)
			if e != nil || v.URI == "" {
				http.NotFound(w, r)
				return
			}
			result = diagnoseScanner(ctx, v.URI)
		}
		result.CheckedAt = time.Now().UTC()
		w.Header().Set("Cache-Control", "no-store")
		respond(w, result, nil)
	})
}
func diagnoseScanner(ctx context.Context, uri string) diagnostics.Report {
	r := diagnostics.New()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(uri, "/")+"/ScannerCapabilities", nil)
	if e != nil {
		r.Add("scanner_uri", "error", "Неверный адрес eSCL.", "Проверьте адрес сканера.")
		return r
	}
	res, e := client.Do(req)
	if e != nil {
		r.Error("scanner_connect", e)
		return r
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		code, msg, hint := "scanner_http", "Сканер вернул неожиданный HTTP-статус.", "Проверьте eSCL/AirScan и журнал устройства."
		switch res.StatusCode {
		case 401, 403:
			code, msg, hint = "scanner_access", "Сканер требует авторизацию или запрещает доступ.", "Проверьте сетевые ограничения и разрешение eSCL на МФУ."
		case 404:
			code, msg, hint = "scanner_path", "Адрес ScannerCapabilities не найден.", "Обычно адрес сканера заканчивается на /eSCL; проверьте документацию МФУ."
		}
		r.Add(code, "error", msg, hint)
		return r
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		r.Add("scanner_response", "error", "Ответ сканера не прочитан или слишком велик.", "Проверьте адрес и ответ eSCL-сервиса.")
		return r
	}
	var root struct{ XMLName xml.Name }
	if xml.Unmarshal(b, &root) != nil || root.XMLName.Local != "ScannerCapabilities" {
		r.Add("scanner_xml", "error", "Ответ не является eSCL ScannerCapabilities.", "Проверьте адрес: веб-страница управления МФУ не является адресом eSCL.")
		return r
	}
	r.Add("scanner_capabilities", "ok", "eSCL ScannerCapabilities доступен; сканирование не запускалось.", "")
	r.Add("scanner_job_unchecked", "warning", "Работа стекла, автоподатчика и получение файла не проверены.", "Выполните отдельное контрольное сканирование.")
	return r
}
