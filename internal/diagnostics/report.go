// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package diagnostics contains safe, structured administrator check results.
package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

type Step struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}
type Report struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
	Steps     []Step    `json:"steps"`
}

func New() Report { return Report{Status: "ok", CheckedAt: time.Now().UTC(), Steps: []Step{}} }
func (r *Report) Add(code, status, message, hint string) {
	r.Steps = append(r.Steps, Step{code, status, message, hint})
	if status == "error" || status == "warning" && r.Status == "ok" {
		r.Status = status
	}
}

// Error deliberately never includes err.Error(): backend replies may contain secrets.
func (r *Report) Error(stage string, err error) {
	code, message, hint := "protocol", "Сервис ответил ошибкой протокола.", "Проверьте тип сервиса, порт и его журнал на сервере."
	var status HTTPStatus
	if errors.As(err, &status) {
		code, message, hint = "http_status", "Сервис вернул неожиданный HTTP-статус.", "Проверьте протокол, адрес и журнал устройства."
		switch status.Code {
		case 401, 403:
			code, message, hint = "access", "Устройство требует авторизацию или запрещает доступ.", "Проверьте сетевые права и настройки аутентификации устройства."
		case 404:
			code, message, hint = "path", "Адрес сервиса не найден (HTTP 404).", "Проверьте путь IPP/eSCL: адрес веб-панели не является адресом печати или сканирования."
		case 503:
			code, message, hint = "unavailable", "Сервис временно недоступен (HTTP 503).", "Проверьте состояние устройства и повторите позже."
		}
		r.Add(stage+"_"+code, "error", message, hint)
		return
	}
	var dns *net.DNSError
	var cert x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		code, message, hint = "canceled", "Проверка отменена.", "Запустите проверку повторно при необходимости."
	case errors.As(err, &dns):
		code, message, hint = "dns", "Имя сервера не разрешается через DNS.", "Проверьте имя и DNS-настройки сервера GoPrint."
	case errors.As(err, &cert):
		code, message, hint = "tls_ca", "Сертификат подписан недоверенным центром.", "Установите доверенную цепочку CA; не отключайте проверку TLS."
	case errors.As(err, &host):
		code, message, hint = "tls_name", "Имя сервера не совпадает с сертификатом.", "Используйте DNS-имя из сертификата или перевыпустите сертификат."
	case errors.As(err, &invalid):
		code, message, hint = "tls_certificate", "Сертификат просрочен или недействителен.", "Проверьте сроки сертификата, цепочку и время на сервере."
	case errors.As(err, &verify):
		code, message, hint = "tls_verify", "Сертификат не прошёл проверку.", "Проверьте DNS-имя, цепочку CA и срок действия сертификата."
	case errors.Is(err, syscall.ECONNREFUSED):
		code, message, hint = "refused", "Сервер отклонил TCP-соединение.", "Проверьте порт, запуск службы и межсетевой экран."
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		code, message, hint = "timeout", "Истекло время ожидания.", "Проверьте маршрутизацию, межсетевой экран и доступность сервера."
	}
	r.Add(stage+"_"+code, "error", message, hint)
}

type HTTPStatus struct{ Code int }

func (e HTTPStatus) Error() string { return "HTTP " + strconv.Itoa(e.Code) }
