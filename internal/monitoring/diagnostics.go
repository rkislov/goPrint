// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package monitoring

import (
	"context"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"github.com/rkislov/goPrint/internal/queue"
)

// Diagnose reads counters without saving snapshots or triggering notifications.
func (s *Service) Diagnose(ctx context.Context, p queue.Printer) diagnostics.Report {
	r := diagnostics.New()
	c, e := s.config(ctx, p.ID)
	if e != nil {
		r.Add("monitor_config", "error", "Не удалось прочитать настройки мониторинга.", "Проверьте БД и monitoring.key.")
		return r
	}
	if !c.Enabled {
		r.Add("monitor_disabled", "warning", "Мониторинг устройства выключен.", "Для проверки счётчиков настройте IPP/SNMP в разделе «Мониторинг».")
		return r
	}
	_, e = Probe(ctx, p, c)
	if e != nil {
		r.Error("monitor_"+c.Method, e)
		if c.Method == "snmp" && r.Steps[len(r.Steps)-1].Code == "monitor_snmp_protocol" {
			r.Steps[len(r.Steps)-1].Message = "SNMP не вернул корректный ответ."
			r.Steps[len(r.Steps)-1].Hint = "Проверьте UDP-порт, версию SNMP, community или имя SNMPv3, алгоритмы и пароли auth/priv."
		}
		return r
	}
	r.Add("monitor_reply", "ok", "Устройство ответило на запрос мониторинга.", "")
	return r
}
