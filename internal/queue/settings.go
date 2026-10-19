// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func (s *Store) Setting(ctx context.Context, key string, value any) error {
	var b string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(b), value)
}
func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}

type AuditEvent struct {
	InstanceID string `json:"instance_id"`
	ID         int64  `json:"event_id"`
	JobID      string `json:"job_id"`
	State      string `json:"state"`
	Detail     string `json:"detail"`
	At         string `json:"timestamp"`
	Owner      string `json:"user"`
	PrinterID  string `json:"printer_id"`
	Printer    string `json:"printer"`
	Format     string `json:"format"`
	Size       int64  `json:"bytes"`
}

func (s *Store) AuditEvents(ctx context.Context, after int64) ([]AuditEvent, error) {
	var instance string
	if err := s.Setting(ctx, "instance_id", &instance); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,e.job_id,e.state,e.detail,e.at,j.owner,j.printer_id,p.name,j.format,j.size FROM events e JOIN jobs j ON e.job_id=j.id JOIN printers p ON j.printer_id=p.id WHERE e.id>? ORDER BY e.id LIMIT 100`, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.JobID, &e.State, &e.Detail, &e.At, &e.Owner, &e.PrinterID, &e.Printer, &e.Format, &e.Size); err != nil {
			return nil, err
		}
		e.InstanceID = instance
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) RecordEvent(ctx context.Context, id, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO events(job_id,state,detail,at) SELECT id,state,?,? FROM jobs WHERE id=?`, detail, now(), id)
	return err
}
