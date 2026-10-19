// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scanning

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Delivery struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

func (s *Service) Undelivered(ctx context.Context) ([]Job, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+columns+` FROM scans WHERE state='completed' AND NOT EXISTS(SELECT 1 FROM scan_delivery d WHERE d.id=scans.id) ORDER BY created_at,id LIMIT 100`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, e := scan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Service) MailStatus(ctx context.Context, id string) (Delivery, error) {
	d := Delivery{ID: id}
	e := s.db.QueryRowContext(ctx, `SELECT state,target,detail FROM scan_delivery WHERE id=?`, id).Scan(&d.State, &d.Target, &d.Detail)
	if errors.Is(e, sql.ErrNoRows) {
		return d, nil
	}
	return d, e
}
func (s *Service) SaveMail(ctx context.Context, d Delivery) error {
	_, e := s.db.ExecContext(ctx, `INSERT INTO scan_delivery(id,state,target,detail,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,target=excluded.target,detail=excluded.detail,updated_at=excluded.updated_at`, d.ID, d.State, d.Target, d.Detail, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
