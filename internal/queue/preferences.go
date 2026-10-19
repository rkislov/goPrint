// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package queue

import (
	"context"
	"encoding/json"
	"errors"
)

type PrintOptions struct {
	FollowMe bool   `json:"follow_me,omitempty"`
	Media    string `json:"media,omitempty"`
	Sides    string `json:"sides,omitempty"`
	Color    string `json:"color,omitempty"`
}
type PrinterAccess struct {
	Public bool     `json:"public"`
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

func (s *Store) Access(ctx context.Context, id string) (PrinterAccess, error) {
	var p PrinterAccess
	p.Users = []string{}
	p.Groups = []string{}
	err := s.Setting(ctx, "access:"+id, &p)
	return p, err
}
func (s *Store) SetAccess(ctx context.Context, id string, p PrinterAccess) error {
	if _, err := s.Printer(ctx, id); err != nil {
		return err
	}
	return s.SetSetting(ctx, "access:"+id, p)
}
func (s *Store) Preferences(ctx context.Context, owner, id string) (PrintOptions, error) {
	var p PrintOptions
	err := s.Setting(ctx, "preferences:"+owner+":"+id, &p)
	return p, err
}
func (s *Store) SetPreferences(ctx context.Context, owner, id string, p PrintOptions) error {
	return s.SetSetting(ctx, "preferences:"+owner+":"+id, p)
}
func (s *Store) SubmitOptions(ctx context.Context, pid, owner, title, format string, r interfaceReader, o PrintOptions) (Job, error) {
	return s.submit(ctx, pid, owner, title, format, r, "", o)
}

type interfaceReader interface{ Read([]byte) (int, error) }

func (s *Store) ReserveIPPOptions(ctx context.Context, printer, owner, title, format string, o PrintOptions) (Job, error) {
	return s.reserveIPP(ctx, printer, owner, title, format, o)
}
func encodeOptions(o PrintOptions) string { b, _ := json.Marshal(o); return string(b) }
func decodeOptions(b string) (PrintOptions, error) {
	var o PrintOptions
	err := json.Unmarshal([]byte(b), &o)
	if err != nil {
		return o, errors.New("invalid persisted print options")
	}
	return o, nil
}

func (s *Store) SettingsAtomic(ctx context.Context, values map[string]any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		b, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) ReleaseHeld(ctx context.Context, id, pid, owner string, o PrintOptions) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET printer_id=?,state='queued',detail='released with personal code',updated_at=? WHERE id=? AND owner=? AND state='held-release'`, pid, now(), id, owner)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	o.FollowMe = false
	if _, err = tx.ExecContext(ctx, `UPDATE job_options SET options=? WHERE job_id=?`, encodeOptions(o), id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO events(job_id,state,detail,at) VALUES(?,'queued','Follow Me released; personal code verified',?)`, id, now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) HeldFor(ctx context.Context, owner string) ([]Job, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE owner=? AND state='held-release' ORDER BY created_at,id LIMIT 100`, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
