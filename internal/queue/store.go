// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// Package queue implements the durable print queue. Documents are committed to
// disk before their database records become visible to workers.
package queue

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const MaxDocumentSize int64 = 100 << 20

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("operation conflicts with current state")
var ErrTooLarge = errors.New("document exceeds size limit")

type Printer struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URI     string   `json:"uri"`
	Formats []string `json:"formats"`
	Paused  bool     `json:"paused"`
	PPDID   string   `json:"ppd_id,omitempty"`
}
type Job struct {
	ID        string `json:"id"`
	PrinterID string `json:"printer_id"`
	Owner     string `json:"owner"`
	Title     string `json:"title"`
	Format    string `json:"format"`
	Size      int64  `json:"size"`
	State     string `json:"state"`
	Detail    string `json:"detail"`
	RemoteID  string `json:"remote_id,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}
type Store struct {
	db    *sql.DB
	spool string
}

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	spool := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spool, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(spool, 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "queue.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, spool: spool}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS printers (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, uri TEXT NOT NULL, formats TEXT NOT NULL, paused INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS printer_profiles (printer_id TEXT PRIMARY KEY REFERENCES printers(id), ppd_id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, printer_id TEXT NOT NULL REFERENCES printers(id), owner TEXT NOT NULL, title TEXT NOT NULL, format TEXT NOT NULL, size INTEGER NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', remote_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS jobs_state_created ON jobs(state,created_at);
 CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), state TEXT NOT NULL, detail TEXT NOT NULL, at TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	_, err = db.Exec(`INSERT INTO settings(key,value) VALUES('instance_id',?) ON CONFLICT(key) DO NOTHING`, "\""+ID()+"\"")
	if err != nil {
		db.Close()
		return nil, err
	}
	// The daemon holds an exclusive process lock before opening this store.
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO events(job_id,state,detail,at) SELECT id,'unknown','server stopped during delivery',? FROM jobs WHERE state='processing'`, now())
	if err == nil {
		_, err = tx.Exec(`UPDATE jobs SET state='unknown',detail='server stopped during delivery; verify printer before resubmitting',updated_at=? WHERE state='processing'`, now())
	}
	if err == nil {
		err = tx.Commit()
	} else {
		tx.Rollback()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) AddPrinter(ctx context.Context, p Printer) (Printer, error) {
	p.ID = ID()
	b, _ := json.Marshal(p.Formats)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO printers(id,name,uri,formats,paused) VALUES(?,?,?,?,?)`, p.ID, p.Name, p.URI, string(b), p.Paused)
	if err == nil && p.PPDID != "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO printer_profiles(printer_id,ppd_id) VALUES(?,?)`, p.ID, p.PPDID)
	}
	if err == nil {
		err = tx.Commit()
	}
	return p, err
}
func (s *Store) Printers(ctx context.Context) ([]Printer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,uri,formats,paused,COALESCE((SELECT ppd_id FROM printer_profiles WHERE printer_id=printers.id),'') FROM printers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Printer{}
	for rows.Next() {
		var p Printer
		var formats string
		if err := rows.Scan(&p.ID, &p.Name, &p.URI, &formats, &p.Paused, &p.PPDID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(formats), &p.Formats); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (s *Store) Printer(ctx context.Context, id string) (Printer, error) {
	var p Printer
	var b string
	err := s.db.QueryRowContext(ctx, `SELECT id,name,uri,formats,paused,COALESCE((SELECT ppd_id FROM printer_profiles WHERE printer_id=printers.id),'') FROM printers WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.URI, &b, &p.Paused, &p.PPDID)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal([]byte(b), &p.Formats)
	}
	return p, err
}
func (s *Store) Pause(ctx context.Context, id string, paused bool) error {
	r, err := s.db.ExecContext(ctx, `UPDATE printers SET paused=? WHERE id=?`, paused, id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) Submit(ctx context.Context, printerID, owner, title, format string, r io.Reader) (Job, error) {
	p, err := s.Printer(ctx, printerID)
	if err != nil {
		return Job{}, err
	}
	allowed := false
	for _, f := range p.Formats {
		if f == format {
			allowed = true
		}
	}
	if !allowed {
		return Job{}, fmt.Errorf("format %q is not configured for printer", format)
	}
	j := Job{ID: ID(), PrinterID: printerID, Owner: owner, Title: title, Format: format, State: "queued", CreatedAt: now(), UpdatedAt: now()}
	f, err := os.CreateTemp(s.spool, ".upload-")
	if err != nil {
		return Job{}, err
	}
	temp := f.Name()
	defer os.Remove(temp)
	n, copyErr := io.Copy(f, io.LimitReader(r, MaxDocumentSize+1))
	if copyErr == nil && n > MaxDocumentSize {
		copyErr = ErrTooLarge
	}
	if copyErr == nil && n == 0 {
		copyErr = errors.New("empty document")
	}
	if copyErr == nil {
		copyErr = f.Sync()
	}
	closeErr := f.Close()
	if copyErr != nil {
		return Job{}, copyErr
	}
	if closeErr != nil {
		return Job{}, closeErr
	}
	j.Size = n
	path := s.Document(j.ID)
	if err = os.Rename(temp, path); err != nil {
		return Job{}, err
	}
	// Sync the directory entry before committing metadata, including after power loss.
	d, err := os.Open(s.spool)
	if err == nil {
		err = d.Sync()
		d.Close()
	}
	if err != nil {
		os.Remove(path)
		return Job{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		os.Remove(path)
		return Job{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,printer_id,owner,title,format,size,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, j.ID, j.PrinterID, j.Owner, j.Title, j.Format, j.Size, j.State, j.CreatedAt, j.UpdatedAt)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO events(job_id,state,detail,at) VALUES(?,'queued','accepted',?)`, j.ID, now())
	}
	if err != nil {
		os.Remove(path)
		return Job{}, err
	}
	if err = tx.Commit(); err != nil {
		// Keep the document when a commit result is uncertain. An orphaned
		// file is safer than deleting a document referenced by a durable row.
		return Job{}, err
	}
	return j, nil
}
func (s *Store) Document(id string) string { return filepath.Join(s.spool, id+".data") }

const jobColumns = `id,printer_id,owner,title,format,size,state,detail,remote_id,created_at,updated_at`

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.PrinterID, &j.Owner, &j.Title, &j.Format, &j.Size, &j.State, &j.Detail, &j.RemoteID, &j.CreatedAt, &j.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return j, err
}
func (s *Store) Job(ctx context.Context, id string) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id=?`, id))
}
func (s *Store) Jobs(ctx context.Context) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) Claim(ctx context.Context) (Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	j, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE state='queued' AND printer_id IN (SELECT id FROM printers WHERE paused=0) AND NOT EXISTS(SELECT 1 FROM jobs active WHERE active.printer_id=jobs.printer_id AND active.state='processing') ORDER BY created_at,id LIMIT 1`))
	if err != nil {
		return Job{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE jobs SET state='processing',updated_at=? WHERE id=?`, now(), j.ID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO events(job_id,state,detail,at) VALUES(?,'processing','delivery started',?)`, j.ID, now())
	}
	if err == nil {
		err = tx.Commit()
	}
	j.State = "processing"
	return j, err
}
func (s *Store) Finish(ctx context.Context, id, state, detail, remote string) error {
	return s.transition(ctx, id, "processing", state, detail, remote)
}
func (s *Store) Cancel(ctx context.Context, id string) error {
	return s.transition(ctx, id, "queued", "canceled", "canceled by administrator", "")
}
func (s *Store) transition(ctx context.Context, id, from, to, detail, remote string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE jobs SET state=?,detail=?,remote_id=?,updated_at=? WHERE id=? AND state=?`, to, detail, remote, now(), id, from)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		var exists int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM jobs WHERE id=?`, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(job_id,state,detail,at) VALUES(?,?,?,?)`, id, to, detail, now())
	if err != nil {
		return err
	}
	return tx.Commit()
}

type Event struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	At     string `json:"at"`
}

func (s *Store) Events(ctx context.Context, id string) ([]Event, error) {
	if _, err := s.Job(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT state,detail,at FROM events WHERE job_id=? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.State, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
