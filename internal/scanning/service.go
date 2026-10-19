// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scanning

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/goPrint/internal/database"
	"github.com/rkislov/goPrint/internal/queue"
)

type Scanner struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URI         string `json:"uri"`
	DeviceToken string `json:"device_token,omitempty"`
}
type Job struct {
	Owner     string `json:"owner"`
	ID        string `json:"id"`
	ScannerID string `json:"scanner_id"`
	Title     string `json:"title"`
	Source    string `json:"source"`
	State     string `json:"state"`
	Detail    string `json:"detail"`
	Format    string `json:"format"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}
type Options struct {
	Owner      string `json:"-"`
	ScannerID  string `json:"scanner_id"`
	Source     string `json:"source"`
	Resolution int    `json:"resolution"`
	Format     string `json:"format"`
}
type Service struct {
	db      *database.DB
	dir     string
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	active  map[string]bool
	closing bool
}

func Open(dir string) (*Service, error) { return OpenDatabase(dir, "") }

func OpenDatabase(dir, dsn string) (*Service, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := database.Open(filepath.Join(dir, "scans.db"), dsn, "goprint_scans")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(Schema)
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`UPDATE scans SET state='failed',detail='server stopped during scan; check device before restarting' WHERE state='processing'`); err != nil {
		db.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Service{db: db, dir: dir, ctx: ctx, cancel: cancel, active: map[string]bool{}}, nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
	return s.db.Close()
}
func (s *Service) Add(ctx context.Context, name, uri string) (Scanner, error) {
	if strings.TrimSpace(name) == "" || len(name) > 128 {
		return Scanner{}, errors.New("укажите название сканера")
	}
	u, err := url.Parse(uri)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Scanner{}, errors.New("нужен HTTP(S)-адрес eSCL без пароля и параметров")
	}
	uri = strings.TrimRight(uri, "/")
	if !strings.HasSuffix(u.Path, "/eSCL") {
		return Scanner{}, errors.New("адрес должен оканчиваться на /eSCL")
	}
	token := queue.ID() + queue.ID()
	hash := sha256.Sum256([]byte(token))
	scanner := Scanner{ID: queue.ID(), Name: name, URI: uri, DeviceToken: token}
	_, err = s.db.ExecContext(ctx, `INSERT INTO scanners VALUES(?,?,?,?)`, scanner.ID, name, uri, hex.EncodeToString(hash[:]))
	return scanner, err
}
func (s *Service) List(ctx context.Context) ([]Scanner, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,uri FROM scanners ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scanner{}
	for rows.Next() {
		var v Scanner
		if err = rows.Scan(&v.ID, &v.Name, &v.URI); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Service) Get(ctx context.Context, id string) (Scanner, error) {
	var v Scanner
	err := s.db.QueryRowContext(ctx, `SELECT id,name,uri FROM scanners WHERE id=?`, id).Scan(&v.ID, &v.Name, &v.URI)
	if errors.Is(err, sql.ErrNoRows) {
		err = queue.ErrNotFound
	}
	return v, err
}
func (s *Service) Authenticate(ctx context.Context, id, token string) bool {
	var expected string
	if err := s.db.QueryRowContext(ctx, `SELECT token_hash FROM scanners WHERE id=?`, id).Scan(&expected); err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hex.EncodeToString(sum[:]))) == 1
}

const columns = `id,scanner_id,title,source,state,detail,format,size,created_at,COALESCE((SELECT owner FROM scan_owners WHERE scan_owners.id=scans.id),'local-admin')`

func scan(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.ScannerID, &j.Title, &j.Source, &j.State, &j.Detail, &j.Format, &j.Size, &j.CreatedAt, &j.Owner)
	if errors.Is(err, sql.ErrNoRows) {
		err = queue.ErrNotFound
	}
	return j, err
}
func (s *Service) Jobs(ctx context.Context) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM scans ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Service) Job(ctx context.Context, id string) (Job, error) {
	return scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM scans WHERE id=?`, id))
}
func (s *Service) Path(id string) string { return filepath.Join(s.dir, id+".data") }
func (s *Service) insert(ctx context.Context, j Job) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?)`, j.ID, j.ScannerID, j.Title, j.Source, j.State, j.Detail, j.Format, j.Size, j.CreatedAt)
	if err != nil {
		return err
	}
	if j.Owner == "" {
		j.Owner = "local-admin"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_owners VALUES(?,?)`, j.ID, j.Owner)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) Receive(ctx context.Context, id, title string, r io.Reader) (Job, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return Job{}, err
	}
	if len(title) > 255 || strings.ContainsAny(title, "\r\n\x00") {
		return Job{}, errors.New("invalid file name")
	}
	j := Job{ID: queue.ID(), ScannerID: id, Title: title, Source: "device", State: "completed", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	f, err := os.CreateTemp(s.dir, ".upload-")
	if err != nil {
		return j, err
	}
	defer os.Remove(f.Name())
	j.Size, err = io.Copy(f, io.LimitReader(r, queue.MaxDocumentSize+1))
	if err == nil && j.Size > queue.MaxDocumentSize {
		err = queue.ErrTooLarge
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return j, err
	}
	if closeErr != nil {
		return j, closeErr
	}
	j.Format, err = detect(f.Name())
	if err != nil {
		return j, err
	}
	if err = os.Rename(f.Name(), s.Path(j.ID)); err != nil {
		return j, err
	}
	if err = syncDir(s.dir); err != nil {
		return j, err
	}
	err = s.insert(ctx, j)
	return j, err
}
func detect(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b [8]byte
	n, _ := f.Read(b[:])
	if n >= 5 && string(b[:5]) == "%PDF-" {
		return "application/pdf", nil
	}
	if n >= 3 && b[0] == 255 && b[1] == 216 && b[2] == 255 {
		return "image/jpeg", nil
	}
	if n == 8 && string(b[:]) == "\x89PNG\r\n\x1a\n" {
		return "image/png", nil
	}
	return "", errors.New("supported scan files: PDF, JPEG, PNG")
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *Service) Start(ctx context.Context, o Options) (Job, error) {
	scanner, err := s.Get(ctx, o.ScannerID)
	if err != nil {
		return Job{}, err
	}
	if o.Source != "Platen" && o.Source != "Feeder" {
		return Job{}, errors.New("источник: Platen или Feeder")
	}
	if o.Resolution != 150 && o.Resolution != 300 && o.Resolution != 600 {
		return Job{}, errors.New("разрешение: 150, 300 или 600 dpi")
	}
	if o.Format != "image/jpeg" && o.Format != "application/pdf" {
		return Job{}, errors.New("формат: image/jpeg или application/pdf")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.active[scanner.ID] || len(s.active) >= 4 {
		return Job{}, queue.ErrConflict
	}
	j := Job{Owner: o.Owner, ID: queue.ID(), ScannerID: scanner.ID, Title: scanner.Name + " · сканирование", Source: "browser", State: "processing", Format: o.Format, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err = s.insert(ctx, j); err != nil {
		return Job{}, err
	}
	s.active[scanner.ID] = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); delete(s.active, scanner.ID); s.mu.Unlock() }()
		scanCtx, cancel := context.WithTimeout(s.ctx, 3*time.Minute)
		defer cancel()
		format, size, err := s.perform(scanCtx, scanner, j, o)
		state, detail := "completed", ""
		if err != nil {
			state = "failed"
			detail = err.Error()
		}
		saveCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, dbErr := s.db.ExecContext(saveCtx, `UPDATE scans SET state=?,detail=?,format=?,size=? WHERE id=?`, state, detail, format, size, j.ID); dbErr != nil {
			fmt.Fprintln(os.Stderr, "persist scan result:", dbErr)
		}
	}()
	return j, nil
}

func (s *Service) JobsFor(ctx context.Context, owner string, admin bool) ([]Job, error) {
	if admin {
		return s.Jobs(ctx)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM scans WHERE COALESCE((SELECT owner FROM scan_owners WHERE scan_owners.id=scans.id),'local-admin')=? ORDER BY created_at DESC LIMIT 200`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Schema is shared by fresh installations and the offline migration tool.
const Schema = `
 CREATE TABLE IF NOT EXISTS scanners(id TEXT PRIMARY KEY,name TEXT NOT NULL,uri TEXT NOT NULL,token_hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS scan_owners(id TEXT PRIMARY KEY,owner TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,scanner_id TEXT NOT NULL REFERENCES scanners(id),title TEXT NOT NULL,source TEXT NOT NULL,state TEXT NOT NULL,detail TEXT NOT NULL,format TEXT NOT NULL,size INTEGER NOT NULL,created_at TEXT NOT NULL);`
