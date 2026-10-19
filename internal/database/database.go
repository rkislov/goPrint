// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	Postgres bool
}
type Tx struct {
	*sql.Tx
	postgres bool
}

func ReadDSN(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 65536 {
		return "", errors.New("PostgreSQL DSN file must be a regular private file (0600), at most 64 KiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", errors.New("empty PostgreSQL DSN")
	}
	return strings.TrimSpace(string(b)), nil
}
func Open(path, dsn, schema string) (*DB, error) {
	if dsn == "" {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
			db.Close()
			return nil, err
		}
		return &DB{DB: db}, nil
	}
	if schema != "goprint_queue" && schema != "goprint_scans" {
		return nil, errors.New("invalid database schema")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL DSN")
	}
	// Remote installations must authenticate the database server, not merely encrypt traffic.
	local := cfg.Host == "localhost" || cfg.Host == "127.0.0.1" || cfg.Host == "::1" || strings.HasPrefix(cfg.Host, "/")
	if !local && (cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName == "") {
		return nil, errors.New("remote PostgreSQL requires sslmode=verify-full")
	}
	if !local {
		for _, fallback := range cfg.Fallbacks {
			if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify || fallback.TLSConfig.ServerName == "" {
				return nil, errors.New("remote PostgreSQL must not allow unverified fallback connections")
			}
		}
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, errors.New("PostgreSQL connection failed (check DSN and server)")
	}
	if _, err = db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{DB: db, Postgres: true}, nil
}
func rewrite(q string, pg bool) string {
	if !pg {
		return q
	}
	q = strings.ReplaceAll(q, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
	q = strings.ReplaceAll(q, "id INTEGER PRIMARY KEY, job_id", "id BIGSERIAL PRIMARY KEY, job_id")
	q = strings.ReplaceAll(q, "size INTEGER NOT NULL", "size BIGINT NOT NULL")
	var b strings.Builder
	n := 0
	quote := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c == '\'' {
			if quote && i+1 < len(q) && q[i+1] == '\'' {
				b.WriteString("''")
				i++
				continue
			}
			quote = !quote
		}
		if c == '?' && !quote {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
func args(a []any) []any {
	out := append([]any(nil), a...)
	for i, v := range out {
		if b, ok := v.(bool); ok {
			if b {
				out[i] = 1
			} else {
				out[i] = 0
			}
		}
	}
	return out
}
func (d *DB) Exec(q string, a ...any) (sql.Result, error) {
	return d.ExecContext(context.Background(), q, a...)
}
func (d *DB) ExecContext(c context.Context, q string, a ...any) (sql.Result, error) {
	return d.DB.ExecContext(c, rewrite(q, d.Postgres), args(a)...)
}
func (d *DB) QueryContext(c context.Context, q string, a ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(c, rewrite(q, d.Postgres), args(a)...)
}
func (d *DB) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	return d.DB.QueryRowContext(c, rewrite(q, d.Postgres), args(a)...)
}
func (d *DB) Begin() (*Tx, error) { return d.BeginTx(context.Background(), nil) }
func (d *DB) BeginTx(c context.Context, o *sql.TxOptions) (*Tx, error) {
	t, e := d.DB.BeginTx(c, o)
	return &Tx{Tx: t, postgres: d.Postgres}, e
}
func (t *Tx) Exec(q string, a ...any) (sql.Result, error) {
	return t.ExecContext(context.Background(), q, a...)
}
func (t *Tx) ExecContext(c context.Context, q string, a ...any) (sql.Result, error) {
	return t.Tx.ExecContext(c, rewrite(q, t.postgres), args(a)...)
}
func (t *Tx) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	return t.Tx.QueryRowContext(c, rewrite(q, t.postgres), args(a)...)
}

// LockClaims serializes the short selection transaction, not document delivery.
func (t *Tx) LockClaims(c context.Context) error {
	if !t.postgres {
		return nil
	}
	_, e := t.Tx.ExecContext(c, `SELECT pg_advisory_xact_lock(7319631)`)
	return e
}

// LockInstance prevents two daemons recovering or delivering the same installation.
func (d *DB) LockInstance(ctx context.Context) (func(), error) {
	if !d.Postgres {
		return func() {}, nil
	}
	c, e := d.DB.Conn(ctx)
	if e != nil {
		return nil, e
	}
	var ok bool
	e = c.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(7319630)`).Scan(&ok)
	if e != nil || !ok {
		c.Close()
		return nil, errors.New("PostgreSQL installation is already in use")
	}
	return func() { c.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7319630)`); c.Close() }, nil
}
