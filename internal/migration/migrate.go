// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rkislov/goPrint/internal/database"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
)

type Table struct {
	Name   string `json:"table"`
	Rows   int    `json:"rows"`
	SHA256 string `json:"sha256"`
}
type Report struct {
	Applied bool    `json:"applied"`
	Tables  []Table `json:"tables"`
}

// Run requires the daemon's local process lock and a globally unused PostgreSQL target.
// Both schemas and all rows are committed together; dry runs always roll back.
func Run(ctx context.Context, dir, dsn string, execute bool) (report Report, err error) {
	if dsn == "" {
		return report, errors.New("PostgreSQL DSN is required")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return report, errors.New("stop goprintd before migration")
	}
	db, err := database.Open("", dsn, "goprint_queue")
	if err != nil {
		return report, err
	}
	defer db.Close()
	unlock, err := db.LockInstance(ctx)
	if err != nil {
		return report, err
	}
	defer unlock()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	specs := []struct {
		schema, path, ddl string
		tables            []string
	}{
		{"goprint_queue", filepath.Join(dir, "queue.db"), queue.Schema, []string{"settings", "printers", "printer_profiles", "jobs", "job_options", "ipp_jobs", "events"}},
		{"goprint_scans", filepath.Join(dir, "scans", "scans.db"), scanning.Schema, []string{"scanners", "scan_owners", "scans"}},
	}
	// An existing schema, even with empty tables, may belong to another installation.
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('goprint_queue','goprint_scans')`).Scan(&count); err != nil {
		return report, err
	}
	if count != 0 {
		return report, errors.New("target schemas must contain no tables; migration never overwrites an installation")
	}
	for _, spec := range specs {
		if _, err = tx.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+spec.schema+`; SET LOCAL search_path TO `+spec.schema+`;`+spec.ddl); err != nil {
			return report, err
		}
		if _, err = os.Stat(spec.path); os.IsNotExist(err) && spec.schema == "goprint_scans" {
			continue
		} else if err != nil {
			return report, err
		}
		// Read-only SQLite transaction gives one consistent snapshot, including WAL.
		src, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(spec.path), RawQuery: "mode=ro"}).String())
		if err != nil {
			return report, err
		}
		src.SetMaxOpenConns(1)
		sourceTx, err := src.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			src.Close()
			return report, err
		}
		copyErr := func() error {
			defer src.Close()
			defer sourceTx.Rollback()
			inventory, err := sourceTx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
			if err != nil {
				return err
			}
			known := map[string]bool{}
			for _, name := range spec.tables {
				known[name] = true
			}
			for inventory.Next() {
				var name string
				if err = inventory.Scan(&name); err != nil {
					inventory.Close()
					return err
				}
				if !known[name] {
					inventory.Close()
					return fmt.Errorf("unsupported source table %s; use a migration tool matching the source version", name)
				}
			}
			err = inventory.Err()
			inventory.Close()
			if err != nil {
				return err
			}
			for _, name := range spec.tables {
				var exists int
				if err := sourceTx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&exists); err != nil {
					return err
				}
				if exists == 0 {
					if name == "jobs" || name == "printers" || name == "settings" || name == "events" || name == "scanners" || name == "scans" {
						return fmt.Errorf("source is missing %s", name)
					}
					continue
				}
				rows, err := sourceTx.QueryContext(ctx, `SELECT * FROM `+name+` ORDER BY 1`)
				if err != nil {
					return err
				}
				cols, err := rows.Columns()
				if err != nil {
					rows.Close()
					return err
				}
				quoted := make([]string, len(cols))
				for i, c := range cols {
					quoted[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `"`
				}
				h := sha256.New()
				n := 0
				for rows.Next() {
					vals := make([]any, len(cols))
					ptr := make([]any, len(cols))
					for i := range vals {
						ptr[i] = &vals[i]
					}
					if err = rows.Scan(ptr...); err != nil {
						rows.Close()
						return err
					}
					for i, v := range vals {
						if b, ok := v.([]byte); ok {
							vals[i] = string(b)
						}
					}
					b, _ := json.Marshal(vals)
					h.Write(b)
					h.Write([]byte{'\n'})
					if _, err = tx.ExecContext(ctx, `INSERT INTO `+name+` (`+strings.Join(quoted, ",")+`) VALUES (`+strings.TrimRight(strings.Repeat("?,", len(cols)), ",")+`)`, vals...); err != nil {
						rows.Close()
						return fmt.Errorf("copy %s failed: %w", name, err)
					}
					n++
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
				target, err := tx.Tx.QueryContext(ctx, `SELECT `+strings.Join(quoted, ",")+` FROM `+name+` ORDER BY 1`)
				if err != nil {
					return err
				}
				th := sha256.New()
				tn := 0
				for target.Next() {
					vals := make([]any, len(cols))
					ptr := make([]any, len(cols))
					for i := range vals {
						ptr[i] = &vals[i]
					}
					if err = target.Scan(ptr...); err != nil {
						target.Close()
						return err
					}
					for i, v := range vals {
						if b, ok := v.([]byte); ok {
							vals[i] = string(b)
						}
					}
					b, _ := json.Marshal(vals)
					th.Write(b)
					th.Write([]byte{'\n'})
					tn++
				}
				err = target.Err()
				target.Close()
				if err != nil {
					return err
				}
				digest := hex.EncodeToString(h.Sum(nil))
				if tn != n || digest != hex.EncodeToString(th.Sum(nil)) {
					return fmt.Errorf("verification failed for %s", name)
				}
				report.Tables = append(report.Tables, Table{spec.schema + "." + name, n, digest})
			}
			return nil
		}()
		if copyErr != nil {
			return report, copyErr
		}
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL search_path TO goprint_queue; SELECT setval(pg_get_serial_sequence('ipp_jobs','id'),COALESCE((SELECT MAX(id) FROM ipp_jobs),0)+1,false); SELECT setval(pg_get_serial_sequence('events','id'),COALESCE((SELECT MAX(id) FROM events),0)+1,false);`); err != nil {
		return report, err
	}
	if execute {
		err = tx.Commit()
		report.Applied = err == nil
	}
	return report, err
}
