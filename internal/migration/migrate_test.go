// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package migration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rkislov/goPrint/internal/database"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
)

func TestPostgresMigrationAndQueue(t *testing.T) {
	dsn := os.Getenv("GOPRINT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GOPRINT_TEST_POSTGRES_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	db, err := database.Open("", dsn, "goprint_queue")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer db.Exec(`DROP SCHEMA IF EXISTS goprint_queue CASCADE; DROP SCHEMA IF EXISTS goprint_scans CASCADE`)
	var existing int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('goprint_queue','goprint_scans')`).Scan(&existing); err != nil || existing != 0 {
		t.Fatal("test requires empty disposable schemas", err)
	}
	dir := t.TempDir()
	src, err := queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := src.AddPrinter(ctx, queue.Printer{Name: "Migration printer", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := src.Submit(ctx, p.ID, "alice@example.test", "Document", "application/pdf", strings.NewReader("%PDF-test"))
	if err != nil {
		t.Fatal(err)
	}
	ipp, err := src.IPPNumber(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = src.SetSetting(ctx, "access:"+p.ID, map[string]any{"users": []string{"alice@example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err = src.SetSetting(ctx, "migration-secret-test", map[string]string{"ciphertext": "preserve-exactly"}); err != nil {
		t.Fatal(err)
	}
	src.Close()
	scans, err := scanning.Open(filepath.Join(dir, "scans"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = scans.Add(ctx, "Scanner", "http://127.0.0.1/eSCL")
	if err != nil {
		t.Fatal(err)
	}
	scans.Close()
	// A broken source reference must roll back both schemas, not leave a partial copy.
	raw, err := sql.Open("sqlite", filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE jobs SET printer_id='missing' WHERE id=?`, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = Run(ctx, dir, dsn, true); err == nil {
		t.Fatal("accepted broken source foreign key")
	}
	var partial int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('goprint_queue','goprint_scans')`).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("failed migration left tables", partial, err)
	}
	if _, err = raw.Exec(`UPDATE jobs SET printer_id=? WHERE id=?`, p.ID, j.ID); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	report, err := Run(ctx, dir, dsn, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Applied || len(report.Tables) != 10 {
		t.Fatalf("dry run report: %+v", report)
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('goprint_queue','goprint_scans')`).Scan(&n); err != nil || n != 0 {
		t.Fatal("dry run persisted tables", n, err)
	}
	report, err = Run(ctx, dir, dsn, true)
	if err != nil || !report.Applied {
		t.Fatal(report, err)
	}
	if _, err = Run(ctx, dir, dsn, true); err == nil {
		t.Fatal("overwrote existing target")
	}
	target, err := queue.OpenDatabase(dir, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if other, e := queue.OpenDatabase(t.TempDir(), dsn); e == nil {
		other.Close()
		t.Fatal("second instance acquired same PostgreSQL installation")
	}
	got, err := target.Job(ctx, j.ID)
	if err != nil || got.Owner != j.Owner {
		t.Fatal("lost job/options/owner", got, err)
	}
	id, err := target.IPPNumber(ctx, j.ID)
	if err != nil || id != ipp {
		t.Fatal("IPP id changed", id, err)
	}
	var access struct {
		Users []string `json:"users"`
	}
	err = target.Setting(ctx, "access:"+p.ID, &access)
	if err != nil || len(access.Users) != 1 {
		t.Fatal("ACL missing", access, err)
	}
	var wg sync.WaitGroup
	claimed := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, e := target.Claim(ctx)
			if e == nil {
				claimed <- job.ID
			} else if !errors.Is(e, queue.ErrNotFound) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	close(claimed)
	count := 0
	for range claimed {
		count++
	}
	if count != 1 {
		t.Fatalf("same printer claimed %d times", count)
	}
	if err = target.Finish(ctx, j.ID, "completed", "ok", "remote-1"); err != nil {
		t.Fatal(err)
	}
	next, err := target.Submit(ctx, p.ID, "alice@example.test", "Next", "application/pdf", strings.NewReader("%PDF-next"))
	if err != nil {
		t.Fatal(err)
	}
	nextID, err := target.IPPNumber(ctx, next.ID)
	if err != nil || nextID <= ipp {
		t.Fatal("sequence not advanced", nextID, err)
	}
	pgScans, err := scanning.OpenDatabase(filepath.Join(dir, "scans"), dsn)
	if err != nil {
		t.Fatal(err)
	}
	pgScans.Close()
	// The original SQLite database remains available for rollback before production use.
	old, err := queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldJob, err := old.Job(ctx, j.ID)
	if err != nil || oldJob.State != "queued" {
		t.Fatal("source was modified", oldJob, err)
	}
}
