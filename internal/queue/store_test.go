package queue

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func setup(t *testing.T) (*Store, Printer) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p, err := s.AddPrinter(context.Background(), Printer{Name: "test", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}
func submit(t *testing.T, s *Store, p Printer) Job {
	t.Helper()
	j, err := s.Submit(context.Background(), p.ID, "test-user", "document", "application/pdf", strings.NewReader("%PDF-test"))
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func TestRecoveryAndDurableSpool(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.AddPrinter(ctx, Printer{Name: "printer", URI: "socket://localhost:9100", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	active := submit(t, s, p)
	pending := submit(t, s, p)
	claimed, err := s.Claim(ctx)
	if err != nil || claimed.ID != active.ID {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j, err := s.Job(ctx, active.ID)
	if err != nil || j.State != "unknown" {
		t.Fatalf("recovered job: %+v %v", j, err)
	}
	j, err = s.Claim(ctx)
	if err != nil || j.ID != pending.ID {
		t.Fatalf("queued job did not survive restart: %+v %v", j, err)
	}
	b, err := os.ReadFile(s.Document(j.ID))
	if err != nil || string(b) != "%PDF-test" {
		t.Fatalf("spool: %q %v", b, err)
	}
	events, err := s.Events(ctx, active.ID)
	if err != nil || len(events) != 3 || events[2].State != "unknown" {
		t.Fatalf("audit: %+v %v", events, err)
	}
}
func TestClaimsSerializePerPrinter(t *testing.T) {
	s, p := setup(t)
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		submit(t, s, p)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Claim(ctx)
			if err == nil {
				mu.Lock()
				claims++
				mu.Unlock()
			} else if !errors.Is(err, ErrNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if claims != 1 {
		t.Fatalf("got %d simultaneous claims for one printer", claims)
	}
}
func TestPauseCancelAndTransitions(t *testing.T) {
	s, p := setup(t)
	ctx := context.Background()
	j := submit(t, s, p)
	if err := s.Pause(ctx, p.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("paused claim: %v", err)
	}
	if err := s.Cancel(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(ctx, j.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel terminal job: %v", err)
	}
	if err := s.Pause(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	j = submit(t, s, p)
	if _, err := s.Claim(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(ctx, j.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel processing job: %v", err)
	}
	if err := s.Finish(ctx, j.ID, "submitted", "accepted", "42"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, j.ID, "failed", "late result", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("overwrote terminal result: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestRejectedUploadsLeaveNoSpool(t *testing.T) {
	s, p := setup(t)
	ctx := context.Background()
	for _, r := range []io.Reader{strings.NewReader(""), io.LimitReader(zeroReader{}, MaxDocumentSize+1), &brokenReader{}} {
		if _, err := s.Submit(ctx, p.ID, "test", "title", "application/pdf", r); err == nil {
			t.Fatal("invalid upload accepted")
		}
	}
	files, err := os.ReadDir(s.spool)
	if err != nil || len(files) != 0 {
		t.Fatalf("spool leak: %v %v", files, err)
	}
	jobs, err := s.Jobs(ctx)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("rejected jobs persisted: %v %v", jobs, err)
	}
}

type brokenReader struct{}

func (*brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
