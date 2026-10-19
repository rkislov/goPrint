// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

package queue

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRunnerDrainsInFlightOnShutdown(t *testing.T) {
	s, p := setup(t)
	j := submit(t, s, p)
	claims, stop := context.WithCancel(context.Background())
	defer stop()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		s.Run(claims, context.Background(), 2, func(ctx context.Context, p Printer, j Job, path string) DeliveryResult {
			close(started)
			<-release
			return DeliveryResult{State: "submitted", Detail: "accepted"}
		})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	next := submit(t, s, p)
	stop()
	select {
	case <-done:
		t.Fatal("shutdown abandoned an in-flight job")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not drain")
	}
	got, err := s.Job(context.Background(), j.ID)
	if err != nil || got.State != "submitted" {
		t.Fatalf("in-flight result: %+v %v", got, err)
	}
	got, err = s.Job(context.Background(), next.ID)
	if err != nil || got.State != "queued" {
		t.Fatalf("pending job: %+v %v", got, err)
	}
}

func TestRunnerProcessesIndependentPrintersConcurrently(t *testing.T) {
	s, p := setup(t)
	ctx := context.Background()
	p2, err := s.AddPrinter(ctx, Printer{Name: "second", URI: "socket://localhost:9101", Formats: []string{"application/pdf"}})
	if err != nil {
		t.Fatal(err)
	}
	submit(t, s, p)
	submit(t, s, p2)
	claims, stop := context.WithCancel(ctx)
	defer stop()
	started := make(chan string, 2)
	release := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { stop(); once.Do(func() { close(release) }); <-done })
	go func() {
		s.Run(claims, ctx, 2, func(_ context.Context, p Printer, _ Job, _ string) DeliveryResult {
			started <- p.ID
			<-release
			return DeliveryResult{State: "submitted"}
		})
		close(done)
	}()
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-started:
			seen[id] = true
		case <-time.After(5 * time.Second):
			t.Fatal("independent printer was blocked")
		}
	}
	if len(seen) != 2 {
		t.Fatalf("expected independent printers, got %v", seen)
	}
	stop()
	once.Do(func() { close(release) })
}
