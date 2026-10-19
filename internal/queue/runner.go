package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type DeliveryResult struct{ State, Detail, RemoteID string }
type DeliverFunc func(context.Context, Printer, Job, string) DeliveryResult

// Run starts a bounded worker pool. Claim serializes jobs per printer.
// Canceling ctx stops new claims; in-flight jobs receive a bounded grace period
// controlled by their delivery timeout and the caller's force context.
func (s *Store) Run(ctx, deliveryCtx context.Context, workers int, deliver DeliverFunc) {
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				j, err := s.Claim(ctx)
				if err != nil {
					if !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
						slog.Error("claim job", "error", err)
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(200 * time.Millisecond):
						continue
					}
				}
				p, err := s.Printer(deliveryCtx, j.PrinterID)
				result := DeliveryResult{State: "failed", Detail: "cannot load printer"}
				if err == nil {
					jobCtx, cancel := context.WithTimeout(deliveryCtx, 2*time.Minute)
					result = deliver(jobCtx, p, j, s.Document(j.ID))
					cancel()
				}
				// Persist the outcome even when shutdown has canceled delivery.
				saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err = s.Finish(saveCtx, j.ID, result.State, result.Detail, result.RemoteID)
				cancel()
				if err != nil {
					slog.Error("persist delivery result", "job", j.ID, "error", err)
				}
			}
		}()
	}
	wg.Wait()
}
