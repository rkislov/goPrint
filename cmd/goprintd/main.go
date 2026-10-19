// goprintd serves the local administrator API and processes durable print jobs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("goprintd stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	data := flag.String("data", "./var/goprint", "private data directory")
	listen := flag.String("listen", "127.0.0.1:8631", "loopback HTTP address")
	workers := flag.Int("workers", 4, "delivery workers (1–50)")
	flag.Parse()
	token := os.Getenv("GOPRINT_TOKEN")
	if len(token) < 32 {
		return errors.New("GOPRINT_TOKEN must contain at least 32 bytes")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("first version requires an explicit loopback listen address")
	}
	if *workers < 1 || *workers > 50 {
		return errors.New("workers must be between 1 and 50")
	}
	if err = os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	// Linux/macOS advisory lock prevents another daemon from recovering live jobs.
	lock, err := os.OpenFile(filepath.Join(*data, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("data directory is already in use: %w", err)
	}
	store, err := queue.Open(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	api := (&server.Server{Store: store, Token: token}).Handler()
	srv := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stopClaims, cancelClaims := context.WithCancel(context.Background())
	defer cancelClaims()
	delivery, cancelDelivery := context.WithCancel(context.Background())
	defer cancelDelivery()
	workersDone := make(chan struct{})
	go func() {
		store.Run(stopClaims, delivery, *workers, func(ctx context.Context, p queue.Printer, j queue.Job, path string) queue.DeliveryResult {
			r := backend.Deliver(ctx, p, j, path)
			return queue.DeliveryResult{State: r.State, Detail: r.Detail, RemoteID: r.RemoteID}
		})
		close(workersDone)
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(listener) }()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	slog.Info("GoPrint listening", "address", listener.Addr().String(), "data", *data)
	select {
	case <-signals:
	case err = <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancelClaims()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := srv.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		srv.Close()
	}
	slog.Info("waiting for in-flight deliveries; send another signal to interrupt")
	select {
	case <-workersDone:
	case <-signals:
		cancelDelivery()
		<-workersDone
	case <-time.After(125 * time.Second):
		cancelDelivery()
		<-workersDone
	}
	return err
}
