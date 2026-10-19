// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// goprintd serves the local administrator API and processes durable print jobs.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/rkislov/goPrint/internal/buildinfo"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rkislov/goPrint/internal/audit"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/filtering"
	"github.com/rkislov/goPrint/internal/printing"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/scanning"
	"github.com/rkislov/goPrint/internal/server"
	"github.com/rkislov/goPrint/internal/watermark"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--watermark-worker" {
		if err := watermark.RunWorker(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("goprintd stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	data := flag.String("data", "./var/goprint", "private data directory")
	listen := flag.String("listen", "127.0.0.1:8631", "loopback HTTP address")
	cert := flag.String("tls-cert", "", "HTTPS certificate PEM file")
	key := flag.String("tls-key", "", "HTTPS private key PEM file")
	workers := flag.Int("workers", 4, "delivery workers (1–50)")
	filterLimit := flag.Int64("filter-output-mib", 512, "maximum prepared PPD document size in MiB (1–4096)")
	preload := flag.Bool("preload-ppds", true, "download OpenPrinting PPD catalog on first start")
	version := flag.Bool("version", false, "print build version")
	flag.Parse()
	if *version {
		fmt.Println(buildinfo.String())
		return nil
	}
	if *filterLimit < 1 || *filterLimit > 4096 {
		return errors.New("filter-output-mib must be between 1 and 4096")
	}
	token := os.Getenv("GOPRINT_TOKEN")
	if len(token) < 32 {
		return errors.New("GOPRINT_TOKEN must contain at least 32 bytes")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if (*cert == "") != (*key == "") {
		return errors.New("tls-cert and tls-key must be provided together")
	}
	if (ip == nil || !ip.IsLoopback()) && *cert == "" {
		return errors.New("non-loopback addresses require tls-cert and tls-key")
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
	catalog, err := drivers.Open(filepath.Join(*data, "ppds"))
	if err != nil {
		return err
	}
	catalogCtx, cancelCatalog := context.WithCancel(context.Background())
	defer cancelCatalog()
	if *preload && catalog.Status().Count == 0 {
		catalog.StartSync(catalogCtx)
	}
	scans, err := scanning.Open(filepath.Join(*data, "scans"))
	if err != nil {
		return err
	}
	defer scans.Close()
	mark, err := watermark.New(filepath.Join(*data, "watermarks"))
	if err != nil {
		return err
	}
	filters, err := filtering.New(filepath.Join(*data, "prepared"), catalog, *filterLimit<<20)
	if err != nil {
		return err
	}
	pipeline := &printing.Pipeline{Store: store, Marker: mark, Filters: filters}
	exporter := audit.New(store)
	auditCtx, cancelAudit := context.WithCancel(context.Background())
	auditDone := make(chan struct{})
	go func() { defer close(auditDone); exporter.Run(auditCtx) }()
	defer func() { cancelAudit(); <-auditDone }()
	api := (&server.Server{Audit: exporter, Store: store, Token: token, Catalog: catalog, Scans: scans, Filters: drivers.NewFilterManager(filepath.Join(*data, "filters")), Background: catalogCtx}).Handler()
	srv := &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stopClaims, cancelClaims := context.WithCancel(context.Background())
	defer cancelClaims()
	delivery, cancelDelivery := context.WithCancel(context.Background())
	defer cancelDelivery()
	workersDone := make(chan struct{})
	go func() {
		store.Run(stopClaims, delivery, *workers, pipeline.Deliver)
		close(workersDone)
	}()
	serveErr := make(chan error, 1)
	go func() {
		if *cert != "" {
			serveErr <- srv.ServeTLS(listener, *cert, *key)
		} else {
			serveErr <- srv.Serve(listener)
		}
	}()
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
