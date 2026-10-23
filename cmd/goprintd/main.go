// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// goprintd serves the local administrator API and processes durable print jobs.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/buildinfo"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rkislov/goPrint/internal/antivirus"
	"github.com/rkislov/goPrint/internal/audit"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/database"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/filtering"
	"github.com/rkislov/goPrint/internal/maildelivery"
	"github.com/rkislov/goPrint/internal/monitoring"
	"github.com/rkislov/goPrint/internal/personal"
	"github.com/rkislov/goPrint/internal/printing"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/sambaprint"
	"github.com/rkislov/goPrint/internal/scaninbox"
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
	sambaConfig := flag.String("samba-config", "", "local Samba UID-to-UPN gateway JSON configuration")
	publicURL := flag.String("public-url", "", "canonical HTTPS origin used by client provisioning and IPP")
	domainConfig := flag.String("domain-config", "", "AD/Samba LDAPS or StartTLS JSON configuration")
	dsnFile := flag.String("postgres-dsn-file", "", "private PostgreSQL DSN file; default uses SQLite")
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
	if err := server.ValidatePublicURL(*publicURL); err != nil {
		return err
	}
	var domain auth.Authenticator
	if *domainConfig != "" {
		var err error
		domain, err = auth.Load(*domainConfig)
		if err != nil {
			return fmt.Errorf("domain config: %w", err)
		}
	}
	var negotiator auth.Negotiator
	if d, ok := domain.(*auth.Domain); ok && d.Config.Kerberos != nil {
		if *cert == "" || *key == "" || *publicURL == "" {
			return errors.New("Kerberos requires tls-cert, tls-key and public-url")
		}
		u, e := url.Parse(*publicURL)
		if e != nil || u.Scheme != "https" || "HTTP/"+u.Hostname() != d.Config.Kerberos.ServicePrincipal {
			return errors.New("public-url DNS name must match Kerberos HTTP SPN")
		}
		pair, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return e
		}
		certificate, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return e
		}
		negotiator, e = auth.NewKerberos(d, certificate)
		if e != nil {
			return fmt.Errorf("Kerberos config: %w", e)
		}
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
	dsn, err := database.ReadDSN(*dsnFile)
	if err != nil {
		return err
	}
	store, err := queue.OpenDatabase(*data, dsn)
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
	if *preload && catalog.Status().SHA256 == "" {
		catalog.StartSync(catalogCtx)
	}
	if *preload && catalog.KatushaStatus().Count == 0 {
		catalog.StartKatushaSync(catalogCtx)
	}
	scans, err := scanning.OpenDatabase(filepath.Join(*data, "scans"), dsn)
	if err != nil {
		return err
	}
	defer scans.Close()
	av := antivirus.New(store)
	scans.Validator = av
	inboxService, err := scaninbox.New(*data, store, scans, func(ctx context.Context, user string) (string, error) {
		if user == "local-admin" {
			return user, nil
		}
		resolver, ok := domain.(interface {
			ResolveUser(context.Context, string) (auth.Identity, error)
		})
		if !ok {
			return "", errors.New("domain directory unavailable")
		}
		id, e := resolver.ResolveUser(ctx, user)
		return id.User, e
	}, func() (*tls.Config, error) {
		if *cert == "" || *key == "" {
			return nil, errors.New("TLS not configured")
		}
		pair, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return nil, e
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
	})
	if err != nil {
		return err
	}
	defer inboxService.Close()

	personalService, err := personal.New(*data, store)
	if err != nil {
		return err
	}
	mailService, err := maildelivery.New(*data, store, scans)
	if err != nil {
		return err
	}
	mailCtx, cancelMail := context.WithCancel(context.Background())
	mailDone := make(chan struct{})
	go func() { defer close(mailDone); mailService.Run(mailCtx) }()
	defer func() { cancelMail(); <-mailDone }()
	mark, err := watermark.New(filepath.Join(*data, "watermarks"))
	if err != nil {
		return err
	}
	filters, err := filtering.New(filepath.Join(*data, "prepared"), catalog, *filterLimit<<20)
	if err != nil {
		return err
	}
	smbService, err := backend.NewSMB(*data, store)
	if err != nil {
		return err
	}
	pipeline := &printing.Pipeline{SMB: smbService, Antivirus: av, Store: store, Marker: mark, Filters: filters}
	exporter := audit.New(store)
	auditCtx, cancelAudit := context.WithCancel(context.Background())
	auditDone := make(chan struct{})
	go func() { defer close(auditDone); exporter.Run(auditCtx) }()
	defer func() { cancelAudit(); <-auditDone }()
	monitorService, err := monitoring.New(*data, store, mailService)
	if err != nil {
		return err
	}
	monitorCtx, cancelMonitor := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); monitorService.Run(monitorCtx) }()
	defer func() { cancelMonitor(); <-monitorDone }()
	application := &server.Server{SMB: smbService, Inboxes: inboxService, Monitoring: monitorService, Antivirus: av, Personal: personalService, Mail: mailService, PublicURL: *publicURL, Domain: domain, SSO: negotiator, Audit: exporter, Store: store, Token: token, Catalog: catalog, Scans: scans, Filters: drivers.NewFilterManager(filepath.Join(*data, "filters")), Background: catalogCtx}
	api := application.Handler()
	srv := &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 256 << 10}
	serveErr := make(chan error, 2)
	var sambaHTTP *http.Server
	if *sambaConfig != "" {
		cfg, e := sambaprint.Load(*sambaConfig)
		if e != nil {
			return e
		}
		directory, configured := domain.(*auth.Domain)
		if !configured || directory.Config.DirectoryBindDN == "" || directory.Config.DirectoryPasswordFile == "" {
			return errors.New("Samba gateway requires domain configuration with directory bind")
		}
		socket, e := sambaprint.Listen(cfg)
		if e != nil {
			return e
		}
		sambaHTTP = &http.Server{Handler: application.SambaHandler(cfg.Users), ConnContext: sambaprint.ConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
		defer sambaHTTP.Close()
		go func() { serveErr <- sambaHTTP.Serve(socket) }()
	}
	stopClaims, cancelClaims := context.WithCancel(context.Background())
	defer cancelClaims()
	delivery, cancelDelivery := context.WithCancel(context.Background())
	defer cancelDelivery()
	workersDone := make(chan struct{})
	go func() {
		store.Run(stopClaims, delivery, *workers, pipeline.Deliver)
		close(workersDone)
	}()

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
	if sambaHTTP != nil {
		if e := sambaHTTP.Shutdown(shutdownCtx); e != nil {
			sambaHTTP.Close()
		}
	}
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
