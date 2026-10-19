// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// Package backend delivers already rendered documents to printers.
package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

type Result struct{ State, Detail, RemoteID string }

func Validate(p queue.Printer) error {
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 128 {
		return errors.New("printer name must contain 1–128 bytes")
	}
	u, err := url.Parse(p.URI)
	if err != nil {
		return errors.New("invalid printer URI")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return errors.New("URI requires host, without credentials, query or fragment")
	}
	switch u.Scheme {
	case "socket":
		if u.Port() == "" || u.Path != "" {
			return errors.New("socket URI must be socket://host:port")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("invalid socket port")
		}
	case "ipp", "ipps":
		if u.Path == "" {
			return errors.New("IPP URI requires printer path")
		}
	default:
		return errors.New("supported URI schemes: socket, ipp, ipps")
	}
	if len(p.Formats) == 0 || len(p.Formats) > 16 {
		return errors.New("specify the document formats accepted by this printer")
	}
	for _, f := range p.Formats {
		switch f {
		case "application/pdf", "application/postscript", "application/octet-stream", "image/pwg-raster", "image/jpeg", "image/png":
		default:
			return fmt.Errorf("unsupported document format %q", f)
		}
	}
	return nil
}
func Deliver(ctx context.Context, p queue.Printer, j queue.Job, path string) Result {
	f, err := os.Open(path)
	if err != nil {
		return Result{State: "failed", Detail: "cannot open spool document"}
	}
	defer f.Close()
	if strings.HasPrefix(p.URI, "ipp://") || strings.HasPrefix(p.URI, "ipps://") {
		return deliverIPP(ctx, p, j, f)
	}
	u, _ := url.Parse(p.URI)
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return Result{State: "failed", Detail: "cannot connect to printer"}
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_, err = io.Copy(conn, f)
	if err != nil {
		return Result{State: "unknown", Detail: "delivery interrupted; verify printer before resubmitting"}
	}
	if err = conn.Close(); err != nil {
		return Result{State: "unknown", Detail: "connection close failed after delivery"}
	}
	return Result{State: "submitted", Detail: "document transferred; physical printing is not confirmed"}
}
