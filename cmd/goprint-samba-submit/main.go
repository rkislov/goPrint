// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// goprint-samba-submit runs as Samba's authenticated Unix user; no API token is used.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkislov/goPrint/internal/buildinfo"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/sambaprint"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "goprint-samba-submit:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	flags := flag.NewFlagSet("goprint-samba-submit", flag.ContinueOnError)
	version := flags.Bool("version", false, "print build version")
	socket := flags.String("socket", "/run/goprint-samba/submit.sock", "local GoPrint Unix socket")
	printer := flags.String("printer", "", "GoPrint printer ID")
	spool := flags.String("spool-dir", "/var/spool/samba", "Samba share spool directory")
	format := flags.String("format", "", "explicit MIME type; default detects PDF, PostScript, JPEG, PNG, PWG")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if *version {
		fmt.Println(buildinfo.String())
		return nil
	}
	if flags.NArg() != 1 || *printer == "" || !filepath.IsAbs(*socket) || !filepath.IsAbs(*spool) {
		return errors.New("required: -printer ID [-socket PATH] [-spool-dir DIR] FILE")
	}
	path := flags.Arg(0)
	if !filepath.IsAbs(path) {
		path = filepath.Join(*spool, path)
	}
	path = filepath.Clean(path)
	rel, e := filepath.Rel(filepath.Clean(*spool), path)
	if e != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." || strings.ContainsRune(rel, os.PathSeparator) {
		return errors.New("document must be directly inside the Samba spool directory")
	}
	before, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !before.Mode().IsRegular() || before.Size() == 0 || before.Size() > queue.MaxDocumentSize {
		return errors.New("spool must be a nonempty regular document, at most 100 MiB")
	}
	f, e := sambaprint.OpenSpool(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(before, st) {
		return errors.New("spool changed while opening")
	}
	head := make([]byte, 512)
	n, e := f.Read(head)
	if e != nil && e != io.EOF {
		return e
	}
	if *format == "" {
		b := head[:n]
		switch {
		case strings.HasPrefix(string(b), "%PDF-"):
			*format = "application/pdf"
		case strings.HasPrefix(string(b), "%!PS"):
			*format = "application/postscript"
		case strings.HasPrefix(string(b), "\x89PNG\r\n\x1a\n"):
			*format = "image/png"
		case len(b) >= 3 && b[0] == 255 && b[1] == 216 && b[2] == 255:
			*format = "image/jpeg"
		case strings.HasPrefix(string(b), "RaS2"):
			*format = "image/pwg-raster"
		default:
			return errors.New("unsupported spool format; use a PDF/PostScript driver or an explicitly configured raw queue")
		}
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%d\x00", filepath.Base(path), st.Size(), st.ModTime().UnixNano())
	if _, e = io.Copy(h, io.LimitReader(f, queue.MaxDocumentSize+1)); e != nil {
		return e
	}
	after, e := f.Stat()
	if e != nil {
		return e
	}
	if after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return errors.New("spool changed while hashing")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequest("POST", "http://unix/submit?"+url.Values{"printer": {*printer}, "title": {filepath.Base(path)}}.Encode(), f)
	if e != nil {
		return e
	}
	request.ContentLength = st.Size()
	request.Header.Set("Content-Type", *format)
	request.Header.Set("X-GoPrint-Spool-ID", hex.EncodeToString(h.Sum(nil)))
	response, e := client.Do(request)
	if e != nil {
		return errors.New("submission acknowledgement unavailable; retain spool and inspect queue before retry")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 && response.StatusCode != 201 {
		return fmt.Errorf("HTTP %d: %s; spool retained", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var result struct {
		State string `json:"state"`
		JobID string `json:"job_id"`
	}
	if json.Unmarshal(body, &result) != nil || result.State != "accepted" || len(result.JobID) != 32 {
		return errors.New("unconfirmed receipt; spool retained")
	}
	current, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !os.SameFile(st, current) || current.Size() != st.Size() || !current.ModTime().Equal(st.ModTime()) {
		return errors.New("accepted, but spool changed; retained for inspection")
	}
	if e = os.Remove(path); e != nil {
		return fmt.Errorf("accepted job %s but spool cleanup failed: %w", result.JobID, e)
	}
	fmt.Println("GoPrint accepted job", result.JobID)
	return nil
}
