// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// goprintctl calls the local GoPrint administrator API.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "goprintctl:", err)
		os.Exit(1)
	}
}
func run() error {
	addr := flag.String("addr", "http://127.0.0.1:8631", "server URL")
	format := flag.String("format", "application/pdf", "document MIME type")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: goprintctl [flags] printers | add-printer NAME URI | jobs | job ID | events ID | submit PRINTER_ID FILE | cancel JOB_ID | pause PRINTER_ID | resume PRINTER_ID")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return errors.New("command required")
	}
	token := os.Getenv("GOPRINT_TOKEN")
	if len(token) < 32 {
		return errors.New("GOPRINT_TOKEN must contain at least 32 bytes")
	}
	u, err := url.Parse(*addr)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid server URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("server URL must use HTTP or HTTPS")
	}
	method, path := http.MethodGet, ""
	var body io.Reader
	content := "application/json"
	switch {
	case args[0] == "printers" && len(args) == 1:
		path = "/api/printers"
	case args[0] == "jobs" && len(args) == 1:
		path = "/api/jobs"
	case args[0] == "job" && len(args) == 2:
		path = "/api/jobs/" + url.PathEscape(args[1])
	case args[0] == "events" && len(args) == 2:
		path = "/api/jobs/" + url.PathEscape(args[1]) + "/events"
	case args[0] == "add-printer" && len(args) == 3:
		method = http.MethodPost
		path = "/api/printers"
		b, _ := json.Marshal(map[string]any{"name": args[1], "uri": args[2], "formats": []string{*format}})
		body = bytes.NewReader(b)
	case args[0] == "submit" && len(args) == 3:
		method = http.MethodPost
		path = "/api/jobs?" + url.Values{"printer": {args[1]}, "title": {filepath.Base(args[2])}}.Encode()
		f, err := os.Open(args[2])
		if err != nil {
			return err
		}
		defer f.Close()
		body = f
		content = *format
	case args[0] == "cancel" && len(args) == 2:
		method = http.MethodPost
		path = "/api/jobs/" + url.PathEscape(args[1]) + "/cancel"
	case (args[0] == "pause" || args[0] == "resume") && len(args) == 2:
		method = http.MethodPut
		path = "/api/printers/" + url.PathEscape(args[1]) + "/paused"
		b, _ := json.Marshal(map[string]bool{"paused": args[0] == "pause"})
		body = bytes.NewReader(b)
	default:
		flag.Usage()
		return errors.New("invalid command or argument count")
	}
	req, err := http.NewRequest(method, strings.TrimRight(*addr, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", content)
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(rsp.Body, 4<<20))
	if err != nil {
		return err
	}
	if rsp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", rsp.StatusCode, strings.TrimSpace(string(b)))
	}
	var pretty bytes.Buffer
	if err = json.Indent(&pretty, b, "", "  "); err != nil {
		return err
	}
	fmt.Println(pretty.String())
	return nil
}
