// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Trusted MTA pipe helper. Sender MUST come from authenticated envelope metadata.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type rejected struct{ status int }

func (e rejected) Error() string {
	return fmt.Sprintf("GoPrint rejected email (HTTP %d); inspect gateway logs and queue before replaying", e.status)
}
func main() {
	server := flag.String("server", "", "GoPrint HTTPS origin")
	tokenFile := flag.String("token-file", "", "private gateway token file (0600)")
	sender := flag.String("sender", "", "authenticated SMTP envelope sender, NEVER the message From header")
	id := flag.String("message-id", "", "stable MTA queue ID; default SHA-256 of the raw message")
	ca := flag.String("ca-file", "", "optional CA PEM for GoPrint")
	flag.Parse()
	if e := run(*server, *tokenFile, *sender, *id, *ca); e != nil {
		fmt.Fprintln(os.Stderr, e)
		var status rejected
		if errors.As(e, &status) && (status.status == 400 || status.status == 403 || status.status == 404 || status.status == 409 || status.status == 413 || status.status == 415) {
			os.Exit(69)
		}
		os.Exit(75)
	}
}
func run(server, path, sender, id, ca string) error {
	u, e := url.Parse(server)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || sender == "" {
		return errors.New("HTTPS server origin and authenticated sender required")
	}
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 256 {
		return errors.New("token file must be private (0600), at most 256 bytes")
	}
	token, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 30<<20+1))
	if e != nil {
		return e
	}
	if len(raw) > 30<<20 {
		return errors.New("message exceeds 30 MiB")
	}
	if id == "" {
		h := sha256.Sum256(raw)
		id = hex.EncodeToString(h[:])
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		pem, e := os.ReadFile(ca)
		if e != nil {
			return e
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("CA file contains no certificate")
		}
		tlsConfig.RootCAs = roots
	}
	request, e := http.NewRequest("POST", server+"/mail/incoming", bytes.NewReader(raw))
	if e != nil {
		return e
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Content-Type", "message/rfc822")
	request.Header.Set("X-GoPrint-Authenticated-Sender", sender)
	request.Header.Set("X-GoPrint-Message-ID", id)
	client := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		return errors.New("GoPrint connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return rejected{response.StatusCode}
	}
	_, e = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return e
}
