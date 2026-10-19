// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/queue"
)

func deliverIPP(ctx context.Context, p queue.Printer, j queue.Job, f *os.File) Result {
	req := goipp.NewRequest(goipp.DefaultVersion, goipp.OpPrintJob, 1)
	req.Operation.Add(goipp.MakeAttribute("attributes-charset", goipp.TagCharset, goipp.String("utf-8")))
	req.Operation.Add(goipp.MakeAttribute("attributes-natural-language", goipp.TagLanguage, goipp.String("en")))
	req.Operation.Add(goipp.MakeAttribute("printer-uri", goipp.TagURI, goipp.String(p.URI)))
	req.Operation.Add(goipp.MakeAttribute("requesting-user-name", goipp.TagName, goipp.String(j.Owner)))
	req.Operation.Add(goipp.MakeAttribute("job-name", goipp.TagName, goipp.String(j.Title)))
	req.Operation.Add(goipp.MakeAttribute("document-format", goipp.TagMimeType, goipp.String(j.Format)))
	if p.PPDID == "" {
		for _, v := range []struct{ name, value string }{{"media", j.Options.Media}, {"sides", j.Options.Sides}, {"print-color-mode", j.Options.Color}} {
			if v.value != "" {
				req.Job.Add(goipp.MakeAttribute(v.name, goipp.TagKeyword, goipp.String(v.value)))
			}
		}
	}
	header, err := req.EncodeBytes()
	if err != nil {
		return Result{State: "failed", Detail: "cannot encode IPP request"}
	}
	u, _ := url.Parse(p.URI)
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "631")
	}
	if u.Scheme == "ipps" {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), io.MultiReader(bytes.NewReader(header), f))
	if err != nil {
		return Result{State: "failed", Detail: "cannot construct IPP request"}
	}
	r.Header.Set("Content-Type", "application/ipp")
	r.ContentLength = int64(len(header)) + j.Size
	// No proxy, redirects or insecure TLS. A Print-Job must never be retried automatically.
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rsp, err := client.Do(r)
	if err != nil {
		return Result{State: "unknown", Detail: "IPP transport failed; verify printer before resubmitting"}
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return Result{State: "unknown", Detail: fmt.Sprintf("printer returned HTTP %d; acceptance is unconfirmed", rsp.StatusCode)}
	}
	var msg goipp.Message
	if err = msg.Decode(io.LimitReader(rsp.Body, 1<<20)); err != nil || msg.RequestID != req.RequestID {
		return Result{State: "unknown", Detail: "invalid IPP response; acceptance is unconfirmed"}
	}
	if msg.Code >= 0x0400 {
		return Result{State: "failed", Detail: "IPP rejected document: " + goipp.Status(msg.Code).String()}
	}
	if msg.Code >= 0x0100 {
		return Result{State: "unknown", Detail: "unexpected IPP status"}
	}
	remote := ""
	for _, a := range msg.Job {
		if a.Name == "job-id" && len(a.Values) > 0 {
			if v, ok := a.Values[0].V.(goipp.Integer); ok {
				remote = strconv.Itoa(int(v))
			}
		}
	}
	return Result{State: "submitted", Detail: "IPP printer accepted document; physical printing is not confirmed", RemoteID: remote}
}
