// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"context"
	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIPPAuthenticatedQueueAndOwnerIsolation(t *testing.T) {
	st, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.AddPrinter(context.Background(), queue.Printer{Name: "IPP", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	st.SetAccess(context.Background(), p.ID, queue.PrinterAccess{Public: true})
	h := (&Server{Store: st, Token: strings.Repeat("x", 32), Domain: fakeDomain{}}).Handler()
	call := func(user string, op goipp.Op, n int, body []byte, option bool) *goipp.Message {
		t.Helper()
		req := goipp.NewRequest(goipp.DefaultVersion, op, 31)
		add(&req.Operation, "document-format", goipp.TagMimeType, goipp.String("application/pdf"))
		add(&req.Operation, "requesting-user-name", goipp.TagName, goipp.String("forged-admin"))
		add(&req.Operation, "job-id", goipp.TagInteger, goipp.Integer(n))
		if option {
			add(&req.Job, "copies", goipp.TagInteger, goipp.Integer(9))
		}
		b, _ := req.EncodeBytes()
		r := httptest.NewRequest("POST", "/ipp/printers/"+p.ID, bytes.NewReader(append(b, body...)))
		r.SetBasicAuth(user, "domain-password")
		r.Header.Set("Content-Type", "application/ipp")
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var rsp goipp.Message
		if err := rsp.DecodeBytes(w.Body.Bytes()); err != nil {
			t.Fatal(err)
		}
		return &rsp
	}
	rsp := call("alice@example.org", goipp.OpPrintJob, 0, []byte("%PDF-1.4 synthetic"), false)
	if rsp.Code != 0 {
		t.Fatal(rsp.Code)
	}
	n := intAttr(rsp.Job, "job-id")
	if n < 1 {
		t.Fatal(n)
	}
	j, err := st.IPPJob(context.Background(), n)
	if err != nil || j.Owner != "alice@example.org" || j.State != "queued" {
		t.Fatal(j, err)
	}
	if rsp = call("bob@example.org", goipp.OpCancelJob, n, nil, false); rsp.Code != goipp.Code(goipp.StatusErrorNotFound) {
		t.Fatal("foreign cancel", rsp.Code)
	}
	if rsp = call("alice@example.org", goipp.OpPrintJob, 0, []byte("bad"), true); rsp.Code != goipp.Code(goipp.StatusErrorAttributesOrValues) {
		t.Fatal("copies silently ignored", rsp.Code)
	}
	if rsp = call("alice@example.org", goipp.OpCancelJob, n, nil, false); rsp.Code != 0 {
		t.Fatal(rsp.Code)
	}
	// IPP document data must begin immediately after the header: no loss to decoder buffering.
	data, err := os.ReadFile(st.Document(j.ID))
	if err != nil || string(data) != "%PDF-1.4 synthetic" {
		t.Fatal("IPP body changed", err, string(data))
	}
	unauth, _ := goipp.NewRequest(goipp.DefaultVersion, goipp.OpPrintJob, 1).EncodeBytes()
	r := httptest.NewRequest("POST", "/ipp/printers/"+p.ID, bytes.NewReader(unauth))
	r.Header.Set("Content-Type", "application/ipp")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("anonymous IPP", w.Code)
	}
}

func TestIPPCreateSendDocument(t *testing.T) {
	st, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.AddPrinter(context.Background(), queue.Printer{Name: "IPP multi step", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	st.SetAccess(context.Background(), p.ID, queue.PrinterAccess{Public: true})
	s := &Server{Store: st, Token: strings.Repeat("z", 32)}
	h := s.Handler()
	call := func(op goipp.Op, n int, document []byte) *goipp.Message {
		req := goipp.NewRequest(goipp.DefaultVersion, op, 1)
		add(&req.Operation, "document-format", goipp.TagMimeType, goipp.String("application/pdf"))
		add(&req.Operation, "job-id", goipp.TagInteger, goipp.Integer(n))
		add(&req.Operation, "last-document", goipp.TagBoolean, goipp.Boolean(true))
		b, _ := req.EncodeBytes()
		r := httptest.NewRequest("POST", "/ipp/printers/"+p.ID, bytes.NewReader(append(b, document...)))
		r.Header.Set("Authorization", "Bearer "+s.Token)
		r.Header.Set("Content-Type", "application/ipp")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var rsp goipp.Message
		if err := rsp.DecodeBytes(w.Body.Bytes()); err != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return &rsp
	}
	rsp := call(goipp.OpCreateJob, 0, nil)
	n := intAttr(rsp.Job, "job-id")
	if rsp.Code != 0 || n < 1 {
		t.Fatal(rsp.Code, n)
	}
	j, err := st.IPPJob(context.Background(), n)
	if err != nil || j.State != "held" {
		t.Fatal(j, err)
	}
	rsp = call(goipp.OpSendDocument, n, []byte("%PDF-1.4 send-document"))
	if rsp.Code != 0 {
		t.Fatal(rsp.Code)
	}
	j, _ = st.IPPJob(context.Background(), n)
	if j.State != "queued" {
		t.Fatal(j.State)
	}
	if rsp = call(goipp.OpSendDocument, n, []byte("replacement")); rsp.Code == 0 {
		t.Fatal("document replaced")
	}
	b, _ := os.ReadFile(st.Document(j.ID))
	if string(b) != "%PDF-1.4 send-document" {
		t.Fatal("original replaced")
	}
}
