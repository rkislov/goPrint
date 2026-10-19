// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"errors"
	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/auth"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/watermark"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func attribute(attrs goipp.Attributes, name string) goipp.Value {
	for _, a := range attrs {
		if a.Name == name && len(a.Values) == 1 {
			return a.Values[0].V
		}
	}
	return nil
}
func strAttr(attrs goipp.Attributes, name string) string {
	if v, ok := attribute(attrs, name).(goipp.String); ok {
		return string(v)
	}
	return ""
}
func intAttr(attrs goipp.Attributes, name string) int {
	if v, ok := attribute(attrs, name).(goipp.Integer); ok {
		return int(v)
	}
	return 0
}
func add(attrs *goipp.Attributes, name string, tag goipp.Tag, v goipp.Value) {
	attrs.Add(goipp.MakeAttribute(name, tag, v))
}
func multi(attrs *goipp.Attributes, name string, tag goipp.Tag, values []string) {
	a := goipp.Attribute{Name: name}
	for _, v := range values {
		a.Values.Add(tag, goipp.String(v))
	}
	attrs.Add(a)
}
func (s *Server) ippIdentity(r *http.Request) (auth.Identity, bool) {
	if id, ok := s.identity(r); ok {
		return id, true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if r.TLS == nil && (ip == nil || !ip.IsLoopback()) {
		return auth.Identity{}, false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return auth.Identity{}, false
	}
	id, err := s.cachedCredentials(r, user, pass)
	return id, err == nil
}
func (s *Server) ipp(w http.ResponseWriter, r *http.Request) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/ipp" {
		http.Error(w, "application/ipp required", 415)
		return
	}
	p, err := s.Store.Printer(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "printer not found", 404)
		return
	}
	body := http.MaxBytesReader(w, r.Body, queue.MaxDocumentSize+(1<<20))
	header := &io.LimitedReader{R: body, N: 1 << 20}
	var req goipp.Message
	if err = req.Decode(header); err != nil {
		http.Error(w, "invalid or oversized IPP header", 400)
		return
	}
	id, ok := s.ippIdentity(r)
	if !ok && goipp.Op(req.Code) != goipp.OpGetPrinterAttributes {
		w.Header().Set("WWW-Authenticate", `Basic realm="GoPrint", charset="UTF-8"`)
		http.Error(w, "authentication required", 401)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
	rsp := goipp.NewResponse(req.Version, goipp.StatusOk, req.RequestID)
	add(&rsp.Operation, "attributes-charset", goipp.TagCharset, goipp.String("utf-8"))
	add(&rsp.Operation, "attributes-natural-language", goipp.TagLanguage, goipp.String("en"))
	status := func(code goipp.Status, message string) {
		rsp.Code = goipp.Code(code)
		add(&rsp.Operation, "status-message", goipp.TagText, goipp.String(message))
	}
	uri := s.baseURL(r) + "/ipp/printers/" + p.ID
	switch goipp.Op(req.Code) {
	case goipp.OpGetPrinterAttributes:
		add(&rsp.Printer, "printer-uri-supported", goipp.TagURI, goipp.String(uri))
		add(&rsp.Printer, "uri-authentication-supported", goipp.TagKeyword, goipp.String("basic"))
		security := "none"
		if strings.HasPrefix(uri, "https:") {
			security = "tls"
		}
		add(&rsp.Printer, "uri-security-supported", goipp.TagKeyword, goipp.String(security))
		defaults, err := s.defaults(p)
		if err != nil {
			status(goipp.StatusErrorInternal, "cannot read PPD defaults")
			break
		}
		rsp.Printer = append(rsp.Printer, defaults.attributes()...)
		add(&rsp.Printer, "printer-location", goipp.TagText, goipp.String("GoPrint"))
		add(&rsp.Printer, "printer-more-info", goipp.TagURI, goipp.String(s.baseURL(r)+"/print"))
		add(&rsp.Printer, "printer-name", goipp.TagName, goipp.String(p.Name))
		add(&rsp.Printer, "printer-info", goipp.TagText, goipp.String(p.Name))
		add(&rsp.Printer, "printer-make-and-model", goipp.TagText, goipp.String("GoPrint PDF Queue"))
		add(&rsp.Printer, "printer-is-accepting-jobs", goipp.TagBoolean, goipp.Boolean(true))
		state := 3
		if p.Paused {
			state = 5
		}
		add(&rsp.Printer, "printer-state", goipp.TagEnum, goipp.Integer(state))
		reason := "none"
		if p.Paused {
			reason = "paused"
		}
		multi(&rsp.Printer, "printer-state-reasons", goipp.TagKeyword, []string{reason})
		multi(&rsp.Printer, "ipp-versions-supported", goipp.TagKeyword, []string{"1.1", "2.0"})
		a := goipp.Attribute{Name: "operations-supported"}
		for _, op := range []goipp.Op{goipp.OpPrintJob, goipp.OpCreateJob, goipp.OpSendDocument, goipp.OpValidateJob, goipp.OpGetPrinterAttributes, goipp.OpGetJobAttributes, goipp.OpGetJobs, goipp.OpCancelJob} {
			a.Values.Add(goipp.TagEnum, goipp.Integer(op))
		}
		rsp.Printer.Add(a)
		formats := queue.AcceptedFormats(p)
		var policy = watermark.Default()
		if err = s.Store.Setting(r.Context(), "watermark", &policy); err != nil {
			status(goipp.StatusErrorInternal, "cannot read policy")
			break
		}
		if policy.Enabled {
			formats = []string{"application/pdf"}
		}
		multi(&rsp.Printer, "document-format-supported", goipp.TagMimeType, formats)
		format := formats[0]
		if queue.Accepts(p, "application/pdf") {
			format = "application/pdf"
		}
		add(&rsp.Printer, "document-format-default", goipp.TagMimeType, goipp.String(format))
		add(&rsp.Printer, "charset-configured", goipp.TagCharset, goipp.String("utf-8"))
		multi(&rsp.Printer, "charset-supported", goipp.TagCharset, []string{"utf-8"})
		add(&rsp.Printer, "natural-language-configured", goipp.TagLanguage, goipp.String("en"))
		multi(&rsp.Printer, "generated-natural-language-supported", goipp.TagLanguage, []string{"en"})
		add(&rsp.Printer, "copies-default", goipp.TagInteger, goipp.Integer(1))
		add(&rsp.Printer, "copies-supported", goipp.TagRange, goipp.Range{Lower: 1, Upper: 1})
		multi(&rsp.Printer, "compression-supported", goipp.TagKeyword, []string{"none"})
		multi(&rsp.Printer, "multiple-document-handling-supported", goipp.TagKeyword, []string{"separate-documents-uncollated-copies"})
		add(&rsp.Printer, "multiple-document-jobs-supported", goipp.TagBoolean, goipp.Boolean(false))
		add(&rsp.Printer, "printer-up-time", goipp.TagInteger, goipp.Integer(1))
		add(&rsp.Printer, "job-creation-attributes-supported", goipp.TagKeyword, goipp.String("job-name"))
	case goipp.OpPrintJob, goipp.OpValidateJob, goipp.OpCreateJob, goipp.OpSendDocument:
		format := strAttr(req.Operation, "document-format")
		if format == "" && goipp.Op(req.Code) == goipp.OpCreateJob {
			format = "application/pdf"
		}
		if format == "" {
			format = "application/octet-stream"
		}
		if !queue.Accepts(p, format) {
			status(goipp.StatusErrorDocumentFormatNotSupported, "document format unsupported")
			break
		}
		policy := watermark.Default()
		if err = s.Store.Setting(r.Context(), "watermark", &policy); err != nil {
			status(goipp.StatusErrorInternal, "cannot read policy")
			break
		}
		if policy.Enabled && format != "application/pdf" {
			status(goipp.StatusErrorDocumentFormatNotSupported, "watermark requires PDF")
			break
		}
		if compression := strAttr(req.Operation, "compression"); compression != "" && compression != "none" {
			status(goipp.StatusErrorCompressionNotSupported, "compression unsupported")
			break
		}
		defaults, e := s.defaults(p)
		if e != nil {
			status(goipp.StatusErrorInternal, "cannot read PPD defaults")
			break
		}
		if !defaults.optionsSupported(req.Job) {
			status(goipp.StatusErrorAttributesOrValues, "only PPD default options are supported")
			break
		}
		if goipp.Op(req.Code) == goipp.OpValidateJob {
			break
		}
		title := strAttr(req.Operation, "job-name")
		if title == "" {
			title = "IPP document"
		}
		if len(title) > 255 || strings.ContainsAny(title, "\r\n\x00") {
			status(goipp.StatusErrorBadRequest, "invalid job title")
			break
		}
		var j queue.Job
		var err error
		switch goipp.Op(req.Code) {
		case goipp.OpCreateJob:
			j, err = s.Store.ReserveIPP(r.Context(), p.ID, id.User, title, format)
		case goipp.OpSendDocument:
			n := intAttr(req.Operation, "job-id")
			existing, e := s.Store.IPPJob(r.Context(), n)
			if e != nil || existing.PrinterID != p.ID || !id.Admin && existing.Owner != id.User {
				status(goipp.StatusErrorNotFound, "job not found")
				break
			}
			last, ok := attribute(req.Operation, "last-document").(goipp.Boolean)
			if !ok || !bool(last) {
				status(goipp.StatusErrorMultipleJobsNotSupported, "only one final document is supported")
				break
			}
			j, err = s.Store.SendIPP(r.Context(), existing, format, body)
		default:
			j, err = s.Store.Submit(r.Context(), p.ID, id.User, title, format, body)
		}
		if rsp.Code != 0 {
			break
		}
		if err != nil {
			if errors.Is(err, queue.ErrTooLarge) {
				status(goipp.StatusErrorRequestEntity, "document too large")
			} else {
				status(goipp.StatusErrorInternal, "cannot accept document")
			}
			break
		}
		number, err := s.Store.IPPNumber(r.Context(), j.ID)
		if err != nil {
			status(goipp.StatusErrorInternal, "accepted; cannot retrieve job id; do not retry blindly")
			break
		}
		rsp.Job = ippJob(j, number, uri)
	case goipp.OpGetJobAttributes, goipp.OpCancelJob:
		n := intAttr(req.Operation, "job-id")
		if r.PathValue("job") != "" {
			pathN, e := strconv.Atoi(r.PathValue("job"))
			if e != nil || n != 0 && n != pathN {
				status(goipp.StatusErrorBadRequest, "job identifier mismatch")
				break
			}
			n = pathN
		}
		if n == 0 {
			if u := strAttr(req.Operation, "job-uri"); strings.HasPrefix(u, uri+"/jobs/") {
				n, _ = strconv.Atoi(strings.TrimPrefix(u, uri+"/jobs/"))
			}
		}
		j, err := s.Store.IPPJob(r.Context(), n)
		if err != nil || j.PrinterID != p.ID || !id.Admin && j.Owner != id.User {
			status(goipp.StatusErrorNotFound, "job not found")
			break
		}
		if goipp.Op(req.Code) == goipp.OpCancelJob {
			if err = s.Store.CancelIPP(r.Context(), j.ID); err != nil {
				status(goipp.StatusErrorNotPossible, "only queued jobs can be canceled")
				break
			}
			j.State = "canceled"
		}
		rsp.Job = ippJob(j, n, uri)
	case goipp.OpGetJobs:
		jobs, err := s.visibleJobs(r)
		if err != nil {
			status(goipp.StatusErrorInternal, "cannot list jobs")
			break
		}
		rsp.Groups = goipp.Groups{{Tag: goipp.TagOperationGroup, Attrs: rsp.Operation}}
		which := strAttr(req.Operation, "which-jobs")
		for _, j := range jobs {
			if j.PrinterID != p.ID {
				continue
			}
			terminal := j.State == "submitted" || j.State == "failed" || j.State == "canceled"
			if which == "completed" && !terminal || which != "all" && which != "completed" && terminal {
				continue
			}
			n, err := s.Store.IPPNumber(r.Context(), j.ID)
			if err == nil {
				rsp.Groups.Add(goipp.Group{Tag: goipp.TagJobGroup, Attrs: ippJob(j, n, uri)})
			}
		}
	default:
		status(goipp.StatusErrorOperationNotSupported, "operation unsupported")
	}
	encoded, err := rsp.EncodeBytes()
	if err != nil {
		http.Error(w, "response error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/ipp")
	w.Write(encoded)
}
func ippJob(j queue.Job, n int, uri string) goipp.Attributes {
	var a goipp.Attributes
	add(&a, "job-id", goipp.TagInteger, goipp.Integer(n))
	add(&a, "job-uri", goipp.TagURI, goipp.String(uri+"/jobs/"+strconv.Itoa(n)))
	add(&a, "job-printer-uri", goipp.TagURI, goipp.String(uri))
	add(&a, "job-name", goipp.TagName, goipp.String(j.Title))
	add(&a, "job-originating-user-name", goipp.TagName, goipp.String(j.Owner))
	state := 9
	reason := "job-completed-successfully"
	switch j.State {
	case "held":
		state = 4
		reason = "job-incoming"
	case "receiving":
		state = 4
		reason = "job-incoming"
	case "queued":
		state = 3
		reason = "job-queued"
	case "processing":
		state = 5
		reason = "job-printing"
	case "canceled":
		state = 7
		reason = "job-canceled-by-user"
	case "failed":
		state = 8
		reason = "aborted-by-system"
	case "unknown":
		state = 6
		reason = "printer-stopped"
	}
	add(&a, "job-state", goipp.TagEnum, goipp.Integer(state))
	multi(&a, "job-state-reasons", goipp.TagKeyword, []string{reason})
	add(&a, "job-state-message", goipp.TagText, goipp.String(j.Detail))
	return a
}
