// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package emailprint

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
)

type Attachment struct {
	Name   string
	Data   []byte
	Format string
}

// Only explicit, unencrypted PDF/JPEG/PNG attachments are printable. The message body never is.
func Parse(r io.Reader) ([]Attachment, error) {
	m, e := mail.ReadMessage(r)
	if e != nil {
		return nil, e
	}
	var out []Attachment
	total := 0
	var walk func(string, string, string, string, io.Reader, int) error
	walk = func(ct, cd, encoding, name string, body io.Reader, depth int) error {
		if depth > 5 {
			return errors.New("MIME nesting too deep")
		}
		typ, params, e := mime.ParseMediaType(ct)
		if e != nil {
			return errors.New("invalid MIME type")
		}
		if strings.HasPrefix(typ, "multipart/") {
			boundary := params["boundary"]
			if boundary == "" {
				return errors.New("missing MIME boundary")
			}
			parts := multipart.NewReader(body, boundary)
			for {
				part, e := parts.NextPart()
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
				e = walk(part.Header.Get("Content-Type"), part.Header.Get("Content-Disposition"), part.Header.Get("Content-Transfer-Encoding"), "", part, depth+1)
				part.Close()
				if e != nil {
					return e
				}
			}
		}
		_, disp, _ := mime.ParseMediaType(cd)
		if name == "" {
			name = disp["filename"]
		}
		if name == "" {
			name = params["name"]
		}
		if name == "" {
			return nil
		}
		if typ != "application/pdf" && typ != "image/jpeg" && typ != "image/png" {
			return errors.New("only PDF, JPEG and PNG attachments are supported")
		}
		switch strings.ToLower(strings.TrimSpace(encoding)) {
		case "base64":
			body = base64.NewDecoder(base64.StdEncoding, body)
		case "quoted-printable":
			body = quotedprintable.NewReader(body)
		case "", "7bit", "8bit", "binary":
		default:
			return errors.New("unsupported MIME encoding")
		}
		b, e := io.ReadAll(io.LimitReader(body, 20<<20+1))
		if e != nil {
			return e
		}
		total += len(b)
		if len(b) == 0 || total > 20<<20 || len(out) >= 10 {
			return errors.New("maximum ten attachments and 20 MiB decoded total")
		}
		valid := typ == "application/pdf" && strings.HasPrefix(string(b), "%PDF-") || typ == "image/jpeg" && len(b) >= 3 && b[0] == 255 && b[1] == 216 && b[2] == 255 || typ == "image/png" && len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n"
		if !valid {
			return errors.New("attachment MIME does not match content")
		}
		if len(name) > 200 || strings.ContainsAny(name, "\r\n\x00") {
			name = "email-document"
		}
		out = append(out, Attachment{Name: name, Data: b, Format: typ})
		return nil
	}
	if e = walk(m.Header.Get("Content-Type"), m.Header.Get("Content-Disposition"), m.Header.Get("Content-Transfer-Encoding"), "", m.Body, 0); e != nil {
		return nil, e
	}
	if len(out) == 0 {
		return nil, errors.New("no supported attachments")
	}
	return out, nil
}
