// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package emailprint

import (
	"strings"
	"testing"
)

func TestAttachmentsOnlyAndMIMEValidation(t *testing.T) {
	message := "From: forged@invalid.test\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody must not print\r\n--x\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=test.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQ=\r\n--x--\r\n"
	a, e := Parse(strings.NewReader(message))
	if e != nil || len(a) != 1 || string(a[0].Data) != "%PDF-1.4" {
		t.Fatal(a, e)
	}
	for _, bad := range []string{strings.Replace(message, "JVBERi0xLjQ=", "aW52YWxpZA==", 1), strings.Replace(message, "application/pdf", "application/msword", 1), "Content-Type: text/plain\r\n\r\nhello"} {
		if _, e = Parse(strings.NewReader(bad)); e == nil {
			t.Fatal("unsupported message accepted")
		}
	}
}
