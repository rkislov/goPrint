// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package diagnostics

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestSafeErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{{&net.DNSError{Err: "sensitive-value", Name: "private"}, "dns"}, {x509.UnknownAuthorityError{}, "tls_ca"}, {x509.HostnameError{}, "tls_name"}, {syscall.ECONNREFUSED, "refused"}, {context.DeadlineExceeded, "timeout"}, {HTTPStatus{404}, "path"}, {errors.New("sensitive-value"), "protocol"}} {
		r := New()
		r.Error("test", tc.err)
		if r.Steps[0].Code != "test_"+tc.code || strings.Contains(r.Steps[0].Message, "sensitive-value") {
			t.Fatal(r)
		}
	}
}
