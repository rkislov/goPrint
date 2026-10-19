// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"github.com/rkislov/goPrint/internal/queue"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedClientPPDPassesSystemCUPSValidation(t *testing.T) {
	program, e := exec.LookPath("cupstestppd")
	if e != nil {
		if os.Getenv("GOPRINT_REQUIRE_CUPS_TEST") == "1" {
			t.Fatal(e)
		}
		t.Skip("system CUPS validator unavailable")
	}
	s := &Server{}
	ppd, e := s.clientPPD(queue.Printer{}, queue.PrintOptions{Media: "iso_a4_210x297mm", Sides: "one-sided", Color: "color"})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "client.ppd")
	if e = os.WriteFile(path, []byte(ppd), 0600); e != nil {
		t.Fatal(e)
	}
	output, e := exec.Command(program, path).CombinedOutput()
	if e != nil {
		t.Fatalf("CUPS rejected generated client profile: %v\n%s", e, output)
	}
}
