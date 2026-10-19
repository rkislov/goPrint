// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"context"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/testutil"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeCUPSIPPClient(t *testing.T) {
	program, err := exec.LookPath("ipptool")
	if err != nil {
		if os.Getenv("GOPRINT_REQUIRE_IPP_TEST") == "1" {
			t.Fatal(err)
		}
		t.Skip("ipptool not installed")
	}
	st, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.AddPrinter(context.Background(), queue.Printer{Name: "Native IPP", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	st.SetAccess(context.Background(), p.ID, queue.PrinterAccess{Public: true})
	token := strings.Repeat("native-test-only", 3)
	srv := httptest.NewServer((&Server{Store: st, Token: token}).Handler())
	defer srv.Close()
	dir := t.TempDir()
	pdf := filepath.Join(dir, "test.pdf")
	os.WriteFile(pdf, testutil.PDF(), 0600)
	spec := `{
 NAME "Discover GoPrint queue"
 OPERATION Get-Printer-Attributes
 GROUP operation-attributes-tag
 ATTR charset attributes-charset utf-8
 ATTR naturalLanguage attributes-natural-language en
 ATTR uri printer-uri $uri
 STATUS successful-ok
 EXPECT document-format-supported WITH-VALUE application/pdf
 EXPECT media-col-default
 EXPECT operations-supported WITH-VALUE 0x0005
}
{
 NAME "Submit PDF through authenticated GoPrint IPP"
 OPERATION Print-Job
 GROUP operation-attributes-tag
 ATTR charset attributes-charset utf-8
 ATTR naturalLanguage attributes-natural-language en
 ATTR uri printer-uri $uri
 ATTR name requesting-user-name forged-owner
 ATTR mimeMediaType document-format application/pdf
 FILE $filename
 STATUS successful-ok
 EXPECT job-id
 EXPECT job-originating-user-name WITH-VALUE local-admin
}
`
	path := filepath.Join(dir, "native.test")
	os.WriteFile(path, []byte(spec), 0600)
	uri := strings.Replace(srv.URL, "http://", "http://local-admin:"+token+"@", 1) + "/ipp/printers/" + p.ID
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "-T", "10", "-t", "-f", pdf, uri, path)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native CUPS client: %v: %s", err, strings.ReplaceAll(string(b), token, "[test password]"))
	}
	jobs, _ := st.Jobs(context.Background())
	if len(jobs) != 1 || jobs[0].Owner != "local-admin" || jobs[0].Size != int64(len(testutil.PDF())) {
		t.Fatal(jobs)
	}
}

func TestLinuxDriverlessGeneratesPPD(t *testing.T) {
	program, err := exec.LookPath("driverless")
	if err != nil {
		for _, p := range []string{"/usr/lib/cups/driver/driverless", "/usr/libexec/cups/driver/driverless"} {
			if info, e := os.Stat(p); e == nil && !info.IsDir() {
				program = p
				err = nil
				break
			}
		}
	}
	if err != nil {
		if os.Getenv("GOPRINT_REQUIRE_DRIVERLESS_TEST") == "1" {
			t.Fatal("CUPS driverless generator missing")
		}
		t.Skip("driverless unavailable")
	}
	st, err := queue.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.AddPrinter(context.Background(), queue.Printer{Name: "Driverless PDF queue", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}, Paused: true})
	st.SetAccess(context.Background(), p.ID, queue.PrinterAccess{Public: true})
	srv := httptest.NewServer((&Server{Store: st, Token: strings.Repeat("q", 32)}).Handler())
	defer srv.Close()
	uri := strings.Replace(srv.URL, "http://", "ipp://", 1) + "/ipp/printers/" + p.ID
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, uri)
	data, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			t.Fatalf("driverless PPD failed: %s", e.Stderr)
		}
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "*PPD-Adobe:") || !strings.Contains(string(data), "application/pdf") {
		t.Fatal("PDF driverless profile not generated", string(data))
	}
}
