// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ulikunitz/xz"
	"os"
	"path/filepath"
	"testing"
)

func TestVendorProfilesSurviveOpenPrintingRefresh(t *testing.T) {
	dir := t.TempDir()
	p, err := Parse([]byte("*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Катюша\"\n*NickName: \"Katusha test\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	p.Source = katushaSource
	b, _ := json.Marshal([]Profile{p})
	os.WriteFile(filepath.Join(dir, "vendor-katusha.json"), b, 0600)
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.KatushaStatus().Count != 1 {
		t.Fatal("vendor not loaded")
	}
	if err = c.Import(bytes.NewReader(archive(t, "test.ppd", "*PPD-Adobe: \"4.3\"\n*ModelName: \"Other\"\n"))); err != nil {
		t.Fatal(err)
	}
	c, err = Open(dir)
	if err != nil || c.Status().Count != 2 || len(c.Search("", "Катюша")) != 1 {
		t.Fatal(c.Status(), err)
	}
	if err = c.ImportKatusha([]byte("changed vendor archive")); err == nil {
		t.Fatal("unpinned archive accepted")
	}
}
func TestDebPPDExtractionDoesNotExecuteOrTrustPaths(t *testing.T) {
	var compressed bytes.Buffer
	x, _ := xz.NewWriter(&compressed)
	tw := tar.NewWriter(x)
	data := []byte("*PPD-Adobe: \"4.3\"\n*ModelName: \"Test\"\n")
	tw.WriteHeader(&tar.Header{Name: "../../escape.ppd", Mode: 0600, Size: int64(len(data))})
	tw.Write(data)
	tw.Close()
	x.Close()
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	fmt.Fprintf(&ar, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", "data.tar.xz/", "0", "0", "0", "100644", compressed.Len())
	ar.Write(compressed.Bytes())
	if compressed.Len()%2 != 0 {
		ar.WriteByte('\n')
	}
	ppds, err := debPPDs(ar.Bytes())
	if err != nil || !bytes.Equal(ppds["escape.ppd"], data) {
		t.Fatal(ppds, err)
	}
}
