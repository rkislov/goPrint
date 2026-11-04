// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSindohManifestAndIntegrity(t *testing.T) {
	if !validateSindohManifest() {
		t.Fatal("invalid download manifest")
	}
	c, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if c.ImportSindoh([]byte("untrusted driver")) == nil {
		t.Fatal("unpinned archive accepted")
	}
}
func TestSindohExtractionNoInstallerOrTraversal(t *testing.T) {
	ppd := []byte("*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Sindoh\"\n*NickName: \"Sindoh test\"\n*LanguageVersion: English\n")
	var nested bytes.Buffer
	gz := gzip.NewWriter(&nested)
	tr := tar.NewWriter(gz)
	tr.WriteHeader(&tar.Header{Name: "../../nested.ppd", Mode: 0600, Size: int64(len(ppd))})
	tr.Write(ppd)
	tr.Close()
	gz.Close()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for n, data := range map[string][]byte{"Linux/CUPS1.2/EN/test.ppd": ppd, "Linux/CUPS1.1/EN/old.ppd": ppd, "Linux/CUPS1.2/DE/de.ppd": ppd, "install.sh": []byte("exit 99"), "x86_64/driver.tar.gz": nested.Bytes()} {
		w, _ := z.Create(n)
		w.Write(data)
	}
	z.Close()
	out, e := sindohPPDs(b.Bytes())
	if e != nil || len(out) != 2 {
		t.Fatal(len(out), e)
	}
	for _, p := range out {
		if !bytes.Equal(p.data, ppd) {
			t.Fatal("PPD changed")
		}
	}
}
func TestSindohSurvivesCatalogRefreshAndRestart(t *testing.T) {
	dir := t.TempDir()
	p, e := Parse([]byte("*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Sindoh\"\n*NickName: \"Sindoh test\"\n"))
	if e != nil {
		t.Fatal(e)
	}
	p.Source = sindohSource
	b, _ := json.Marshal([]Profile{p})
	os.WriteFile(filepath.Join(dir, "vendor-sindoh.json"), b, 0600)
	c, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if c.SindohStatus().Count != 1 {
		t.Fatal("Sindoh index not loaded")
	}
	if e = c.Import(bytes.NewReader(archive(t, "other.ppd", "*PPD-Adobe: \"4.3\"\n*ModelName: \"Other\"\n"))); e != nil {
		t.Fatal(e)
	}
	c, e = Open(dir)
	if e != nil || c.SindohStatus().Count != 1 || len(c.Search("", "Sindoh")) != 1 {
		t.Fatal("vendor lost", e)
	}
}
