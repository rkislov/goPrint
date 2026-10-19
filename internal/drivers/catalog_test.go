// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func archive(t *testing.T, name, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	if err := w.WriteHeader(&tar.Header{Name: name, Size: int64(len(content)), Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(content))
	w.Close()
	g.Close()
	return b.Bytes()
}
func TestCatalogPersistsAndDoesNotUseArchivePaths(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := archive(t, "../../escaped.ppd", "*PPD-Adobe: \"4.3\"\n*Manufacturer: \"HP\"\n*NickName: \"LaserJet Test\"\n*cupsFilter: \"application/vnd.cups-raster 0 rastertohp\"\n")
	if err = c.Import(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	c, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	matches := c.Search("laserjet", "HP")
	if len(matches) != 1 || len(matches[0].Filters) != 1 {
		t.Fatalf("catalog: %+v", matches)
	}
	if _, err = os.Stat(filepath.Join(dir, matches[0].ID+".ppd")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "escaped.ppd")); !os.IsNotExist(err) {
		t.Fatal("archive destination used")
	}
	if c.Status().SHA256 == "" {
		t.Fatal("missing source digest")
	}
}
func TestInvalidUpdateKeepsPreviousCatalog(t *testing.T) {
	c, _ := Open(t.TempDir())
	good := archive(t, "good.ppd", "*PPD-Adobe: \"4.3\"\n*ModelName: \"Printer\"\n")
	if err := c.Import(bytes.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	if err := c.Import(bytes.NewReader(archive(t, "bad.ppd", "garbage"))); err == nil {
		t.Fatal("bad archive accepted")
	}
	if c.Status().Count != 1 {
		t.Fatal("valid catalog lost")
	}
}
