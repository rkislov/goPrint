// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package main

import (
	"flag"
	"fmt"
	"github.com/rkislov/goPrint/internal/buildinfo"
	"github.com/rkislov/goPrint/internal/drivers"
	"os"
)

func main() {
	dir := flag.String("dir", "./var/goprint/ppds", "catalog directory")
	vendor := flag.Bool("katusha", false, "import official Katusha ZIP instead of OpenPrinting tar.gz")
	archive := flag.String("archive", "", "local OpenPrinting .tar.gz archive")
	version := flag.Bool("version", false, "print build version")
	flag.Parse()
	if *version {
		fmt.Println(buildinfo.String())
		return
	}
	if *archive == "" {
		fmt.Fprintln(os.Stderr, "specify -archive PATH")
		os.Exit(1)
	}
	var importErr error
	if *vendor {
		c, e := drivers.Open(*dir)
		importErr = e
		if e == nil {
			var b []byte
			b, importErr = os.ReadFile(*archive)
			if importErr == nil {
				importErr = c.ImportKatusha(b)
			}
		}
	} else {
		importErr = run(*dir, *archive)
	}
	if err := importErr; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(dir, path string) error {
	c, err := drivers.Open(dir)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = c.Import(f); err != nil {
		return err
	}
	s := c.Status()
	fmt.Printf("Indexed %d PPDs; skipped %d; source SHA-256 %s\n", s.Count, s.Skipped, s.SHA256)
	return nil
}
