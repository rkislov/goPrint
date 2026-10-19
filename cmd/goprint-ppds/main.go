// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package main

import (
	"flag"
	"fmt"
	"github.com/rkislov/goPrint/internal/drivers"
	"os"
)

func main() {
	dir := flag.String("dir", "./var/goprint/ppds", "catalog directory")
	archive := flag.String("archive", "", "local OpenPrinting .tar.gz archive")
	flag.Parse()
	if *archive == "" {
		fmt.Fprintln(os.Stderr, "specify -archive PATH")
		os.Exit(1)
	}
	if err := run(*dir, *archive); err != nil {
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
