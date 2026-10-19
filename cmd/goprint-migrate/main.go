// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rkislov/goPrint/internal/database"
	"github.com/rkislov/goPrint/internal/migration"
	"os"
)

func main() {
	dir := flag.String("data", "./var/goprint", "stopped installation data directory")
	file := flag.String("postgres-dsn-file", "", "private target DSN file")
	execute := flag.Bool("execute", false, "commit migration; default validates then rolls back")
	flag.Parse()
	dsn, err := database.ReadDSN(*file)
	if err == nil {
		var report migration.Report
		report, err = migration.Run(context.Background(), *dir, dsn, *execute)
		if err == nil {
			json.NewEncoder(os.Stdout).Encode(report)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "migration failed:", err)
		os.Exit(1)
	}
}
