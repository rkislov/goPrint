// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

package buildinfo

import "fmt"

var Version = "dev"
var Commit = "unknown"
var Date = "unknown"

func String() string { return fmt.Sprintf("GoPrint %s (%s, %s)", Version, Commit, Date) }
