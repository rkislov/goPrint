//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package sambaprint

import (
	"errors"
	"os"
)

func peerUID(fd uintptr) (uint32, error) {
	return 0, errors.New("Samba peer authentication unsupported on this OS")
}

func openSpool(path string) (*os.File, error) {
	return nil, errors.New("Samba spool helper requires Linux or macOS")
}
