//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package sambaprint

import (
	"golang.org/x/sys/unix"
	"os"
)

func peerUID(fd uintptr) (uint32, error) {
	c, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if e != nil {
		return 0, e
	}
	return c.Uid, nil
}

func openSpool(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
