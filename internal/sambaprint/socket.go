// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package sambaprint authenticates local print submitters using kernel peer credentials.
package sambaprint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Socket    string            `json:"socket"`
	SocketGID *int              `json:"socket_gid,omitempty"`
	Users     map[string]string `json:"users"`
}

func Load(path string) (Config, error) {
	var c Config
	st, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > 1<<20 {
		return c, errors.New("Samba config must be a regular file without group/other write access")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("unexpected Samba config data")
	}
	if !filepath.IsAbs(c.Socket) || len(c.Socket) > 100 || len(c.Users) == 0 || len(c.Users) > 10000 {
		return c, errors.New("Samba config requires an absolute socket path and UID-to-UPN mappings")
	}
	if c.SocketGID != nil && (*c.SocketGID < 0 || uint64(*c.SocketGID) >= 1<<32-1) {
		return c, errors.New("invalid socket group")
	}
	for uid, upn := range c.Users {
		n, e := strconv.ParseUint(uid, 10, 32)
		if e != nil || (n == 0 || n == 1<<32-1) || strconv.FormatUint(n, 10) != uid || len(upn) > 254 || strings.Count(upn, "@") != 1 || strings.ContainsAny(upn, "\r\n\x00\t ") {
			return c, errors.New("map non-root numeric Unix UIDs to domain UPNs")
		}
	}
	return c, nil
}
func Listen(c Config) (*net.UnixListener, error) {
	st, e := os.Stat(filepath.Dir(c.Socket))
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("socket directory must not be writable by group/others")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(c.Socket, 0660); e == nil && c.SocketGID != nil {
		e = os.Chown(c.Socket, -1, *c.SocketGID)
	}
	if e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}

type peerKey struct{}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return ctx
	}
	var uid uint32
	var peerErr error
	e = raw.Control(func(fd uintptr) { uid, peerErr = peerUID(fd) })
	if e != nil || peerErr != nil {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, uid)
}
func UID(ctx context.Context) (uint32, bool) {
	v, ok := ctx.Value(peerKey{}).(uint32)
	return v, ok && v != 0
}

// OpenSpool prevents symlink substitution and a blocking FIFO-open race.
func OpenSpool(path string) (*os.File, error) { return openSpool(path) }
