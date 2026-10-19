// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package filtering

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"
)

var errOutputLimit = errors.New("filter output limit exceeded")

type boundedWriter struct {
	w        io.Writer
	n, limit int64
	cancel   context.CancelFunc
	exceeded bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.n {
		w.exceeded = true
		if w.cancel != nil {
			w.cancel()
		}
		return 0, errOutputLimit
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

// discardTail keeps diagnostics bounded without blocking the filter's stderr.
type discardTail struct {
	b     []byte
	limit int
}

func (w *discardTail) Write(p []byte) (int, error) {
	n := len(p)
	if len(w.b) < w.limit {
		left := w.limit - len(w.b)
		if len(p) > left {
			p = p[:left]
		}
		w.b = append(w.b, p...)
	}
	return n, nil
}
func run(ctx context.Context, program string, args, env []string, dir string, out io.Writer, limit int64) (int64, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	writer := &boundedWriter{w: out, limit: limit, cancel: cancel}
	diagnostic := &discardTail{limit: 32 << 10}
	cmd := exec.CommandContext(child, program, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = writer
	cmd.Stderr = diagnostic
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	err := cmd.Wait()
	// Drivers may start child processes: never leave their group running after
	// conversion, including when cupsfilter itself exits before its children.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if writer.exceeded {
		return writer.n, errOutputLimit
	}
	if ctx.Err() != nil {
		return writer.n, ctx.Err()
	}
	return writer.n, err
}
