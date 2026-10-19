// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package watermark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/goPrint/internal/queue"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type workerInput struct {
	Directory string
	Config    Config
	Job       queue.Job
	Input     string
}
type workerResult struct {
	Path  string
	Error string
}

// RunWorker is an internal subprocess entry point, before daemon flags/auth startup.
func RunWorker(in io.Reader, out io.Writer) error {
	var v workerInput
	if err := json.NewDecoder(io.LimitReader(in, 16<<10)).Decode(&v); err != nil {
		return err
	}
	e, err := New(v.Directory)
	if err != nil {
		return err
	}
	path, _, err := e.Prepare(context.Background(), v.Config, v.Job, v.Input)
	r := workerResult{Path: path}
	if err != nil {
		r.Error = err.Error()
	}
	return json.NewEncoder(out).Encode(r)
}

// PrepareIsolated keeps PDF parsing out of the daemon and enforces its context
// deadline by terminating the worker. The child never inherits the admin token.
func (e *Engine) PrepareIsolated(ctx context.Context, c Config, j queue.Job, input string) (string, func(), error) {
	noop := func() {}
	if !c.Enabled {
		return input, noop, nil
	}
	if j.Format != "application/pdf" {
		return "", noop, errors.New("обязательный watermark поддерживает только PDF; документ не отправлен")
	}
	dir, err := os.MkdirTemp(e.dir, ".job-")
	if err != nil {
		return "", noop, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	executable, err := os.Executable()
	if err != nil {
		cleanup()
		return "", noop, err
	}
	b, _ := json.Marshal(workerInput{Directory: dir, Config: c, Job: j, Input: input})
	cmd := exec.CommandContext(ctx, executable, "--watermark-worker")
	cmd.Stdin = bytes.NewReader(b)
	cmd.Env = []string{"GOMEMLIMIT=512MiB", "PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir()}
	output, err := cmd.Output()
	if err != nil {
		cleanup()
		return "", noop, errors.New("обработка watermark не завершилась; документ не отправлен")
	}
	var r workerResult
	if err = json.Unmarshal(output, &r); err != nil {
		cleanup()
		return "", noop, errors.New("некорректный результат watermark; документ не отправлен")
	}
	if r.Error != "" {
		cleanup()
		return "", noop, errors.New(r.Error)
	}
	absolute, _ := filepath.Abs(r.Path)
	allowed, _ := filepath.Abs(dir)
	if filepath.Dir(absolute) != allowed {
		cleanup()
		return "", noop, errors.New("некорректный путь watermark")
	}
	return r.Path, cleanup, nil
}
