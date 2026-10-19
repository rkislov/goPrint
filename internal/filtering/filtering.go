// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package filtering prepares printer-ready data using a verified PPD and the
// system CUPS filter subsystem, without involving the CUPS queue or backends.
package filtering

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/queue"
)

const DefaultOutputLimit int64 = 512 << 20

var ErrUnavailable = errors.New("cupsfilter не установлен; установите CUPS и пакет фильтров")

type Result struct {
	Path    string
	Format  string
	Size    int64
	Chain   []string
	Cleanup func()
}
type Engine struct {
	dir     string
	catalog *drivers.Catalog
	program string
	limit   int64
}

func New(dir string, catalog *drivers.Catalog, limit int64) (*Engine, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("filter output limit must be positive")
	}
	return &Engine{dir: dir, catalog: catalog, limit: limit}, nil
}
func Executable() (string, error) {
	for _, p := range []string{"/usr/sbin/cupsfilter", "/usr/bin/cupsfilter", "/opt/homebrew/sbin/cupsfilter", "/opt/homebrew/bin/cupsfilter", "/usr/local/sbin/cupsfilter", "/usr/local/bin/cupsfilter"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return p, nil
		}
	}
	if p, err := exec.LookPath("cupsfilter"); err == nil {
		return filepath.Abs(p)
	}
	return "", ErrUnavailable
}
func (e *Engine) prepare(ctx context.Context, p queue.Printer, j queue.Job, input string) (Result, error) {
	r := Result{Cleanup: func() {}}
	if p.PPDID == "" {
		info, err := os.Stat(input)
		if err != nil {
			return r, err
		}
		r.Path = input
		r.Format = j.Format
		r.Size = info.Size()
		return r, nil
	}
	if !queue.Accepts(p, j.Format) {
		return r, errors.New("выбранный PPD требует PDF, PostScript или изображение; RAW не отправлен")
	}
	if os.Geteuid() == 0 {
		return r, errors.New("PPD-фильтры нельзя запускать от root; используйте пользователя goprint")
	}
	program := e.program
	var err error
	if program == "" {
		program, err = Executable()
		if err != nil {
			return r, err
		}
	}
	if e.catalog == nil {
		return r, errors.New("каталог PPD недоступен")
	}
	data, err := e.catalog.PPD(p.PPDID)
	if err != nil {
		return r, err
	}
	spec, err := parseSpec(data)
	if err != nil {
		return r, err
	}
	dir, err := os.MkdirTemp(e.dir, ".job-")
	if err != nil {
		return r, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	absolute, err := filepath.Abs(input)
	if err != nil {
		return r, err
	}
	ppd := filepath.Join(dir, "printer.ppd")
	ppd, err = filepath.Abs(ppd)
	if err != nil {
		return r, err
	}
	if err = os.WriteFile(ppd, data, 0600); err != nil {
		return r, err
	}
	absoluteDir, err := filepath.Abs(dir)
	if err != nil {
		return r, err
	}
	// Preserve helper search paths, but do not inherit admin/device tokens, proxy
	// credentials, loader overrides or CUPS environment overrides from the daemon.
	env := []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C", "TMPDIR=" + absoluteDir, "RIP_MAX_CACHE=128m"}
	var selected []string
	if j.Options != (queue.PrintOptions{}) {
		caps, err := drivers.CapabilitiesFor(data)
		if err != nil {
			return r, err
		}
		selected, err = caps.CUPSOptions(j.Options)
		if err != nil {
			return r, err
		}
	}
	args := []string{"-p", ppd, "-i", j.Format, "-m", "printer/goprint", "-e", "-U", j.Owner, "-t", "GoPrint " + j.ID, "-n", "1"}
	for _, option := range selected {
		args = append(args, "-o", option)
	}
	args = append(args, "--", absolute)
	var plan bytes.Buffer
	if _, err = run(ctx, program, append([]string{"--list-filters"}, args...), env, absoluteDir, &plan, 64<<10); err != nil {
		return r, fmt.Errorf("не удалось построить цепочку PPD%s; проверьте установку драйверов и MIME-фильтров", spec.required())
	}
	chain, err := parseChain(plan.String())
	if err != nil {
		return r, err
	}
	output := filepath.Join(absoluteDir, "document.data")
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return r, err
	}
	n, err := run(ctx, program, args, env, absoluteDir, f, e.limit)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		if errors.Is(err, errOutputLimit) {
			return r, fmt.Errorf("результат фильтрации превышает лимит %d МиБ; документ не отправлен", e.limit>>20)
		}
		if ctx.Err() != nil {
			return r, errors.New("превышено время обработки PPD; документ не отправлен")
		}
		return r, fmt.Errorf("ошибка цепочки PPD%s; документ не отправлен", spec.required())
	}
	if closeErr != nil {
		return r, closeErr
	}
	if n == 0 {
		return r, errors.New("фильтры вернули пустой документ; печать заблокирована")
	}
	success = true
	return Result{Path: output, Format: spec.outputFormat(), Size: n, Chain: chain, Cleanup: cleanup}, nil
}
func (e *Engine) Prepare(ctx context.Context, p queue.Printer, j queue.Job, input string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return e.prepare(ctx, p, j, input)
}

type rule struct{ input, output, program string }
type specification struct {
	rules  []rule
	legacy bool
}

func parseSpec(data []byte) (specification, error) {
	var s specification
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		key, v, ok := strings.Cut(scanner.Text(), ":")
		if !ok || (key != "*cupsFilter" && key != "*cupsFilter2") {
			continue
		}
		fields := strings.Fields(strings.Trim(strings.TrimSpace(v), "\""))
		want := 3
		if key == "*cupsFilter2" {
			want = 4
		}
		if len(fields) != want {
			return s, errors.New("некорректное описание cupsFilter в PPD")
		}
		r := rule{input: fields[0], program: fields[want-1]}
		if want == 4 {
			r.output = fields[1]
		} else {
			s.legacy = true
		}
		s.rules = append(s.rules, r)
		if len(s.rules) > 64 {
			return s, errors.New("слишком много фильтров в PPD")
		}
	}
	return s, scanner.Err()
}
func (s specification) required() string {
	set := map[string]bool{}
	var names []string
	for _, r := range s.rules {
		n := filepath.Base(r.program)
		if n != "-" && safeName(n) && !set[n] {
			names = append(names, n)
			set[n] = true
		}
	}
	if len(names) == 0 {
		return ""
	}
	return " (требуется: " + strings.Join(names, ", ") + ")"
}
func (s specification) outputFormat() string {
	if len(s.rules) == 0 {
		return "application/postscript"
	}
	// CUPS legacy filter rules do not declare a wire MIME type. Use IPP's raw
	// auto-detection type instead of incorrectly sending rendered PCL as PDF.
	out := ""
	for _, r := range s.rules {
		if r.output == "" {
			continue
		}
		v := wireFormat(r.output)
		if out != "" && out != v {
			return "application/octet-stream"
		}
		out = v
	}
	if out != "" {
		return out
	}
	return "application/octet-stream"
}
func wireFormat(value string) string {
	switch value {
	case "application/vnd.cups-postscript":
		return "application/postscript"
	case "application/vnd.cups-pdf":
		return "application/pdf"
	}
	v, _, err := mime.ParseMediaType(value)
	if err != nil || !strings.Contains(v, "/") {
		return "application/octet-stream"
	}
	return v
}
func parseChain(value string) ([]string, error) {
	out := []string{}
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name := filepath.Base(line)
		if !safeName(name) || len(out) >= 64 {
			return nil, errors.New("некорректный список фильтров CUPS")
		}
		out = append(out, name)
	}
	return out, nil
}
func safeName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}
