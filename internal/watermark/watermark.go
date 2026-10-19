// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package watermark

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/rkislov/goPrint/internal/queue"
)

type Config struct {
	Enabled  bool    `json:"enabled"`
	Text     string  `json:"text"`
	Opacity  float64 `json:"opacity"`
	Angle    int     `json:"angle"`
	FontSize int     `json:"font_size"`
	Version  string  `json:"version,omitempty"`
}

func Default() Config {
	return Config{Text: "КОНФИДЕНЦИАЛЬНО · {{user}}", Opacity: .15, Angle: 45, FontSize: 32}
}
func Validate(c Config) error {
	if len(strings.TrimSpace(c.Text)) == 0 || len(c.Text) > 1024 {
		return errors.New("текст watermark должен содержать от 1 до 1024 байт")
	}
	for _, r := range c.Text {
		if unicode.IsControl(r) && r != '\n' {
			return errors.New("управляющие символы в тексте запрещены")
		}
	}
	if c.Opacity < .05 || c.Opacity > .8 {
		return errors.New("непрозрачность должна быть от 0.05 до 0.8")
	}
	if c.Angle < -90 || c.Angle > 90 {
		return errors.New("угол должен быть от -90 до 90")
	}
	if c.FontSize < 8 || c.FontSize > 100 {
		return errors.New("размер шрифта должен быть от 8 до 100")
	}
	return nil
}

type Engine struct{ dir string }

var renderMu sync.Mutex
var initializedDir string

func New(dir string) (*Engine, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Engine{dir: dir}, nil
}
func (e *Engine) Prepare(ctx context.Context, c Config, j queue.Job, input string) (string, func(), error) {
	noop := func() {}
	if !c.Enabled {
		return input, noop, nil
	}
	if j.Format != "application/pdf" {
		return "", noop, errors.New("обязательный watermark поддерживает только PDF; документ не отправлен")
	}
	if err := Validate(c); err != nil {
		return "", noop, err
	}
	if err := ctx.Err(); err != nil {
		return "", noop, err
	}
	renderMu.Lock()
	defer renderMu.Unlock()
	// Initialize bundled Roboto in our private directory, including Cyrillic glyphs.
	if initializedDir != e.dir {
		if err := model.EnsureDefaultConfigAt(e.dir, false); err != nil {
			return "", noop, err
		}
		api.DisableConfigDir()
		initializedDir = e.dir
	}
	text := strings.NewReplacer("{{user}}", j.Owner, "{{job}}", j.ID, "{{date}}", time.Now().UTC().Format(time.RFC3339)).Replace(c.Text)
	f, err := os.CreateTemp(e.dir, ".marked-*.pdf")
	if err != nil {
		return "", noop, err
	}
	path := f.Name()
	f.Close()
	cleanup := func() { os.Remove(path) }
	desc := fmt.Sprintf("fontname:Roboto-Regular, points:%d, rotation:%d, opacity:%.3f, scalefactor:1 abs, position:c, fillcolor:0.45 0.45 0.45", c.FontSize, c.Angle, c.Opacity)
	conf := model.NewDefaultConfiguration()
	conf.Offline = true
	if err = api.AddTextWatermarksFile(input, path, nil, true, text, desc, conf); err != nil {
		cleanup()
		return "", noop, errors.New("не удалось нанести обязательный watermark; документ не отправлен")
	}
	if err = ctx.Err(); err != nil {
		cleanup()
		return "", noop, err
	}
	return path, cleanup, nil
}
