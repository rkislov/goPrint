// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"math"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const poweredBy = "Работает на GoPrint"
const maxBrandLogo = 256 << 10

type brandingConfig struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	Logo  []byte `json:"logo,omitempty"`
}

type brandingView struct {
	Name        string `json:"name"`
	Color       string `json:"color"`
	LogoURL     string `json:"logo_url"`
	Attribution string `json:"attribution"`
}

func (c brandingConfig) view() brandingView {
	v := brandingView{Name: c.Name, Color: c.Color, Attribution: poweredBy}
	if len(c.Logo) > 0 {
		v.LogoURL = "/assets/brand-logo"
	}
	return v
}

func (s *Server) branding(ctx context.Context) (brandingConfig, error) {
	c := brandingConfig{Name: "GoPrint", Color: "#17654b"}
	if s.Store == nil {
		return c, nil
	}
	err := s.Store.Setting(ctx, "branding", &c)
	return c, err
}

func brandColor(value string) ([]byte, error) {
	if len(value) != 7 || value[0] != '#' {
		return nil, fmt.Errorf("Цвет должен иметь формат #RRGGBB")
	}
	rgb, err := hex.DecodeString(value[1:])
	if err != nil {
		return nil, fmt.Errorf("Цвет должен иметь формат #RRGGBB")
	}
	luminance := 0.0
	for i, weight := range []float64{.2126, .7152, .0722} {
		channel := float64(rgb[i]) / 255
		if channel <= .04045 {
			channel /= 12.92
		} else {
			channel = math.Pow((channel+.055)/1.055, 2.4)
		}
		luminance += weight * channel
	}
	if 1.05/(luminance+.05) < 4.5 {
		return nil, fmt.Errorf("Выберите более тёмный цвет: контраст с белым текстом должен быть не ниже 4,5:1")
	}
	return rgb, nil
}

func brandShade(rgb []byte, factor float64) string {
	return fmt.Sprintf("#%02x%02x%02x", byte(float64(rgb[0])*factor), byte(float64(rgb[1])*factor), byte(float64(rgb[2])*factor))
}

func normalizeBrandLogo(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) > maxBrandLogo {
		return nil, fmt.Errorf("Логотип: PNG или JPEG размером до 256 КиБ")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "png" && format != "jpeg") || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 1024 || cfg.Height > 1024 {
		return nil, fmt.Errorf("Логотип: PNG или JPEG, не более 1024 × 1024 пикселей")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("Не удалось прочитать изображение логотипа")
	}
	var out bytes.Buffer
	if err = png.Encode(&out, img); err != nil {
		return nil, err
	}
	if out.Len() > 1<<20 {
		return nil, fmt.Errorf("Уменьшите разрешение или сложность логотипа")
	}
	return out.Bytes(), nil
}

func (s *Server) brandingRoutes(public, api *http.ServeMux) {
	public.HandleFunc("GET /api/branding", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.branding(r.Context())
		respond(w, c.view(), err)
	})
	public.HandleFunc("GET /assets/brand-logo", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.branding(r.Context())
		if err != nil {
			http.Error(w, "branding unavailable", 500)
			return
		}
		if len(c.Logo) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(c.Logo)
	})
	public.HandleFunc("GET /assets/branding.css", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.branding(r.Context())
		if err != nil {
			http.Error(w, "branding unavailable", 500)
			return
		}
		rgb, err := brandColor(c.Color)
		if err != nil {
			http.Error(w, "branding unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		fmt.Fprintf(w, ":root{--accent:%s;--brand-hover:%s;--brand-story:%s}", c.Color, brandShade(rgb, .8), brandShade(rgb, .65))
	})
	api.HandleFunc("PUT /api/branding", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name       string `json:"name"`
			Color      string `json:"color"`
			Logo       string `json:"logo_base64"`
			RemoveLogo bool   `json:"remove_logo"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 384<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			http.Error(w, "invalid branding JSON", 400)
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			http.Error(w, "expected one JSON object", 400)
			return
		}
		input.Name = strings.TrimSpace(input.Name)
		if !utf8.ValidString(input.Name) || utf8.RuneCountInString(input.Name) < 1 || utf8.RuneCountInString(input.Name) > 80 || strings.ContainsFunc(input.Name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			http.Error(w, "Название: от 1 до 80 символов без управляющих и скрытых знаков", 400)
			return
		}
		if _, err := brandColor(input.Color); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if input.RemoveLogo && input.Logo != "" {
			http.Error(w, "Выберите загрузку или удаление логотипа", 400)
			return
		}
		c, err := s.branding(r.Context())
		if err != nil || s.Store == nil {
			http.Error(w, "branding unavailable", 500)
			return
		}
		c.Name = input.Name
		c.Color = strings.ToLower(input.Color)
		if input.RemoveLogo {
			c.Logo = nil
		}
		if input.Logo != "" {
			c.Logo, err = normalizeBrandLogo(input.Logo)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		err = s.Store.SetSetting(r.Context(), "branding", c)
		respond(w, c.view(), err)
	})
}

func brandPage(page []byte, c brandingConfig) []byte {
	mark := `<span class="brand-mark">G</span>`
	if len(c.Logo) > 0 {
		mark = `<img class="brand-logo" src="/assets/brand-logo" alt="">`
	}
	title := c.Name
	if title != "GoPrint" {
		title += " · GoPrint"
	}
	return []byte(strings.NewReplacer("@@BRAND_TITLE@@", html.EscapeString(title), "@@BRAND_NAME@@", html.EscapeString(c.Name), "@@BRAND_MARK@@", mark).Replace(string(page)))
}
