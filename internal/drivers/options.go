// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/rkislov/goPrint/internal/queue"
	"math"
	"strconv"
	"strings"
)

type Media struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Choice string `json:"-"`
}
type Capabilities struct {
	Defaults     queue.PrintOptions `json:"defaults"`
	Media        []Media            `json:"media"`
	Sides        []string           `json:"sides"`
	Color        []string           `json:"color"`
	Editable     bool               `json:"editable"`
	sideKey      string
	sideChoices  map[string]string
	colorKey     string
	colorChoices map[string]string
}

var paperSizes = map[string]Media{"A4": {Key: "iso_a4_210x297mm", Label: "A4", Width: 21000, Height: 29700}, "A3": {Key: "iso_a3_297x420mm", Label: "A3", Width: 29700, Height: 42000}, "A5": {Key: "iso_a5_148x210mm", Label: "A5", Width: 14800, Height: 21000}, "Letter": {Key: "na_letter_8.5x11in", Label: "Letter", Width: 21590, Height: 27940}, "Legal": {Key: "na_legal_8.5x14in", Label: "Legal", Width: 21590, Height: 35560}, "B5": {Key: "iso_b5_176x250mm", Label: "B5", Width: 17600, Height: 25000}}

func DirectCapabilities() Capabilities {
	m := paperSizes["A4"]
	return Capabilities{Defaults: queue.PrintOptions{Media: m.Key, Sides: "one-sided", Color: "color"}, Media: []Media{m}, Sides: []string{"one-sided"}, Color: []string{"color"}}
}
func CapabilitiesFor(data []byte) (Capabilities, error) {
	c := Capabilities{Editable: true, sideChoices: map[string]string{}, colorChoices: map[string]string{}}
	values := map[string]string{}
	choices := map[string][]string{}
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 4096), maxPPD)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		k = strings.Split(k, "/")[0]
		values[k] = strings.Trim(strings.TrimSpace(v), "\"")
		if key, choice, ok := strings.Cut(k, " "); ok {
			choices[key] = append(choices[key], choice)
		}
	}
	if err := s.Err(); err != nil {
		return c, err
	}
	for _, choice := range choices["*PageSize"] {
		if m, ok := paperSizes[choice]; ok {
			dims := strings.Fields(values["*PaperDimension "+choice])
			if len(dims) == 2 {
				w, e1 := strconv.ParseFloat(dims[0], 64)
				h, e2 := strconv.ParseFloat(dims[1], 64)
				if e1 != nil || e2 != nil {
					continue
				}
				width, height := w*2540/72, h*2540/72
				if choice == "B5" && math.Abs(width-18200) < 100 && math.Abs(height-25700) < 100 {
					m.Key = "jis_b5_182x257mm"
					m.Label = "B5 (JIS)"
					m.Width = 18200
					m.Height = 25700
				}
				if math.Abs(width-float64(m.Width)) > 100 || math.Abs(height-float64(m.Height)) > 100 {
					continue
				}
			} else if choice == "B5" {
				continue
			}
			m.Choice = choice
			c.Media = append(c.Media, m)
			if choice == values["*DefaultPageSize"] {
				c.Defaults.Media = m.Key
			}
		}
	}
	if len(c.Media) == 0 || c.Defaults.Media == "" {
		return c, errors.New("PPD не описывает поддерживаемый формат бумаги по умолчанию")
	}
	c.sideKey = "Duplex"
	if len(choices["*Duplex"]) == 0 {
		c.sideKey = "JCLDuplex"
	}
	for _, choice := range choices["*"+c.sideKey] {
		var name string
		switch choice {
		case "None", "False", "Off":
			name = "one-sided"
		case "DuplexNoTumble":
			name = "two-sided-long-edge"
		case "DuplexTumble":
			name = "two-sided-short-edge"
		default:
			continue
		}
		if _, exists := c.sideChoices[name]; !exists {
			c.Sides = append(c.Sides, name)
			c.sideChoices[name] = choice
		}
		if choice == values["*Default"+c.sideKey] {
			c.Defaults.Sides = name
		}
	}
	if len(c.Sides) == 0 {
		c.Sides = []string{"one-sided"}
		c.Defaults.Sides = "one-sided"
		c.sideKey = ""
	} else if c.Defaults.Sides == "" {
		c.Defaults.Sides = c.Sides[0]
	}
	for _, key := range []string{"ColorModel", "ColorMode"} {
		m := map[string]string{}
		var ordered []string
		def := ""
		for _, choice := range choices["*"+key] {
			name := ""
			switch strings.ToLower(choice) {
			case "gray", "grayscale", "grey", "black", "mono", "monochrome":
				name = "monochrome"
			case "rgb", "cmyk", "color", "colour":
				name = "color"
			}
			if name == "" {
				continue
			}
			if _, ok := m[name]; !ok {
				m[name] = choice
				ordered = append(ordered, name)
			}
			if choice == values["*Default"+key] {
				def = name
			}
		}
		if len(m) > 0 && def != "" {
			c.colorKey = key
			c.colorChoices = m
			c.Color = ordered
			c.Defaults.Color = def
			break
		}
	}
	if len(c.Color) == 0 {
		c.Defaults.Color = "color"
		if strings.EqualFold(values["*ColorDevice"], "False") || values["*DefaultColorSpace"] == "Gray" {
			c.Defaults.Color = "monochrome"
		}
		c.Color = []string{c.Defaults.Color}
	}
	return c, nil
}
func (c Capabilities) Resolve(base, override queue.PrintOptions) (queue.PrintOptions, error) {
	out := c.Defaults
	for _, v := range []queue.PrintOptions{base, override} {
		if v.Media != "" {
			out.Media = v.Media
		}
		if v.Sides != "" {
			out.Sides = v.Sides
		}
		if v.Color != "" {
			out.Color = v.Color
		}
	}
	found := false
	for _, m := range c.Media {
		if m.Key == out.Media {
			found = true
		}
	}
	if !found || !contains(c.Sides, out.Sides) || !contains(c.Color, out.Color) {
		return out, errors.New("бумага, дуплекс или цвет не поддерживаются выбранным PPD")
	}
	return out, nil
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func (c Capabilities) CUPSOptions(o queue.PrintOptions) ([]string, error) {
	o, err := c.Resolve(queue.PrintOptions{}, o)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range c.Media {
		if m.Key == o.Media && m.Choice != "" {
			out = append(out, "PageSize="+m.Choice)
		}
	}
	if c.sideKey != "" {
		out = append(out, c.sideKey+"="+c.sideChoices[o.Sides])
	}
	if c.colorKey != "" {
		out = append(out, c.colorKey+"="+c.colorChoices[o.Color])
	}
	return out, nil
}
