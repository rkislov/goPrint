// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/queue"

	"strings"
)

type printDefaults struct {
	media, sides, color string
	x, y                int
}

func (s *Server) defaults(p queue.Printer) (printDefaults, error) {
	d := printDefaults{media: "iso_a4_210x297mm", sides: "one-sided", color: "color", x: 21000, y: 29700}
	if p.PPDID == "" {
		return d, nil
	}
	if s.Catalog == nil {
		return d, fmt.Errorf("PPD catalog unavailable")
	}
	data, err := s.Catalog.PPD(p.PPDID)
	if err != nil {
		return d, err
	}
	values := map[string]string{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 4<<20)
	for scan.Scan() {
		k, v, ok := strings.Cut(scan.Text(), ":")
		if ok {
			values[strings.Split(k, "/")[0]] = strings.Trim(strings.TrimSpace(v), "\"")
		}
	}
	page := values["*DefaultPageSize"]
	switch page {
	case "A3":
		d.media = "iso_a3_297x420mm"
		d.x = 29700
		d.y = 42000
	case "Letter":
		d.media = "na_letter_8.5x11in"
		d.x = 21590
		d.y = 27940
	case "Legal":
		d.media = "na_legal_8.5x14in"
		d.x = 21590
		d.y = 35560
	case "A4":
	default:
		return d, fmt.Errorf("unsupported PPD default paper size for client provisioning")
	}
	switch values["*DefaultDuplex"] {
	case "DuplexNoTumble":
		d.sides = "two-sided-long-edge"
	case "DuplexTumble":
		d.sides = "two-sided-short-edge"
	}
	if values["*ColorDevice"] == "False" || values["*DefaultColorSpace"] == "Gray" {
		d.color = "monochrome"
	}
	return d, scan.Err()
}
func (d printDefaults) mediaCollection() goipp.Collection {
	var size goipp.Attributes
	add(&size, "x-dimension", goipp.TagInteger, goipp.Integer(d.x))
	add(&size, "y-dimension", goipp.TagInteger, goipp.Integer(d.y))
	var col goipp.Attributes
	add(&col, "media-size", goipp.TagBeginCollection, goipp.Collection(size))
	return goipp.Collection(col)
}
func (d printDefaults) optionsSupported(attrs goipp.Attributes) bool {
	for _, a := range attrs {
		if len(a.Values) != 1 {
			return false
		}
		v := a.Values[0].V
		switch a.Name {
		case "copies", "number-up":
			if n, ok := v.(goipp.Integer); !ok || n != 1 {
				return false
			}
		case "media":
			if x, ok := v.(goipp.String); !ok || string(x) != d.media {
				return false
			}
		case "sides":
			if x, ok := v.(goipp.String); !ok || string(x) != d.sides {
				return false
			}
		case "print-color-mode":
			if x, ok := v.(goipp.String); !ok || string(x) != d.color {
				return false
			}
		case "media-col":
			col, ok := v.(goipp.Collection)
			if !ok {
				return false
			}
			for _, member := range col {
				if len(member.Values) != 1 {
					return false
				}
				switch member.Name {
				case "media-size":
					size, ok := member.Values[0].V.(goipp.Collection)
					if !ok || len(size) != 2 || intAttr(goipp.Attributes(size), "x-dimension") != d.x || intAttr(goipp.Attributes(size), "y-dimension") != d.y {
						return false
					}
				case "media-size-name":
					if name, ok := member.Values[0].V.(goipp.String); !ok || string(name) != d.media {
						return false
					}
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
func (d printDefaults) attributes() goipp.Attributes {
	var a goipp.Attributes
	add(&a, "media-col-default", goipp.TagBeginCollection, d.mediaCollection())
	add(&a, "media-col-database", goipp.TagBeginCollection, d.mediaCollection())
	multi(&a, "media-col-supported", goipp.TagKeyword, []string{"media-size", "media-size-name"})
	add(&a, "media-default", goipp.TagKeyword, goipp.String(d.media))
	multi(&a, "media-supported", goipp.TagKeyword, []string{d.media})
	add(&a, "media-ready", goipp.TagKeyword, goipp.String(d.media))
	add(&a, "sides-default", goipp.TagKeyword, goipp.String(d.sides))
	multi(&a, "sides-supported", goipp.TagKeyword, []string{d.sides})
	add(&a, "print-color-mode-default", goipp.TagKeyword, goipp.String(d.color))
	multi(&a, "print-color-mode-supported", goipp.TagKeyword, []string{d.color})
	add(&a, "color-supported", goipp.TagBoolean, goipp.Boolean(d.color == "color"))
	return a
}
