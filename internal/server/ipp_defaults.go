// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"errors"
	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/drivers"
	"github.com/rkislov/goPrint/internal/queue"
	"net/http"
)

type printDefaults struct {
	caps    drivers.Capabilities
	options queue.PrintOptions
}

func (s *Server) defaults(p queue.Printer) (printDefaults, error) {
	c, err := s.capabilities(p)
	return printDefaults{c, c.Defaults}, err
}
func (s *Server) defaultsFor(r *http.Request, p queue.Printer) (printDefaults, error) {
	d, err := s.defaults(p)
	if err != nil {
		return d, err
	}
	if id, ok := s.identity(r); ok && id.User != "" {
		d.options, err = s.effectiveOptions(r, p, queue.PrintOptions{})
	}
	return d, err
}
func mediaCollection(m drivers.Media) goipp.Collection {
	var size goipp.Attributes
	add(&size, "x-dimension", goipp.TagInteger, goipp.Integer(m.Width))
	add(&size, "y-dimension", goipp.TagInteger, goipp.Integer(m.Height))
	var a goipp.Attributes
	add(&a, "media-size", goipp.TagBeginCollection, goipp.Collection(size))
	return goipp.Collection(a)
}
func (d printDefaults) selected(attrs goipp.Attributes) (queue.PrintOptions, error) {
	var o queue.PrintOptions
	bad := errors.New("unsupported print option")
	for _, a := range attrs {
		if len(a.Values) != 1 {
			return o, bad
		}
		v := a.Values[0].V
		switch a.Name {
		case "copies", "number-up":
			if n, ok := v.(goipp.Integer); !ok || n != 1 {
				return o, bad
			}
		case "media":
			x, ok := v.(goipp.String)
			if !ok {
				return o, bad
			}
			o.Media = string(x)
		case "sides":
			x, ok := v.(goipp.String)
			if !ok {
				return o, bad
			}
			o.Sides = string(x)
		case "print-color-mode":
			x, ok := v.(goipp.String)
			if !ok {
				return o, bad
			}
			o.Color = string(x)
		case "media-col":
			col, ok := v.(goipp.Collection)
			if !ok {
				return o, bad
			}
			for _, member := range col {
				if len(member.Values) != 1 {
					return o, bad
				}
				switch member.Name {
				case "media-size":
					size, ok := member.Values[0].V.(goipp.Collection)
					if !ok {
						return o, bad
					}
					matched := ""
					for _, m := range d.caps.Media {
						if intAttr(goipp.Attributes(size), "x-dimension") == m.Width && intAttr(goipp.Attributes(size), "y-dimension") == m.Height {
							matched = m.Key
						}
					}
					if matched == "" || o.Media != "" && o.Media != matched {
						return o, bad
					}
					o.Media = matched
				case "media-size-name":
					name, ok := member.Values[0].V.(goipp.String)
					if !ok || o.Media != "" && o.Media != string(name) {
						return o, bad
					}
					o.Media = string(name)
				default:
					return o, bad
				}
			}
		case "job-priority":
			if n, ok := v.(goipp.Integer); !ok || n != 50 {
				return o, bad
			}
		case "job-hold-until":
			if str, ok := v.(goipp.String); !ok || str != "no-hold" {
				return o, bad
			}
		default:
			return o, bad
		}
	}
	return d.caps.Resolve(d.options, o)
}
func (d printDefaults) attributes() goipp.Attributes {
	var a goipp.Attributes
	var media []string
	database := goipp.Attribute{Name: "media-col-database"}
	for _, m := range d.caps.Media {
		media = append(media, m.Key)
		database.Values.Add(goipp.TagBeginCollection, mediaCollection(m))
		if m.Key == d.options.Media {
			add(&a, "media-col-default", goipp.TagBeginCollection, mediaCollection(m))
		}
	}
	a.Add(database)
	multi(&a, "media-col-supported", goipp.TagKeyword, []string{"media-size", "media-size-name"})
	multi(&a, "media-supported", goipp.TagKeyword, media)
	add(&a, "media-default", goipp.TagKeyword, goipp.String(d.options.Media))
	add(&a, "media-ready", goipp.TagKeyword, goipp.String(d.options.Media))
	multi(&a, "sides-supported", goipp.TagKeyword, d.caps.Sides)
	add(&a, "sides-default", goipp.TagKeyword, goipp.String(d.options.Sides))
	multi(&a, "print-color-mode-supported", goipp.TagKeyword, d.caps.Color)
	add(&a, "print-color-mode-default", goipp.TagKeyword, goipp.String(d.options.Color))
	add(&a, "color-supported", goipp.TagBoolean, goipp.Boolean(func() bool {
		for _, c := range d.caps.Color {
			if c == "color" {
				return true
			}
		}
		return false
	}()))
	return a
}
