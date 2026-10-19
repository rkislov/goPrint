// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"fmt"
	"github.com/rkislov/goPrint/internal/queue"
	"strings"
)

// A virtual PDF queue profile avoids unauthenticated driver discovery for private queues.
func (s *Server) clientPPD(p queue.Printer, o queue.PrintOptions) (string, error) {
	c, e := s.capabilities(p)
	if e != nil {
		return "", e
	}
	var b strings.Builder
	b.WriteString(`*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "GOPRINT.PPD"
*Manufacturer: "GoPrint"
*Product: "(GoPrint PDF Queue)"
*ModelName: "GoPrint PDF Queue"
*NickName: "GoPrint PDF Queue"
*ShortNickName: "GoPrint PDF"
*cupsVersion: 2.4
*cupsManualCopies: True
*cupsFilter2: "application/pdf application/pdf 0 -"
*cupsFilter2: "application/vnd.cups-pdf application/pdf 0 -"
*LanguageLevel: "3"
*PSVersion: "(3010.000) 0"
*FileSystem: False
*LandscapeOrientation: Plus90
*TTRasterizer: Type42
*DefaultFont: Courier
*Font Courier: Standard "(001.007)" Standard ROM
`)
	colorDevice, colorSpace := "False", "Gray"
	for _, v := range c.Color {
		if v == "color" {
			colorDevice, colorSpace = "True", "RGB"
		}
	}
	fmt.Fprintf(&b, "*ColorDevice: %s\n*DefaultColorSpace: %s\n", colorDevice, colorSpace)
	mediaName := func(key string) string {
		names := map[string]string{"iso_a4_210x297mm": "A4", "iso_a3_297x420mm": "A3", "iso_a5_148x210mm": "A5", "na_letter_8.5x11in": "Letter", "na_legal_8.5x14in": "Legal", "iso_b5_176x250mm": "ISOB5", "jis_b5_182x257mm": "B5"}
		return names[key]
	}

	fmt.Fprintf(&b, "*OpenUI *PageSize/Paper: PickOne\n*DefaultPageSize: %s\n", mediaName(o.Media))
	for _, m := range c.Media {
		fmt.Fprintf(&b, "*PageSize %s/%s: \"<</PageSize[%.3f %.3f]>>setpagedevice\"\n", mediaName(m.Key), m.Label, float64(m.Width)*72/2540, float64(m.Height)*72/2540)
	}
	b.WriteString("*CloseUI: *PageSize\n")
	fmt.Fprintf(&b, "*OpenUI *PageRegion: PickOne\n*DefaultPageRegion: %s\n", mediaName(o.Media))
	for _, m := range c.Media {
		fmt.Fprintf(&b, "*PageRegion %s/%s: \"<</PageSize[%.3f %.3f]>>setpagedevice\"\n", mediaName(m.Key), m.Label, float64(m.Width)*72/2540, float64(m.Height)*72/2540)
	}
	b.WriteString("*CloseUI: *PageRegion\n")
	fmt.Fprintf(&b, "*DefaultImageableArea: %s\n*DefaultPaperDimension: %s\n", mediaName(o.Media), mediaName(o.Media))
	for _, m := range c.Media {
		w, h := float64(m.Width)*72/2540, float64(m.Height)*72/2540
		fmt.Fprintf(&b, "*ImageableArea %s: \"0 0 %.3f %.3f\"\n*PaperDimension %s: \"%.3f %.3f\"\n", mediaName(m.Key), w, h, mediaName(m.Key), w, h)
	}
	side := map[string]string{"one-sided": "None", "two-sided-long-edge": "DuplexNoTumble", "two-sided-short-edge": "DuplexTumble"}
	fmt.Fprintf(&b, "*OpenUI *Duplex: PickOne\n*DefaultDuplex: %s\n", side[o.Sides])
	for _, v := range c.Sides {
		code := "<</Duplex false>>setpagedevice"
		if v == "two-sided-long-edge" {
			code = "<</Duplex true/Tumble false>>setpagedevice"
		}
		if v == "two-sided-short-edge" {
			code = "<</Duplex true/Tumble true>>setpagedevice"
		}
		fmt.Fprintf(&b, "*Duplex %s: \"%s\"\n", side[v], code)
	}
	b.WriteString("*CloseUI: *Duplex\n")
	color := map[string]string{"color": "RGB", "monochrome": "Gray"}
	fmt.Fprintf(&b, "*OpenUI *ColorModel: PickOne\n*DefaultColorModel: %s\n", color[o.Color])
	for _, v := range c.Color {
		fmt.Fprintf(&b, "*ColorModel %s: \"\"\n", color[v])
	}
	b.WriteString("*CloseUI: *ColorModel\n")
	return b.String(), nil
}
