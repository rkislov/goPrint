// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"github.com/rkislov/goPrint/internal/queue"
	"reflect"
	"testing"
)

func TestDeclaredPPDChoicesAndSafeCUPSOptions(t *testing.T) {
	ppd := []byte(`*PPD-Adobe: "4.3"
*DefaultPageSize: A4
*PageSize A4/A4: ""
*PageSize A3/A3: ""
*DefaultDuplex: None
*Duplex None: ""
*Duplex DuplexNoTumble: ""
*Duplex DuplexTumble: ""
*DefaultColorModel: RGB
*ColorModel RGB: ""
*ColorModel Gray: ""
`)
	c, e := CapabilitiesFor(ppd)
	if e != nil {
		t.Fatal(e)
	}
	o := queue.PrintOptions{Media: "iso_a3_297x420mm", Sides: "two-sided-long-edge", Color: "monochrome"}
	args, e := c.CUPSOptions(o)
	if e != nil || !reflect.DeepEqual(args, []string{"PageSize=A3", "Duplex=DuplexNoTumble", "ColorModel=Gray"}) {
		t.Fatal(args, e)
	}
	o.Media = "A4;exec arbitrary"
	if _, e = c.CUPSOptions(o); e == nil {
		t.Fatal("unlisted choice accepted")
	}
}
