// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package testutil contains synthetic, non-confidential integration fixtures.
package testutil

import (
	"fmt"
	"strings"
)

func PDF() []byte {
	content := "BT /F1 12 Tf 70 760 Td (GoPrint integration test) Tj ET\n"
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content)}
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := []int{}
	for i, o := range objects {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	b.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for _, offset := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return []byte(b.String())
}

const PPD = `*PPD-Adobe: "4.3"
*% SPDX-License-Identifier: Apache-2.0
*% Copyright 2026 Кислов Роман Сергеевич
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "GOPRINT.PPD"
*Manufacturer: "GoPrint"
*Product: "(GoPrint PostScript)"
*ModelName: "GoPrint PostScript"
*ShortNickName: "GoPrint PostScript"
*NickName: "GoPrint PostScript Test"
*PSVersion: "(3010.000) 0"
*LanguageLevel: "2"
*ColorDevice: False
*DefaultColorSpace: Gray
*FileSystem: False
*Throughput: "10"
*TTRasterizer: Type42
*JCLBegin: "<1B>%-12345X@PJL COMMENT GOPRINT_PPD_APPLIED<0A>"
*JCLToPSInterpreter: "@PJL ENTER LANGUAGE=POSTSCRIPT<0A>"
*JCLEnd: "<1B>%-12345X"
*OpenUI *PageSize/Page Size: PickOne
*OrderDependency: 10 AnySetup *PageSize
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]>>setpagedevice"
*CloseUI: *PageSize
*DefaultImageableArea: A4
*ImageableArea A4/A4: "0 0 595 842"
*DefaultPaperDimension: A4
*PaperDimension A4/A4: "595 842"
*OpenUI *Duplex/Duplex: PickOne
*OrderDependency: 20 AnySetup *Duplex
*DefaultDuplex: DuplexNoTumble
*Duplex None/Off: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble/Long Edge: "<</Duplex true /Tumble false>>setpagedevice"
*CloseUI: *Duplex
*DefaultFont: Courier
*Font Courier: Standard "(001.007)" Standard ROM
`
