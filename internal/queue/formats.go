// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package queue

// AcceptedFormats describes upload formats, independently of the device's native
// wire format. A selected PPD always invokes the conversion pipeline, even when
// its input format is already supported directly by the device.
func AcceptedFormats(p Printer) []string {
	if p.PPDID != "" {
		return []string{"application/pdf", "application/postscript", "image/jpeg", "image/png", "image/pwg-raster"}
	}
	return append([]string(nil), p.Formats...)
}
func Accepts(p Printer, format string) bool {
	for _, f := range AcceptedFormats(p) {
		if f == format {
			return true
		}
	}
	return false
}
