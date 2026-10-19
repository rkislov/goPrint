// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package watermark

import (
	"context"
	"fmt"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/rkislov/goPrint/internal/queue"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func samplePDF() []byte {
	stream := "BT /F1 12 Tf 70 760 Td (Original document) Tj ET\n"
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream)}
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, o := range objects {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 6\n0000000000 65535 f \n")
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return []byte(b.String())
}
func TestCyrillicWatermarkAndOriginalPreserved(t *testing.T) {
	dir := t.TempDir()
	e, err := New(filepath.Join(dir, "engine"))
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "original.pdf")
	original := samplePDF()
	os.WriteFile(input, original, 0600)
	c := Default()
	c.Enabled = true
	j := queue.Job{ID: "test-job", Owner: "DOMAIN\\Иванов", Format: "application/pdf"}
	output, cleanup, err := e.Prepare(context.Background(), c, j, input)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	marked, err := api.HasWatermarksFile(output, model.NewDefaultConfiguration())
	if err != nil || !marked {
		t.Fatalf("missing watermark: %v %v", marked, err)
	}
	b, _ := os.ReadFile(input)
	if string(b) != string(original) {
		t.Fatal("original spool file modified")
	}
	j.Format = "application/postscript"
	if _, _, err = e.Prepare(context.Background(), c, j, input); err == nil {
		t.Fatal("required policy bypassed by raw format")
	}
}
func TestWatermarkFailureDoesNotReturnUnmarkedDocument(t *testing.T) {
	dir := t.TempDir()
	e, _ := New(filepath.Join(dir, "engine"))
	input := filepath.Join(dir, "bad.pdf")
	os.WriteFile(input, []byte("not a PDF"), 0600)
	c := Default()
	c.Enabled = true
	if path, _, err := e.Prepare(context.Background(), c, queue.Job{Format: "application/pdf"}, input); err == nil || path != "" {
		t.Fatalf("unmarked fallback: %q %v", path, err)
	}
}
