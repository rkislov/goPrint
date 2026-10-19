// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
// Package printing orders policy enforcement, PPD preparation and delivery.
package printing

import (
	"context"
	"fmt"
	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/filtering"
	"github.com/rkislov/goPrint/internal/queue"
	"github.com/rkislov/goPrint/internal/watermark"
	"strings"
)

type FileValidator interface {
	Check(context.Context, string) error
}
type Pipeline struct {
	Antivirus FileValidator
	Store     *queue.Store
	Marker    *watermark.Engine
	Filters   *filtering.Engine
}

func (p *Pipeline) Deliver(ctx context.Context, printer queue.Printer, j queue.Job, path string) queue.DeliveryResult {
	fail := func(err error) queue.DeliveryResult {
		return queue.DeliveryResult{State: "failed", Detail: err.Error()}
	}
	if p.Antivirus != nil {
		if err := p.Antivirus.Check(ctx, path); err != nil {
			return fail(err)
		}
		if err := p.Store.RecordEvent(ctx, j.ID, "antivirus policy checked before document processing"); err != nil {
			return fail(fmt.Errorf("cannot audit antivirus check; document not sent"))
		}
	}
	policy := watermark.Default()
	if err := p.Store.Setting(ctx, "watermark", &policy); err != nil {
		return fail(fmt.Errorf("cannot read watermark policy; document not sent"))
	}
	if policy.Enabled {
		if p.Marker == nil {
			return fail(fmt.Errorf("watermark engine unavailable; document not sent"))
		}
		marked, cleanup, err := p.Marker.PrepareIsolated(ctx, policy, j, path)
		if err != nil {
			return fail(err)
		}
		defer cleanup()
		path = marked
		if err = p.Store.RecordEvent(ctx, j.ID, "watermark applied; policy="+policy.Version); err != nil {
			return fail(fmt.Errorf("cannot audit watermark; document not sent"))
		}
	}
	if j.Options != (queue.PrintOptions{}) {
		if err := p.Store.RecordEvent(ctx, j.ID, fmt.Sprintf("print options; media=%s; sides=%s; color=%s", j.Options.Media, j.Options.Sides, j.Options.Color)); err != nil {
			return fail(fmt.Errorf("cannot audit print options; document not sent"))
		}
	}
	if p.Filters == nil {
		return fail(fmt.Errorf("document preparation unavailable; document not sent"))
	}
	prepared, err := p.Filters.Prepare(ctx, printer, j, path)
	if err != nil {
		return fail(err)
	}
	defer prepared.Cleanup()
	if printer.PPDID != "" {
		detail := fmt.Sprintf("PPD filters applied; ppd=%s; chain=%s; output=%s; bytes=%d", printer.PPDID, strings.Join(prepared.Chain, ","), prepared.Format, prepared.Size)
		if err = p.Store.RecordEvent(ctx, j.ID, detail); err != nil {
			return fail(fmt.Errorf("cannot audit PPD conversion; document not sent"))
		}
	}
	// The IPP header and Content-Length must describe the prepared file, not the
	// original uploaded PDF or the intermediate watermark result.
	j.Format = prepared.Format
	j.Size = prepared.Size
	r := backend.Deliver(ctx, printer, j, prepared.Path)
	return queue.DeliveryResult{State: r.State, Detail: r.Detail, RemoteID: r.RemoteID}
}
