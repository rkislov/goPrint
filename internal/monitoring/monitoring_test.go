// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenPrinting/goipp"
	"github.com/gosnmp/gosnmp"
	"github.com/rkislov/goPrint/internal/queue"
)

func TestIPPWireUnknownLevelsAndStandardSupplies(t *testing.T) {
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req goipp.Message
		if e := req.Decode(r.Body); e != nil || req.Code != goipp.Code(goipp.OpGetPrinterAttributes) {
			t.Error("wrong IPP operation", e)
			w.WriteHeader(400)
			return
		}
		m := goipp.NewResponse(req.Version, goipp.StatusOk, req.RequestID)
		m.Printer.Add(goipp.MakeAttribute("printer-state", goipp.TagEnum, goipp.Integer(3)))
		names := goipp.MakeAttribute("marker-names", goipp.TagName, goipp.String("Black"))
		names.Values.Add(goipp.TagName, goipp.String("Waste"))
		m.Printer.Add(names)
		levels := goipp.MakeAttribute("marker-levels", goipp.TagInteger, goipp.Integer(-2))
		levels.Values.Add(goipp.TagInteger, goipp.Integer(95))
		m.Printer.Add(levels)
		types := goipp.MakeAttribute("marker-types", goipp.TagKeyword, goipp.String("toner"))
		types.Values.Add(goipp.TagKeyword, goipp.String("waste-toner"))
		m.Printer.Add(types)
		b, _ := m.EncodeBytes()
		w.Header().Set("Content-Type", "application/ipp")
		w.Write(b)
	}))
	defer device.Close()
	c := Defaults()
	r, e := Probe(context.Background(), queue.Printer{URI: strings.Replace(device.URL, "http:", "ipp:", 1)}, c)
	if e != nil || len(r.Supplies) != 2 || r.Supplies[0].Percent != nil || r.Supplies[1].Percent == nil || *r.Supplies[1].Percent != 95 || !r.Supplies[1].Filled {
		t.Fatal(r, e)
	}
	attrs := goipp.Attributes{goipp.MakeAttribute("printer-supply", goipp.TagString, goipp.Binary("index=1;class=supplyThatIsConsumed;type=ink;unit=milliliters;maxcapacity=200;level=40;"))}
	r = parseIPP(attrs)
	if len(r.Supplies) != 1 || r.Supplies[0].Percent == nil || *r.Supplies[0].Percent != 20 {
		t.Fatal(r)
	}
}
func TestSNMPWireNonDefaultIndexesAndUnits(t *testing.T) {
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	pdus := []gosnmp.SnmpPDU{
		{Name: markerRoot + "3.7.4", Type: gosnmp.Integer, Value: 7}, {Name: markerRoot + "4.7.4", Type: gosnmp.Counter32, Value: uint32(123456)},
		{Name: supplyRoot + "4.7.9", Type: gosnmp.Integer, Value: 4}, {Name: supplyRoot + "6.7.9", Type: gosnmp.OctetString, Value: []byte("Waste")}, {Name: supplyRoot + "7.7.9", Type: gosnmp.Integer, Value: 13}, {Name: supplyRoot + "8.7.9", Type: gosnmp.Integer, Value: 200}, {Name: supplyRoot + "9.7.9", Type: gosnmp.Integer, Value: 190},
		{Name: supplyRoot + "6.7.10", Type: gosnmp.OctetString, Value: []byte("Unknown")}, {Name: supplyRoot + "8.7.10", Type: gosnmp.Integer, Value: 100}, {Name: supplyRoot + "9.7.10", Type: gosnmp.Integer, Value: -3},
	}
	sort.Slice(pdus, func(i, j int) bool { return oidAfter(pdus[j].Name, pdus[i].Name) })
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := conn.ReadFrom(b)
			if e != nil {
				return
			}
			g := &gosnmp.GoSNMP{}
			req, e := g.SnmpDecodePacket(b[:n])
			if e != nil {
				t.Error(e)
				return
			}
			if req.Community != "read-only-test" {
				t.Error("wrong community")
				return
			}
			oid := "." + strings.TrimPrefix(req.Variables[0].Name, ".")
			out := []gosnmp.SnmpPDU{}
			root := ""
			for _, candidate := range []string{markerRoot, supplyRoot, ".1.3.6.1.2.1.43.5.1.1.17"} {
				if strings.TrimSuffix(oid, ".") == strings.TrimSuffix(candidate, ".") {
					root = candidate
				}
			}
			if root != "" {
				for _, p := range pdus {
					if strings.HasPrefix(p.Name, root) {
						out = append(out, p)
					}
				}
			}
			out = append(out, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView, Value: nil})
			resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID, Variables: out}
			data, e := resp.MarshalMsg()
			if e != nil {
				t.Error(e)
				return
			}
			conn.WriteTo(data, addr)
		}
	}()
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	n, _ := strconv.Atoi(port)
	c := Defaults()
	c.Method = "snmp"
	c.Port = n
	c.Version = "2c"
	c.Community = "read-only-test"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := Probe(ctx, queue.Printer{URI: "socket://127.0.0.1:9100"}, c)
	if e != nil || len(r.Counters) != 1 || r.Counters[0].Value != 123456 || r.Counters[0].Unit != "impressions" || len(r.Supplies) != 2 {
		t.Fatal(r, e)
	}
	for _, s := range r.Supplies {
		if s.Name == "Waste" && (s.Percent == nil || *s.Percent != 95 || !s.Filled) {
			t.Fatal(s)
		}
		if s.Name == "Unknown" && s.Percent != nil {
			t.Fatal(s)
		}
	}
}

type noticeRecorder struct{ Subjects []string }

func (n *noticeRecorder) SendNotice(_ context.Context, to, subject, body string) (string, error) {
	n.Subjects = append(n.Subjects, subject)
	return "sent", nil
}
func TestAlertsPersistenceEscalationAckRecoveryUnknownAndOffline(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	p, _ := q.AddPrinter(ctx, queue.Printer{Name: "Office", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
	mail := &noticeRecorder{}
	s, e := New(dir, q, mail)
	if e != nil {
		t.Fatal(e)
	}
	c := Defaults()
	c.Enabled = true
	c.Method = "snmp"
	c.Version = "2c"
	c.Community = "never-plaintext-community"
	if _, e = s.Configure(ctx, p.ID, c); e != nil {
		t.Fatal(e)
	}
	var stored savedConfig
	q.Setting(ctx, "monitor-config:"+p.ID, &stored)
	b, _ := json.Marshal(stored)
	if strings.Contains(string(b), c.Community) {
		t.Fatal("secret leaked")
	}
	v, _ := s.Snapshot(ctx, p)
	if v.Config.Community != "" || !v.Config.CredentialsSet {
		t.Fatal(v.Config)
	}
	s.SetPolicy(ctx, Policy{Email: true, Recipients: []string{"admin@example.org"}, ReminderHours: 24, Recovery: true})
	level := 15
	unknown := false
	offline := false
	s.Probe = func(context.Context, queue.Printer, Config) (Reading, error) {
		if offline {
			return Reading{}, errors.New("unreachable")
		}
		var n *int
		if !unknown {
			x := level
			n = &x
		}
		return Reading{Supplies: []Supply{{ID: "black", Name: "Black", Percent: n}}}, nil
	}
	poll := func() Snapshot {
		t.Helper()
		var v Snapshot
		q.Setting(ctx, "monitor-snapshot:"+p.ID, &v)
		v.CheckedAt = time.Now().Add(-time.Hour)
		q.SetSetting(ctx, "monitor-snapshot:"+p.ID, v)
		v, e = s.Poll(ctx, p, true)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	v = poll()
	if len(v.Alerts) != 1 || len(mail.Subjects) != 1 {
		t.Fatal(v, mail)
	}
	poll()
	if len(mail.Subjects) != 1 {
		t.Fatal("duplicate email")
	}
	s2, e := New(dir, q, mail)
	if e != nil {
		t.Fatal(e)
	}
	s2.Probe = s.Probe
	s = s2
	poll()
	if len(mail.Subjects) != 1 {
		t.Fatal("restart resent email")
	}
	s.Acknowledge(ctx, p, v.Alerts[0].ID)
	level = 4
	v = poll()
	if len(mail.Subjects) != 2 || v.Alerts[0].Acknowledged || v.Alerts[0].Severity != "critical" {
		t.Fatal(v, mail)
	}
	unknown = true
	v = poll()
	if !v.Alerts[0].Active || len(mail.Subjects) != 2 {
		t.Fatal("unknown reading resolved alert")
	}
	unknown = false
	level = 21
	v = poll()
	if !v.Alerts[0].Active {
		t.Fatal("hysteresis missing")
	}
	level = 25
	v = poll()
	if v.Alerts[0].Active || !strings.Contains(mail.Subjects[len(mail.Subjects)-1], "Восстановлено") {
		t.Fatal(v, mail)
	}
	count := len(mail.Subjects)
	poll()
	if len(mail.Subjects) != count {
		t.Fatal("duplicate recovery")
	}
	offline = true
	poll()
	poll()
	v = poll()
	if v.Error == "" || v.LastSuccess.IsZero() || v.Failures != 3 || len(v.Alerts) != 2 {
		t.Fatal(v)
	}
}

func TestNotificationBatchResumesWithoutDuplicates(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	q, e := queue.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	p, _ := q.AddPrinter(ctx, queue.Printer{Name: "Batch", URI: "socket://127.0.0.1:9100", Formats: []string{"application/pdf"}})
	mail := &noticeRecorder{}
	s, e := New(dir, q, mail)
	if e != nil {
		t.Fatal(e)
	}
	c := Defaults()
	c.Enabled = true
	s.Configure(ctx, p.ID, c)
	policy := Policy{Email: true, ReminderHours: 24, Recovery: true}
	for i := 0; i < 10; i++ {
		policy.Recipients = append(policy.Recipients, "admin"+strconv.Itoa(i)+"@example.org")
	}
	if _, e = s.SetPolicy(ctx, policy); e != nil {
		t.Fatal(e)
	}
	s.Probe = func(context.Context, queue.Printer, Config) (Reading, error) {
		n := 4
		return Reading{Supplies: []Supply{{ID: "black", Name: "Black", Percent: &n}}}, nil
	}
	v, e := s.Poll(ctx, p, true)
	if e != nil || len(mail.Subjects) != 8 {
		t.Fatal(len(mail.Subjects), e)
	}
	v.CheckedAt = time.Now().Add(-time.Hour)
	q.SetSetting(ctx, "monitor-snapshot:"+p.ID, v)
	v, e = s.Poll(ctx, p, true)
	if e != nil || len(mail.Subjects) != 10 {
		t.Fatal(len(mail.Subjects), e)
	}
	v.CheckedAt = time.Now().Add(-time.Hour)
	q.SetSetting(ctx, "monitor-snapshot:"+p.ID, v)
	s.Poll(ctx, p, true)
	if len(mail.Subjects) != 10 {
		t.Fatal("completed batch sent again")
	}
}
