// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package monitoring

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenPrinting/goipp"
	"github.com/gosnmp/gosnmp"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"github.com/rkislov/goPrint/internal/queue"
)

type Supply struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Color   string `json:"color,omitempty"`
	Percent *int   `json:"percent"`
	Filled  bool   `json:"filled"`
}
type Counter struct {
	ID    string `json:"id"`
	Value uint64 `json:"value"`
	Unit  string `json:"unit"`
}
type Reading struct {
	Model    string    `json:"model,omitempty"`
	Serial   string    `json:"serial,omitempty"`
	State    string    `json:"state,omitempty"`
	Reasons  []string  `json:"reasons"`
	Supplies []Supply  `json:"supplies"`
	Counters []Counter `json:"counters"`
}

func Probe(ctx context.Context, p queue.Printer, c Config) (Reading, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if c.Method == "snmp" {
		return probeSNMP(ctx, p, c)
	}
	return probeIPP(ctx, p, c)
}
func probeIPP(ctx context.Context, p queue.Printer, c Config) (Reading, error) {
	uri := c.IPPURI
	if uri == "" {
		uri = p.URI
	}
	u, e := url.Parse(uri)
	if e != nil || (u.Scheme != "ipp" && u.Scheme != "ipps") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return Reading{}, errors.New("configure an ipp:// or ipps:// monitoring URI")
	}
	req := goipp.NewRequest(goipp.DefaultVersion, goipp.OpGetPrinterAttributes, 1)
	req.Operation.Add(goipp.MakeAttribute("attributes-charset", goipp.TagCharset, goipp.String("utf-8")))
	req.Operation.Add(goipp.MakeAttribute("attributes-natural-language", goipp.TagLanguage, goipp.String("en")))
	req.Operation.Add(goipp.MakeAttribute("printer-uri", goipp.TagURI, goipp.String(uri)))
	requested := goipp.Attribute{Name: "requested-attributes"}
	for _, name := range []string{"printer-make-and-model", "printer-state", "printer-state-reasons", "marker-names", "marker-types", "marker-colors", "marker-levels", "printer-supply", "printer-supply-description"} {
		requested.Values.Add(goipp.TagKeyword, goipp.String(name))
	}
	req.Operation.Add(requested)
	b, e := req.EncodeBytes()
	if e != nil {
		return Reading{}, e
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "631")
	}
	if u.Scheme == "ipps" {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(b))
	if e != nil {
		return Reading{}, e
	}
	r.Header.Set("Content-Type", "application/ipp")
	resp, e := client.Do(r)
	if e != nil {
		return Reading{}, fmt.Errorf("IPP transport or TLS failed: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Reading{}, diagnostics.HTTPStatus{Code: resp.StatusCode}
	}
	var msg goipp.Message
	if e = msg.Decode(io.LimitReader(resp.Body, 1<<20)); e != nil || msg.RequestID != 1 || msg.Code >= 0x0100 {
		return Reading{}, errors.New("invalid or rejected IPP response")
	}
	return parseIPP(msg.Printer), nil
}
func parseIPP(attrs goipp.Attributes) Reading {
	out := Reading{State: "unknown", Supplies: []Supply{}, Counters: []Counter{}, Reasons: []string{}}
	a := map[string][]goipp.Value{}
	for _, attr := range attrs {
		for _, v := range attr.Values {
			a[attr.Name] = append(a[attr.Name], v.V)
		}
	}
	str := func(k string, i int) string {
		if i < len(a[k]) {
			if s, ok := a[k][i].(goipp.String); ok {
				return string(s)
			}
		}
		return ""
	}
	integer := func(k string, i int) (int, bool) {
		if i < len(a[k]) {
			v, ok := a[k][i].(goipp.Integer)
			return int(v), ok
		}
		return 0, false
	}
	out.Model = str("printer-make-and-model", 0)
	if n, ok := integer("printer-state", 0); ok {
		out.State = map[int]string{3: "idle", 4: "processing", 5: "stopped"}[n]
		if out.State == "" {
			out.State = "unknown"
		}
	}
	for i := range a["printer-state-reasons"] {
		if s := str("printer-state-reasons", i); s != "" && s != "none" {
			out.Reasons = append(out.Reasons, s)
		}
	}
	n := max(len(a["marker-names"]), len(a["marker-levels"]))
	for i := 0; i < n && i < 128; i++ {
		s := Supply{ID: fmt.Sprintf("ipp:%d", i), Name: str("marker-names", i), Kind: str("marker-types", i), Color: str("marker-colors", i)}
		if s.Name == "" {
			s.Name = fmt.Sprintf("Supply %d", i+1)
		}
		s.Filled = strings.Contains(s.Kind, "waste")
		if v, ok := integer("marker-levels", i); ok && v >= 0 && v <= 100 {
			s.Percent = &v
		}
		out.Supplies = append(out.Supplies, s)
	}
	// Standard printer-supply values are semicolon-separated key=value octet strings.
	if n == 0 {
		for i, v := range a["printer-supply"] {
			if i >= 128 {
				break
			}
			var raw string
			switch b := v.(type) {
			case goipp.String:
				raw = string(b)
			case goipp.Binary:
				raw = string(b)
			}
			m := map[string]string{}
			for _, part := range strings.Split(raw, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok {
					m[k] = v
				}
			}
			s := Supply{ID: fmt.Sprintf("ipp-supply:%d", i), Name: str("printer-supply-description", i), Kind: m["type"], Color: m["colorantname"], Filled: m["class"] == "receptacleThatIsFilled"}
			if s.Name == "" {
				s.Name = fmt.Sprintf("Supply %d", i+1)
			}
			level, e := strconv.Atoi(m["level"])
			cap, ce := strconv.Atoi(m["maxcapacity"])
			if e == nil && level >= 0 {
				if m["unit"] == "percent" && level <= 100 {
					s.Percent = &level
				} else if ce == nil && cap > 0 && level <= cap {
					p := int(float64(level) / float64(cap) * 100)
					s.Percent = &p
				}
			}
			out.Supplies = append(out.Supplies, s)
		}
	}
	return out
}

const markerRoot = ".1.3.6.1.2.1.43.10.2.1."
const supplyRoot = ".1.3.6.1.2.1.43.11.1.1."

func probeSNMP(ctx context.Context, p queue.Printer, c Config) (Reading, error) {
	u, e := url.Parse(p.URI)
	if e != nil || u.Hostname() == "" {
		return Reading{}, errors.New("printer hostname required")
	}
	g := &gosnmp.GoSNMP{Target: u.Hostname(), Port: uint16(c.Port), Version: gosnmp.Version2c, Community: c.Community, Timeout: 2 * time.Second, Retries: 0, MaxOids: 32, MaxRepetitions: 10, Context: ctx}
	if c.Version == "3" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: c.Username, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: c.AuthPassword, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: c.PrivPassword}
	}
	if e = g.Connect(); e != nil {
		return Reading{}, errors.New("SNMP connection failed")
	}
	defer g.Conn.Close()
	all := []gosnmp.SnmpPDU{}
	for _, root := range []string{markerRoot, supplyRoot, ".1.3.6.1.2.1.43.5.1.1.17"} {
		err := walkSNMP(g, strings.TrimSuffix(root, "."), func(v gosnmp.SnmpPDU) error {
			if len(all) >= 2048 {
				return errors.New("SNMP response exceeds row limit")
			}
			all = append(all, v)
			return nil
		})
		if err != nil {
			return Reading{}, errors.New("SNMP query failed or timed out")
		}
	}
	return parseSNMP(all), nil
}
func parseSNMP(all []gosnmp.SnmpPDU) Reading {
	out := Reading{State: "unknown", Supplies: []Supply{}, Counters: []Counter{}, Reasons: []string{}}
	rows := map[string]map[int]gosnmp.SnmpPDU{}
	markers := map[string]map[int]gosnmp.SnmpPDU{}
	for _, p := range all {
		oid := "." + strings.TrimPrefix(p.Name, ".")
		root := supplyRoot
		table := rows
		if strings.HasPrefix(oid, markerRoot) {
			root = markerRoot
			table = markers
		}
		if strings.HasPrefix(oid, root) {
			column, index, ok := strings.Cut(strings.TrimPrefix(oid, root), ".")
			col, e := strconv.Atoi(column)
			if ok && e == nil {
				if table[index] == nil {
					table[index] = map[int]gosnmp.SnmpPDU{}
				}
				table[index][col] = p
			}
		} else if strings.HasPrefix(oid, ".1.3.6.1.2.1.43.5.1.1.17.") {
			out.Serial = pduString(p)
		}
	}
	keys := func(m map[string]map[int]gosnmp.SnmpPDU) []string {
		k := []string{}
		for v := range m {
			k = append(k, v)
		}
		sort.Strings(k)
		return k
	}
	for _, id := range keys(markers) {
		r := markers[id]
		v, ok := pduNumber(r[4])
		unit, _ := pduNumber(r[3])
		if ok && v >= 0 {
			u := map[int64]string{7: "impressions", 8: "sheets", 11: "hours", 5: "characters", 6: "lines", 16: "feet", 17: "meters"}[unit]
			if u == "" {
				u = fmt.Sprintf("unit:%d", unit)
			}
			out.Counters = append(out.Counters, Counter{ID: id, Value: uint64(v), Unit: u})
		}
	}
	for _, id := range keys(rows) {
		r := rows[id]
		class, _ := pduNumber(r[4])
		kind, _ := pduNumber(r[5])
		s := Supply{ID: "snmp:" + id, Name: pduString(r[6]), Kind: fmt.Sprintf("type:%d", kind), Filled: class == 4}
		if s.Name == "" {
			s.Name = "Supply " + id
		}
		level, ok := pduNumber(r[9])
		capacity, cok := pduNumber(r[8])
		unit, _ := pduNumber(r[7])
		if ok && level >= 0 {
			if unit == 19 && level <= 100 {
				v := int(level)
				s.Percent = &v
			} else if cok && capacity > 0 && level <= capacity {
				v := int(float64(level) / float64(capacity) * 100)
				s.Percent = &v
			}
		}
		out.Supplies = append(out.Supplies, s)
	}
	return out
}
func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		return strings.ToValidUTF8(string(v), "�")
	case string:
		return v
	}
	return ""
}
func pduNumber(p gosnmp.SnmpPDU) (int64, bool) {
	switch p.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Counter64, gosnmp.Gauge32, gosnmp.Uinteger32:
		b := gosnmp.ToBigInt(p.Value)
		if b.IsInt64() {
			return b.Int64(), true
		}
	}
	return 0, false
}

// walkSNMP keeps protocol errors distinct from an unsupported subtree and bounds
// requests even if an agent returns a malformed/non-progressing walk.
func walkSNMP(g *gosnmp.GoSNMP, root string, fn func(gosnmp.SnmpPDU) error) error {
	cursor := root
	for request := 0; request < 256; request++ {
		packet, e := g.GetBulk([]string{cursor}, 0, 10)
		if e != nil {
			return e
		}
		if packet.Error != gosnmp.NoError {
			return errors.New("SNMP agent rejected read")
		}
		if len(packet.Variables) == 0 {
			return nil
		}
		for _, p := range packet.Variables {
			if p.Type == gosnmp.EndOfMibView || p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance {
				return nil
			}
			name := "." + strings.TrimPrefix(p.Name, ".")
			if !strings.HasPrefix(name, root+".") {
				return nil
			}
			if !oidAfter(name, cursor) {
				return errors.New("non-increasing SNMP OID")
			}
			if e = fn(p); e != nil {
				return e
			}
			cursor = name
		}
	}
	return errors.New("SNMP request limit exceeded")
}
func oidAfter(a, b string) bool {
	aa := strings.Split(strings.Trim(a, "."), ".")
	bb := strings.Split(strings.Trim(b, "."), ".")
	for i := 0; i < min(len(aa), len(bb)); i++ {
		x, e := strconv.ParseUint(aa[i], 10, 32)
		if e != nil {
			return false
		}
		y, e := strconv.ParseUint(bb[i], 10, 32)
		if e != nil {
			return false
		}
		if x != y {
			return x > y
		}
	}
	return len(aa) > len(bb)
}
