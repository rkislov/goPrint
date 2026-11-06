// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rkislov/goPrint/internal/queue"
)

func TestBrandingPermissionsPersistenceAndAttribution(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { q.Close() }()
	token := strings.Repeat("b", 32)
	h := (&Server{Store: q, Token: token, Domain: emailDomain{}}).Handler()
	user := domainCookie(t, h, "alice@example.org")
	request := func(method, path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth == "admin" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if auth == "user" {
			r.AddCookie(user)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for auth, status := range map[string]int{"": 401, "user": 403} {
		if w := request("PUT", "/api/branding", `{"name":"Other","color":"#123456"}`, auth); w.Code != status {
			t.Fatal(auth, w.Code)
		}
	}
	var logo bytes.Buffer
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.NRGBA{R: 255, A: 255})
	png.Encode(&logo, img)
	name := `ACME <img src=x onerror=alert(1)> & Co`
	body, _ := json.Marshal(map[string]any{"name": name, "color": "#123456", "logo_base64": base64.StdEncoding.EncodeToString(logo.Bytes())})
	if w := request("PUT", "/api/branding", string(body), "admin"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	q.Close()
	q, err = queue.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h = (&Server{Store: q, Token: token}).Handler()
	for _, path := range []string{"/login", "/print", "/device/test"} {
		w := request("GET", path, "", "admin")
		if w.Code != 200 || strings.Contains(w.Body.String(), name) || !strings.Contains(w.Body.String(), "ACME &lt;img") || !strings.Contains(w.Body.String(), "Работает на GoPrint") || strings.Contains(w.Body.String(), "@@BRAND") {
			t.Fatal(path, w.Code)
		}
		if !strings.Contains(w.Body.String(), `class="powered-by"`) {
			t.Fatal("Missing fixed attribution")
		}
	}
	w := request("GET", "/api/branding", "", "")
	var view brandingView
	if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Attribution != poweredBy || view.Name != name || view.LogoURL != "/assets/brand-logo" || strings.Contains(w.Body.String(), "logo_base64") {
		t.Fatal(w.Body.String(), err)
	}
	w = request("GET", "/assets/brand-logo", "", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatal(w.Code)
	}
	if _, err = png.Decode(w.Body); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/assets/branding.css", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "--accent:#123456") || strings.Contains(w.Body.String(), "powered-by") {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "style-src 'self';") {
		t.Fatal("CSP was weakened")
	}
	for _, bad := range []string{
		`{"name":"ACME","color":"#123456","hide_attribution":true}`,
		`{"name":"ACME","color":"#123456","attribution":""}`,
		`{"name":"ACME","color":"#123456","css":".powered-by{display:none}"}`,
		`{"name":"ACME","color":"#ffffff"}`,
		`{"name":"ACME","color":"red;display:none"}`,
		`{"name":"ACME\u202e","color":"#123456"}`,
		`{"name":"ACME","color":"#123456","logo_base64":"PHN2Zz48L3N2Zz4="}`,
		`{"name":"ACME","color":"#123456"} {}`,
	} {
		if w = request("PUT", "/api/branding", bad, "admin"); w.Code != 400 {
			t.Fatal(bad, w.Code)
		}
	}
	w = request("PUT", "/api/branding", `{"name":"New name","color":"#123456"}`, "admin")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/assets/brand-logo") {
		t.Fatal("Logo lost when changing name", w.Body.String())
	}
	w = request("PUT", "/api/branding", `{"name":"GoPrint","color":"#17654b","remove_logo":true}`, "admin")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("GET", "/assets/brand-logo", "", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestBrandLogoBounds(t *testing.T) {
	for _, bounds := range []image.Rectangle{image.Rect(0, 0, 1025, 1), image.Rect(0, 0, 1, 1025)} {
		var b bytes.Buffer
		png.Encode(&b, image.NewNRGBA(bounds))
		if _, err := normalizeBrandLogo(base64.StdEncoding.EncodeToString(b.Bytes())); err == nil {
			t.Fatal("Oversized dimensions accepted")
		}
	}
	if _, err := normalizeBrandLogo(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, maxBrandLogo+1))); err == nil {
		t.Fatal("Oversized input accepted")
	}
}
