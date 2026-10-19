// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scanning

import (
	"archive/zip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDeviceCredentialsAndIncomingDocument(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := s.Add(ctx, "MFP", "http://localhost/eSCL")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Authenticate(ctx, v.ID, v.DeviceToken) || s.Authenticate(ctx, v.ID, "wrong") {
		t.Fatal("device authentication failed")
	}
	list, _ := s.List(ctx)
	if list[0].DeviceToken != "" {
		t.Fatal("device token leaked")
	}
	j, err := s.Receive(ctx, v.ID, "scan.pdf", strings.NewReader("%PDF-1.7\ntest"))
	if err != nil {
		t.Fatal(err)
	}
	if j.State != "completed" || j.Source != "device" {
		t.Fatal(j)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j, err = s.Job(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.Path(j.ID))
	if err != nil || string(b) != "%PDF-1.7\ntest" {
		t.Fatalf("document: %q %v", b, err)
	}
	if _, err = s.Receive(ctx, v.ID, "bad.pdf", strings.NewReader("not a scan")); err == nil {
		t.Fatal("invalid content accepted")
	}
}
func TestRemoteScanAndJobLocationBoundary(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "foreign_location"}[bad], func(t *testing.T) {
			pages := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "POST":
					b, _ := io.ReadAll(r.Body)
					if !strings.Contains(string(b), "<pwg:InputSource>Platen</pwg:InputSource>") {
						t.Error("missing scan source")
					}
					location := "/eSCL/ScanJobs/1"
					if bad {
						location = "http://example.org/ScanJobs/1"
					}
					w.Header().Set("Location", location)
					w.WriteHeader(201)
				case r.Method == "DELETE":
					w.WriteHeader(200)
				case strings.HasSuffix(r.URL.Path, "/NextDocument"):
					pages++
					if pages > 1 {
						w.WriteHeader(404)
						return
					}
					w.Header().Set("Content-Type", "image/jpeg")
					w.Write([]byte{255, 216, 255, 1, 2, 3})
				default:
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			v, err := s.Add(context.Background(), "MFP", srv.URL+"/eSCL")
			if err != nil {
				t.Fatal(err)
			}
			j, err := s.Start(context.Background(), Options{ScannerID: v.ID, Source: "Platen", Resolution: 300, Format: "image/jpeg"})
			if err != nil {
				t.Fatal(err)
			}
			until := time.Now().Add(5 * time.Second)
			for time.Now().Before(until) {
				j, err = s.Job(context.Background(), j.ID)
				if err != nil {
					t.Fatal(err)
				}
				if j.State != "processing" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			want := "completed"
			if bad {
				want = "failed"
			}
			if j.State != want {
				t.Fatalf("job: %+v", j)
			}
			if bad && pages != 0 {
				t.Fatal("followed untrusted job location")
			}
		})
	}
}

func TestFeederReturnsArchiveOfAllPages(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			w.Header().Set("Location", "/eSCL/ScanJobs/1")
			w.WriteHeader(201)
		case r.Method == "DELETE":
			w.WriteHeader(200)
		default:
			pages++
			if pages > 2 {
				w.WriteHeader(404)
				return
			}
			w.Write([]byte{255, 216, 255, byte(pages)})
		}
	}))
	defer srv.Close()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, _ := s.Add(context.Background(), "ADF", srv.URL+"/eSCL")
	j, err := s.Start(context.Background(), Options{ScannerID: v.ID, Source: "Feeder", Resolution: 300, Format: "image/jpeg"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, _ = s.Job(context.Background(), j.ID)
		if j.State != "processing" {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	if j.State != "completed" || j.Format != "application/zip" {
		t.Fatalf("scan: %+v", j)
	}
	z, err := zip.OpenReader(s.Path(j.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 2 {
		t.Fatalf("pages: %d", len(z.File))
	}
	for i, file := range z.File {
		r, _ := file.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		if len(b) != 4 || b[3] != byte(i+1) {
			t.Fatalf("bad page: %v", b)
		}
	}
}
