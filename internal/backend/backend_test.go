package backend

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenPrinting/goipp"
	"github.com/rkislov/goPrint/internal/queue"
)

func document(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "job.data")
	if err := os.WriteFile(p, []byte("%PDF-test"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSocketTransfer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		received <- string(b)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Deliver(ctx, queue.Printer{URI: "socket://" + ln.Addr().String()}, queue.Job{}, document(t))
	if r.State != "submitted" {
		t.Fatalf("result: %+v", r)
	}
	select {
	case b := <-received:
		if b != "%PDF-test" {
			t.Fatalf("document corrupted: %q", b)
		}
	case <-ctx.Done():
		t.Fatal("no data delivered")
	}
}
func TestIPPTransferAndRemoteID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/ipp" {
			t.Error("wrong content type")
		}
		var msg goipp.Message
		if err := msg.Decode(r.Body); err != nil {
			t.Error(err)
			http.Error(w, "decode", 400)
			return
		}
		if msg.Code != goipp.Code(goipp.OpPrintJob) {
			t.Errorf("unexpected op: %v", msg.Code)
		}
		b, _ := io.ReadAll(r.Body)
		if !bytes.Equal(b, []byte("%PDF-test")) {
			t.Errorf("bad document: %q", b)
		}
		response := goipp.NewResponse(goipp.DefaultVersion, goipp.StatusOk, msg.RequestID)
		response.Job.Add(goipp.MakeAttribute("job-id", goipp.TagInteger, goipp.Integer(42)))
		w.Header().Set("Content-Type", "application/ipp")
		response.Encode(w)
	}))
	defer srv.Close()
	p := queue.Printer{URI: strings.Replace(srv.URL, "http://", "ipp://", 1) + "/ipp/print"}
	r := Deliver(context.Background(), p, queue.Job{Owner: "admin", Title: "test", Format: "application/pdf", Size: 9}, document(t))
	if r.State != "submitted" || r.RemoteID != "42" {
		t.Fatalf("result: %+v", r)
	}
}
func TestIPPAmbiguousResponseNeverRetries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("broken response"))
	}))
	defer srv.Close()
	r := Deliver(context.Background(), queue.Printer{URI: strings.Replace(srv.URL, "http://", "ipp://", 1) + "/ipp/print"}, queue.Job{Size: 9}, document(t))
	if r.State != "unknown" || calls != 1 {
		t.Fatalf("ambiguous result: %+v, calls: %d", r, calls)
	}
}
func TestValidatePrinter(t *testing.T) {
	for _, uri := range []string{"file:///etc/passwd", "socket://127.0.0.1:9100/path", "ipp://user:secret@localhost/ipp/print", "http://localhost/print"} {
		if err := Validate(queue.Printer{Name: "test", URI: uri, Formats: []string{"application/pdf"}}); err == nil {
			t.Errorf("accepted %s", uri)
		}
	}
}
