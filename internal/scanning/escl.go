// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package scanning

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkislov/goPrint/internal/queue"
)

func (s *Service) perform(ctx context.Context, scanner Scanner, j Job, o Options) (string, int64, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Only validated enum/integer values enter this XML document.
	settings := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:escl="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm"><pwg:Version>2.0</pwg:Version><scan:Intent>Document</scan:Intent><pwg:ScanRegions><pwg:ScanRegion><pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits><pwg:XOffset>0</pwg:XOffset><pwg:YOffset>0</pwg:YOffset><pwg:Width>2480</pwg:Width><pwg:Height>3508</pwg:Height></pwg:ScanRegion></pwg:ScanRegions><pwg:InputSource>%s</pwg:InputSource><scan:ColorMode>RGB24</scan:ColorMode><pwg:DocumentFormat>%s</pwg:DocumentFormat><scan:XResolution>%d</scan:XResolution><scan:YResolution>%d</scan:YResolution></scan:ScanSettings>`, o.Source, o.Format, o.Resolution, o.Resolution)
	req, _ := http.NewRequestWithContext(ctx, "POST", scanner.URI+"/ScanJobs", strings.NewReader(settings))
	req.Header.Set("Content-Type", "text/xml")
	rsp, err := client.Do(req)
	if err != nil {
		return "", 0, errors.New("не удалось создать задание на сканере; проверьте устройство перед повтором")
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusCreated {
		return "", 0, fmt.Errorf("сканер отклонил параметры: HTTP %d", rsp.StatusCode)
	}
	remote, err := rsp.Location()
	base, _ := url.Parse(scanner.URI)
	if err != nil || remote.Scheme != base.Scheme || remote.Host != base.Host || remote.User != nil || remote.RawQuery != "" || remote.Fragment != "" || remote.RawPath != "" || path.Clean(remote.Path) != strings.TrimRight(remote.Path, "/") || !strings.HasPrefix(remote.Path, base.Path+"/ScanJobs/") {
		return "", 0, errors.New("сканер вернул недопустимый адрес задания")
	}
	remote.Path = strings.TrimRight(remote.Path, "/")
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r, _ := http.NewRequestWithContext(cleanupCtx, "DELETE", remote.String(), nil)
		if response, e := client.Do(r); e == nil {
			response.Body.Close()
		}
	}()
	tmp, err := os.MkdirTemp(s.dir, ".scan-")
	if err != nil {
		return "", 0, err
	}
	defer os.RemoveAll(tmp)
	var pages []string
	total := int64(0)
	format := ""
	for len(pages) < 100 {
		next := *remote
		next.Path += "/NextDocument"
		r, _ := http.NewRequestWithContext(ctx, "GET", next.String(), nil)
		response, err := client.Do(r)
		if err != nil {
			return "", 0, errors.New("прервана загрузка сканирования; проверьте устройство")
		}
		if response.StatusCode == 404 {
			response.Body.Close()
			break
		}
		if response.StatusCode == 503 {
			response.Body.Close()
			select {
			case <-ctx.Done():
				return "", 0, ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			return "", 0, fmt.Errorf("загрузка сканирования: HTTP %d", response.StatusCode)
		}
		path := filepath.Join(tmp, fmt.Sprintf("page-%03d", len(pages)+1))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			response.Body.Close()
			return "", 0, err
		}
		n, err := io.Copy(f, io.LimitReader(response.Body, queue.MaxDocumentSize-total+1))
		response.Body.Close()
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return "", 0, err
		}
		if closeErr != nil {
			return "", 0, closeErr
		}
		total += n
		if total > queue.MaxDocumentSize {
			return "", 0, queue.ErrTooLarge
		}
		detected, err := detect(path)
		if err != nil {
			return "", 0, err
		}
		if format != "" && format != detected {
			return "", 0, errors.New("сканер изменил формат между страницами")
		}
		format = detected
		pages = append(pages, path)
		if o.Source == "Platen" {
			break
		}
	}
	if len(pages) == 0 {
		return "", 0, errors.New("сканер не вернул документы")
	}
	if len(pages) == 100 {
		return "", 0, errors.New("превышен лимит 99 страниц; разбейте документ на части")
	}
	if len(pages) == 1 {
		err = os.Rename(pages[0], s.Path(j.ID))
		if err == nil {
			err = syncDir(s.dir)
		}
		return format, total, err
	}
	// Keep multipage results without requiring a PDF rendering engine.
	path := filepath.Join(tmp, "pages.zip")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", 0, err
	}
	zw := zip.NewWriter(f)
	ext := map[string]string{"application/pdf": ".pdf", "image/jpeg": ".jpg", "image/png": ".png"}[format]
	for i, p := range pages {
		entry, e := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("page-%03d%s", i+1, ext), Method: zip.Store})
		if e != nil {
			err = e
			break
		}
		src, e := os.Open(p)
		if e != nil {
			err = e
			break
		}
		_, err = io.Copy(entry, src)
		src.Close()
		if err != nil {
			break
		}
	}
	zerr := zw.Close()
	if err == nil {
		err = zerr
	}
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	stat, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if err = os.Rename(path, s.Path(j.ID)); err == nil {
		err = syncDir(s.dir)
	}
	return "application/zip", stat.Size(), err
}
