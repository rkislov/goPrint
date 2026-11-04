// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sindohSource = "Sindoh / официальный Linux PPD"
const SindohDownloadPage = "https://www.sindoh.com/en/business/printing-solution/download"

//go:embed sindoh-sources.json
var sindohManifest []byte

type sindohArchive struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

func sindohArchives() []sindohArchive {
	var v []sindohArchive
	_ = json.Unmarshal(sindohManifest, &v)
	return v
}
func (c *Catalog) SindohStatus() VendorStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v := c.sindoh
	v.Source = SindohDownloadPage
	sum := sha256.Sum256(sindohManifest)
	v.SHA256 = hex.EncodeToString(sum[:])
	for _, p := range c.profiles {
		if p.Source == sindohSource {
			v.Count++
		}
	}
	return v
}
func (c *Catalog) StartSindohSync(ctx context.Context) bool {
	c.mu.Lock()
	if c.sindoh.Syncing {
		c.mu.Unlock()
		return false
	}
	c.sindoh.Syncing = true
	c.sindoh.Error = ""
	c.mu.Unlock()
	go func() {
		err := c.syncSindoh(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.sindoh.Syncing = false
		if err != nil {
			c.sindoh.Error = err.Error()
		}
	}()
	return true
}
func (c *Catalog) syncSindoh(ctx context.Context) error {
	if !validateSindohManifest() {
		return errors.New("invalid Sindoh source manifest")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || r.URL.Scheme != "https" || r.URL.Hostname() != "www.sindoh.com" || r.URL.User != nil {
			return errors.New("unexpected Sindoh redirect")
		}
		return nil
	}}
	for _, a := range sindohArchives() {
		// Reuse the verified source archive for offline restarts and retries.
		path := filepath.Join(c.dir, "sindoh-source-"+a.SHA256+".zip")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			req, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
			if e != nil {
				return e
			}
			rsp, e := client.Do(req)
			if e != nil {
				return errors.New("не удалось скачать пакет Sindoh; проверьте доступ к www.sindoh.com")
			}
			if rsp.StatusCode != http.StatusOK {
				rsp.Body.Close()
				return errors.New("сервер Sindoh не отдал пакет драйвера")
			}
			data, err = io.ReadAll(io.LimitReader(rsp.Body, (32<<20)+1))
			rsp.Body.Close()
		}
		if err != nil {
			return err
		}
		if len(data) > 32<<20 {
			return errors.New("Sindoh archive exceeds 32 MiB")
		}
		if err = c.ImportSindoh(data); err != nil {
			return err
		}
	}
	return nil
}

// ImportSindoh accepts only pinned official ZIP archives; it never runs installers.
func (c *Catalog) ImportSindoh(data []byte) error {
	if len(data) > 32<<20 {
		return errors.New("Sindoh archive exceeds 32 MiB")
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	approved := false
	for _, a := range sindohArchives() {
		if a.SHA256 == digest {
			approved = true
			break
		}
	}
	if !approved {
		return errors.New("контрольная сумма пакета Sindoh не подтверждена; требуется проверка новой версии")
	}
	files, err := sindohPPDs(data)
	if err != nil {
		return err
	}
	profiles := []Profile{}
	seen := map[string]bool{}
	for _, file := range files {
		p, err := Parse(file.data)
		if err != nil {
			return err
		}
		if !strings.EqualFold(p.Manufacturer, "Sindoh") {
			return errors.New("unexpected PPD manufacturer in Sindoh archive")
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		p.Manufacturer = "Sindoh"
		p.Filename = filepath.Base(file.name)
		p.Source = sindohSource
		if err = os.WriteFile(filepath.Join(c.dir, p.ID+".ppd"), file.data, 0600); err != nil {
			return err
		}
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		return errors.New("Sindoh archive contains no supported English PPDs")
	}
	if err = os.WriteFile(filepath.Join(c.dir, "sindoh-source-"+digest+".zip"), data, 0600); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	merged := mergeProfiles(c.profiles, profiles)
	vendor := []Profile{}
	for _, p := range merged {
		if p.Source == sindohSource {
			vendor = append(vendor, p)
		}
	}
	b, err := json.Marshal(vendor)
	if err != nil {
		return err
	}
	if err = atomicIndex(c.dir, "vendor-sindoh.json", b); err != nil {
		return err
	}
	c.profiles = merged
	c.status.Count = len(merged)
	return nil
}

type sindohPPD struct {
	name string
	data []byte
}

func sindohPPDs(data []byte) ([]sindohPPD, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if len(z.File) > 10000 {
		return nil, errors.New("too many Sindoh archive entries")
	}
	out := []sindohPPD{}
	total := 0
	add := func(name string, r io.Reader) error {
		b, e := io.ReadAll(io.LimitReader(r, maxPPD+1))
		if e != nil {
			return e
		}
		total += len(b)
		if len(b) > maxPPD || total > 32<<20 {
			return errors.New("Sindoh PPD data exceeds size limit")
		}
		if !bytes.Contains(b, []byte("*LanguageVersion: English")) {
			return nil
		}
		out = append(out, sindohPPD{name, b})
		return nil
	}
	for _, f := range z.File {
		if !f.Mode().IsRegular() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".ppd") && strings.Contains(f.Name, "/CUPS1.2/EN/") {
			r, e := f.Open()
			if e != nil {
				return nil, e
			}
			e = add(f.Name, r)
			r.Close()
			if e != nil {
				return nil, e
			}
		}
		if !strings.HasSuffix(f.Name, ".tar.gz") {
			continue
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		gz, e := gzip.NewReader(io.LimitReader(r, 16<<20))
		if e != nil {
			r.Close()
			return nil, e
		}
		tr := tar.NewReader(io.LimitReader(gz, 32<<20))
		for n := 0; n < 10000; n++ {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				gz.Close()
				r.Close()
				return nil, e
			}
			if h.Typeflag == tar.TypeReg && strings.HasSuffix(strings.ToLower(h.Name), ".ppd") {
				if e = add(h.Name, tr); e != nil {
					gz.Close()
					r.Close()
					return nil, e
				}
			}
		}
		gz.Close()
		r.Close()
	}
	return out, nil
}

// Validate the embedded download manifest without permitting arbitrary fetch URLs.
func validateSindohManifest() bool {
	for _, a := range sindohArchives() {
		u, e := url.Parse(a.URL)
		b, he := hex.DecodeString(a.SHA256)
		if e != nil || u.Scheme != "https" || u.Host != "www.sindoh.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/hubfs/site/driver/") || he != nil || len(b) != 32 {
			return false
		}
	}
	return len(sindohArchives()) > 0
}
