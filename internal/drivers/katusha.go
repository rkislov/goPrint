// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ulikunitz/xz"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const KatushaURL = "https://www.katusha-it.ru/storage/filemanager/downloads/Katusha%20Devices/Unidrv/Katusha-Universal-Driver_installer.zip"
const KatushaSHA256 = "83457754520049c4c8138d493013e0d21068e4a9d2b5259977688fa1eecc514c"
const katushaSource = "Катюша / официальный универсальный драйвер 2.1-1"

type VendorStatus struct {
	Source  string `json:"source"`
	SHA256  string `json:"sha256"`
	Count   int    `json:"count"`
	Syncing bool   `json:"syncing"`
	Error   string `json:"error,omitempty"`
}

func (c *Catalog) KatushaStatus() VendorStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v := c.katusha
	v.Source = KatushaURL
	v.SHA256 = KatushaSHA256
	for _, p := range c.profiles {
		if p.Source == katushaSource {
			v.Count++
		}
	}
	return v
}
func (c *Catalog) StartKatushaSync(ctx context.Context) bool {
	c.mu.Lock()
	if c.katusha.Syncing {
		c.mu.Unlock()
		return false
	}
	c.katusha.Syncing = true
	c.katusha.Error = ""
	c.mu.Unlock()
	go func() {
		err := c.syncKatusha(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.katusha.Syncing = false
		if err != nil {
			c.katusha.Error = err.Error()
		}
	}()
	return true
}
func (c *Catalog) syncKatusha(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", KatushaURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Scheme != "https" || r.URL.Hostname() != "www.katusha-it.ru" && r.URL.Hostname() != "katusha-it.ru" {
			return errors.New("unexpected vendor redirect")
		}
		return nil
	}}
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return errors.New("vendor download failed")
	}
	data, err := io.ReadAll(io.LimitReader(rsp.Body, 64<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("vendor archive too large")
	}
	return c.ImportKatusha(data)
}

// ImportKatusha reads data only: vendor installers, package hooks and binaries are never executed.
func (c *Catalog) ImportKatusha(data []byte) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != KatushaSHA256 {
		return errors.New("контрольная сумма пакета Катюша изменилась; требуется проверка новой версии")
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	profiles := []Profile{}
	seen := map[string]bool{}
	for _, f := range z.File {
		if !strings.HasSuffix(f.Name, ".tar") {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		defer r.Close()
		tr := tar.NewReader(io.LimitReader(r, 64<<20))
		for n := 0; n < 10000; n++ {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if h.Typeflag != tar.TypeReg || !strings.HasPrefix(h.Name, "packages/katusha-") || !strings.HasSuffix(h.Name, ".deb") {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, 16<<20+1))
			if err != nil || len(b) > 16<<20 {
				return errors.New("invalid vendor package")
			}
			packageDir := filepath.Join(c.dir, "katusha-packages")
			if err = os.MkdirAll(packageDir, 0700); err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(packageDir, filepath.Base(h.Name)), b, 0600); err != nil {
				return err
			}
			ppds, err := debPPDs(b)
			if err != nil {
				return err
			}
			for filename, ppd := range ppds {
				p, err := Parse(ppd)
				if err != nil {
					return err
				}
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				p.Manufacturer = "Катюша"
				p.Filename = filename
				p.Source = katushaSource
				if err = os.WriteFile(filepath.Join(c.dir, p.ID+".ppd"), ppd, 0600); err != nil {
					return err
				}
				profiles = append(profiles, p)
			}
		}
	}
	if len(profiles) == 0 {
		return errors.New("vendor archive contains no PPDs")
	}
	if err = os.WriteFile(filepath.Join(c.dir, "katusha-source-"+KatushaSHA256+".zip"), data, 0600); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(profiles)
	if err = atomicIndex(c.dir, "vendor-katusha.json", b); err != nil {
		return err
	}
	base := []Profile{}
	for _, p := range c.profiles {
		if p.Source != katushaSource {
			base = append(base, p)
		}
	}
	c.profiles = mergeProfiles(base, profiles)
	c.status.Count = len(c.profiles)
	return nil
}
func debPPDs(data []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(data) < 8 || string(data[:8]) != "!<arch>\n" {
		return nil, errors.New("invalid deb header")
	}
	for off := 8; off+60 <= len(data); {
		h := data[off : off+60]
		n, err := strconv.Atoi(strings.TrimSpace(string(h[48:58])))
		if err != nil || n < 0 || n > len(data)-off-60 {
			return nil, errors.New("invalid deb size")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(h[:16])), "/")
		b := data[off+60 : off+60+n]
		off += 60 + n + n%2
		if name != "data.tar.xz" {
			continue
		}
		r, err := (xz.ReaderConfig{DictCap: 16 << 20}).NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(io.LimitReader(r, 256<<20))
		total := 0
		for count := 0; count < 10000; count++ {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg || !strings.HasSuffix(strings.ToLower(h.Name), ".ppd") {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, maxPPD+1))
			if err != nil || len(b) > maxPPD {
				return nil, errors.New("invalid vendor PPD")
			}
			total += len(b)
			if total > 16<<20 {
				return nil, errors.New("too much vendor PPD data")
			}
			out[filepath.Base(h.Name)] = b
		}
	}
	return out, nil
}
func mergeProfiles(a, b []Profile) []Profile {
	seen := map[string]bool{}
	out := []Profile{}
	for _, p := range append(append([]Profile{}, a...), b...) {
		if !seen[p.ID] {
			out = append(out, p)
			seen[p.ID] = true
		}
	}
	return out
}
func atomicIndex(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, ".index-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	e := f.Close()
	if err != nil {
		return err
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

func (c *Catalog) KatushaPackage(name string) (string, error) {
	switch name {
	case "katusha-mfp-driver-m130-series-amd64.deb", "katusha-mfp-driver-m247-series-amd64.deb", "katusha-mfp-driver-m348-series-amd64.deb", "katusha-mfp-driver-universal-amd64.deb":
	default:
		return "", os.ErrNotExist
	}
	p := filepath.Join(c.dir, "katusha-packages", name)
	_, err := os.Stat(p)
	return p, err
}
