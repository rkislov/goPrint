// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич

// Package drivers indexes PPD descriptions. It never executes PPD directives.
package drivers

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const SourceURL = "https://codeload.github.com/OpenPrinting/foomatic-db/tar.gz/refs/heads/master"
const maxPPD = 4 << 20

type Profile struct {
	ID           string   `json:"id"`
	Manufacturer string   `json:"manufacturer"`
	Model        string   `json:"model"`
	Filename     string   `json:"filename"`
	Filters      []string `json:"filters"`
	Source       string   `json:"source"`
}
type Status struct {
	Count     int    `json:"count"`
	Syncing   bool   `json:"syncing"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Skipped   int    `json:"skipped"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256,omitempty"`
}
type Catalog struct {
	katusha  VendorStatus
	mu       sync.RWMutex
	dir      string
	profiles []Profile
	status   Status
}

func Open(dir string) (*Catalog, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	c := &Catalog{dir: dir, status: Status{Source: SourceURL}, profiles: []Profile{}}
	b, err := os.ReadFile(filepath.Join(dir, "catalog.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, c.loadVendor()
	}
	if err != nil {
		return nil, err
	}
	var saved struct {
		Profiles []Profile `json:"profiles"`
		Status   Status    `json:"status"`
	}
	if err = json.Unmarshal(b, &saved); err != nil {
		return nil, err
	}
	c.profiles = saved.Profiles
	c.status = saved.Status
	c.status.Syncing = false
	c.status.Count = len(c.profiles)
	return c, c.loadVendor()
}
func (c *Catalog) Status() Status { c.mu.RLock(); defer c.mu.RUnlock(); return c.status }
func (c *Catalog) Find(id string) (Profile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}
func (c *Catalog) Search(query, manufacturer string) []Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := []Profile{}
	q := strings.ToLower(query)
	for _, p := range c.profiles {
		if manufacturer != "" && !strings.EqualFold(p.Manufacturer, manufacturer) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Manufacturer+" "+p.Model+" "+p.Filename), q) {
			continue
		}
		out = append(out, p)
		if len(out) == 150 {
			break
		}
	}
	return out
}
func (c *Catalog) Manufacturers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	set := map[string]string{}
	for _, p := range c.profiles {
		key := strings.ToLower(p.Manufacturer)
		if _, ok := set[key]; !ok {
			set[key] = p.Manufacturer
		}
	}
	out := []string{}
	for _, m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
func (c *Catalog) StartSync(ctx context.Context) bool {
	c.mu.Lock()
	if c.status.Syncing {
		c.mu.Unlock()
		return false
	}
	c.status.Syncing = true
	c.status.Error = ""
	c.mu.Unlock()
	go func() {
		err := c.download(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Syncing = false
		if err != nil {
			c.status.Error = err.Error()
		}
	}()
	return true
}
func (c *Catalog) download(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", SourceURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Scheme != "https" {
			return errors.New("HTTPS required")
		}
		return nil
	}}
	rsp, err := client.Do(req)
	if err != nil {
		return errors.New("could not download OpenPrinting archive; retry later")
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return fmt.Errorf("OpenPrinting returned HTTP %d", rsp.StatusCode)
	}
	return c.Import(rsp.Body)
}

// Import keeps the original source archive with its copyright/license material.
// No upstream file names are used as destination paths.
func (c *Catalog) Import(r io.Reader) error {
	f, err := os.CreateTemp(c.dir, ".source-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(r, (256<<20)+1))
	if err == nil && n > 256<<20 {
		err = errors.New("archive exceeds 256 MiB")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	src, err := os.Open(name)
	if err != nil {
		return err
	}
	defer src.Close()
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, (2<<30)+1))
	profiles := []Profile{}
	skipped := 0
	seen := map[string]bool{}
	total := int64(0)
	for entries := 0; ; entries++ {
		if entries > 100000 {
			return errors.New("archive has too many entries")
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		lower := strings.ToLower(h.Name)
		if !strings.HasSuffix(lower, ".ppd") && !strings.HasSuffix(lower, ".ppd.gz") {
			continue
		}
		var reader io.Reader = tr
		var inner *gzip.Reader
		if strings.HasSuffix(lower, ".gz") {
			inner, err = gzip.NewReader(tr)
			if err != nil {
				skipped++
				continue
			}
			reader = inner
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxPPD+1))
		if inner != nil {
			inner.Close()
		}
		if err != nil || len(data) > maxPPD {
			skipped++
			continue
		}
		total += int64(len(data))
		if total > 1<<30 {
			return errors.New("PPD content exceeds 1 GiB")
		}
		p, err := Parse(data)
		if err != nil {
			skipped++
			continue
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		p.Filename = filepath.Base(h.Name)
		p.Source = "OpenPrinting / foomatic-db"
		if err = os.WriteFile(filepath.Join(c.dir, p.ID+".ppd"), data, 0600); err != nil {
			return err
		}
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		return errors.New("archive contains no valid PPD files")
	}
	sort.Slice(profiles, func(i, j int) bool {
		a, b := profiles[i], profiles[j]
		if a.Manufacturer != b.Manufacturer {
			return a.Manufacturer < b.Manufacturer
		}
		return a.Model < b.Model
	})
	digest := hex.EncodeToString(hash.Sum(nil))
	status := Status{Count: len(profiles), Source: SourceURL, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Skipped: skipped, SHA256: digest}
	// Content-addressed files and source archives can safely coexist across updates.
	if err = os.Rename(name, filepath.Join(c.dir, "source-"+digest+".tar.gz")); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.profiles {
		if p.Source == katushaSource {
			profiles = mergeProfiles(profiles, []Profile{p})
		}
	}
	status.Count = len(profiles)
	b, err := json.Marshal(struct {
		Profiles []Profile `json:"profiles"`
		Status   Status    `json:"status"`
	}{profiles, status})
	if err != nil {
		return err
	}
	index, err := os.CreateTemp(c.dir, ".index-")
	if err != nil {
		return err
	}
	defer os.Remove(index.Name())
	if _, err = index.Write(b); err == nil {
		err = index.Sync()
	}
	closeErr = index.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(index.Name(), filepath.Join(c.dir, "catalog.json")); err != nil {
		return err
	}
	c.profiles = profiles
	status.Syncing = c.status.Syncing
	c.status = status
	return nil
}
func Parse(data []byte) (Profile, error) {
	p := Profile{Filters: []string{}}
	if !strings.HasPrefix(string(data), "*PPD-Adobe:") {
		return p, errors.New("invalid PPD header")
	}
	sum := sha256.Sum256(data)
	p.ID = hex.EncodeToString(sum[:])
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxPPD)
	model := ""
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		if len(value) > 2048 {
			value = value[:2048]
		}
		switch key {
		case "*Manufacturer":
			p.Manufacturer = value
		case "*NickName":
			p.Model = value
		case "*ModelName":
			model = value
		case "*cupsFilter", "*cupsFilter2":
			if len(p.Filters) < 32 {
				p.Filters = append(p.Filters, value)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return p, err
	}
	if p.Model == "" {
		p.Model = model
	}
	if p.Model == "" {
		return p, errors.New("PPD has no model name")
	}
	if p.Manufacturer == "" {
		p.Manufacturer = "Other"
	}
	return p, nil
}

// PPD returns a verified copy of a content-addressed PPD. Keeping the file hash
// pinned also makes existing printer profiles independent of catalog updates.
func (c *Catalog) PPD(id string) ([]byte, error) {
	if len(id) != 64 {
		return nil, errors.New("invalid PPD identifier")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, errors.New("invalid PPD identifier")
	}
	f, err := os.Open(filepath.Join(c.dir, id+".ppd"))
	if err != nil {
		return nil, errors.New("selected PPD file is unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPPD+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPPD {
		return nil, errors.New("PPD exceeds size limit")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != id {
		return nil, errors.New("PPD integrity check failed")
	}
	return data, nil
}

func (c *Catalog) loadVendor() error {
	b, err := os.ReadFile(filepath.Join(c.dir, "vendor-katusha.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p []Profile
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	c.profiles = mergeProfiles(c.profiles, p)
	c.status.Count = len(c.profiles)
	return nil
}
