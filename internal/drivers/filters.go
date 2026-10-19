// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package drivers

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type Filter struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
}

func InstalledFilters() []Filter {
	filters := []Filter{{Name: "cupsfilter", Description: "Построение цепочки преобразования CUPS"}, {Name: "gs", Description: "Ghostscript · PostScript и PDF"}, {Name: "pdftops", Description: "Poppler · PDF → PostScript"}, {Name: "foomatic-rip", Description: "Foomatic · преобразование для legacy-принтеров"}, {Name: "rastertohp", Description: "Растровый вывод для HP"}, {Name: "rastertobrlaser", Description: "Растровый вывод для Brother"}, {Name: "rastertospl", Description: "SpliX · Samsung SPL"}}
	for i := range filters {
		if _, err := exec.LookPath(filters[i].Name); err == nil {
			filters[i].Installed = true
			continue
		}
		for _, dir := range []string{"/usr/lib/cups/filter", "/usr/libexec/cups/filter", "/usr/sbin"} {
			if info, err := os.Stat(filepath.Join(dir, filters[i].Name)); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
				filters[i].Installed = true
				break
			}
		}
	}
	return filters
}

type FilterManager struct {
	mu          sync.Mutex
	dir, status string
	busy        bool
}

func NewFilterManager(dir string) *FilterManager { return &FilterManager{dir: dir} }
func (f *FilterManager) Status() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status != "" {
		return f.status
	}
	if runtime.GOOS != "linux" {
		return "Сервер работает на " + runtime.GOOS + ". Linux-фильтры устанавливаются на целевом Linux-сервере; ниже показаны доступные локальные компоненты."
	}
	return "Загрузите пакеты из настроенных репозиториев Debian/Ubuntu. Установка зависимостей выполняется администратором через apt."
}
func (f *FilterManager) Download(ctx context.Context) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("загрузка .deb-пакетов доступна на Debian/Ubuntu; на macOS используются системные фильтры")
	}
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		return "", errors.New("apt-get не найден; используйте пакетный менеджер вашей Linux-системы")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy {
		return "Пакеты уже загружаются", nil
	}
	if err = os.MkdirAll(f.dir, 0700); err != nil {
		return "", err
	}
	dir, err := filepath.Abs(f.dir)
	if err != nil {
		return "", err
	}
	f.busy = true
	f.status = "Загрузка .deb-пакетов в фоне…"
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, apt, "download", "cups-filters", "cups-filters-core-drivers", "ghostscript", "poppler-utils", "printer-driver-gutenprint", "printer-driver-hpcups", "printer-driver-brlaser", "printer-driver-splix", "foomatic-db-engine")
		cmd.Dir = dir
		err := cmd.Run()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.busy = false
		if err != nil {
			f.status = "Не удалось скачать пакеты. Проверьте настроенные репозитории apt и доступность сети."
		} else {
			f.status = "Пакеты загружены в " + dir + ". Установите их через apt для разрешения системных зависимостей. Фильтры не включаются автоматически."
		}
	}()
	return "Загрузка пакетов запущена. Статус доступен в разделе фильтров.", nil
}
