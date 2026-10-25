// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package backend

import (
	"context"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"github.com/rkislov/goPrint/internal/queue"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Diagnose only authenticates and opens the configured share, then quits.
func (s *SMBService) Diagnose(ctx context.Context, p queue.Printer) diagnostics.Report {
	r := diagnostics.New()
	if e := Validate(p); e != nil || !strings.HasPrefix(p.URI, "smb://") {
		r.Add("smb_uri", "error", "Некорректный адрес SMB-принтера.", "Используйте smb://сервер/очередь без пароля и порта.")
		return r
	}
	executable, e := exec.LookPath("smbclient")
	if e != nil {
		r.Add("smb_client_missing", "error", "На сервере GoPrint не установлен smbclient.", "Установите пакет smbclient (Debian/Ubuntu) или samba-client (RHEL).")
		return r
	}
	r.Add("smb_client", "ok", "smbclient найден.", "")
	var v smbStored
	if e = s.store.Setting(ctx, "smb:"+p.ID, &v); e != nil {
		r.Add("smb_config", "error", "Не удалось прочитать настройки SMB.", "Проверьте БД.")
		return r
	}
	if !v.Config.Enabled || v.Config.Username == "" || len(v.Secret) == 0 {
		r.Add("smb_unconfigured", "warning", "SMB выключен или служебные учётные данные не заданы.", "Откройте «Подключение SMB» в карточке принтера, сохраните настройки и включите отправку.")
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	u, _ := url.Parse(p.URI)
	conn, connectErr := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), "445"))
	if connectErr != nil {
		r.Error("smb_connect", connectErr)
		return r
	}
	conn.Close()
	r.Add("smb_tcp", "ok", "TCP 445 доступен.", "")
	a := s.aead()
	if len(v.Secret) < a.NonceSize() {
		r.Add("smb_secret", "error", "Повреждены сохранённые учётные данные SMB.", "Сохраните пароль заново.")
		return r
	}
	password, e := a.Open(nil, v.Secret[:a.NonceSize()], v.Secret[a.NonceSize():], []byte(p.ID))
	if e != nil {
		r.Add("smb_secret", "error", "Не удалось расшифровать пароль SMB.", "Восстановите smb.key или сохраните пароль заново.")
		return r
	}
	dir, e := os.MkdirTemp("", "goprint-smb-check-")
	if e != nil {
		r.Add("smb_temp", "error", "Не удалось создать приватный временный каталог.", "Проверьте место и права временного каталога службы.")
		return r
	}
	defer os.RemoveAll(dir)
	if e = os.WriteFile(filepath.Join(dir, "auth"), []byte("username = "+v.Config.Username+"\ndomain = "+v.Config.Domain+"\npassword = "+string(password)+"\n"), 0600); e != nil {
		r.Add("smb_temp", "error", "Не удалось подготовить учётные данные.", "Проверьте место и права временного каталога службы.")
		return r
	}
	return diagnoseSMBCommand(ctx, executable, dir, u, r)
}

func diagnoseSMBCommand(ctx context.Context, executable, dir string, u *url.URL, r diagnostics.Report) diagnostics.Report {
	cmd := exec.CommandContext(ctx, executable, "//"+u.Host+u.Path, "-A", "auth", "--use-kerberos=off", "--client-protection=encrypt", "--option=client min protocol=SMB3_00", "--option=client max protocol=SMB3", "--option=client ntlmv2 auth=yes", "-t", "8", "-c", "quit")
	cmd.Dir = dir
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "HOME=" + dir, "TMPDIR=" + dir}
	var out limitedSMBOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	e := cmd.Run()
	text := strings.ToUpper(string(out.data))
	if ctx.Err() != nil {
		r.Error("smb", ctx.Err())
		return r
	}
	code, msg, hint := "smb_protocol", "Не удалось открыть SMB-сеанс.", "Проверьте SMB3, обязательное шифрование и журнал Samba."
	switch {
	case strings.Contains(text, "NT_STATUS_LOGON_FAILURE") || strings.Contains(text, "NT_STATUS_WRONG_PASSWORD"):
		code, msg, hint = "smb_credentials", "Сервер отклонил учётные данные.", "Проверьте домен, имя и пароль служебной записи."
	case strings.Contains(text, "NT_STATUS_ACCOUNT_LOCKED_OUT"):
		code, msg, hint = "smb_locked", "Служебная запись заблокирована.", "Разблокируйте запись и исправьте сохранённый пароль перед повторной проверкой."
	case strings.Contains(text, "NT_STATUS_BAD_NETWORK_NAME"):
		code, msg, hint = "smb_share", "SMB-очередь не найдена.", "Проверьте имя опубликованной шары."
	case strings.Contains(text, "NT_STATUS_ACCESS_DENIED"):
		code, msg, hint = "smb_access", "Доступ к SMB-очереди запрещён.", "Разрешите служебной записи доступ к нужной очереди."
	case strings.Contains(text, "NT_STATUS_CONNECTION_REFUSED"):
		code, msg, hint = "smb_refused", "SMB-соединение отклонено.", "Проверьте службу Samba и доступ TCP 445."
	case strings.Contains(text, "NT_STATUS_IO_TIMEOUT") || strings.Contains(text, "NT_STATUS_HOST_UNREACHABLE"):
		code, msg, hint = "smb_timeout", "SMB-сервер недоступен.", "Проверьте маршрутизацию и межсетевой экран для TCP 445."
	case strings.Contains(text, "NT_STATUS_NOT_SUPPORTED") || strings.Contains(text, "ENCRYPTION REQUIRED"):
		code, msg, hint = "smb_encryption", "Не согласованы SMB3 и шифрование.", "Включите SMB3 с шифрованием на принимающем сервере."
	case strings.Contains(text, "INVALID OPTION") || strings.Contains(text, "UNRECOGNIZED OPTION"):
		code, msg, hint = "smb_client_version", "Версия smbclient не поддерживает нужные параметры.", "Обновите Samba client до версии с --client-protection и --use-kerberos."
	}
	if e != nil || strings.Contains(text, "NT_STATUS_") || strings.Contains(text, "FAILED") || strings.Contains(text, "ERROR") {
		r.Add(code, "error", msg, hint)
		return r
	}
	r.Add("smb_session", "ok", "SMB3-сеанс с шифрованием открыт; доступ к шаре подтверждён.", "")
	r.Add("smb_print_unchecked", "warning", "Задание не отправлялось; право печати и обработка удалённой очереди не проверены.", "Перед внедрением напечатайте одну согласованную тестовую страницу.")
	return r
}
