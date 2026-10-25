// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Кислов Роман Сергеевич
package backend

import (
	"context"
	"encoding/json"
	"github.com/rkislov/goPrint/internal/diagnostics"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSMBDiagnosticsQuitOnlySafeReasons(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "smbclient")
	u, _ := url.Parse("smb://server/office")
	t.Setenv("GOPRINT_TOKEN", "sensitive-value")
	for _, tc := range []struct{ reply, code string }{{"", "smb_session"}, {"NT_STATUS_LOGON_FAILURE sensitive-value", "smb_credentials"}, {"NT_STATUS_BAD_NETWORK_NAME", "smb_share"}, {"NT_STATUS_ACCESS_DENIED", "smb_access"}, {"NT_STATUS_ACCOUNT_LOCKED_OUT", "smb_locked"}, {"NT_STATUS_NOT_SUPPORTED", "smb_encryption"}} {
		// Shell fixtures inspect argv; production never uses a shell.
		script := "#!/bin/sh\n[ -z \"$GOPRINT_TOKEN\" ] || exit 9\ncase \"$*\" in *'print '*) exit 8;; esac\ncase \"$*\" in *'-c quit'*) ;; *) exit 7;; esac\nprintf '%s\\n' '" + tc.reply + "'\nexit 0\n"
		if e := os.WriteFile(exe, []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		r := diagnoseSMBCommand(context.Background(), exe, dir, u, diagnostics.New())
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "sensitive-value") {
			t.Fatal("secret leaked")
		}
		found := false
		for _, s := range r.Steps {
			if s.Code == tc.code {
				found = true
			}
		}
		if !found {
			t.Fatal(tc.code, r)
		}
	}
}
