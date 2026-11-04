# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roman Sergeevich Kislov
Name: goprint
Version: %{rpm_version}
Release: %{rpm_release}
Summary: GoPrint print and scan server
License: Apache-2.0
Group: System/Servers
Url: https://github.com/rkislov/goPrint
Source0: goprint-%{upstream_tag}-linux-%{go_arch}.tar.gz
Source1: goprint.service
Source2: goprint-setup
Source3: environment
BuildRequires: rpm-build
Requires(pre): shadow-utils
Requires: systemd coreutils grep cups cups-filters ghostscript
AutoReqProv: no
# Release binaries are static Go executables, already stripped by the Go linker.
%define __find_provides /bin/true
%define __find_requires /bin/true

%description
GoPrint provides persistent print queues, domain authentication, PPD filtering,
Follow Me, scan inboxes and administrator connection diagnostics.
This package wraps the upstream static release binaries. Printer vendor drivers
are downloaded separately and retain their own licenses.

%prep
%setup -q -n goprint-%{upstream_tag}-linux-%{go_arch}

%build
# Compiled by packaging/release.sh with pinned version/commit build metadata.

%install
mkdir -p %buildroot%_bindir %buildroot%_sbindir %buildroot%_unitdir
mkdir -p %buildroot%_sysconfdir/goprint %buildroot/var/lib/goprint
for name in goprintd goprintctl goprint-ppds goprint-migrate goprint-mail-submit goprint-samba-submit; do
    install -m755 "$name" %buildroot%_bindir/"$name"
done
install -m755 %SOURCE2 %buildroot%_sbindir/goprint-setup
install -m644 %SOURCE1 %buildroot%_unitdir/goprint.service
install -m640 %SOURCE3 %buildroot%_sysconfdir/goprint/environment
mkdir -p %buildroot%_defaultdocdir/%name
cp -a LICENSE NOTICE THIRD_PARTY_NOTICES.md third_party docs packaging README.md RELEASE-NOTES.md BUILDINFO %buildroot%_defaultdocdir/%name/

%pre
getent group goprint >/dev/null || groupadd -r goprint
getent passwd goprint >/dev/null || useradd -r -g goprint -d /var/lib/goprint -s /sbin/nologin -M goprint

%post
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
# No automatic start or restart: an administrator controls active print jobs.

%preun
if [ "$1" = 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now goprint.service || :
fi

%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
# Keep the account and state directory: queued documents and keys must survive.

%files
%_bindir/goprintd
%_bindir/goprintctl
%_bindir/goprint-ppds
%_bindir/goprint-migrate
%_bindir/goprint-mail-submit
%_bindir/goprint-samba-submit
%_sbindir/goprint-setup
%_unitdir/goprint.service
%dir %attr(0750,root,goprint) %_sysconfdir/goprint
%config(noreplace) %attr(0640,root,goprint) %_sysconfdir/goprint/environment
%dir %attr(0700,goprint,goprint) /var/lib/goprint
%_defaultdocdir/%name
