#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
tag=${1:?release tag required}
target=${2:?ubuntu24.04 or astra1.8 required}
arch=${3:?amd64 or arm64 required}
case "$target/$arch" in ubuntu24.04/amd64|ubuntu24.04/arm64|astra1.8/amd64) ;; *) exit 2;; esac
version=$(printf '%s' "$tag" | sed -n 's/^v\([0-9][0-9.]*\)-beta\.\([0-9][0-9]*\)$/\1~beta.\2/p')
test -n "$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "/release/goprint-$tag-linux-$arch.tar.gz" -C "$work"
source="$work/goprint-$tag-linux-$arch"
root="$work/pkg"
install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/sbin" "$root/lib/systemd/system" "$root/etc/goprint" "$root/var/lib/goprint" "$root/usr/share/doc/goprint"
for name in goprintd goprintctl goprint-ppds goprint-migrate goprint-mail-submit goprint-samba-submit; do
 install -m755 "$source/$name" "$root/usr/bin/"
done
install -m755 /packaging/altlinux/goprint-setup "$root/usr/sbin/"
install -m644 /packaging/altlinux/goprint.service "$root/lib/systemd/system/"
install -m640 /packaging/altlinux/environment "$root/etc/goprint/"
cp -R "$source/LICENSE" "$source/NOTICE" "$source/THIRD_PARTY_NOTICES.md" "$source/third_party" "$source/docs" "$source/README.md" "$source/RELEASE-NOTES.md" "$source/BUILDINFO" "$root/usr/share/doc/goprint/"
cp "$source/LICENSE" "$root/usr/share/doc/goprint/copyright"
cat > "$root/DEBIAN/control" <<CONTROL
Package: goprint
Version: $version-1+$target
Architecture: $arch
Maintainer: Roman Sergeevich Kislov <rkislov@users.noreply.github.com>
Section: net
Priority: optional
Depends: passwd, systemd, cups, cups-filters, ghostscript
Homepage: https://github.com/rkislov/goPrint
Description: GoPrint print and scan server
 GoPrint provides print queues, PPD filtering and scan inboxes.
CONTROL
printf '/etc/goprint/environment\n' > "$root/DEBIAN/conffiles"
cat > "$root/DEBIAN/postinst" <<'SCRIPT'
#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 getent group goprint >/dev/null || groupadd -r goprint
 getent passwd goprint >/dev/null || useradd -r -g goprint -d /var/lib/goprint -s /usr/sbin/nologin -M goprint
 chown root:goprint /etc/goprint
 chmod 0750 /etc/goprint
 if [ -f /etc/goprint/environment ]; then
  chown root:goprint /etc/goprint/environment
  chmod 0640 /etc/goprint/environment
 fi
 chown goprint:goprint /var/lib/goprint
 chmod 0700 /var/lib/goprint
 if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
fi
SCRIPT
cat > "$root/DEBIAN/prerm" <<'SCRIPT'
#!/bin/sh
set -eu
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
 systemctl disable --now goprint.service || :
fi
SCRIPT
cat > "$root/DEBIAN/postrm" <<'SCRIPT'
#!/bin/sh
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
SCRIPT
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
# Gzip compression is readable by dpkg versions predating zstd packages.
dpkg-deb --root-owner-group -Zgzip --build "$root" "/release/goprint-$tag-$target-$arch.deb"
