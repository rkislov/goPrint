#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
tag=${1:?release tag required}
target=${2:?el9 or redos8 required}
case "$target" in el9|redos8) ;; *) exit 2;; esac
fields=$(printf '%s' "$tag" | sed -n 's/^v\([0-9][0-9.]*\)-beta\.\([0-9][0-9]*\)$/\1 \2/p')
set -- $fields
test "$#" = 2
version=$1
beta=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/SOURCES"
cp "/release/goprint-$tag-linux-amd64.tar.gz" "$work/SOURCES/"
cp /packaging/altlinux/goprint.service /packaging/altlinux/goprint-setup /packaging/altlinux/environment "$work/SOURCES/"
# Use the same payload, service and scriptlets as ALT with paths and macros understood by RPM on these targets.
sed -e '/^Group:/d' -e '/^%define __find_/d' -e 's/%_unitdir/\/usr\/lib\/systemd\/system/g' -e 's/%_defaultdocdir\/\%name/\%{_docdir}\/goprint/g' -e 's|/sbin/nologin|/usr/sbin/nologin|' /packaging/altlinux/goprint.spec > "$work/goprint.spec"
rpmbuild -bb --target x86_64 --define "_topdir $work" --define "upstream_tag $tag" --define "go_arch amd64" \
 --define "rpm_version $version" --define "rpm_release 0.beta.$beta.1.$target" \
 --define 'debug_package %{nil}' --define '__os_install_post %{nil}' "$work/goprint.spec"
cp "$work/RPMS/x86_64/"*.rpm /release/
