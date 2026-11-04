#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
set -eu
tag=${1:?release tag required}
branch=${2:?p10 or p11 required}
go_arch=${3:?amd64 or arm64 required}
case "$branch" in p10|p11) ;; *) exit 2;; esac
case "$go_arch" in amd64) rpm_arch=x86_64;; arm64) rpm_arch=aarch64;; *) exit 2;; esac
base=${tag#v};version=${base%-beta.*};beta=${base##*-beta.}
case "$version" in *[!0-9.]*|'') exit 2;; esac
case "$beta" in *[!0-9]*|'') exit 2;; esac
[ "$base" != "$version" ] || exit 2
root=$(mktemp -d /tmp/goprint-rpm.XXXXXX)
trap 'rm -rf "$root"' EXIT
for name in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do mkdir -p "$root/$name"; done
cp "/release/goprint-$tag-linux-$go_arch.tar.gz" "$root/SOURCES/"
cp /packaging/goprint.service /packaging/goprint-setup /packaging/environment "$root/SOURCES/"
cp /packaging/goprint.spec "$root/SPECS/"
rpmbuild -bb --target "$rpm_arch" --define "_topdir $root" \
 --define "upstream_tag $tag" --define "rpm_version $version" \
 --define "rpm_release alt0.beta.$beta.$branch.1" --define "alt_branch $branch" \
 --define "go_arch $go_arch" "$root/SPECS/goprint.spec"
mkdir -p /build/output
cp "$root/RPMS/$rpm_arch/"*.rpm /build/output/
