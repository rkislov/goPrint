#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
set -eu
cd "$(dirname "$0")/.."
version=${1:?Usage: packaging/release.sh v0.2.0-beta.3}
case "$version" in v[0-9]* ) ;; *) echo 'Version must begin with v and a digit' >&2; exit 1;; esac
case "$version" in *[!a-zA-Z0-9._-]*) echo 'Invalid version' >&2; exit 1;; esac
if [ -n "$(git status --porcelain)" ]; then echo 'Commit changes before packaging' >&2; exit 1; fi
commit=$(git rev-parse HEAD)
date=$(git show -s --format=%cI HEAD)
for arch in amd64 arm64; do
 name="goprint-$version-linux-$arch"
 root="dist/release/$name"
 mkdir -p "$root/packaging" "$root/docs"
 for command in goprintd goprintctl goprint-ppds goprint-migrate goprint-mail-submit goprint-samba-submit; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X github.com/rkislov/goPrint/internal/buildinfo.Version=$version -X github.com/rkislov/goPrint/internal/buildinfo.Commit=$commit -X github.com/rkislov/goPrint/internal/buildinfo.Date=$date" -o "$root/$command" "./cmd/$command"
 done
 cp LICENSE NOTICE THIRD_PARTY_NOTICES.md README.md "$root/"
 if [ -f "docs/RELEASE-NOTES-$version.md" ]; then cp "docs/RELEASE-NOTES-$version.md" "$root/RELEASE-NOTES.md"; fi
 cp -Rf third_party "$root/"
 cp packaging/postgresql-init.sql packaging/sqlite-to-postgresql.sh "$root/packaging/"
 cp docs/POSTGRESQL.md docs/MONITORING.md docs/SCAN-INBOX.md docs/SAMBA.md "$root/docs/"
 cp packaging/goprint.service packaging/domain.example.json packaging/domain-sso.example.json packaging/samba.example.json packaging/samba-share.example.conf packaging/samba-systemd.example.conf "$root/packaging/"
 cp docs/ADMINISTRATOR.md docs/USER.md docs/DOMAIN-AND-CLIENTS.md docs/BETA-OPERATIONS.md "$root/docs/"
 cp -R docs/images "$root/docs/"
 cp -R docs/presentation "$root/docs/"
 cp output/pdf/GoPrint-Administrator.pdf output/pdf/GoPrint-User.pdf "$root/docs/"
 printf 'version=%s\ncommit=%s\ndate=%s\nplatform=linux/%s\n' "$version" "$commit" "$date" "$arch" > "$root/BUILDINFO"
 tar -czf "dist/release/$name.tar.gz" -C dist/release "$name"
done
cp output/pdf/GoPrint-Administrator.pdf output/pdf/GoPrint-User.pdf dist/release/
cp docs/presentation/GoPrint-Product.pptx docs/presentation/GoPrint-Product.pdf dist/release/
(cd dist/release && shasum -a 256 "goprint-$version-linux-amd64.tar.gz" "goprint-$version-linux-arm64.tar.gz" GoPrint-Administrator.pdf GoPrint-User.pdf GoPrint-Product.pptx GoPrint-Product.pdf > SHA256SUMS)
