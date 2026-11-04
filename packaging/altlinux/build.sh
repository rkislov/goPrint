#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
set -eu
cd "$(dirname "$0")/../.."
tag=${1:?Usage: packaging/altlinux/build.sh v0.2.0-beta.5}
case "$tag" in v[0-9]*-beta.[0-9]*) ;; *) echo 'Expected a beta release tag' >&2; exit 2;; esac
for branch in ${GOPRINT_ALT_BRANCHES:-p10 p11}; do
 case "$branch" in p10|p11) ;; *) exit 2;; esac
 case "$branch" in p10) mirror=https://mirror.truenetwork.ru/altlinux;; p11) mirror=https://mirror.yandex.ru/altlinux;; esac
 for arch in ${GOPRINT_ALT_ARCHS:-amd64 arm64}; do
  case "$arch" in amd64|arm64) ;; *) exit 2;; esac
  test -s "dist/release/goprint-$tag-linux-$arch.tar.gz"
  image="goprint-alt-$branch-$arch-builder"
  docker build --platform "linux/$arch" --build-arg "ALT_BRANCH=$branch" --build-arg "ALT_MIRROR=$mirror" -t "$image" -f packaging/altlinux/Dockerfile packaging/altlinux
  container="goprint-rpm-$branch-$arch-$$"
  trap 'docker rm -f "$container" >/dev/null 2>&1 || :' EXIT HUP INT TERM
  docker create --name "$container" --network none --platform "linux/$arch" \
   -v "$PWD/dist/release:/release:ro" -v "$PWD/packaging/altlinux:/packaging:ro" \
   "$image" sh /packaging/build-in-container.sh "$tag" "$branch" "$arch"
  docker start -a "$container"
  docker cp "$container:/build/output/." dist/release/
  docker rm "$container"
  trap - EXIT HUP INT TERM
  case "$arch" in amd64) rpm_arch=x86_64;; arm64) rpm_arch=aarch64;; esac
  rpm_version=${tag#v}; rpm_version=${rpm_version%-beta.*}; beta=${tag##*-beta.}
  rpm="goprint-$rpm_version-alt0.beta.$beta.$branch.1.$rpm_arch.rpm"
  docker run --rm --user 0 --network none --platform "linux/$arch" \
   -v "$PWD/dist/release:/release:ro" -v "$PWD/packaging/altlinux:/packaging:ro" \
   "$image" python3 /packaging/smoke.py "/release/$rpm" "$tag"
 done
done

(cd dist/release && shasum -a 256 "goprint-$tag-linux-amd64.tar.gz" "goprint-$tag-linux-arm64.tar.gz" goprint-*-alt0.beta.*.rpm GoPrint-Administrator.pdf GoPrint-User.pdf GoPrint-Product.pptx GoPrint-Product.pdf > SHA256SUMS)
