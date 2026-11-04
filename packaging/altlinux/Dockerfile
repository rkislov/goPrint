# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
ARG ALT_BRANCH=p10
FROM alpine:3.21 AS trust
FROM alt:${ALT_BRANCH}
ARG ALT_MIRROR=https://mirror.truenetwork.ru/altlinux
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /tmp/goprint-ca.pem
# Use the ALT mirror over HTTPS; repository signature checks remain enabled.
RUN sed -i "s|http://ftp.altlinux.org/pub/distributions/ALTLinux|${ALT_MIRROR}|g" /etc/apt/sources.list.d/*.list && \
    apt-get -o Acquire::https::CaInfo=/tmp/goprint-ca.pem -o Acquire::Retries=2 update && \
    apt-get -o Acquire::https::CaInfo=/tmp/goprint-ca.pem -y install ca-certificates rpm-build shadow-utils systemd cups cups-filters ghostscript curl python3 && \
    apt-get clean
RUN apt-get -o Acquire::https::CaInfo=/tmp/goprint-ca.pem -y install systemd-analyze && apt-get clean
WORKDIR /build
RUN groupadd -r builder && useradd -r -g builder -d /build -s /bin/sh -M builder && chown builder:builder /build
USER builder
