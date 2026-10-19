#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
 echo "Usage: $0 DATA_DIRECTORY PRIVATE_DSN_FILE [--execute]" >&2
 exit 2
fi
if [ "$#" -eq 3 ] && [ "$3" != --execute ]; then
 echo 'Only --execute is accepted as the third argument' >&2
 exit 2
fi
# The binary enforces the daemon lock, an unused target, transactional copy,
# row counts and SHA-256 verification. Without --execute it rolls back.
exec "${GOPRINT_MIGRATE_BIN:-goprint-migrate}" -data "$1" -postgres-dsn-file "$2" ${3:+-execute}
