# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич

.PHONY: build test check linux clean

build:
	CGO_ENABLED=0 go build -trimpath -o bin/goprintd ./cmd/goprintd
	CGO_ENABLED=0 go build -trimpath -o bin/goprintctl ./cmd/goprintctl
	CGO_ENABLED=0 go build -trimpath -o bin/goprint-ppds ./cmd/goprint-ppds
	CGO_ENABLED=0 go build -trimpath -o bin/goprint-migrate ./cmd/goprint-migrate

test:
	go test -race ./...

check:
	go vet ./...
	go test -race ./...

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/linux-amd64/goprintd ./cmd/goprintd
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/linux-amd64/goprintctl ./cmd/goprintctl
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/linux-arm64/goprintd ./cmd/goprintd
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/linux-arm64/goprintctl ./cmd/goprintctl
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/linux-amd64/goprint-ppds ./cmd/goprint-ppds
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/linux-arm64/goprint-ppds ./cmd/goprint-ppds
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/linux-amd64/goprint-migrate ./cmd/goprint-migrate
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/linux-arm64/goprint-migrate ./cmd/goprint-migrate
	cp LICENSE NOTICE THIRD_PARTY_NOTICES.md dist/linux-amd64/
	cp LICENSE NOTICE THIRD_PARTY_NOTICES.md dist/linux-arm64/
	cp -R third_party dist/linux-amd64/
	cp -R third_party dist/linux-arm64/

clean:
	rm -rf bin dist
