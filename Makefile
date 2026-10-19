.PHONY: build test check linux clean

build:
	CGO_ENABLED=0 go build -trimpath -o bin/goprintd ./cmd/goprintd
	CGO_ENABLED=0 go build -trimpath -o bin/goprintctl ./cmd/goprintctl

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

clean:
	rm -rf bin dist
