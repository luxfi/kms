.PHONY: build test clean docker dev

BINARY := kms
IMAGE  := ghcr.io/luxfi/kms:latest

build:
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/

test:
	go test -v -race ./...

clean:
	rm -f $(BINARY)

dev:
	KMS_DATA_DIR=./data KMS_LISTEN=:8080 go run ./cmd/kms/

docker:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/
	docker build --platform linux/amd64 -t $(IMAGE) -f Dockerfile.runtime .
