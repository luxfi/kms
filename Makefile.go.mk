.PHONY: build-go test-go clean-go docker-go

BINARY := kms
IMAGE  := ghcr.io/luxfi/kms:latest

build-go:
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/

test-go:
	go test -v -race ./...

clean-go:
	rm -f $(BINARY)

docker-go:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/
	docker build --platform linux/amd64 -t $(IMAGE) -f Dockerfile.kms .

