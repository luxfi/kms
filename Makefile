.PHONY: build build-ui copy-ui test clean docker dev

BINARY := kms
IMAGE  := ghcr.io/luxfi/kms:latest

# Vite SPA → cmd/kms/web/ (//go:embed reads from there).
build-ui:
	cd frontend && pnpm install --frozen-lockfile && pnpm build

copy-ui:
	rm -rf cmd/kms/web && mkdir -p cmd/kms/web
	@if [ -d frontend/dist ]; then cp -R frontend/dist/. cmd/kms/web/; \
	else echo "warning: frontend/dist not found — UI will be empty in this build"; touch cmd/kms/web/.empty; fi

build: copy-ui
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/

test:
	go test -v -race ./...

clean:
	rm -f $(BINARY)
	rm -rf cmd/kms/web

dev: copy-ui
	KMS_DATA_DIR=./data KMS_LISTEN=:8080 go run ./cmd/kms/

docker: copy-ui
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY) ./cmd/kms/
	docker build --platform linux/amd64 -t $(IMAGE) -f Dockerfile.runtime .
