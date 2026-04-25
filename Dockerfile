# luxfi/kms — MPC-backed KMS + secrets UI on Hanzo Base
# Frontend: KMS React SPA
# Backend: Go + sqlcipher + MPC/ZAP

FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY frontend/ .
RUN pnpm vite build

FROM golang:1.25-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher-dev gcc libc6-dev pkg-config git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
ENV GOPRIVATE=github.com/luxfi/*,github.com/hanzoai/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=1 go build -tags "sqlite_fts5 sqlcipher" \
    -ldflags="-s -w" -o /usr/local/bin/kms ./cmd/kms

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/kms /usr/local/bin/kms
COPY --from=frontend /src/frontend/dist /app/frontend
RUN mkdir -p /data/kms

ENV KMS_FRONTEND_DIR=/app/frontend
ENV BASE_SKIP_ROOT_REDIRECT=1
ENV BASE_DISABLE_ADMIN_UI=1

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1
ENTRYPOINT ["kms", "serve", "--http=0.0.0.0:8080"]
