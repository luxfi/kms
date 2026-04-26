// Package kms is the canonical Go client for Lux KMS.
//
// Transport: native luxfi/zap binary protocol on port 9999. There is no
// HTTP fallback in this package — services that need cross-cluster reach
// can shell out to /v1/kms/secrets/{name} via curl, but in-cluster Go is
// always ZAP.
//
// Defaults read from environment:
//
//	KMS_ADDR   host:port             (default kms.lux-kms-go.svc.cluster.local:9999)
//	KMS_PATH   secret path prefix    (default "/")
//	KMS_ENV    secret environment    (default "default")
//
// Bootstrap pattern — populate os.Setenv at process start, then read with
// the standard library:
//
//	func main() {
//	    kms.LoadEnv()
//	    db := os.Getenv("DATABASE_URL")
//	    run(db)
//	}
//
// Programmatic pattern:
//
//	v, err := kms.Get(ctx, "DATABASE_URL")
//	all, err := kms.GetSecrets(ctx)
package kms

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/luxfi/kms/pkg/zapclient"
)

const (
	defaultAddr = "kms.lux-kms-go.svc.cluster.local:9999"
	defaultPath = "/"
	defaultEnv  = "default"
)

// Config overrides the env-var defaults. The zero value works in-cluster
// and is the recommended way to call.
type Config struct {
	Addr string // KMS host:port
	Path string // secret path prefix
	Env  string // secret environment slug
}

func (c Config) resolve() Config {
	if c.Addr == "" {
		c.Addr = envOr("KMS_ADDR", defaultAddr)
	}
	if c.Path == "" {
		c.Path = envOr("KMS_PATH", defaultPath)
	}
	if c.Env == "" {
		c.Env = envOr("KMS_ENV", defaultEnv)
	}
	return c
}

// Get fetches a single secret value at the configured path/env.
func Get(ctx context.Context, name string) (string, error) {
	return GetWith(ctx, Config{}, name)
}

// GetWith fetches a single secret value with explicit configuration.
func GetWith(ctx context.Context, cfg Config, name string) (string, error) {
	cfg = cfg.resolve()
	c, err := zapclient.Dial(ctx, cfg.Addr, cfg.Path)
	if err != nil {
		return "", fmt.Errorf("kms: dial %s: %w", cfg.Addr, err)
	}
	defer c.Close()
	v, err := c.GetAt(ctx, cfg.Path, name, cfg.Env)
	if err != nil {
		return "", fmt.Errorf("kms: get %s/%s@%s: %w", cfg.Path, name, cfg.Env, err)
	}
	return v, nil
}

// GetSecrets fetches every secret at the configured path/env.
func GetSecrets(ctx context.Context) (map[string]string, error) {
	return GetSecretsWith(ctx, Config{})
}

// GetSecretsWith fetches every secret with explicit configuration.
func GetSecretsWith(ctx context.Context, cfg Config) (map[string]string, error) {
	cfg = cfg.resolve()
	c, err := zapclient.Dial(ctx, cfg.Addr, cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("kms: dial %s: %w", cfg.Addr, err)
	}
	defer c.Close()

	names, err := c.ListAt(ctx, cfg.Path, cfg.Env)
	if err != nil {
		return nil, fmt.Errorf("kms: list %s@%s: %w", cfg.Path, cfg.Env, err)
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		v, err := c.GetAt(ctx, cfg.Path, n, cfg.Env)
		if err != nil {
			return nil, fmt.Errorf("kms: get %s/%s@%s: %w", cfg.Path, n, cfg.Env, err)
		}
		out[n] = v
	}
	return out, nil
}

// LoadEnv fetches every secret at the configured path/env and writes each
// to os.Setenv. Fails fast (log.Fatalf) on error so the process exits
// before silently running with missing config.
func LoadEnv() {
	if err := LoadEnvCtx(context.Background()); err != nil {
		log.Fatalf("kms: LoadEnv: %v", err)
	}
}

// LoadEnvCtx is the context-aware form of LoadEnv. Use this from tests or
// when you want to control the timeout.
func LoadEnvCtx(ctx context.Context) error {
	return LoadEnvWith(ctx, Config{})
}

// LoadEnvWith populates os.Setenv with secrets fetched using the given config.
func LoadEnvWith(ctx context.Context, cfg Config) error {
	secrets, err := GetSecretsWith(ctx, cfg)
	if err != nil {
		return err
	}
	for k, v := range secrets {
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("kms: setenv %s: %w", k, err)
		}
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
