package kms

import (
	"os"
	"testing"
)

func TestConfigResolve_Defaults(t *testing.T) {
	t.Setenv("KMS_ADDR", "")
	t.Setenv("KMS_PATH", "")
	t.Setenv("KMS_ENV", "")
	got := Config{}.resolve()
	if got.Addr != defaultAddr || got.Path != defaultPath || got.Env != defaultEnv {
		t.Fatalf("defaults drifted: %+v", got)
	}
}

func TestConfigResolve_FromEnv(t *testing.T) {
	t.Setenv("KMS_ADDR", "localhost:9999")
	t.Setenv("KMS_PATH", "/cloud")
	t.Setenv("KMS_ENV", "dev")
	got := Config{}.resolve()
	if got.Addr != "localhost:9999" || got.Path != "/cloud" || got.Env != "dev" {
		t.Fatalf("env override broken: %+v", got)
	}
}

func TestConfigResolve_ExplicitWins(t *testing.T) {
	t.Setenv("KMS_ADDR", "from-env:9999")
	got := Config{Addr: "explicit:1234"}.resolve()
	if got.Addr != "explicit:1234" {
		t.Fatalf("explicit should beat env: %+v", got)
	}
}

func TestEnvOr(t *testing.T) {
	if envOr("KMS_DEFINITELY_UNSET_XYZ", "fallback") != "fallback" {
		t.Fatal("envOr should return default for unset var")
	}
	os.Setenv("KMS_DEFINITELY_UNSET_XYZ", "set-value")
	defer os.Unsetenv("KMS_DEFINITELY_UNSET_XYZ")
	if envOr("KMS_DEFINITELY_UNSET_XYZ", "fallback") != "set-value" {
		t.Fatal("envOr should return env value when set")
	}
}
