package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewKMSClient_DefaultURL(t *testing.T) {
	t.Setenv("LUX_KMS_URL", "")
	c := NewKMSClient(context.Background(), Config{})
	if c.baseURL != "http://kms.lux-kms.svc.cluster.local" {
		t.Errorf("default URL = %s, want http://kms.lux-kms.svc.cluster.local", c.baseURL)
	}
}

func TestNewKMSClient_CustomURL(t *testing.T) {
	c := NewKMSClient(context.Background(), Config{SiteUrl: "https://kms.lux.network"})
	if c.baseURL != "https://kms.lux.network" {
		t.Errorf("URL = %s, want https://kms.lux.network", c.baseURL)
	}
}

func TestAuth_UniversalAuthLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kms/auth/login" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["clientId"] != "test-id" {
			t.Errorf("clientId = %s", body["clientId"])
		}
		json.NewEncoder(w).Encode(map[string]string{"accessToken": "tok-123"})
	}))
	defer srv.Close()

	c := NewKMSClient(context.Background(), Config{SiteUrl: srv.URL})
	tok, err := c.Auth().UniversalAuthLogin("test-id", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-123" {
		t.Errorf("token = %s", tok)
	}
	if c.token != "tok-123" {
		t.Error("token not stored on client")
	}
}

func TestSecrets_List(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			t.Error("missing auth header")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []Secret{
				{SecretKey: "DB_URL", SecretValue: "postgres://..."},
				{SecretKey: "API_KEY", SecretValue: "sk-abc"},
			},
		})
	}))
	defer srv.Close()

	c := NewKMSClient(context.Background(), Config{SiteUrl: srv.URL})
	c.token = "tok-123"

	secrets, err := c.Secrets().List(ListSecretsOptions{
		ProjectSlug: "test", Environment: "dev", SecretPath: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("secrets = %d, want 2", len(secrets))
	}
	if secrets[0].SecretKey != "DB_URL" {
		t.Errorf("key = %s", secrets[0].SecretKey)
	}
}

func TestSecrets_Get(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secret": Secret{SecretKey: "DB_URL", SecretValue: "postgres://..."},
		})
	}))
	defer srv.Close()

	c := NewKMSClient(context.Background(), Config{SiteUrl: srv.URL})
	c.token = "tok"

	s, err := c.Secrets().Get("proj", "dev", "DB_URL")
	if err != nil {
		t.Fatal(err)
	}
	if s.SecretValue != "postgres://..." {
		t.Errorf("value = %s", s.SecretValue)
	}
}

func TestSecrets_CreateUpdateDelete(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewKMSClient(context.Background(), Config{SiteUrl: srv.URL})
	c.token = "tok"

	if err := c.Secrets().Create("p", "dev", "K", "V"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets().Update("p", "dev", "K", "V2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets().Delete("p", "dev", "K"); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestAuth_FailedLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	c := NewKMSClient(context.Background(), Config{SiteUrl: srv.URL})
	_, err := c.Auth().UniversalAuthLogin("bad", "creds")
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestClient_Timeout(t *testing.T) {
	c := NewKMSClient(context.Background(), Config{})
	if c.httpClient.Timeout != 10e9 {
		t.Errorf("timeout = %v, want 10s", c.httpClient.Timeout)
	}
}
