// Package client provides a Go SDK for the Lux KMS API.
// Replaces github.com/luxfi/kms-go (archived Infisical fork).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client connects to the Lux KMS service.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Config holds KMS client configuration.
type Config struct {
	SiteUrl          string
	AutoTokenRefresh bool
	SilentMode       bool
}

// Secret represents a key-value secret.
type Secret struct {
	SecretKey   string `json:"secretKey"`
	SecretValue string `json:"secretValue"`
	Type        string `json:"type,omitempty"`
	Environment string `json:"environment,omitempty"`
	Version     int    `json:"version,omitempty"`
}

// ListSecretsOptions controls secret listing.
type ListSecretsOptions struct {
	ProjectSlug            string
	Environment            string
	SecretPath             string
	ExpandSecretReferences bool
	IncludeImports         bool
	Recursive              bool
}

// NewKMSClient creates a new KMS client. Drop-in replacement for kms-go.
func NewKMSClient(_ context.Context, cfg Config) *Client {
	baseURL := cfg.SiteUrl
	if baseURL == "" {
		baseURL = os.Getenv("LUX_KMS_URL")
	}
	if baseURL == "" {
		baseURL = "https://kms.hanzo.ai"
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Auth returns the auth interface.
func (c *Client) Auth() *AuthClient {
	return &AuthClient{c: c}
}

// Secrets returns the secrets interface.
func (c *Client) Secrets() *SecretsClient {
	return &SecretsClient{c: c}
}

// AuthClient handles authentication.
type AuthClient struct {
	c *Client
}

// UniversalAuthLogin authenticates with machine identity credentials.
func (a *AuthClient) UniversalAuthLogin(clientID, clientSecret string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
	})

	req, err := http.NewRequest("POST", a.c.baseURL+"/api/v1/auth/universal-auth/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("kms auth: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("kms auth failed (%d): %s", resp.StatusCode, b)
	}

	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("kms auth decode: %w", err)
	}

	a.c.token = result.AccessToken
	return result.AccessToken, nil
}

// SecretsClient handles secret operations.
type SecretsClient struct {
	c *Client
}

// List returns all secrets for a project/environment.
func (s *SecretsClient) List(opts ListSecretsOptions) ([]Secret, error) {
	url := fmt.Sprintf("%s/api/v3/secrets/raw?workspaceSlug=%s&environment=%s&secretPath=%s&expandSecretReferences=%t&include_imports=%t&recursive=%t",
		s.c.baseURL, opts.ProjectSlug, opts.Environment, opts.SecretPath,
		opts.ExpandSecretReferences, opts.IncludeImports, opts.Recursive)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("kms list: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.c.token)

	resp, err := s.c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms list request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kms list failed (%d): %s", resp.StatusCode, b)
	}

	var result struct {
		Secrets []Secret `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("kms list decode: %w", err)
	}

	return result.Secrets, nil
}

// Get returns a single secret by key.
func (s *SecretsClient) Get(project, env, key string) (*Secret, error) {
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceSlug=%s&environment=%s&secretPath=/",
		s.c.baseURL, key, project, env)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("kms get: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.c.token)

	resp, err := s.c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms get request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kms get failed (%d): %s", resp.StatusCode, b)
	}

	var result struct {
		Secret Secret `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("kms get decode: %w", err)
	}

	return &result.Secret, nil
}

// Create creates a new secret.
func (s *SecretsClient) Create(project, env, key, value string) error {
	body, _ := json.Marshal(map[string]string{
		"workspaceSlug": project,
		"environment":   env,
		"secretPath":    "/",
		"secretKey":     key,
		"secretValue":   value,
	})
	return s.mutate("POST", s.c.baseURL+"/api/v3/secrets/raw", body)
}

// Update updates an existing secret.
func (s *SecretsClient) Update(project, env, key, value string) error {
	body, _ := json.Marshal(map[string]string{
		"workspaceSlug": project,
		"environment":   env,
		"secretPath":    "/",
		"secretValue":   value,
	})
	return s.mutate("PATCH", fmt.Sprintf("%s/api/v3/secrets/raw/%s", s.c.baseURL, key), body)
}

// Delete deletes a secret.
func (s *SecretsClient) Delete(project, env, key string) error {
	body, _ := json.Marshal(map[string]string{
		"workspaceSlug": project,
		"environment":   env,
		"secretPath":    "/",
	})
	return s.mutate("DELETE", fmt.Sprintf("%s/api/v3/secrets/raw/%s", s.c.baseURL, key), body)
}

func (s *SecretsClient) mutate(method, url string, body []byte) error {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("kms %s: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kms %s request: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kms %s failed (%d): %s", method, resp.StatusCode, b)
	}
	return nil
}
