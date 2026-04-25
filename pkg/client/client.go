// Package client provides a Go SDK for the Lux KMS API.
//
// All routes hit `/v1/kms/<path>` per the Hanzo "/v1/<service>/<path>" standard.
// No legacy /api/v1 or /api/v3 paths.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	ProjectSlug            string // → org segment in /v1/kms/orgs/{org}/secrets
	Environment            string // → ?env=prod
	SecretPath             string // → ?path=/some/sub
	ExpandSecretReferences bool
	IncludeImports         bool
	Recursive              bool
}

// NewKMSClient creates a new KMS client.
func NewKMSClient(_ context.Context, cfg Config) *Client {
	site := cfg.SiteUrl
	if site == "" {
		site = os.Getenv("LUX_KMS_URL")
	}
	if site == "" {
		site = "http://kms.lux-kms.svc.cluster.local"
	}
	return &Client{
		baseURL: site,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Auth returns the authentication client.
func (c *Client) Auth() *AuthClient { return &AuthClient{c: c} }

// Secrets returns the secrets client.
func (c *Client) Secrets() *SecretsClient { return &SecretsClient{c: c} }

// SetAccessToken sets the bearer token for authenticated requests.
func (c *Client) SetAccessToken(token string) { c.token = token }

// AuthClient handles authentication.
type AuthClient struct{ c *Client }

// UniversalAuthLogin authenticates with machine identity credentials.
// POST /v1/kms/auth/login { clientId, clientSecret } → { accessToken }
func (a *AuthClient) UniversalAuthLogin(clientID, clientSecret string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
	})

	req, err := http.NewRequest("POST", a.c.baseURL+"/v1/kms/auth/login", bytes.NewReader(body))
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

// secretsBaseURL → `${baseURL}/v1/kms/orgs/{org}/secrets`
func (s *SecretsClient) secretsBaseURL(org string) string {
	return fmt.Sprintf("%s/v1/kms/orgs/%s/secrets", s.c.baseURL, url.PathEscape(org))
}

// List returns all secrets for a project/environment.
// GET /v1/kms/orgs/{org}/secrets?env=ENV&path=PATH&recursive=BOOL
func (s *SecretsClient) List(opts ListSecretsOptions) ([]Secret, error) {
	q := url.Values{}
	q.Set("env", opts.Environment)
	if opts.SecretPath != "" {
		q.Set("path", opts.SecretPath)
	}
	if opts.Recursive {
		q.Set("recursive", "true")
	}
	if opts.ExpandSecretReferences {
		q.Set("expand", "true")
	}
	if opts.IncludeImports {
		q.Set("includeImports", "true")
	}
	u := s.secretsBaseURL(opts.ProjectSlug) + "?" + q.Encode()

	req, err := http.NewRequest("GET", u, nil)
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
// GET /v1/kms/orgs/{org}/secrets/{key}?env=ENV
func (s *SecretsClient) Get(project, env, key string) (*Secret, error) {
	q := url.Values{}
	q.Set("env", env)
	u := s.secretsBaseURL(project) + "/" + url.PathEscape(key) + "?" + q.Encode()

	req, err := http.NewRequest("GET", u, nil)
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
// POST /v1/kms/orgs/{org}/secrets { env, path, secretKey, secretValue }
func (s *SecretsClient) Create(project, env, key, value string) error {
	body, _ := json.Marshal(map[string]string{
		"env":         env,
		"path":        "/",
		"secretKey":   key,
		"secretValue": value,
	})
	return s.mutate("POST", s.secretsBaseURL(project), body)
}

// Update updates an existing secret.
// PATCH /v1/kms/orgs/{org}/secrets/{key} { env, path, secretValue }
func (s *SecretsClient) Update(project, env, key, value string) error {
	body, _ := json.Marshal(map[string]string{
		"env":         env,
		"path":        "/",
		"secretValue": value,
	})
	return s.mutate("PATCH", s.secretsBaseURL(project)+"/"+url.PathEscape(key), body)
}

// Delete deletes a secret.
// DELETE /v1/kms/orgs/{org}/secrets/{key}?env=ENV
func (s *SecretsClient) Delete(project, env, key string) error {
	q := url.Values{}
	q.Set("env", env)
	q.Set("path", "/")
	u := s.secretsBaseURL(project) + "/" + url.PathEscape(key) + "?" + q.Encode()
	return s.mutate("DELETE", u, nil)
}

func (s *SecretsClient) mutate(method, urlStr string, body []byte) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return fmt.Errorf("kms %s: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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
