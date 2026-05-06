// Package iamclient mints OAuth2 client_credentials tokens against
// Hanzo IAM and caches them for downstream services to attach as
// Authorization bearers.
//
// Used by KMS to authenticate the ZAP handshake against MPC's
// pkg/zapauth gate (LP-103). One service identity per KMS pod
// (clientId "liquid-kms" by default), one audience per upstream
// (e.g. "liquid-mpc"). Tokens are cached until 60 s before expiry
// so callers always have a valid bearer to attach.
//
// Wire contract (Hanzo IAM, OIDC discovery `token_endpoint`):
//
//   POST {KMS_IAM_URL}/oauth/token
//   Content-Type: application/x-www-form-urlencoded
//   Authorization: Basic base64(client_id:client_secret)
//
//   grant_type=client_credentials&audience=<aud>&scope=zap
//
// Response body shape:
//
//   { "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }
//
// Error responses follow RFC 6749 §5.2: { "error": "...", "error_description": "..." }.
//
// Note: Hanzo IAM (Casdoor-derived) does not currently honor the
// `audience` request parameter — the issued JWT's `aud` claim equals
// the client_id (e.g. `lux-kms`). Upstream MPC pkg/zapauth
// configures `ZAP_EXPECTED_AUDIENCES` accordingly.
package iamclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors callers should check explicitly.
var (
	ErrConfigIncomplete = errors.New("iamclient: config incomplete")
	ErrTokenRequest     = errors.New("iamclient: token request failed")
	ErrTokenResponse    = errors.New("iamclient: malformed token response")
	ErrTokenEmpty       = errors.New("iamclient: empty access_token in response")
)

// Config wires a Client to a Hanzo IAM tenant. ClientID + ClientSecret
// are issued when the cluster operator registers the service identity
// (universe/k8s/platforms/{env}.yaml LiquidIAM tenants[]).
type Config struct {
	// IAMBaseURL is the IAM origin without trailing slash, e.g.
	// "http://liquid-iam.lux.svc.cluster.local:8000". Required.
	IAMBaseURL string
	// TokenPath overrides the default token endpoint path. Default
	// "/oauth/token" (matches Hanzo IAM OIDC discovery
	// `token_endpoint`). Reset for testing or alternate IAM forks.
	TokenPath string
	// ClientID is the IAM application identifier, e.g. "liquid-kms".
	ClientID string
	// ClientSecret is the corresponding shared secret, fetched from
	// KMS at boot via universal-auth or KMS_IAM_CLIENT_SECRET env.
	ClientSecret string
	// HTTPClient overrides the default 10-second-timeout HTTP client.
	HTTPClient *http.Client
	// EarlyRefresh subtracts a margin from expires_in so we mint a
	// fresh token before the cached one expires. Default 60 seconds.
	EarlyRefresh time.Duration
	// Now substitutes time.Now for tests.
	Now func() time.Time
}

// Validate enforces invariants so NewClient never returns a partially
// configured object.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.IAMBaseURL) == "" {
		return fmt.Errorf("%w: IAMBaseURL required", ErrConfigIncomplete)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: ClientID required", ErrConfigIncomplete)
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("%w: ClientSecret required", ErrConfigIncomplete)
	}
	return nil
}

// Client mints + caches client_credentials tokens, one cache entry per
// audience. Safe for concurrent use.
type Client struct {
	cfg Config
	url string
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// NewClient validates cfg, normalizes optional fields, and returns a
// ready-to-use Client. The first Mint() call performs the HTTP fetch.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.TokenPath == "" {
		cfg.TokenPath = "/oauth/token"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.EarlyRefresh == 0 {
		cfg.EarlyRefresh = 60 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{
		cfg:   cfg,
		url:   strings.TrimRight(cfg.IAMBaseURL, "/") + cfg.TokenPath,
		now:   cfg.Now,
		cache: make(map[string]cachedToken),
	}, nil
}

// Mint returns a valid access_token for the given audience. Cached
// tokens within EarlyRefresh of expiry trigger a fresh fetch so callers
// don't race the upstream verifier's exp check.
func (c *Client) Mint(ctx context.Context, audience string) (string, error) {
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("%w: audience required", ErrConfigIncomplete)
	}
	c.mu.Lock()
	if t, ok := c.cache[audience]; ok && c.now().Before(t.expires) {
		token := t.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	token, ttl, err := c.fetchToken(ctx, audience)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.cache[audience] = cachedToken{
		token:   token,
		expires: c.now().Add(ttl - c.cfg.EarlyRefresh),
	}
	c.mu.Unlock()
	return token, nil
}

// Invalidate drops the cached entry for audience. Useful when a
// downstream rejects the token (kid rotation, exp drift) so the next
// Mint goes back to IAM.
func (c *Client) Invalidate(audience string) {
	c.mu.Lock()
	delete(c.cache, audience)
	c.mu.Unlock()
}

// fetchToken does the actual HTTP POST and parses the response. Always
// returns a positive TTL on success; on failure returns a wrapped
// ErrTokenRequest / ErrTokenResponse.
func (c *Client) fetchToken(ctx context.Context, audience string) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", audience)
	form.Set("scope", "zap")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("%w: build req: %v", ErrTokenRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte(c.cfg.ClientID + ":" + c.cfg.ClientSecret))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("Accept", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: do: %v", ErrTokenRequest, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", 0, fmt.Errorf("%w: read: %v", ErrTokenRequest, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%w: status=%d body=%s", ErrTokenRequest, resp.StatusCode, string(body))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error,omitempty"`
		Description string `json:"error_description,omitempty"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("%w: %v body=%s", ErrTokenResponse, err, string(body))
	}
	if tr.Error != "" {
		return "", 0, fmt.Errorf("%w: %s: %s", ErrTokenRequest, tr.Error, tr.Description)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return "", 0, ErrTokenEmpty
	}
	if tr.ExpiresIn <= 0 {
		// Conservative default if IAM returns no exp.
		tr.ExpiresIn = 300
	}
	if tr.ExpiresIn <= int64(c.cfg.EarlyRefresh.Seconds()) {
		return "", 0, fmt.Errorf("%w: TTL %ds <= EarlyRefresh %v",
			ErrTokenResponse, tr.ExpiresIn, c.cfg.EarlyRefresh)
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}
