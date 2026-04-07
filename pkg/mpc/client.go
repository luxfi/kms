// Package mpc provides an HTTP client for the Lux MPC daemon API.
package mpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the MPC daemon HTTP API.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates an MPC client pointing at the given base URL.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// KeygenRequest is the body sent to POST /v1/vaults/{vaultID}/wallets.
type KeygenRequest struct {
	Name     string `json:"name"`
	KeyType  string `json:"key_type"`
	Protocol string `json:"protocol"`
}

// KeygenResult is the wallet object returned after keygen.
type KeygenResult struct {
	ID           string   `json:"id"`
	WalletID     string   `json:"walletId"`
	VaultID      string   `json:"vaultId"`
	Name         *string  `json:"name"`
	KeyType      string   `json:"keyType"`
	Protocol     string   `json:"protocol"`
	ECDSAPubkey  *string  `json:"ecdsaPubkey"`
	EDDSAPubkey  *string  `json:"eddsaPubkey"`
	EthAddress   *string  `json:"ethAddress"`
	BtcAddress   *string  `json:"btcAddress"`
	SolAddress   *string  `json:"solAddress"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	Version      int      `json:"version"`
	Status       string   `json:"status"`
}

// SignRequest is the body sent to POST /v1/generate_mpc_sig or through
// the transaction flow. For validator signing we use the bridge sign endpoint.
type SignRequest struct {
	KeyType  string `json:"key_type"`
	WalletID string `json:"wallet_id"`
	Message  []byte `json:"message"`
}

// SignResult is the response from a signing operation.
type SignResult struct {
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// ReshareRequest is the body sent to POST /v1/wallets/{id}/reshare.
type ReshareRequest struct {
	NewThreshold    int      `json:"new_threshold"`
	NewParticipants []string `json:"new_participants"`
}

// ClusterStatus is the response from GET /v1/status.
type ClusterStatus struct {
	NodeID         string `json:"node_id"`
	Mode           string `json:"mode"`
	ExpectedPeers  int    `json:"expected_peers"`
	ConnectedPeers int    `json:"connected_peers"`
	Ready          bool   `json:"ready"`
	Threshold      int    `json:"threshold"`
	Version        string `json:"version"`
}

// Wallet is the response from GET /v1/wallets/{id}.
type Wallet struct {
	ID           string   `json:"id"`
	WalletID     string   `json:"walletId"`
	VaultID      string   `json:"vaultId"`
	Name         *string  `json:"name"`
	KeyType      string   `json:"keyType"`
	Protocol     string   `json:"protocol"`
	ECDSAPubkey  *string  `json:"ecdsaPubkey"`
	EDDSAPubkey  *string  `json:"eddsaPubkey"`
	EthAddress   *string  `json:"ethAddress"`
	BtcAddress   *string  `json:"btcAddress"`
	SolAddress   *string  `json:"solAddress"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	Version      int      `json:"version"`
	Status       string   `json:"status"`
}

// APIError represents an error response from the MPC API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mpc api: %d %s", e.StatusCode, e.Message)
}

// Keygen triggers distributed key generation via the MPC daemon.
// vaultID is the MPC vault that will hold the wallet.
func (c *Client) Keygen(ctx context.Context, vaultID string, req KeygenRequest) (*KeygenResult, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/wallets", c.BaseURL, vaultID)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("mpc: marshal keygen request: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result KeygenResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("mpc: decode keygen response: %w", err)
	}
	return &result, nil
}

// Sign triggers threshold signing via the MPC daemon.
// This uses the transaction creation flow.
func (c *Client) Sign(ctx context.Context, walletID, keyType string, message []byte) (*SignResult, error) {
	url := fmt.Sprintf("%s/v1/transactions", c.BaseURL)
	body, err := json.Marshal(map[string]interface{}{
		"wallet_id": walletID,
		"key_type":  keyType,
		"payload":   message,
		"type":      "sign",
	})
	if err != nil {
		return nil, fmt.Errorf("mpc: marshal sign request: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, readError(resp)
	}

	var result SignResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("mpc: decode sign response: %w", err)
	}
	return &result, nil
}

// Reshare triggers key resharing to change threshold or participants.
func (c *Client) Reshare(ctx context.Context, walletID string, req ReshareRequest) error {
	url := fmt.Sprintf("%s/v1/wallets/%s/reshare", c.BaseURL, walletID)
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("mpc: marshal reshare request: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return readError(resp)
	}
	return nil
}

// GetWallet retrieves wallet metadata from the MPC daemon.
func (c *Client) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	url := fmt.Sprintf("%s/v1/wallets/%s", c.BaseURL, walletID)

	resp, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var wallet Wallet
	if err := json.NewDecoder(resp.Body).Decode(&wallet); err != nil {
		return nil, fmt.Errorf("mpc: decode wallet response: %w", err)
	}
	return &wallet, nil
}

// Status returns the MPC cluster status.
func (c *Client) Status(ctx context.Context) (*ClusterStatus, error) {
	url := fmt.Sprintf("%s/v1/status", c.BaseURL)

	resp, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var status ClusterStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("mpc: decode status response: %w", err)
	}
	return &status, nil
}

func (c *Client) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("mpc: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mpc: request to %s: %w", url, err)
	}
	return resp, nil
}

func readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return &APIError{StatusCode: resp.StatusCode, Message: errResp.Error}
	}
	return &APIError{StatusCode: resp.StatusCode, Message: string(body)}
}
