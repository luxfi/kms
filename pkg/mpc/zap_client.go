package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/luxfi/zap"
)

// ZAP opcodes for KMS ↔ MPC protocol.
const (
	OpStatus  uint16 = 0x0001
	OpKeygen  uint16 = 0x0010
	OpSign    uint16 = 0x0011
	OpReshare uint16 = 0x0012
	OpWallet  uint16 = 0x0020
	OpEncrypt uint16 = 0x0030 // MPC threshold encrypt (ML-KEM)
	OpDecrypt uint16 = 0x0031 // MPC threshold decrypt (ML-KEM)
)

// ZapClient communicates with the MPC daemon over ZAP.
type ZapClient struct {
	node   *zap.Node
	peerID string
}

// NewZapClient creates a ZAP client for MPC communication.
// If mpcAddr is empty, uses mDNS discovery. Otherwise connects directly.
func NewZapClient(nodeID, mpcAddr string) (*ZapClient, error) {
	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_lux-kms._tcp",
		NoDiscovery: mpcAddr != "",
		Logger:      slog.Default(),
	})

	c := &ZapClient{node: node}

	if mpcAddr != "" {
		if err := node.ConnectDirect(mpcAddr); err != nil {
			return nil, fmt.Errorf("mpc: connect %s: %w", mpcAddr, err)
		}
		peers := node.Peers()
		if len(peers) > 0 {
			c.peerID = peers[0]
		}
	}

	return c, nil
}

func (c *ZapClient) call(ctx context.Context, op uint16, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Build ZAP message: opcode (2 bytes) + JSON payload
	b := zap.NewBuilder(len(data) + 64)
	opBytes := make([]byte, 2)
	opBytes[0] = byte(op)
	opBytes[1] = byte(op >> 8)
	b.WriteBytes(append(opBytes, data...))
	raw := b.Finish()

	msg, err := zap.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("mpc: zap build: %w", err)
	}

	resp, err := c.node.Call(ctx, c.peerID, msg)
	if err != nil {
		return nil, fmt.Errorf("mpc: zap call op=0x%04x: %w", op, err)
	}

	// Response body is the full message bytes after header
	body := resp.Bytes()
	if len(body) <= zap.HeaderSize+2 {
		return []byte("{}"), nil
	}
	return body[zap.HeaderSize+2:], nil // skip header + opcode
}

// Keygen creates a new MPC wallet.
func (c *ZapClient) Keygen(ctx context.Context, vaultID string, req KeygenRequest) (*KeygenResult, error) {
	payload := struct {
		VaultID string       `json:"vault_id"`
		Request KeygenRequest `json:"request"`
	}{vaultID, req}

	data, err := c.call(ctx, OpKeygen, payload)
	if err != nil {
		return nil, err
	}
	var result KeygenResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode keygen: %w", err)
	}
	return &result, nil
}

// Sign requests a threshold signature.
func (c *ZapClient) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	data, err := c.call(ctx, OpSign, req)
	if err != nil {
		return nil, err
	}
	var result SignResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode sign: %w", err)
	}
	return &result, nil
}

// Reshare triggers key resharing.
func (c *ZapClient) Reshare(ctx context.Context, walletID string, req ReshareRequest) error {
	payload := struct {
		WalletID string         `json:"wallet_id"`
		Request  ReshareRequest `json:"request"`
	}{walletID, req}
	_, err := c.call(ctx, OpReshare, payload)
	return err
}

// GetWallet retrieves wallet metadata.
func (c *ZapClient) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	data, err := c.call(ctx, OpWallet, map[string]string{"wallet_id": walletID})
	if err != nil {
		return nil, err
	}
	var wallet Wallet
	if err := json.Unmarshal(data, &wallet); err != nil {
		return nil, fmt.Errorf("mpc: decode wallet: %w", err)
	}
	return &wallet, nil
}

// Status returns the MPC cluster status.
func (c *ZapClient) Status(ctx context.Context) (*ClusterStatus, error) {
	data, err := c.call(ctx, OpStatus, nil)
	if err != nil {
		return nil, err
	}
	var status ClusterStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("mpc: decode status: %w", err)
	}
	return &status, nil
}

// Encrypt threshold-encrypts plaintext using the collective FHE public key.
// Anyone can encrypt — the public key is published by the validator set.
// Ciphertext can only be decrypted via threshold FHE (t-of-n E2S protocol).
// Uses TFHE for secret storage (bit-level encryption, exact decryption).
func (c *ZapClient) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	payload := struct {
		KeyID     string `json:"key_id"`
		Plaintext []byte `json:"plaintext"`
		Scheme    string `json:"scheme"` // tfhe for secrets, ckks for ML
	}{keyID, plaintext, "tfhe"}

	data, err := c.call(ctx, OpEncrypt, payload)
	if err != nil {
		return nil, err
	}
	var result EncryptResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode encrypt: %w", err)
	}
	return &result, nil
}

// Decrypt threshold-decrypts ciphertext using t-of-n FHE key shares.
// Each validator produces an E2S (Encrypt-to-Share) decryption share.
// Combiner aggregates t shares to recover plaintext.
// Uses luxfi/lattice TFHE threshold decryption protocol.
func (c *ZapClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	payload := struct {
		KeyID      string `json:"key_id"`
		Ciphertext []byte `json:"ciphertext"`
		Scheme     string `json:"scheme"`
	}{keyID, ciphertext, "tfhe"}

	data, err := c.call(ctx, OpDecrypt, payload)
	if err != nil {
		return nil, err
	}
	var result DecryptResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode decrypt: %w", err)
	}
	return &result, nil
}

// Close shuts down the ZAP node.
func (c *ZapClient) Close() {
	c.node.Stop()
}
