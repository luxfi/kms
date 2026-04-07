package mpc

import (
	"context"
	"encoding/binary"
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
	OpEncrypt uint16 = 0x0030 // encrypt (aes-gcm default, tfhe for threshold reveal)
	OpDecrypt uint16 = 0x0031 // decrypt (aes-gcm default, tfhe needs t-of-n)
)

// ZapClient communicates with the MPC daemon over ZAP.
type ZapClient struct {
	node   *zap.Node
	peerID string
}

// NewZapClient creates a ZAP client for MPC communication.
// If mpcAddr is empty, uses mDNS discovery. Otherwise connects directly.
//
// SECURITY: ZAP does not yet support mutual TLS. Before production launch,
// the ZAP library must add mTLS support and this client must be updated to
// require it. Until then, deploy only on trusted networks (K8s pod network
// with NetworkPolicy restricting traffic to the MPC namespace).
func NewZapClient(nodeID, mpcAddr string) (*ZapClient, error) {
	useMDNS := mpcAddr == ""
	if useMDNS {
		slog.Warn("mpc: mDNS discovery enabled — this is unsafe outside development; set MPC_ADDR for production")
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_lux-kms._tcp",
		NoDiscovery: !useMDNS,
		Logger:      slog.Default(),
	})

	c := &ZapClient{node: node}

	if !useMDNS {
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

	// Build ZAP message: opcode (2 bytes LE) + JSON payload.
	b := zap.NewBuilder(len(data) + 64)
	opBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(opBytes, op)
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

	// Response body is the full message bytes after header.
	body := resp.Bytes()
	if len(body) < zap.HeaderSize+2 {
		return nil, fmt.Errorf("mpc: zap response too short (%d bytes) for op=0x%04x", len(body), op)
	}

	// Validate response opcode matches request.
	respOp := binary.LittleEndian.Uint16(body[zap.HeaderSize : zap.HeaderSize+2])
	if respOp != op {
		return nil, fmt.Errorf("mpc: zap response opcode mismatch: sent=0x%04x got=0x%04x", op, respOp)
	}

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

// Encrypt encrypts plaintext. Default: AES-256-GCM with ML-KEM wrapped DEK (fast, PQ-safe).
// For threshold-gated reveal, use EncryptThreshold which uses TFHE.
func (c *ZapClient) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	payload := struct {
		KeyID     string `json:"key_id"`
		Plaintext []byte `json:"plaintext"`
		Scheme    string `json:"scheme"`
	}{keyID, plaintext, SchemeAESGCM}

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

// Decrypt decrypts ciphertext. Scheme auto-detected from ciphertext header.
// AES-GCM: unwraps DEK via ML-KEM, decrypts locally (no threshold needed).
// TFHE: requires t-of-n validator E2S shares via T-Chain.
func (c *ZapClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	payload := struct {
		KeyID      string `json:"key_id"`
		Ciphertext []byte `json:"ciphertext"`
		Scheme     string `json:"scheme"`
	}{keyID, ciphertext, ""} // empty = auto-detect from ciphertext

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
