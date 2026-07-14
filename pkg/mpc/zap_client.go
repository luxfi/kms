package mpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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
// mpcAddr may be a single `host:port` or a comma-separated list. The
// client tries each address in order and binds to the first one that
// accepts a connection — the rest are fall-overs for the case where one
// MPC pod is restarting. Once connected, ZAP-level peer-set logic owns
// further selection inside the cluster.
//
// Trust is enforced at the network boundary (NetworkPolicy + ZAP wire).
// Deploy only on trusted networks (K8s pod network with NetworkPolicy
// restricting traffic to the MPC namespace).
func NewZapClient(nodeID, mpcAddr string) (*ZapClient, error) {
	addrs := splitAddrs(mpcAddr)
	useMDNS := len(addrs) == 0
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
		var dialErrs []error
		var connected string
		for _, addr := range addrs {
			if err := node.ConnectDirect(addr); err != nil {
				dialErrs = append(dialErrs, fmt.Errorf("%s: %w", addr, err))
				slog.Warn("mpc: ConnectDirect failed; trying next", "addr", addr, "err", err)
				continue
			}
			connected = addr
			break
		}
		if connected == "" {
			return nil, fmt.Errorf("mpc: connect %s: %w", mpcAddr, errors.Join(dialErrs...))
		}
		slog.Info("mpc: connected", "addr", connected, "candidates", len(addrs))
		peers := node.Peers()
		if len(peers) > 0 {
			c.peerID = peers[0]
		}
	}

	return c, nil
}

// splitAddrs parses a CSV of host:port (with optional whitespace) into a
// non-empty slice of trimmed entries. Empty input → empty slice. Empty
// entries inside the CSV are dropped.
func splitAddrs(mpcAddr string) []string {
	if mpcAddr == "" {
		return nil
	}
	parts := strings.Split(mpcAddr, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
	respBody := body[zap.HeaderSize+2:] // skip header + opcode

	// Surface server-side errors. mpcd frames failures as {"error":"..."}
	// under the SAME opcode as the request (pkg/api/zap_kms_server.go errBody).
	// Without this, the caller would json-decode the error object into a
	// zero-value SignResult/KeygenResult and return success with empty fields —
	// the "false-green" empty-signature footgun. Fail closed instead.
	if msg := zapErrorString(respBody); msg != "" {
		return nil, fmt.Errorf("mpc: op=0x%04x rejected by daemon: %s", op, msg)
	}
	return respBody, nil
}

// zapErrorString returns the top-level "error" string if body is a JSON object
// carrying a non-empty one, else "". None of the success payloads
// (SignResult/KeygenResult/ClusterStatus/Wallet) define an "error" field, so a
// present, non-empty "error" is unambiguously a daemon-side failure.
func zapErrorString(body []byte) string {
	var probe struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "" // not a JSON object (or not decodable) → treat as payload
	}
	return probe.Error
}

// Keygen creates a new MPC wallet.
func (c *ZapClient) Keygen(ctx context.Context, vaultID string, req KeygenRequest) (*KeygenResult, error) {
	payload := struct {
		VaultID string        `json:"vault_id"`
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
