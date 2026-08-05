package mpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/luxfi/zap"

	kmszap "github.com/luxfi/kms/pkg/zap"
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

// TokenSource yields a native Hanzo IAM access token for this service.
// KMS mints one with the client_credentials grant against the IAM client
// it derives from its brand — see cmd/kms/oidc.go, which owns that
// derivation so it exists in exactly one place.
type TokenSource func(ctx context.Context) (string, error)

// ZapClient communicates with the MPC daemon over ZAP.
type ZapClient struct {
	node   *zap.Node
	peerID string
	sess   *kmszap.Session
}

// NewZapClient dials the MPC daemon, runs the hybrid post-quantum
// handshake, and authenticates with an IAM credential. The returned client
// is ready to issue threshold operations; every payload it sends from here
// on is sealed under the negotiated key.
//
// mpcAddr may be a single `host:port` or a comma-separated list. The
// client tries each address in order and binds to the first one that
// accepts a connection — the rest are fall-overs for the case where one
// MPC pod is restarting.
//
// token is required. MPC refuses a peer it cannot identify, so a client
// with no credential could only ever be refused; failing here says so
// plainly instead of at the first threshold operation.
func NewZapClient(nodeID, mpcAddr string, token TokenSource) (*ZapClient, error) {
	if token == nil {
		return nil, errors.New("mpc: an IAM token source is required; MPC refuses unauthenticated peers")
	}
	addrs := splitAddrs(mpcAddr)
	if len(addrs) == 0 {
		// mDNS would let anything that answers a multicast query claim to be
		// the MPC cluster. The handshake and IAM check happen against
		// whatever we dial, so the address must come from configuration.
		return nil, errors.New("mpc: MPC_ADDR is required (host:port, comma-separated for replicas)")
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_lux-kms._tcp",
		NoDiscovery: true,
		Logger:      slog.Default(),
	})

	c := &ZapClient{node: node}

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
	peers := node.Peers()
	if len(peers) == 0 {
		node.Stop()
		return nil, fmt.Errorf("mpc: connected to %s but learned no peer", connected)
	}
	c.peerID = peers[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.handshake(ctx); err != nil {
		node.Stop()
		return nil, fmt.Errorf("mpc: handshake with %s: %w", connected, err)
	}
	if err := c.authenticate(ctx, token); err != nil {
		node.Stop()
		return nil, fmt.Errorf("mpc: authenticate to %s: %w", connected, err)
	}
	slog.Info("mpc: connected", "addr", connected, "candidates", len(addrs),
		"alg", "X25519+ML-KEM-768", "auth", "hanzo-iam")
	return c, nil
}

// handshake runs ClientHello/ServerHello and installs the session key.
func (c *ZapClient) handshake(ctx context.Context) error {
	st, hello, err := kmszap.NewClient(kmszap.CapMLKEM768)
	if err != nil {
		return fmt.Errorf("client hello: %w", err)
	}
	op, body, err := c.exchange(ctx, kmszap.OpClientHello, hello)
	if err != nil {
		return err
	}
	if op != kmszap.OpServerHello {
		return fmt.Errorf("handshake reply opcode 0x%04x", op)
	}
	if msg := wireErrorText(body); msg != "" {
		return errors.New(msg)
	}
	res, err := st.ClientFinish(body)
	if err != nil {
		return fmt.Errorf("client finish: %w", err)
	}
	if !res.Hybrid {
		// We asked for ML-KEM-768 and did not get it. Continuing would give
		// up post-quantum key agreement on the link that carries the root
		// key material.
		return errors.New("peer declined ML-KEM-768")
	}
	sess, err := kmszap.NewSession(res.SessionKey, res.Hybrid)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	c.sess = sess
	return nil
}

// authenticate presents the IAM credential, sealed under the session key.
func (c *ZapClient) authenticate(ctx context.Context, token TokenSource) error {
	tok, err := token(ctx)
	if err != nil {
		return fmt.Errorf("mint IAM token: %w", err)
	}
	if tok == "" {
		return errors.New("IAM token source returned an empty token")
	}
	if _, err := c.call(ctx, kmszap.OpAuth, map[string]string{"token": tok}); err != nil {
		return err
	}
	return nil
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

// exchange sends opcode(2 LE) || body verbatim and returns the response
// opcode and body. It is the raw transport: no sealing, no error parsing.
// Only the handshake uses it directly — everything else goes through call.
func (c *ZapClient) exchange(ctx context.Context, op uint16, body []byte) (uint16, []byte, error) {
	out := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(out[0:2], op)
	copy(out[2:], body)

	b := zap.NewBuilder(len(out) + 64)
	b.WriteBytes(out)
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		return 0, nil, fmt.Errorf("mpc: zap build: %w", err)
	}
	resp, err := c.node.Call(ctx, c.peerID, msg)
	if err != nil {
		return 0, nil, fmt.Errorf("mpc: zap call op=0x%04x: %w", op, err)
	}
	raw := resp.Bytes()
	if len(raw) < zap.HeaderSize+2 {
		return 0, nil, fmt.Errorf("mpc: zap response too short (%d bytes) for op=0x%04x", len(raw), op)
	}
	return binary.LittleEndian.Uint16(raw[zap.HeaderSize : zap.HeaderSize+2]), raw[zap.HeaderSize+2:], nil
}

// call issues an opcode with a JSON payload sealed under the session key,
// and returns the opened response body.
func (c *ZapClient) call(ctx context.Context, op uint16, payload any) ([]byte, error) {
	if c.sess == nil {
		return nil, errors.New("mpc: no session; the handshake did not complete")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sealed, err := c.sess.Seal(kmszap.DirClientToServer, data)
	if err != nil {
		return nil, fmt.Errorf("mpc: seal op=0x%04x: %w", op, err)
	}

	respOp, body, err := c.exchange(ctx, op, sealed)
	if err != nil {
		return nil, err
	}
	if respOp != op {
		return nil, fmt.Errorf("mpc: zap response opcode mismatch: sent=0x%04x got=0x%04x", op, respOp)
	}
	if len(body) == 0 {
		return []byte("{}"), nil
	}

	// A refusal the server issued before the session existed on its side
	// comes back unsealed; anything else must open under the session key.
	respBody, openErr := c.sess.Open(kmszap.DirServerToClient, body)
	if openErr != nil {
		if msg := wireErrorText(body); msg != "" {
			return nil, &WireError{Op: op, Message: msg}
		}
		return nil, fmt.Errorf("mpc: open response op=0x%04x: %w", op, openErr)
	}

	// The server signals every handler failure as {"error": "..."} under
	// the SAME opcode it was asked for, so the opcode check above cannot
	// catch it. Go's json decoder ignores unknown fields, so an unread
	// "error" key decodes cleanly into any success struct and surfaces as
	// a zero-valued success — Reshare, whose only signal is this error
	// return, would report a refused reshare as done. Read it here, once,
	// for every opcode.
	if msg := wireErrorText(respBody); msg != "" {
		return nil, &WireError{Op: op, Message: msg}
	}
	return respBody, nil
}

// wireErrorText returns the "error" field of a JSON body, or "" when the
// body is not an error envelope.
func wireErrorText(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error
}

// WireError is an error body returned by the MPC server over ZAP. It is
// the ZAP-transport sibling of APIError: same contract ({"error": "..."}),
// keyed by opcode instead of HTTP status.
type WireError struct {
	Op      uint16
	Message string
}

func (e *WireError) Error() string {
	return fmt.Sprintf("mpc zap: op=0x%04x: %s", e.Op, e.Message)
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
