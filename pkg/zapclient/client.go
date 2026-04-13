// Package zapclient is the native ZAP-transport counterpart to pkg/zapserver.
//
// Services wanting to fetch secrets from Lux KMS without a REST round-trip
// spin up a short-lived ZAP Node (mDNS-discovered or direct-addressed) and
// call the four opcodes defined in zapserver:
//
//	0x0040  OpSecretGet    { path, name, env }            → { value }
//	0x0041  OpSecretPut    { path, name, env, value }     → { ok:true }   (admin)
//	0x0042  OpSecretList   { path, env }                  → { names }
//	0x0043  OpSecretDelete { path, name, env }            → { ok:true }   (admin)
//
// Example:
//
//	c, _ := zapclient.Dial(ctx, "kms:9652", "secret/data/onyxplus/dev")
//	defer c.Close()
//	v, _ := c.Get(ctx, "SIGNING_KEY_PEM", "dev")
//
// This is the preferred path for in-cluster consumers. REST via pkg/client
// remains available for external / cross-cluster callers.
package zapclient

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/luxfi/zap"
)

// Opcodes mirror the server; kept verbatim to avoid drift.
const (
	OpSecretGet    uint16 = 0x0040
	OpSecretPut    uint16 = 0x0041
	OpSecretList   uint16 = 0x0042
	OpSecretDelete uint16 = 0x0043
)

const (
	statusOK       byte = 0x00
	statusNotFound byte = 0x01
	statusError    byte = 0x02
	statusForbid   byte = 0x03
)

// ErrNotFound is returned when a secret path/name does not exist.
var ErrNotFound = errors.New("zapclient: secret not found")

// ErrForbidden is returned when the caller lacks role=admin for Put/Delete.
var ErrForbidden = errors.New("zapclient: forbidden (admin role required)")

// Client is a thin wrapper over a zap.Node plus a resolved KMS peer ID.
type Client struct {
	node      *zap.Node
	peerID    string
	defaultPath string
	log       *slog.Logger
}

// Config controls client construction.
type Config struct {
	// NodeID we present to the mesh. Defaults to "kmsclient-<random>".
	NodeID string
	// Port to listen on (0 = OS-assigned). ZAP requires a listener even for callers.
	Port int
	// PeerAddr (host:port) of the KMS node. If non-empty, Dial uses
	// ConnectDirect. If empty, Dial uses mDNS discovery by ServiceType.
	PeerAddr string
	// ServiceType for mDNS discovery. Defaults to "_kms._tcp".
	ServiceType string
	// DefaultPath prefixes all calls that omit an explicit path.
	DefaultPath string
	// Logger (optional).
	Logger *slog.Logger
}

// Dial brings up a ZAP node, connects to the KMS peer, and returns a ready
// client. Close when done.
func Dial(ctx context.Context, peerAddr, defaultPath string) (*Client, error) {
	return DialWithConfig(ctx, Config{PeerAddr: peerAddr, DefaultPath: defaultPath})
}

// DialWithConfig is the full-options form.
func DialWithConfig(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = "kmsclient"
	}
	if cfg.ServiceType == "" {
		cfg.ServiceType = "_kms._tcp"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Direct-address callers don't need mDNS and shouldn't advertise
	// themselves on the network. Only request discovery when the caller
	// explicitly leaves PeerAddr empty.
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      cfg.NodeID,
		ServiceType: cfg.ServiceType,
		Port:        cfg.Port,
		NoDiscovery: cfg.PeerAddr != "",
	})
	if err := n.Start(); err != nil {
		return nil, fmt.Errorf("zapclient: start node: %w", err)
	}

	c := &Client{node: n, defaultPath: cfg.DefaultPath, log: cfg.Logger}

	if cfg.PeerAddr != "" {
		if err := n.ConnectDirect(cfg.PeerAddr); err != nil {
			n.Stop()
			return nil, fmt.Errorf("zapclient: connect %s: %w", cfg.PeerAddr, err)
		}
		// ConnectDirect registers the peer under its advertised NodeID; we
		// pick the first peer we see as our target.
		for _, pid := range n.Peers() {
			c.peerID = pid
			break
		}
	} else {
		// mDNS discovery. Wait briefly for a peer to show up.
		timeout, cancel := context.WithCancel(ctx)
		defer cancel()
		for {
			peers := n.Peers()
			if len(peers) > 0 {
				c.peerID = peers[0]
				break
			}
			select {
			case <-timeout.Done():
				n.Stop()
				return nil, fmt.Errorf("zapclient: no KMS peer discovered")
			default:
			}
		}
	}

	if c.peerID == "" {
		n.Stop()
		return nil, fmt.Errorf("zapclient: peer not resolved")
	}
	return c, nil
}

// Close tears down the underlying ZAP node.
func (c *Client) Close() { c.node.Stop() }

// Get reads a secret. `path` falls back to DefaultPath if empty.
func (c *Client) Get(ctx context.Context, name, env string) (string, error) {
	return c.GetAt(ctx, c.defaultPath, name, env)
}

// GetAt reads a secret at an explicit path.
func (c *Client) GetAt(ctx context.Context, path, name, env string) (string, error) {
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env})
	resp, err := c.call(ctx, OpSecretGet, body)
	if err != nil {
		return "", err
	}
	var out struct{ Value string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("zapclient: decode Get: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(out.Value)
	if err != nil {
		return "", fmt.Errorf("zapclient: decode value: %w", err)
	}
	return string(b), nil
}

// Put writes a secret. Requires admin role on the caller principal.
func (c *Client) Put(ctx context.Context, name, env, value string) error {
	return c.PutAt(ctx, c.defaultPath, name, env, value)
}

// PutAt writes a secret at an explicit path.
func (c *Client) PutAt(ctx context.Context, path, name, env, value string) error {
	body, _ := json.Marshal(map[string]string{
		"path":  path,
		"name":  name,
		"env":   env,
		"value": base64.StdEncoding.EncodeToString([]byte(value)),
	})
	_, err := c.call(ctx, OpSecretPut, body)
	return err
}

// List names at a path.
func (c *Client) List(ctx context.Context, env string) ([]string, error) {
	return c.ListAt(ctx, c.defaultPath, env)
}

// ListAt names at an explicit path.
func (c *Client) ListAt(ctx context.Context, path, env string) ([]string, error) {
	body, _ := json.Marshal(map[string]string{"path": path, "env": env})
	resp, err := c.call(ctx, OpSecretList, body)
	if err != nil {
		return nil, err
	}
	var out struct{ Names []string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("zapclient: decode List: %w", err)
	}
	return out.Names, nil
}

// Delete removes a secret. Admin-only.
func (c *Client) Delete(ctx context.Context, name, env string) error {
	return c.DeleteAt(ctx, c.defaultPath, name, env)
}

// DeleteAt removes a secret at an explicit path. Admin-only.
func (c *Client) DeleteAt(ctx context.Context, path, name, env string) error {
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env})
	_, err := c.call(ctx, OpSecretDelete, body)
	return err
}

// call is the shared request/response wrapper around zap.Node.Call.
//
// Wire format on both directions: opcode(2 LE) || body for the request,
// status(1 byte) || json for the response, all packed in a ZAP Message via
// the Builder.
func (c *Client) call(ctx context.Context, op uint16, body []byte) ([]byte, error) {
	// Request: op || body.
	reqPayload := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(reqPayload[:2], op)
	copy(reqPayload[2:], body)
	reqMsg := buildMessage(reqPayload)
	if reqMsg == nil {
		return nil, errors.New("zapclient: failed to build request message")
	}

	resp, err := c.node.Call(ctx, c.peerID, reqMsg)
	if err != nil {
		return nil, fmt.Errorf("zapclient: call: %w", err)
	}
	raw := resp.Bytes()
	if len(raw) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	status, payload := raw[0], raw[1:]
	switch status {
	case statusOK:
		return payload, nil
	case statusNotFound:
		return nil, ErrNotFound
	case statusForbid:
		return nil, ErrForbidden
	default:
		return nil, fmt.Errorf("zapclient: server error: %s", string(payload))
	}
}

// buildMessage packs bytes into a parseable ZAP Message.
func buildMessage(body []byte) *zap.Message {
	b := zap.NewBuilder(len(body) + 8)
	b.WriteBytes(body)
	raw := b.Finish()
	msg, err := zap.Parse(raw)
	if err != nil {
		return nil
	}
	return msg
}
