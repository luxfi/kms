// Package zapserver exposes the KMS Secret store over luxfi/zap.
//
// Wire format per request: opcode(2 LE) || JSON payload.
// Response: 1-byte status (0x00 ok, 0x01 not found, 0x02 error) || payload.
//
// Opcodes:
//
//	0x0040  OpSecretGet   { path, name, env }          → { value: base64 } or not-found
//	0x0041  OpSecretPut   { path, name, env, value }   → { ok: true }           (admin only)
//	0x0042  OpSecretList  { path, env }                → { names: []string }
//	0x0043  OpSecretDelete{ path, name, env }          → { ok: true }           (admin only)
//
// Auth: the caller identity is the peer NodeID established by the ZAP
// transport handshake (PQ-TLS in production — see upstream luxfi/zap).
// Authorization is enforced by an ACL: each NodeID is bound to a role
// (read | admin) at a path prefix. Read permits Get + List; admin
// permits all four opcodes. The path prefix is segment-aligned to mirror
// the HTTP-side `canActOnOrg` contract from cmd/kmsd/main.go.
//
// When no ACL is configured the server runs in open mode and emits a
// startup warning. Once `KMS_ZAP_ACL` is set the server is fail-closed:
// any request from an unknown NodeID receives 0x03 forbidden.
package zapserver

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
)

const (
	OpSecretGet    uint16 = 0x0040
	OpSecretPut    uint16 = 0x0041
	OpSecretList   uint16 = 0x0042
	OpSecretDelete uint16 = 0x0043
)

// status byte values in the response.
const (
	statusOK       byte = 0x00
	statusNotFound byte = 0x01
	statusError    byte = 0x02
	statusForbid   byte = 0x03
)

// Server wires a SecretStore onto a ZAP Node. It does not own the node's
// lifecycle — the caller registers the server and starts the node.
type Server struct {
	store     *store.SecretStore
	masterKey []byte
	acl       *ACL
	log       log.Logger
}

// Config wires a Server with the required dependencies.
type Config struct {
	Store     *store.SecretStore
	MasterKey []byte
	// ACL gates every secret opcode by peer NodeID + path + role. nil
	// means open mode — the server permits every request and emits a
	// one-line warning at boot. Mirror the HTTP-side `canActOnOrg`
	// contract from cmd/kmsd/main.go: a request is permitted iff the
	// principal's role allows the opcode AND the requested path begins
	// with one of the principal's allowed path prefixes.
	ACL *ACL
	// Logger is the luxfi/log Logger. nil falls back to the package
	// root logger (log.Root()).
	Logger log.Logger
}

// New returns a Server ready to attach to a ZAP node via Register.
// Panics if masterKey is not 32 bytes — the caller must unseal first.
func New(cfg Config) *Server {
	if len(cfg.MasterKey) != 32 {
		panic("zapserver: master key must be 32 bytes")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Root()
	}
	s := &Server{
		store:     cfg.Store,
		masterKey: cfg.MasterKey,
		acl:       cfg.ACL,
		log:       cfg.Logger,
	}
	if cfg.ACL == nil {
		s.log.Warn("kms.zap acl=open — every peer permitted (set KMS_ZAP_ACL to enable)")
	} else {
		s.log.Info("kms.zap acl=enforced")
	}
	return s
}

// Register attaches the Server's handlers to the ZAP Node.
//
// Handlers are registered at both the opcode-specific message type (for
// callers that set the ZAP flags/type field correctly) AND at type 0 (the
// default when callers use zap.Builder without setting flags). Type 0 is a
// universal multiplexer that reads the opcode from the first 2 bytes of the
// payload and dispatches internally.
func (s *Server) Register(n *zap.Node) {
	// Per-opcode (future: once Builder supports setting msg type)
	n.Handle(OpSecretGet, s.wrap(s.handleGet))
	n.Handle(OpSecretPut, s.wrap(s.handlePut))
	n.Handle(OpSecretList, s.wrap(s.handleList))
	n.Handle(OpSecretDelete, s.wrap(s.handleDelete))

	// Universal handler at type 0: reads opcode from body, dispatches.
	handlers := map[uint16]handlerFn{
		OpSecretGet:    s.handleGet,
		OpSecretPut:    s.handlePut,
		OpSecretList:   s.handleList,
		OpSecretDelete: s.handleDelete,
	}
	n.Handle(0, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		raw := msg.Root().Bytes(0)
		if raw == nil {
			// Fallback: caller wrote raw bytes via Builder.WriteBytes without
			// an enclosing Object — strip the 16-byte ZAP frame header.
			b := msg.Bytes()
			if len(b) > zap.HeaderSize {
				raw = b[zap.HeaderSize:]
			}
		}
		if len(raw) < 2 {
			return respond(statusError, errJSON("empty payload")), nil
		}
		op := binary.LittleEndian.Uint16(raw[:2])
		payload := raw[2:]
		h, ok := handlers[op]
		if !ok {
			return respond(statusError, errJSON("unknown opcode")), nil
		}
		status, body, err := h(ctx, from, payload)
		if err != nil {
			s.log.Warn("kms.zap handler error (mux)", "from", from, "op", op, "err", err)
			return respond(statusError, errJSON(err.Error())), nil
		}
		return respond(status, body), nil
	})
}

// handlerFn is the shape of our op handlers before wrapping with framing.
type handlerFn func(ctx context.Context, from string, payload []byte) (byte, []byte, error)

// wrap marshals the {status || body} response and logs errors with the
// caller's principal ID.
func (s *Server) wrap(h handlerFn) zap.Handler {
	return func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		// Access body via Root Object. Builder writes the payload at field 0.
		raw := msg.Root().Bytes(0)
		if raw == nil {
			// Fallback: raw frame bytes (for callers that don't use structured
			// objects) — strip the 16-byte ZAP header so payload begins with the
			// opcode prefix.
			b := msg.Bytes()
			if len(b) > zap.HeaderSize {
				raw = b[zap.HeaderSize:]
			}
		}
		// Opcode was already matched by Node — but we carry it in for tracing.
		if len(raw) < 2 {
			return respond(statusError, errJSON("empty payload")), nil
		}
		payload := raw[2:]
		status, body, err := h(ctx, from, payload)
		if err != nil {
			s.log.Warn("kms.zap handler error", "from", from, "err", err)
			return respond(statusError, errJSON(err.Error())), nil
		}
		return respond(status, body), nil
	}
}

// respond frames { status || json } as a ZAP message.
func respond(status byte, body []byte) *zap.Message {
	b := zap.NewBuilder(len(body) + 8)
	b.WriteBytes(append([]byte{status}, body...))
	raw := b.Finish()
	msg, err := zap.Parse(raw)
	if err != nil {
		// Should never happen — Builder output is always parseable.
		return nil
	}
	return msg
}

func errJSON(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

// ---- handlers ----

// authz runs the ACL check for an opcode and returns true if the request
// is permitted. On a deny it logs an audit row at INFO and the caller
// should respond with statusForbid. The audit row mirrors the HTTP
// authorize() pattern in cmd/kmsd/main.go: structured key/value with
// the opcode, NodeID, decision, and the requested path/name.
func (s *Server) authz(from, path, name, env string, op uint16) bool {
	if err := s.acl.Decide(from, path, op); err != nil {
		s.log.Info("kms.zap authz",
			"decision", "forbid",
			"op", opName(op),
			"from", from,
			"path", path,
			"name", name,
			"env", env,
		)
		return false
	}
	s.log.Info("kms.zap authz",
		"decision", "ok",
		"op", opName(op),
		"from", from,
		"path", path,
		"name", name,
		"env", env,
	)
	return true
}

type getReq struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Env  string `json:"env"`
}

type getResp struct {
	Value string `json:"value"` // base64 plaintext
}

func (s *Server) handleGet(_ context.Context, from string, payload []byte) (byte, []byte, error) {
	var req getReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if !s.authz(from, req.Path, req.Name, req.Env, OpSecretGet) {
		return statusForbid, errJSON("forbidden"), nil
	}
	sec, err := s.store.Get(req.Path, req.Name, req.Env)
	if errors.Is(err, store.ErrSecretNotFound) {
		return statusNotFound, errJSON("not found"), nil
	}
	if err != nil {
		return statusError, nil, err
	}
	pt, err := store.Open(s.masterKey, sec)
	if err != nil {
		return statusError, nil, err
	}
	defer zero(pt)
	b, _ := json.Marshal(getResp{Value: base64.StdEncoding.EncodeToString(pt)})
	s.log.Debug("kms.zap get", "from", from, "path", req.Path, "name", req.Name, "env", req.Env)
	return statusOK, b, nil
}

type putReq struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Env   string `json:"env"`
	Value string `json:"value"` // base64 plaintext
}

func (s *Server) handlePut(_ context.Context, from string, payload []byte) (byte, []byte, error) {
	var req putReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if !s.authz(from, req.Path, req.Name, req.Env, OpSecretPut) {
		return statusForbid, errJSON("forbidden"), nil
	}
	pt, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		return statusError, errJSON("bad base64"), nil
	}
	defer zero(pt)
	sec, err := store.Seal(s.masterKey, req.Path, req.Name, req.Env, pt)
	if err != nil {
		return statusError, nil, err
	}
	if err := s.store.Put(sec); err != nil {
		return statusError, nil, err
	}
	s.log.Info("kms.zap put", "from", from, "path", req.Path, "name", req.Name, "env", req.Env)
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return statusOK, b, nil
}

type listReq struct {
	Path string `json:"path"`
	Env  string `json:"env"`
}

type listResp struct {
	Names []string `json:"names"`
}

func (s *Server) handleList(_ context.Context, from string, payload []byte) (byte, []byte, error) {
	var req listReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if !s.authz(from, req.Path, "", req.Env, OpSecretList) {
		return statusForbid, errJSON("forbidden"), nil
	}
	secs, err := s.store.List(req.Path, req.Env)
	if err != nil {
		return statusError, nil, err
	}
	names := make([]string, 0, len(secs))
	for _, sec := range secs {
		names = append(names, sec.Name)
	}
	b, _ := json.Marshal(listResp{Names: names})
	return statusOK, b, nil
}

type delReq struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Env  string `json:"env"`
}

func (s *Server) handleDelete(_ context.Context, from string, payload []byte) (byte, []byte, error) {
	var req delReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if !s.authz(from, req.Path, req.Name, req.Env, OpSecretDelete) {
		return statusForbid, errJSON("forbidden"), nil
	}
	if err := s.store.Delete(req.Path, req.Name, req.Env); err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return statusNotFound, errJSON("not found"), nil
		}
		return statusError, nil, err
	}
	s.log.Info("kms.zap delete", "from", from, "path", req.Path, "name", req.Name, "env", req.Env)
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return statusOK, b, nil
}

// zero wipes a byte slice (best effort — caller must still avoid copies).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// BuildRequest is a helper for clients: frames opcode(2 LE) || JSON payload.
// Returns the raw bytes ready for zap.NewBuilder.WriteBytes.
func BuildRequest(op uint16, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	out := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(out[0:2], op)
	copy(out[2:], data)
	return out, nil
}

// ParseResponse extracts the status byte and JSON body from a reply message.
func ParseResponse(raw []byte) (status byte, body []byte, err error) {
	if len(raw) < 1 {
		return 0, nil, fmt.Errorf("empty response")
	}
	return raw[0], raw[1:], nil
}
