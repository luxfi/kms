// Principal-role authorization for ZAP secret opcodes.
//
// ZAP has no JWT/IAM concept at the wire layer — the only principal we can
// trust is the peer NodeID set during handshake (over PQ-TLS in production).
// To map a NodeID to (role, scope) we accept an ACL: each line binds a
// NodeID to a role for a path prefix.
//
// Role grants:
//
//	role=read   → OpSecretGet, OpSecretList
//	role=admin  → all four opcodes
//
// Path scoping mirrors the HTTP-side `canActOnOrg` contract from
// hanzo/kms/cmd/kmsd/main.go: a request is permitted iff the requested
// `path` begins with the principal's allowed `pathPrefix`, segment-aligned.
// A NodeID with `pathPrefix=""` is unscoped (analogous to the "admin" role
// with cross-org reach on the HTTP path).
//
// When no ACL is configured the server permits every request and logs an
// "open" mode banner at boot — this preserves the pre-authn behaviour for
// rollouts that have not yet wired an ACL. Once `KMS_ZAP_ACL` is set the
// server is fail-closed: unknown NodeIDs receive 0x03 forbidden.
package zapserver

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Role is the bundle of opcodes a principal may invoke.
type Role string

const (
	// RoleRead permits Get + List.
	RoleRead Role = "read"
	// RoleAdmin permits all four secret opcodes.
	RoleAdmin Role = "admin"
)

// ACLEntry binds a peer NodeID to a role at a path prefix.
//
// PathPrefix is segment-aligned: "ats" matches "ats" and "ats/foo", but
// not "atsx". Empty PathPrefix is unscoped — the principal may operate
// on any path. Use sparingly; reserve for break-glass admin nodes.
type ACLEntry struct {
	NodeID     string
	PathPrefix string
	Role       Role
}

// ACL is the principal-role registry. Lookup is by NodeID; a single
// NodeID may appear with multiple entries (e.g. both `read` on `ats` and
// `admin` on `ats/own`). Decide picks the most-permissive matching rule.
type ACL struct {
	entries []ACLEntry
}

// NewACL builds an ACL from a slice of entries. Order is preserved but
// does not matter for matching — Decide considers every entry.
func NewACL(entries []ACLEntry) *ACL {
	clean := make([]ACLEntry, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.NodeID) == "" || strings.TrimSpace(string(e.Role)) == "" {
			continue
		}
		clean = append(clean, ACLEntry{
			NodeID:     strings.TrimSpace(e.NodeID),
			PathPrefix: strings.Trim(strings.TrimSpace(e.PathPrefix), "/"),
			Role:       Role(strings.ToLower(strings.TrimSpace(string(e.Role)))),
		})
	}
	return &ACL{entries: clean}
}

// LoadACLFromEnv reads the ACL from the file referenced by KMS_ZAP_ACL.
//
// File format: one entry per line, `nodeId,pathPrefix,role`. Blank lines
// and `#`-prefixed comments are ignored. Returns nil if the env var is
// unset, signalling open mode to the caller.
func LoadACLFromEnv() (*ACL, error) {
	path := strings.TrimSpace(os.Getenv("KMS_ZAP_ACL"))
	if path == "" {
		return nil, nil
	}
	return LoadACLFromFile(path)
}

// LoadACLFromFile parses a CSV-ish ACL file at path.
func LoadACLFromFile(path string) (*ACL, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("zapserver: open acl %q: %w", path, err)
	}
	defer f.Close()

	var entries []ACLEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("zapserver: acl %s:%d: want 3 fields, got %d", path, lineNo, len(parts))
		}
		role := Role(strings.ToLower(strings.TrimSpace(parts[2])))
		if role != RoleRead && role != RoleAdmin {
			return nil, fmt.Errorf("zapserver: acl %s:%d: unknown role %q", path, lineNo, parts[2])
		}
		entries = append(entries, ACLEntry{
			NodeID:     strings.TrimSpace(parts[0]),
			PathPrefix: strings.Trim(strings.TrimSpace(parts[1]), "/"),
			Role:       role,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("zapserver: read acl %s: %w", path, err)
	}
	return NewACL(entries), nil
}

// errACLNoMatch is the sentinel decisions return so handlers can map a
// no-match to the wire-level statusForbid byte without leaking ACL
// internals back to the caller.
var errACLNoMatch = errors.New("zapserver: acl: no matching rule")

// Decide returns nil if the (nodeID, op, path) tuple is permitted by some
// rule in the ACL, otherwise errACLNoMatch.
//
// The decision rule is: at least one ACL entry must satisfy
//
//	entry.NodeID == nodeID
//	pathPrefixMatches(entry.PathPrefix, path)
//	roleAllowsOp(entry.Role, op)
//
// The first matching entry returns nil; we do not enumerate further.
func (a *ACL) Decide(nodeID, path string, op uint16) error {
	if a == nil {
		return nil // open mode — no ACL configured
	}
	cleanPath := strings.Trim(path, "/")
	for _, e := range a.entries {
		if e.NodeID != nodeID {
			continue
		}
		if !pathPrefixMatches(e.PathPrefix, cleanPath) {
			continue
		}
		if !roleAllowsOp(e.Role, op) {
			continue
		}
		return nil
	}
	return errACLNoMatch
}

// pathPrefixMatches enforces segment-aligned prefix matching. An empty
// allowed prefix matches any path (unscoped principal).
func pathPrefixMatches(allowedPrefix, requestedPath string) bool {
	if allowedPrefix == "" {
		return true
	}
	if requestedPath == allowedPrefix {
		return true
	}
	// Require the next byte after the prefix to be a path separator so
	// "ats" does not match "atsx".
	if strings.HasPrefix(requestedPath, allowedPrefix+"/") {
		return true
	}
	return false
}

// roleAllowsOp returns true if role permits the given opcode.
func roleAllowsOp(role Role, op uint16) bool {
	switch role {
	case RoleAdmin:
		switch op {
		case OpSecretGet, OpSecretPut, OpSecretList, OpSecretDelete:
			return true
		}
	case RoleRead:
		switch op {
		case OpSecretGet, OpSecretList:
			return true
		}
	}
	return false
}

// opName is a small helper for audit logs.
func opName(op uint16) string {
	switch op {
	case OpSecretGet:
		return "OpSecretGet"
	case OpSecretPut:
		return "OpSecretPut"
	case OpSecretList:
		return "OpSecretList"
	case OpSecretDelete:
		return "OpSecretDelete"
	}
	return fmt.Sprintf("Op_0x%04X", op)
}
