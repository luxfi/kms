// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// http.go — the HTTP /v1/sdk secrets surface.
//
// This is a thin transport adapter over the SAME verify→authorize→
// dispatch core the ZAP wire uses (verifyAndAuthorize + dispatch). There
// is exactly ONE implementation of "authenticate an enveloped KMS op and
// run it"; ZAP and HTTP are two framings of it.
//
// The surface is a single RPC-style endpoint:
//
//	POST /v1/sdk/secrets   body: a signed Envelope (see pkg/envelope)
//
// The operation is taken from the SIGNED env.Op field, never from the
// URL. This is deliberate: the read/write authorization decision keys
// off the signed op, so no URL framing can escalate a read identity into
// a write. Every request — get/put/list/delete secret, sign/verify key —
// rides the same signed envelope and the same authorization core.
//
// Op → verb map (env.Op):
//
//	OpSecretGet    0x0040  read   (validator authority)  { path, name, env }
//	OpSecretPut    0x0041  write  (operator authority)   { path, name, env, value }  (also the rotate op — upsert)
//	OpSecretList   0x0042  read   (validator authority)  { path, env }
//	OpSecretDelete 0x0043  write  (operator authority)   { path, name, env }
//	OpSign         0x0050  write  (operator authority)   { validator_id, key_type, message }
//	OpVerify       0x0051  read   (validator authority)  { validator_id, key_type, message, signature }

package zapserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// MaxEnvelopeBytes caps the /v1/sdk request body. A Put envelope carries
// a base64 secret value; 4 MiB is generous for certs / key bundles while
// bounding the parse/alloc DoS surface. Bodies larger than this are
// rejected with 413 before any JSON is parsed.
const MaxEnvelopeBytes = 4 << 20

// HTTPHandler returns the /v1/sdk transport. Mount it on the KMS HTTP
// mux; it owns only the /v1/sdk/* routes.
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sdk/secrets", s.handleHTTP)
	return mux
}

// handleHTTP is the single /v1/sdk/secrets entry. It reads the signed
// envelope, verifies + authorizes it (shared core), dispatches on the
// signed op, and maps the internal status byte to an HTTP status.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Bounded read. LimitReader + 1 lets us detect the over-cap case
	// without allocating the whole oversized body.
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxEnvelopeBytes+1))
	if err != nil {
		httpJSON(w, http.StatusBadRequest, "read body failed")
		return
	}
	if len(raw) > MaxEnvelopeBytes {
		httpJSON(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	// Structural parse. A malformed envelope is a client error (400) and
	// carries no secret, so echoing the shape reason is safe. The op is
	// read from the SIGNED field below.
	env, err := ParseEnvelope(raw)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify (ML-DSA-65 signature + wall-clock freshness + replay) and
	// run the consensus authorizer keyed on the signed op. Every failure
	// — bad signature, stale timestamp, replayed nonce, not-authorized —
	// collapses to 403. Replay is deliberately vague ("forbidden") so an
	// off-network attacker cannot probe the nonce ledger via status; the
	// other reasons carry no secret and match the ZAP wire behaviour.
	ident, inner, err := s.verifyAndAuthorize(r.Context(), raw, env.Op)
	if err != nil {
		httpJSON(w, http.StatusForbidden, forbidReason(err))
		return
	}

	status, body, err := s.dispatch(r.Context(), ident, env.Op, inner)
	if err != nil {
		// Handler-internal failure (store/backend). Do NOT leak the
		// internal error to the client; audit-log it and return a
		// generic 500.
		s.log.Warn("kms.sdk handler error", "ident", ident.String(), "op", Op(env.Op).String(), "err", err)
		httpJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusFor(status))
	_, _ = w.Write(body)
}

// httpStatusFor maps the internal status byte to an HTTP status code.
func httpStatusFor(status byte) int {
	switch status {
	case statusOK:
		return http.StatusOK
	case statusNotFound:
		return http.StatusNotFound
	case statusForbid:
		return http.StatusForbidden
	default: // statusError
		return http.StatusBadRequest
	}
}

// forbidReason returns a wire-safe reason for a verify/authorize
// failure. Replay is masked behind a generic "forbidden" so the nonce
// ledger state is unprobeable; other reasons (stale, not-a-validator,
// not-an-operator, bad-signature) carry no secret and aid the caller.
func forbidReason(err error) string {
	if errors.Is(err, ErrEnvelopeReplay) {
		return "forbidden"
	}
	return err.Error()
}

// httpJSON writes {"error": msg} with the given status.
func httpJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
