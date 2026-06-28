// Approvals — access-approval + change(secret)-approval policy/request surface.
//
// Three distinct policy families the SPA drives, each at its own version-literal
// path (Infisical-derived; versions are LITERAL, not aliased):
//
//	access-approval policies/requests   /v1/access-approvals/...
//	generic approval-policy engine      /v1/approval-policies/{policyType}/...
//	  (policies + grants + requests; policyType e.g. "pam-access")
//	secret(change)-approval policies     /v1/secret-approvals, /v2/secret-approvals/{id}
//	secret-approval requests            /v1/secret-approval-requests/...
//
// Policy CONFIG entities are real CRUD persisted as JSON-KV in ZapDB under
// "kms/approvals/...". The request/grant *workflow* surfaces (review/approve/
// reject/merge/revoke + their list+count tabs) are approval-engine semantics
// (multi-step quorum, membership resolution, PAM grant leasing, secret-change
// merge) — those persist the request entity where simple and otherwise return
// the correctly-shaped wrapper with an EMPTY array / zero count + HTTP 200 so
// the dashboard tabs navigate without erroring. No crypto here; the heavy
// review/merge/grant-lease logic is the stubbed part.
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── storage keys ─────────────────────────────────────────────────────────
// access-approval policies are project(slug)-scoped; the generic + secret
// policies key by their own id. Each family gets its own prefix so a List
// iteration over one never sees another.

func aaPolicyKey(id string) []byte  { return []byte("kms/approvals/aa-policy/" + id) }
func aaPolicyIdx(projectSlug, id string) []byte {
	return []byte("kms/approvals/aa-policy-by-proj/" + projectSlug + "/" + id)
}
func aaPolicyPrefix(projectSlug string) []byte {
	return []byte("kms/approvals/aa-policy-by-proj/" + projectSlug + "/")
}

func apPolicyKey(policyType, id string) []byte {
	return []byte("kms/approvals/ap-policy/" + policyType + "/" + id)
}
func apPolicyPrefix(policyType string) []byte {
	return []byte("kms/approvals/ap-policy/" + policyType + "/")
}

func sapPolicyKey(id string) []byte { return []byte("kms/approvals/sap-policy/" + id) }
func sapPolicyIdx(projectID, id string) []byte {
	return []byte("kms/approvals/sap-policy-by-proj/" + projectID + "/" + id)
}
func sapPolicyPrefix(projectID string) []byte {
	return []byte("kms/approvals/sap-policy-by-proj/" + projectID + "/")
}

// ── stored shapes ────────────────────────────────────────────────────────

// aaPolicy backs the access-approval policy (TAccessApprovalPolicy). Stored
// verbatim from the create/update body so the round-trip preserves approver/
// bypasser graphs the UI sent; computed/defaulted fields are filled at render.
type aaPolicy struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ProjectSlug          string         `json:"projectSlug"`
	Environments         []string       `json:"environments"`
	SecretPath           string         `json:"secretPath"`
	Approvals            int            `json:"approvals"`
	Approvers            []any          `json:"approvers"`
	Bypassers            []any          `json:"bypassers"`
	EnforcementLevel     string         `json:"enforcementLevel"`
	AllowedSelfApprovals bool           `json:"allowedSelfApprovals"`
	ApprovalsRequired    []any          `json:"approvalsRequired"`
	MaxTimePeriod        any            `json:"maxTimePeriod"`
	CreatedAt            time.Time      `json:"createdAt"`
	UpdatedAt            time.Time      `json:"updatedAt"`
}

// apPolicy backs the generic approval-policy engine (TApprovalPolicy):
// conditions/constraints/steps are opaque to us, persisted as-is.
type apPolicy struct {
	ID            string          `json:"id"`
	ProjectID     string          `json:"projectId"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	MaxRequestTtl any             `json:"maxRequestTtl"`
	Conditions    json.RawMessage `json:"conditions"`
	Constraints   json.RawMessage `json:"constraints"`
	Steps         json.RawMessage `json:"steps"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

// sapPolicy backs the secret(change)-approval policy (TSecretApprovalPolicy).
type sapPolicy struct {
	ID                   string    `json:"id"`
	ProjectID            string    `json:"projectId"`
	Name                 string    `json:"name"`
	Environments         []string  `json:"environments"`
	SecretPath           string    `json:"secretPath"`
	Approvals            int       `json:"approvals"`
	Approvers            []any     `json:"approvers"`
	Bypassers            []any     `json:"bypassers"`
	EnforcementLevel     string    `json:"enforcementLevel"`
	AllowedSelfApprovals bool      `json:"allowedSelfApprovals"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// ── render helpers (fill computed/defaulted fields the SPA reads) ─────────

func aaPolicyJSON(p *aaPolicy) map[string]any {
	envs := approvalEnvObjs(p.Environments)
	return map[string]any{
		"id": p.ID, "name": p.Name, "projectId": p.ProjectSlug, "workspace": p.ProjectSlug,
		"environments": envs, "secretPath": p.SecretPath, "approvals": p.Approvals,
		"approvers": orEmpty(p.Approvers), "bypassers": orEmpty(p.Bypassers),
		"policyType": "access", "approversRequired": true,
		"enforcementLevel": orStr(p.EnforcementLevel, "hard"), "allowedSelfApprovals": p.AllowedSelfApprovals,
		"maxTimePeriod": p.MaxTimePeriod, "updatedAt": p.UpdatedAt, "createdAt": p.CreatedAt,
	}
}

func apPolicyJSON(p *apPolicy) map[string]any {
	return map[string]any{
		"id": p.ID, "projectId": p.ProjectID, "name": p.Name, "type": p.Type,
		"maxRequestTtl": p.MaxRequestTtl,
		"conditions":    rawOr(p.Conditions, map[string]any{"version": 1, "conditions": []any{}}),
		"constraints":   rawOr(p.Constraints, map[string]any{"version": 1, "constraints": map[string]any{}}),
		"steps":         rawOr(p.Steps, []any{}),
		"createdAt":     p.CreatedAt, "updatedAt": p.UpdatedAt,
	}
}

func sapPolicyJSON(p *sapPolicy) map[string]any {
	return map[string]any{
		"id": p.ID, "project": p.ProjectID, "name": p.Name,
		"environments": approvalEnvObjs(p.Environments), "secretPath": p.SecretPath,
		"approvals": p.Approvals, "approvers": orEmpty(p.Approvers), "bypassers": orEmpty(p.Bypassers),
		"enforcementLevel": orStr(p.EnforcementLevel, "hard"), "allowedSelfApprovals": p.AllowedSelfApprovals,
		"updatedAt": p.UpdatedAt,
	}
}

// approvalEnvObjs maps env slugs to the ProjectEnv shape the UI deserializes.
func approvalEnvObjs(slugs []string) []map[string]any {
	out := make([]map[string]any, 0, len(slugs))
	for _, s := range slugs {
		out = append(out, map[string]any{"id": s, "name": s, "slug": s})
	}
	return out
}

func orEmpty(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}
func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
func rawOr(r json.RawMessage, def any) any {
	if len(r) == 0 {
		return def
	}
	return r
}

func registerApprovalsAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ════════════════════════════════════════════════════════════════════
	// access-approval policies  (/v1/access-approvals/policies)
	// ════════════════════════════════════════════════════════════════════

	// GET …/policies/count — registered before the bare …/policies list so the
	// literal "count" segment is unambiguous (it is anyway under {placeholder}
	// precedence, but keep it explicit).
	mux.HandleFunc("GET /v1/access-approvals/policies/count", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0})
	})

	mux.HandleFunc("GET /v1/access-approvals/policies", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		out := []any{}
		for _, p := range listAAPolicies(st, r.URL.Query().Get("projectSlug")) {
			out = append(out, aaPolicyJSON(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
	})

	mux.HandleFunc("POST /v1/access-approvals/policies", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Name                 string   `json:"name"`
			ProjectSlug          string   `json:"projectSlug"`
			Environments         []string `json:"environments"`
			SecretPath           string   `json:"secretPath"`
			Approvals            int      `json:"approvals"`
			Approvers            []any    `json:"approvers"`
			Bypassers            []any    `json:"bypassers"`
			EnforcementLevel     string   `json:"enforcementLevel"`
			AllowedSelfApprovals bool     `json:"allowedSelfApprovals"`
			ApprovalsRequired    []any    `json:"approvalsRequired"`
			MaxTimePeriod        any      `json:"maxTimePeriod"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		p := &aaPolicy{
			ID: newID(), Name: req.Name, ProjectSlug: req.ProjectSlug, Environments: req.Environments,
			SecretPath: req.SecretPath, Approvals: req.Approvals, Approvers: req.Approvers,
			Bypassers: req.Bypassers, EnforcementLevel: req.EnforcementLevel,
			AllowedSelfApprovals: req.AllowedSelfApprovals, ApprovalsRequired: req.ApprovalsRequired,
			MaxTimePeriod: req.MaxTimePeriod, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(aaPolicyKey(p.ID), p)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(aaPolicyIdx(p.ProjectSlug, p.ID), []byte(p.ID)) })
		writeJSON(w, http.StatusOK, map[string]any{"approval": aaPolicyJSON(p)})
	})

	mux.HandleFunc("PATCH /v1/access-approvals/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p aaPolicy
		if st.getJSON(aaPolicyKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		var req struct {
			Name                 *string  `json:"name"`
			Environments         []string `json:"environments"`
			SecretPath           *string  `json:"secretPath"`
			Approvals            *int     `json:"approvals"`
			Approvers            []any    `json:"approvers"`
			Bypassers            []any    `json:"bypassers"`
			EnforcementLevel     *string  `json:"enforcementLevel"`
			AllowedSelfApprovals *bool    `json:"allowedSelfApprovals"`
			ApprovalsRequired    []any    `json:"approvalsRequired"`
			MaxTimePeriod        any      `json:"maxTimePeriod"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			p.Name = *req.Name
		}
		if req.Environments != nil {
			p.Environments = req.Environments
		}
		if req.SecretPath != nil {
			p.SecretPath = *req.SecretPath
		}
		if req.Approvals != nil {
			p.Approvals = *req.Approvals
		}
		if req.Approvers != nil {
			p.Approvers = req.Approvers
		}
		if req.Bypassers != nil {
			p.Bypassers = req.Bypassers
		}
		if req.EnforcementLevel != nil {
			p.EnforcementLevel = *req.EnforcementLevel
		}
		if req.AllowedSelfApprovals != nil {
			p.AllowedSelfApprovals = *req.AllowedSelfApprovals
		}
		if req.ApprovalsRequired != nil {
			p.ApprovalsRequired = req.ApprovalsRequired
		}
		if req.MaxTimePeriod != nil {
			p.MaxTimePeriod = req.MaxTimePeriod
		}
		p.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(aaPolicyKey(p.ID), &p)
		writeJSON(w, http.StatusOK, map[string]any{"approval": aaPolicyJSON(&p)})
	})

	mux.HandleFunc("DELETE /v1/access-approvals/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p aaPolicy
		if st.getJSON(aaPolicyKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(aaPolicyKey(p.ID))
			return txn.Delete(aaPolicyIdx(p.ProjectSlug, p.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"approval": aaPolicyJSON(&p)})
	})

	// ── access-approval requests (workflow surface — shaped, count-zero) ──
	mux.HandleFunc("GET /v1/access-approvals/requests/count", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pendingCount": 0, "finalizedCount": 0})
	})
	mux.HandleFunc("GET /v1/access-approvals/requests", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": []any{}})
	})
	mux.HandleFunc("POST /v1/access-approvals/requests", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			PolicyId    string `json:"policyId"`
			PrivilegeId string `json:"privilegeId"`
		}
		_ = decode(w, r, &req)
		// TAccessApproval shape; persisting the lease/privilege grant is
		// approval-engine work, so we return the created envelope only.
		writeJSON(w, http.StatusOK, map[string]any{
			"id": newID(), "policyId": req.PolicyId, "privilegeId": req.PrivilegeId,
			"requestedBy": cl.UserID,
		})
	})
	mux.HandleFunc("PATCH /v1/access-approvals/requests/{requestId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"approval": map[string]any{"id": r.PathValue("requestId")}})
	})
	mux.HandleFunc("POST /v1/access-approvals/requests/{requestId}/review", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Status       string `json:"status"`
			BypassReason string `json:"bypassReason"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"review": map[string]any{"id": r.PathValue("requestId"), "status": req.Status}})
	})

	// ════════════════════════════════════════════════════════════════════
	// generic approval-policy engine  (/v1/approval-policies/{policyType}/…)
	// ServeMux precedence: literal segments (grants, requests, check-policy-
	// match) outrank {policyId}, so the order of registration is irrelevant.
	// ════════════════════════════════════════════════════════════════════

	mux.HandleFunc("GET /v1/approval-policies/{policyType}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		out := []any{}
		for _, p := range listAPPolicies(st, r.PathValue("policyType")) {
			out = append(out, apPolicyJSON(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": out})
	})

	mux.HandleFunc("POST /v1/approval-policies/{policyType}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			ProjectID     string          `json:"projectId"`
			Name          string          `json:"name"`
			MaxRequestTtl any             `json:"maxRequestTtl"`
			Conditions    json.RawMessage `json:"conditions"`
			Constraints   json.RawMessage `json:"constraints"`
			Steps         json.RawMessage `json:"steps"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		p := &apPolicy{
			ID: newID(), ProjectID: req.ProjectID, Name: req.Name, Type: r.PathValue("policyType"),
			MaxRequestTtl: req.MaxRequestTtl, Conditions: req.Conditions, Constraints: req.Constraints,
			Steps: req.Steps, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(apPolicyKey(p.Type, p.ID), p)
		writeJSON(w, http.StatusOK, map[string]any{"policy": apPolicyJSON(p)})
	})

	mux.HandleFunc("GET /v1/approval-policies/{policyType}/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p apPolicy
		if st.getJSON(apPolicyKey(r.PathValue("policyType"), r.PathValue("policyId")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policy": apPolicyJSON(&p)})
	})

	mux.HandleFunc("PATCH /v1/approval-policies/{policyType}/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		pt, id := r.PathValue("policyType"), r.PathValue("policyId")
		var p apPolicy
		if st.getJSON(apPolicyKey(pt, id), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		var req struct {
			Name          *string         `json:"name"`
			MaxRequestTtl any             `json:"maxRequestTtl"`
			Conditions    json.RawMessage `json:"conditions"`
			Constraints   json.RawMessage `json:"constraints"`
			Steps         json.RawMessage `json:"steps"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			p.Name = *req.Name
		}
		if req.MaxRequestTtl != nil {
			p.MaxRequestTtl = req.MaxRequestTtl
		}
		if len(req.Conditions) > 0 {
			p.Conditions = req.Conditions
		}
		if len(req.Constraints) > 0 {
			p.Constraints = req.Constraints
		}
		if len(req.Steps) > 0 {
			p.Steps = req.Steps
		}
		p.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(apPolicyKey(pt, id), &p)
		writeJSON(w, http.StatusOK, map[string]any{"policy": apPolicyJSON(&p)})
	})

	mux.HandleFunc("DELETE /v1/approval-policies/{policyType}/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		pt, id := r.PathValue("policyType"), r.PathValue("policyId")
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(apPolicyKey(pt, id)) })
		writeJSON(w, http.StatusOK, map[string]any{"policyId": id})
	})

	mux.HandleFunc("POST /v1/approval-policies/{policyType}/check-policy-match", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		// TCheckPolicyMatchResult — no policy ⇒ no approval required, no grant.
		writeJSON(w, http.StatusOK, map[string]any{"requiresApproval": false, "hasActiveGrant": false})
	})

	// ── approval grants (PAM lease workflow — shaped/empty) ──────────────
	mux.HandleFunc("GET /v1/approval-policies/{policyType}/grants", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": []any{}})
	})
	mux.HandleFunc("GET /v1/approval-policies/{policyType}/grants/{grantId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusNotFound, msg("grant not found"))
	})
	mux.HandleFunc("POST /v1/approval-policies/{policyType}/grants/{grantId}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			RevocationReason string `json:"revocationReason"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"grant": map[string]any{
			"id": r.PathValue("grantId"), "status": "revoked", "revocationReason": req.RevocationReason,
		}})
	})

	// ── generic approval requests (multi-step quorum workflow — shaped) ───
	mux.HandleFunc("GET /v1/approval-policies/{policyType}/requests", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": []any{}})
	})
	mux.HandleFunc("POST /v1/approval-policies/{policyType}/requests", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			ProjectID     string          `json:"projectId"`
			Justification any             `json:"justification"`
			RequestData   json.RawMessage `json:"requestData"`
		}
		_ = decode(w, r, &req)
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"request": map[string]any{
			"id": newID(), "projectId": req.ProjectID, "type": r.PathValue("policyType"),
			"status": "pending", "requesterId": cl.UserID, "justification": req.Justification,
			"requestData": map[string]any{"version": 1, "requestData": rawOr(req.RequestData, map[string]any{})},
			"steps":       []any{}, "createdAt": now, "updatedAt": now,
		}})
	})
	mux.HandleFunc("GET /v1/approval-policies/{policyType}/requests/{requestId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusNotFound, msg("request not found"))
	})
	apReqAction := func(status string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			now := time.Now().UTC()
			writeJSON(w, http.StatusOK, map[string]any{"request": map[string]any{
				"id": r.PathValue("requestId"), "type": r.PathValue("policyType"),
				"status": status, "updatedAt": now,
			}})
		}
	}
	mux.HandleFunc("POST /v1/approval-policies/{policyType}/requests/{requestId}/approve", apReqAction("approved"))
	mux.HandleFunc("POST /v1/approval-policies/{policyType}/requests/{requestId}/reject", apReqAction("rejected"))
	mux.HandleFunc("POST /v1/approval-policies/{policyType}/requests/{requestId}/cancel", apReqAction("cancelled"))

	// ════════════════════════════════════════════════════════════════════
	// secret(change)-approval policies  (/v1/secret-approvals, /v2/…/{id})
	// ════════════════════════════════════════════════════════════════════

	// GET …/board — policy governing a specific (env, secretPath). Literal
	// "board" outranks nothing here (no {id} sibling at this depth on GET),
	// kept distinct from the list root.
	mux.HandleFunc("GET /v1/secret-approvals/board", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		// No board policy ⇒ "" (the UI tolerates policy || "").
		writeJSON(w, http.StatusOK, map[string]any{"policy": ""})
	})

	mux.HandleFunc("GET /v1/secret-approvals", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		out := []any{}
		for _, p := range listSAPPolicies(st, r.URL.Query().Get("projectId")) {
			out = append(out, sapPolicyJSON(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
	})

	mux.HandleFunc("POST /v1/secret-approvals", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			ProjectID            string   `json:"projectId"`
			Name                 string   `json:"name"`
			Environments         []string `json:"environments"`
			SecretPath           string   `json:"secretPath"`
			Approvals            int      `json:"approvals"`
			Approvers            []any    `json:"approvers"`
			Bypassers            []any    `json:"bypassers"`
			EnforcementLevel     string   `json:"enforcementLevel"`
			AllowedSelfApprovals bool     `json:"allowedSelfApprovals"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		p := &sapPolicy{
			ID: newID(), ProjectID: req.ProjectID, Name: req.Name, Environments: req.Environments,
			SecretPath: req.SecretPath, Approvals: req.Approvals, Approvers: req.Approvers,
			Bypassers: req.Bypassers, EnforcementLevel: req.EnforcementLevel,
			AllowedSelfApprovals: req.AllowedSelfApprovals, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(sapPolicyKey(p.ID), p)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sapPolicyIdx(p.ProjectID, p.ID), []byte(p.ID)) })
		writeJSON(w, http.StatusOK, map[string]any{"approval": sapPolicyJSON(p)})
	})

	mux.HandleFunc("PATCH /v2/secret-approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p sapPolicy
		if st.getJSON(sapPolicyKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		var req struct {
			Name                 *string  `json:"name"`
			Environments         []string `json:"environments"`
			SecretPath           *string  `json:"secretPath"`
			Approvals            *int     `json:"approvals"`
			Approvers            []any    `json:"approvers"`
			Bypassers            []any    `json:"bypassers"`
			EnforcementLevel     *string  `json:"enforcementLevel"`
			AllowedSelfApprovals *bool    `json:"allowedSelfApprovals"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			p.Name = *req.Name
		}
		if req.Environments != nil {
			p.Environments = req.Environments
		}
		if req.SecretPath != nil {
			p.SecretPath = *req.SecretPath
		}
		if req.Approvals != nil {
			p.Approvals = *req.Approvals
		}
		if req.Approvers != nil {
			p.Approvers = req.Approvers
		}
		if req.Bypassers != nil {
			p.Bypassers = req.Bypassers
		}
		if req.EnforcementLevel != nil {
			p.EnforcementLevel = *req.EnforcementLevel
		}
		if req.AllowedSelfApprovals != nil {
			p.AllowedSelfApprovals = *req.AllowedSelfApprovals
		}
		p.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(sapPolicyKey(p.ID), &p)
		writeJSON(w, http.StatusOK, map[string]any{"approval": sapPolicyJSON(&p)})
	})

	mux.HandleFunc("DELETE /v2/secret-approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p sapPolicy
		if st.getJSON(sapPolicyKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("policy not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(sapPolicyKey(p.ID))
			return txn.Delete(sapPolicyIdx(p.ProjectID, p.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"approval": sapPolicyJSON(&p)})
	})

	// ════════════════════════════════════════════════════════════════════
	// secret-approval requests  (/v1/secret-approval-requests/…)
	// The change-set merge surface — shaped wrappers, empty/zero lists; the
	// secret-diff merge + reviewer-quorum logic is the stubbed part.
	// ════════════════════════════════════════════════════════════════════

	mux.HandleFunc("GET /v1/secret-approval-requests/count", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"approvals": map[string]any{"open": 0, "closed": 0}})
	})
	mux.HandleFunc("GET /v1/secret-approval-requests", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"approvals": []any{}, "totalCount": 0})
	})
	mux.HandleFunc("GET /v1/secret-approval-requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusNotFound, msg("approval request not found"))
	})
	mux.HandleFunc("POST /v1/secret-approval-requests/{id}/review", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Status  string `json:"status"`
			Comment string `json:"comment"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"review": map[string]any{
			"id": r.PathValue("id"), "status": req.Status, "comment": req.Comment,
		}})
	})
	mux.HandleFunc("POST /v1/secret-approval-requests/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"approval": map[string]any{"id": r.PathValue("id"), "status": req.Status}})
	})
	mux.HandleFunc("POST /v1/secret-approval-requests/{id}/merge", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			BypassReason string `json:"bypassReason"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"approval": map[string]any{
			"id": r.PathValue("id"), "hasMerged": true, "status": "close",
		}})
	})
}

// ── list iterators (mirror ProjectsForOrg's prefix-scan pattern) ─────────

func listAAPolicies(st *webStore, projectSlug string) []*aaPolicy {
	out := []*aaPolicy{}
	if projectSlug == "" {
		return out
	}
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = aaPolicyPrefix(projectSlug)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := aaPolicyPrefix(projectSlug)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		var p aaPolicy
		if st.getJSON(aaPolicyKey(id), &p) == nil {
			out = append(out, &p)
		}
	}
	return out
}

func listAPPolicies(st *webStore, policyType string) []*apPolicy {
	out := []*apPolicy{}
	if policyType == "" {
		return out
	}
	pfx := apPolicyPrefix(policyType)
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var p apPolicy
				if json.Unmarshal(v, &p) == nil {
					out = append(out, &p)
				}
				return nil
			})
		}
		return nil
	})
	return out
}

func listSAPPolicies(st *webStore, projectID string) []*sapPolicy {
	out := []*sapPolicy{}
	if projectID == "" {
		return out
	}
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = sapPolicyPrefix(projectID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := sapPolicyPrefix(projectID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		var p sapPolicy
		if st.getJSON(sapPolicyKey(id), &p) == nil {
			out = append(out, &p)
		}
	}
	return out
}
