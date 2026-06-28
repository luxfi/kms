// PKI / cert-manager — Certificate Authorities, certificates, templates,
// profiles, policies, alerts (v1 + v2), collections, subscribers, and syncs.
//
// The SPA's cert-manager pages call a mix of /v1/cert-manager/* (current) and
// /v1/pki/* (deprecated-but-still-wired) endpoints, plus a handful of
// project-scoped list endpoints under /v1/projects/{id}/* that back dashboard
// tabs. This file serves all of them, ZapDB-backed, matching the JSON shapes in
// frontend/src/hooks/api/{ca,certificates,certificateTemplates,
// certificateProfiles,certificatePolicies,pkiAlerts,pkiAlertsV2,pkiCollections,
// pkiSubscriber,pkiSyncs}.
//
// CONFIG entities (CAs, templates, profiles, policies, alerts, collections,
// subscribers, syncs) are persisted as JSON-KV under "kms/pki/<kind>/{id}" with
// a per-project secondary index "kms/pki/<kind>/by-proj/{projectId}/{id}". The
// deep cryptographic operations — certificate issuance/signing, CA cert/CSR/CRL
// generation, intermediate signing, renewal, PKCS#12 export, dynamic syncs — are
// STUBBED: they persist/echo the request and return plausible-shaped responses
// or empty lists (never 404 for list tabs), because real X.509 issuance belongs
// to the MPC/crypto layer, not this HTTP shim. Stubs are flagged below with
// "crypto stub".
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── storage keys ─────────────────────────────────────────────────────────────

func pkiKey(kind, id string) []byte { return []byte("kms/pki/" + kind + "/" + id) }
func pkiProjIdx(kind, projectID, id string) []byte {
	return []byte("kms/pki/" + kind + "/by-proj/" + projectID + "/" + id)
}
func pkiProjPrefix(kind, projectID string) []byte {
	return []byte("kms/pki/" + kind + "/by-proj/" + projectID + "/")
}

// pkiEntity is the generic persisted record: it carries the project index plus
// the free-form fields the SPA round-trips for a given kind.
type pkiEntity struct {
	ID        string         `json:"id"`
	ProjectID string         `json:"projectId"`
	Fields    map[string]any `json:"fields"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// ── webStore helpers (area-prefixed; no collision with package helpers) ───────

func (s *webStore) pkiPut(kind string, e *pkiEntity) error {
	if err := s.putJSON(pkiKey(kind, e.ID), e); err != nil {
		return err
	}
	if e.ProjectID == "" {
		return nil
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(pkiProjIdx(kind, e.ProjectID, e.ID), []byte(e.ID))
	})
}

func (s *webStore) pkiGet(kind, id string) (*pkiEntity, error) {
	var e pkiEntity
	if err := s.getJSON(pkiKey(kind, id), &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *webStore) pkiDelete(kind, id string) (*pkiEntity, error) {
	e, err := s.pkiGet(kind, id)
	if err != nil {
		return nil, err
	}
	_ = s.db.Update(func(txn *badger.Txn) error {
		_ = txn.Delete(pkiKey(kind, id))
		if e.ProjectID != "" {
			_ = txn.Delete(pkiProjIdx(kind, e.ProjectID, id))
		}
		return nil
	})
	return e, nil
}

func (s *webStore) pkiList(kind, projectID string) []*pkiEntity {
	out := []*pkiEntity{}
	if projectID == "" {
		return out
	}
	var ids []string
	pfx := pkiProjPrefix(kind, projectID)
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		if e, err := s.pkiGet(kind, id); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// pkiView renders the persisted entity as the flat JSON object the SPA expects:
// {id, projectId, createdAt, updatedAt, ...fields}.
func pkiView(e *pkiEntity) map[string]any {
	m := map[string]any{}
	for k, v := range e.Fields {
		m[k] = v
	}
	m["id"] = e.ID
	m["projectId"] = e.ProjectID
	m["createdAt"] = e.CreatedAt
	m["updatedAt"] = e.UpdatedAt
	return m
}

func pkiViews(es []*pkiEntity) []any {
	out := make([]any, 0, len(es))
	for _, e := range es {
		out = append(out, pkiView(e))
	}
	return out
}

// pkiDecode reads an arbitrary JSON body into a map so we can persist whatever
// the SPA sent without enumerating every field of every kind.
func pkiDecode(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	body := map[string]any{}
	if r.Body == nil {
		return body, true
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// Empty body is acceptable for trigger-style POSTs.
		if err.Error() == "EOF" {
			return map[string]any{}, true
		}
		writeJSON(w, http.StatusBadRequest, msg("invalid request body"))
		return nil, false
	}
	return body, true
}

func pkiStr(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// registerPkiAPI wires every cert-manager / PKI route onto mux.
func registerPkiAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// ok gates a request; returns the claims (nil response already written on 401).
	ok := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── Certificate Authorities (kind "ca") ──────────────────────────────────
	// List across all types for a project: {certificateAuthorities: [...]}.
	mux.HandleFunc("GET /v1/cert-manager/ca", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"certificateAuthorities": pkiViews(st.pkiList("ca", r.URL.Query().Get("projectId"))),
		})
	})

	// Create a CA of a given type. We persist the config and stamp status active.
	mux.HandleFunc("POST /v1/cert-manager/ca/{type}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		body["type"] = r.PathValue("type")
		if _, has := body["status"]; !has {
			body["status"] = "active"
		}
		if _, has := body["enableDirectIssuance"]; !has {
			body["enableDirectIssuance"] = true
		}
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		if err := st.pkiPut("ca", e); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})

	// List CAs of a single type for a project: bare array (per useListCasByTypeAndProjectId).
	mux.HandleFunc("GET /v1/cert-manager/ca/{type}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		typ := r.PathValue("type")
		all := st.pkiList("ca", r.URL.Query().Get("projectId"))
		out := make([]any, 0, len(all))
		for _, e := range all {
			if pkiStr(e.Fields, "type") == typ {
				out = append(out, pkiView(e))
			}
		}
		writeJSON(w, http.StatusOK, out)
	})

	// Get / update / delete a single CA by type + id.
	mux.HandleFunc("GET /v1/cert-manager/ca/{type}/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("ca", r.PathValue("caId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate authority not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("PATCH /v1/cert-manager/ca/{type}/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("ca", r.PathValue("caId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate authority not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("ca", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/cert-manager/ca/{type}/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("ca", r.PathValue("caId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate authority not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})

	// Internal-CA cryptographic surface — crypto stubs (issuance/signing live in
	// the MPC/crypto layer). List endpoints return empty arrays; single-object
	// endpoints echo a plausible empty-PEM shape so the UI renders.
	mux.HandleFunc("GET /v1/cert-manager/ca/internal/{caId}/ca-certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{}) // crypto stub: no issued CA certs yet
	})
	mux.HandleFunc("GET /v1/cert-manager/ca/internal/{caId}/certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{"certificate": "", "certificateChain": "", "serialNumber": ""})
	})
	mux.HandleFunc("GET /v1/cert-manager/ca/internal/{caId}/csr", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"csr": ""}) // crypto stub
	})
	mux.HandleFunc("GET /v1/cert-manager/ca/internal/{caId}/crls", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{}) // crypto stub: no CRLs
	})
	mux.HandleFunc("POST /v1/cert-manager/ca/internal/{caId}/sign-intermediate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "certificateChain": "", "issuingCaCertificate": "", "serialNumber": "",
		})
	})
	mux.HandleFunc("POST /v1/cert-manager/ca/internal/{caId}/import-certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		caID := r.PathValue("caId")
		_, _ = pkiDecode(w, r)
		// Mark the CA active now that a cert is "imported" (config-only).
		if e, err := st.pkiGet("ca", caID); err == nil {
			e.Fields["status"] = "active"
			e.UpdatedAt = time.Now().UTC()
			_ = st.pkiPut("ca", e)
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "Successfully imported certificate to CA", "caId": caID})
	})
	mux.HandleFunc("POST /v1/cert-manager/ca/internal/{caId}/renew", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, _ := pkiDecode(w, r)
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "certificateChain": "", "serialNumber": "", "projectId": pkiStr(body, "projectId"),
		})
	})
	mux.HandleFunc("GET /v1/cert-manager/ca/azure-ad-cs/{caId}/templates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"templates": []any{}}) // external CA — empty
	})

	// Deprecated: CA → cert-template listing.
	mux.HandleFunc("GET /v1/pki/ca/{caId}/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplates": []any{}})
	})

	// ── Certificates (kind "certificate") ────────────────────────────────────
	// Single-cert read by serial number (deprecated /v1/pki path). Empty-shape
	// crypto stub when not found rather than 404 so detail pages render.
	mux.HandleFunc("GET /v1/pki/certificates/{serialNumber}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		sn := r.PathValue("serialNumber")
		if e, err := st.pkiGet("certificate", sn); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"certificate": pkiView(e)})
			return
		}
		writeJSON(w, http.StatusNotFound, msg("certificate not found"))
	})
	mux.HandleFunc("GET /v1/pki/certificates/{serialNumber}/certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{"certificate": "", "certificateChain": "", "serialNumber": r.PathValue("serialNumber")})
	})
	mux.HandleFunc("GET /v1/pki/certificates/{serialNumber}/bundle", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "certificateChain": "", "serialNumber": r.PathValue("serialNumber"), "privateKey": nil,
		})
	})

	// Unified issuance — crypto stub: record a certificate-request entity and
	// return the request-shaped response (status pending).
	mux.HandleFunc("POST /v1/cert-manager/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		body["status"] = "pending"
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("certificate-request", e)
		writeJSON(w, http.StatusOK, map[string]any{
			"certificateRequestId": e.ID, "status": "pending", "projectId": e.ProjectID,
		})
	})

	// Issue-certificate (deprecated v1 + cert-manager v3) — crypto stubs.
	issueCert := func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "issuingCertificate": "", "certificateChain": "", "privateKey": "", "serialNumber": "",
		})
	}
	mux.HandleFunc("POST /v1/pki/certificates/issue-certificate", issueCert)
	mux.HandleFunc("POST /v1/cert-manager/certificates/issue-certificate", issueCert)

	mux.HandleFunc("POST /v1/cert-manager/certificates/order-certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		// crypto stub (ACME order)
		writeJSON(w, http.StatusOK, map[string]any{
			"orderId": newID(), "status": "pending", "subjectAlternativeNames": []any{},
			"authorizations": []any{}, "expires": "", "notBefore": "", "notAfter": "",
		})
	})

	// Certificate-requests list + detail.
	mux.HandleFunc("GET /v1/cert-manager/certificates/certificate-requests", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateRequests": []any{}, "totalCount": 0})
	})
	mux.HandleFunc("GET /v1/cert-manager/certificates/certificate-requests/{requestId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		now := time.Now().UTC()
		e, err := st.pkiGet("certificate-request", r.PathValue("requestId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate request not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": pkiStr(e.Fields, "status"), "certificate": nil, "errorMessage": nil,
			"createdAt": e.CreatedAt, "updatedAt": now,
		})
	})

	// Per-certificate mutations (delete/revoke/renew/config/pkcs12) — by id.
	mux.HandleFunc("DELETE /v1/cert-manager/certificates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = st.pkiDelete("certificate", r.PathValue("id"))
		writeJSON(w, http.StatusOK, map[string]any{"certificate": map[string]any{"id": r.PathValue("id")}})
	})
	mux.HandleFunc("POST /v1/cert-manager/certificates/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"certificate": map[string]any{"id": r.PathValue("id"), "status": "revoked"}})
	})
	mux.HandleFunc("POST /v1/cert-manager/certificates/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "issuingCaCertificate": "", "certificateChain": "", "serialNumber": "",
			"certificateId": r.PathValue("id"), "projectId": "",
		})
	})
	mux.HandleFunc("PATCH /v1/cert-manager/certificates/{id}/config", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, _ := pkiDecode(w, r)
		out := map[string]any{"message": "Successfully updated renewal configuration"}
		if v, has := body["renewBeforeDays"]; has {
			out["renewBeforeDays"] = v
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /v1/cert-manager/certificates/{id}/import-certificate", issueCert)
	mux.HandleFunc("POST /v1/cert-manager/certificates/import-certificate", issueCert)
	mux.HandleFunc("POST /v1/cert-manager/certificates/{id}/pkcs12", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		// crypto stub: PKCS#12 export not implemented; return empty octet-stream.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{})
	})

	// ── Certificate Templates (kind "cert-template") ─────────────────────────
	// Deprecated v1 list/CRUD + EST config. List shape: {certificateTemplates, totalCount}.
	mux.HandleFunc("GET /v1/pki/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		es := st.pkiList("cert-template", r.URL.Query().Get("projectId"))
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplates": pkiViews(es), "totalCount": len(es)})
	})
	mux.HandleFunc("POST /v1/pki/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("cert-template", e)
		// v1 returns the bare template; v2 callers read {certificateTemplate}. Provide both.
		v := pkiView(e)
		v["certificateTemplate"] = pkiView(e)
		writeJSON(w, http.StatusOK, v)
	})
	mux.HandleFunc("GET /v1/pki/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-template", r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate template not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("PATCH /v1/pki/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-template", r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate template not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("cert-template", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/pki/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("cert-template", r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate template not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	// EST config (crypto/enrollment stub).
	mux.HandleFunc("GET /v1/pki/certificate-templates/{id}/est-config", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("est-config", r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("est config not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	upsertEst := func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()
		e, err := st.pkiGet("est-config", id)
		if err != nil {
			e = &pkiEntity{ID: id, ProjectID: pkiStr(body, "projectId"), Fields: map[string]any{}, CreatedAt: now}
		}
		body["certificateTemplateId"] = id
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = now
		_ = st.pkiPut("est-config", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	}
	mux.HandleFunc("POST /v1/pki/certificate-templates/{id}/est-config", upsertEst)
	mux.HandleFunc("PATCH /v1/pki/certificate-templates/{id}/est-config", upsertEst)

	// V2 template mutations are keyed by templateName.
	mux.HandleFunc("PATCH /v2/pki/certificate-templates/{templateName}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		// Look up by name within the project; else create.
		name := r.PathValue("templateName")
		proj := pkiStr(body, "projectId")
		var e *pkiEntity
		for _, cand := range st.pkiList("cert-template", proj) {
			if pkiStr(cand.Fields, "name") == name {
				e = cand
				break
			}
		}
		now := time.Now().UTC()
		if e == nil {
			e = &pkiEntity{ID: newID(), ProjectID: proj, Fields: map[string]any{"name": name}, CreatedAt: now}
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = now
		_ = st.pkiPut("cert-template", e)
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplate": pkiView(e)})
	})
	mux.HandleFunc("DELETE /v2/pki/certificate-templates/{templateName}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, _ := pkiDecode(w, r)
		name := r.PathValue("templateName")
		proj := pkiStr(body, "projectId")
		for _, cand := range st.pkiList("cert-template", proj) {
			if pkiStr(cand.Fields, "name") == name {
				e, _ := st.pkiDelete("cert-template", cand.ID)
				writeJSON(w, http.StatusOK, map[string]any{"certificateTemplate": pkiView(e)})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplate": map[string]any{"name": name}})
	})

	// ── Certificate Profiles (kind "cert-profile") ───────────────────────────
	mux.HandleFunc("GET /v1/cert-manager/certificate-profiles", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		es := st.pkiList("cert-profile", r.URL.Query().Get("projectId"))
		writeJSON(w, http.StatusOK, map[string]any{"certificateProfiles": pkiViews(es), "totalCount": len(es)})
	})
	mux.HandleFunc("POST /v1/cert-manager/certificate-profiles", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("cert-profile", e)
		writeJSON(w, http.StatusOK, map[string]any{"certificateProfile": pkiView(e)})
	})
	mux.HandleFunc("GET /v1/cert-manager/certificate-profiles/{profileId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-profile", r.PathValue("profileId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate profile not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateProfile": pkiView(e)})
	})
	mux.HandleFunc("PATCH /v1/cert-manager/certificate-profiles/{profileId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-profile", r.PathValue("profileId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate profile not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("cert-profile", e)
		writeJSON(w, http.StatusOK, map[string]any{"certificateProfile": pkiView(e)})
	})
	mux.HandleFunc("DELETE /v1/cert-manager/certificate-profiles/{profileId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("cert-profile", r.PathValue("profileId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate profile not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateProfile": pkiView(e)})
	})
	// Two-segment GET dispatcher: disambiguates the by-slug lookup
	// (".../slug/{slug}") from the profile-certificates list
	// (".../{profileId}/certificates") — Go's ServeMux cannot tell these two
	// wildcard patterns apart, so they share one handler that branches on the
	// leading segment. (ACME EAB reveal is its own 3-segment route below.)
	mux.HandleFunc("GET /v1/cert-manager/certificate-profiles/{profileId}/{sub}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		seg, sub := r.PathValue("profileId"), r.PathValue("sub")
		if seg == "slug" {
			// by-slug lookup: {sub} is the slug.
			proj := r.URL.Query().Get("projectId")
			for _, e := range st.pkiList("cert-profile", proj) {
				if pkiStr(e.Fields, "slug") == sub {
					writeJSON(w, http.StatusOK, map[string]any{"certificateProfile": pkiView(e)})
					return
				}
			}
			writeJSON(w, http.StatusNotFound, msg("certificate profile not found"))
			return
		}
		if sub == "certificates" {
			writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}}) // crypto/empty stub
			return
		}
		writeJSON(w, http.StatusNotFound, msg("not found"))
	})
	mux.HandleFunc("GET /v1/cert-manager/certificate-profiles/{profileId}/acme/eab-secret/reveal", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"eabKid": "", "eabSecret": ""}) // crypto stub
	})

	// ── Certificate Policies (kind "cert-policy") ────────────────────────────
	mux.HandleFunc("GET /v1/cert-manager/certificate-policies", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		es := st.pkiList("cert-policy", r.URL.Query().Get("projectId"))
		writeJSON(w, http.StatusOK, map[string]any{"certificatePolicies": pkiViews(es), "totalCount": len(es)})
	})
	mux.HandleFunc("POST /v1/cert-manager/certificate-policies", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("cert-policy", e)
		writeJSON(w, http.StatusOK, map[string]any{"certificatePolicy": pkiView(e)})
	})
	mux.HandleFunc("GET /v1/cert-manager/certificate-policies/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-policy", r.PathValue("policyId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate policy not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificatePolicy": pkiView(e)})
	})
	mux.HandleFunc("PATCH /v1/cert-manager/certificate-policies/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("cert-policy", r.PathValue("policyId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate policy not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("cert-policy", e)
		writeJSON(w, http.StatusOK, map[string]any{"certificatePolicy": pkiView(e)})
	})
	mux.HandleFunc("DELETE /v1/cert-manager/certificate-policies/{policyId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("cert-policy", r.PathValue("policyId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("certificate policy not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificatePolicy": pkiView(e)})
	})

	// ── PKI Alerts v1 (kind "pki-alert", deprecated) ─────────────────────────
	mux.HandleFunc("POST /v1/pki/alerts", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-alert", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("GET /v1/pki/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-alert", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("PATCH /v1/pki/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-alert", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("pki-alert", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/pki/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("pki-alert", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})

	// ── PKI Alerts v2 (kind "pki-alert-v2") ──────────────────────────────────
	mux.HandleFunc("GET /v1/cert-manager/alerts", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		es := st.pkiList("pki-alert-v2", r.URL.Query().Get("projectId"))
		writeJSON(w, http.StatusOK, map[string]any{"alerts": pkiViews(es), "total": len(es)})
	})
	mux.HandleFunc("POST /v1/cert-manager/alerts", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		if _, has := body["enabled"]; !has {
			body["enabled"] = true
		}
		if _, has := body["channels"]; !has {
			body["channels"] = []any{}
		}
		if _, has := body["filters"]; !has {
			body["filters"] = []any{}
		}
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-alert-v2", e)
		writeJSON(w, http.StatusOK, map[string]any{"alert": pkiView(e)})
	})
	mux.HandleFunc("POST /v1/cert-manager/alerts/preview/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "total": 0, "limit": 0, "offset": 0})
	})
	mux.HandleFunc("GET /v1/cert-manager/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-alert-v2", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"alert": pkiView(e)})
	})
	mux.HandleFunc("PATCH /v1/cert-manager/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-alert-v2", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("pki-alert-v2", e)
		writeJSON(w, http.StatusOK, map[string]any{"alert": pkiView(e)})
	})
	mux.HandleFunc("DELETE /v1/cert-manager/alerts/{alertId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("pki-alert-v2", r.PathValue("alertId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("alert not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"alert": pkiView(e)})
	})
	mux.HandleFunc("GET /v1/cert-manager/alerts/{alertId}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "total": 0, "limit": 0, "offset": 0})
	})

	// ── PKI Collections (kind "pki-collection") ──────────────────────────────
	mux.HandleFunc("POST /v1/pki/collections", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-collection", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("GET /v1/pki/collections/{collectionId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-collection", r.PathValue("collectionId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("collection not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("PATCH /v1/pki/collections/{collectionId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-collection", r.PathValue("collectionId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("collection not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("pki-collection", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/pki/collections/{collectionId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("pki-collection", r.PathValue("collectionId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("collection not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	// Collection items: persisted as a sub-collection keyed by item id.
	mux.HandleFunc("GET /v1/pki/collections/{collectionId}/items", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		es := st.pkiList("pki-collection-item", r.PathValue("collectionId"))
		writeJSON(w, http.StatusOK, map[string]any{"collectionItems": pkiViews(es), "totalCount": len(es)})
	})
	mux.HandleFunc("POST /v1/pki/collections/{collectionId}/items", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		cid := r.PathValue("collectionId")
		body["collectionId"] = cid
		// Index items under the collection id so list() can find them.
		e := &pkiEntity{ID: newID(), ProjectID: cid, Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-collection-item", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/pki/collections/{collectionId}/items/{itemId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("pki-collection-item", r.PathValue("itemId"))
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("itemId"), "collectionId": r.PathValue("collectionId")})
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})

	// ── PKI Subscribers (kind "pki-subscriber") ──────────────────────────────
	// Subscribers are addressed by NAME (scoped to project), not id.
	findSubscriber := func(name, proj string) *pkiEntity {
		for _, e := range st.pkiList("pki-subscriber", proj) {
			if pkiStr(e.Fields, "name") == name {
				return e
			}
		}
		return nil
	}
	mux.HandleFunc("POST /v1/pki/subscribers", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		if _, has := body["status"]; !has {
			body["status"] = "active"
		}
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-subscriber", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("GET /v1/pki/subscribers/{subscriberName}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e := findSubscriber(r.PathValue("subscriberName"), r.URL.Query().Get("projectId"))
		if e == nil {
			writeJSON(w, http.StatusNotFound, msg("subscriber not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("PATCH /v1/pki/subscribers/{subscriberName}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		e := findSubscriber(r.PathValue("subscriberName"), pkiStr(body, "projectId"))
		if e == nil {
			writeJSON(w, http.StatusNotFound, msg("subscriber not found"))
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("pki-subscriber", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/pki/subscribers/{subscriberName}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, _ := pkiDecode(w, r)
		e := findSubscriber(r.PathValue("subscriberName"), pkiStr(body, "projectId"))
		if e == nil {
			writeJSON(w, http.StatusNotFound, msg("subscriber not found"))
			return
		}
		out, _ := st.pkiDelete("pki-subscriber", e.ID)
		writeJSON(w, http.StatusOK, pkiView(out))
	})
	mux.HandleFunc("GET /v1/pki/subscribers/{subscriberName}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "totalCount": 0})
	})
	mux.HandleFunc("POST /v1/pki/subscribers/{subscriberName}/issue-certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		// crypto stub
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": "", "issuingCertificate": "", "certificateChain": "", "privateKey": "", "serialNumber": "",
		})
	})
	mux.HandleFunc("POST /v1/pki/subscribers/{subscriberName}/order-certificate", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		writeJSON(w, http.StatusOK, msg("Successfully ordered certificate")) // crypto stub
	})

	// ── PKI Syncs (kind "pki-sync") ──────────────────────────────────────────
	// Syncs are addressed by {destination} + id; we persist by id and ignore the
	// destination segment for lookup (it's part of the config).
	mux.HandleFunc("GET /v1/cert-manager/syncs/options", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pkiSyncOptions": []any{}}) // no destinations wired
	})
	mux.HandleFunc("GET /v1/cert-manager/syncs", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pkiSyncs": pkiViews(st.pkiList("pki-sync", r.URL.Query().Get("projectId")))})
	})
	mux.HandleFunc("GET /v1/cert-manager/syncs/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-sync", r.PathValue("syncId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("sync not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("GET /v1/cert-manager/syncs/{syncId}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "totalCount": 0})
	})
	// Create: POST /v1/cert-manager/syncs/{destination}
	mux.HandleFunc("POST /v1/cert-manager/syncs/{destination}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		now := time.Now().UTC()
		body["destination"] = r.PathValue("destination")
		e := &pkiEntity{ID: newID(), ProjectID: pkiStr(body, "projectId"), Fields: body, CreatedAt: now, UpdatedAt: now}
		_ = st.pkiPut("pki-sync", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	// Add/remove certs to a sync by sync id (POST/DELETE .../syncs/{syncId}/certificates
	// collide in segment-count with the {destination}/{syncId} update routes; Go's
	// mux disambiguates by the trailing literal "certificates").
	mux.HandleFunc("POST /v1/cert-manager/syncs/{syncId}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		writeJSON(w, http.StatusOK, msg("Successfully added certificates to sync"))
	})
	mux.HandleFunc("DELETE /v1/cert-manager/syncs/{syncId}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		_, _ = pkiDecode(w, r)
		writeJSON(w, http.StatusOK, msg("Successfully removed certificates from sync"))
	})
	// Update/delete by destination + id.
	mux.HandleFunc("PATCH /v1/cert-manager/syncs/{destination}/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiGet("pki-sync", r.PathValue("syncId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("sync not found"))
			return
		}
		body, good := pkiDecode(w, r)
		if !good {
			return
		}
		for k, v := range body {
			e.Fields[k] = v
		}
		e.UpdatedAt = time.Now().UTC()
		_ = st.pkiPut("pki-sync", e)
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	mux.HandleFunc("DELETE /v1/cert-manager/syncs/{destination}/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		e, err := st.pkiDelete("pki-sync", r.PathValue("syncId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("sync not found"))
			return
		}
		writeJSON(w, http.StatusOK, pkiView(e))
	})
	// Trigger sync/import/remove — crypto/integration stubs (no destination wired).
	syncTrigger := func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("Sync job queued"))
	}
	mux.HandleFunc("POST /v1/cert-manager/syncs/{destination}/{syncId}/sync", syncTrigger)
	mux.HandleFunc("POST /v1/cert-manager/syncs/{destination}/{syncId}/import", syncTrigger)
	mux.HandleFunc("POST /v1/cert-manager/syncs/{destination}/{syncId}/remove-certificates", syncTrigger)

	// ── Project-scoped PKI list tabs (under /v1/projects/{id}/...) ────────────
	// These back the cert-manager dashboard's project tabs. They live under the
	// projects path prefix but are PKI-domain; api_projects.go does not register
	// them. Empty arrays keep the tabs from erroring.
	mux.HandleFunc("GET /v1/projects/{id}/cas", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"cas": pkiViews(st.pkiList("ca", r.PathValue("id")))})
	})
	mux.HandleFunc("GET /v1/projects/{id}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "totalCount": 0})
	})
	mux.HandleFunc("GET /v1/projects/{id}/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplates": pkiViews(st.pkiList("cert-template", r.PathValue("id")))})
	})
	mux.HandleFunc("GET /v1/projects/{id}/pki-alerts", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"alerts": pkiViews(st.pkiList("pki-alert", r.PathValue("id")))})
	})
	mux.HandleFunc("GET /v1/projects/{id}/pki-collections", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"collections": pkiViews(st.pkiList("pki-collection", r.PathValue("id")))})
	})
	mux.HandleFunc("GET /v1/projects/{id}/pki-subscribers", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"subscribers": pkiViews(st.pkiList("pki-subscriber", r.PathValue("id")))})
	})
}
