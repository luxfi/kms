// Identities — machine identities + their auth methods, org/project bindings,
// auth templates, and project additional privileges.
//
// Core identity (entity persisted as JSON-KV):
//
//	POST   /v1/identities/                         {identity}   (create; note trailing slash)
//	GET    /v1/identities/{id}                      {identity}
//	PATCH  /v1/identities/{id}                      {identity}
//	DELETE /v1/identities/{id}                      {identity}
//	POST   /v1/identities/search                    {identities, totalCount}
//	GET    /v1/identities/{id}/identity-memberships {identityMemberships: []}
//
// Org binding:
//
//	GET    /v1/org-identities                       {identities, totalCount}
//	GET    /v1/org-identities/{id}                  {identity}
//	GET    /v1/org-available-identities             {identities: []}
//	POST   /v1/org-identity-memberships/{id}        {identityMembership}
//	DELETE /v1/org-identity-memberships/{id}        {identityMembership}
//
// Project binding (project-scoped identities + memberships):
//
//	GET/POST           /v1/projects/{projectId}/identities
//	GET/PATCH/DELETE    /v1/projects/{projectId}/identities/{identityId}
//	GET                 /v1/projects/{projectId}/memberships/available-identities
//	GET/POST            /v1/projects/{projectId}/memberships/identities[/{identityId}]
//	PATCH/DELETE        /v1/projects/{projectId}/memberships/identities/{identityId}
//	GET                 /v1/projects/{projectId}/identity-memberships/{identityId}
//
// Auth methods — one config entity per (identity, method) for all 12 methods:
//
//	GET/POST/PATCH/DELETE /v1/auth/{universal,token,aws,azure,gcp,kubernetes,
//	                       oidc,jwt,ldap,oci,tls-cert,alicloud}-auth/identities/{id}
//	+ universal-auth client-secrets & clear-lockouts; token-auth tokens; ldap clear-lockouts.
//
// Auth templates (LDAP credential templates):
//
//	GET/POST            /v1/identity-templates
//	GET                 /v1/identity-templates/search
//	GET/PATCH/DELETE    /v1/identity-templates/{templateId}
//	GET                 /v1/identity-templates/{templateId}/usage
//	POST                /v1/identity-templates/{templateId}/delete-usage
//
// Project additional privileges:
//
//	GET/POST            /v1/identity-project-additional-privilege
//	GET/PATCH/DELETE    /v2/identity-project-additional-privilege/{privilegeId}
//
// Auth-method configs persist their full request body (so GET round-trips what
// the SPA form posted) under kms/identities/auth/{method}/{identityId}; this is a
// metadata/config store — KMS does not itself perform the cloud-IAM/JWT/LDAP
// credential verification those methods describe at runtime (that lives in the
// MPC/auth path). client-secrets and tokens return plausible-shaped values
// without minting real long-lived credentials.
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── storage keys ───────────────────────────────────────────────────────────

func identityKey(id string) []byte { return []byte("kms/identities/" + id) }
func identityOrgIdx(orgID, id string) []byte {
	return []byte("kms/identities/by-org/" + orgID + "/" + id)
}
func identityOrgPrefix(orgID string) []byte { return []byte("kms/identities/by-org/" + orgID + "/") }

func identityAuthKey(method, identityID string) []byte {
	return []byte("kms/identities/auth/" + method + "/" + identityID)
}

func identityProjBindKey(projectID, identityID string) []byte {
	return []byte("kms/identities/proj/" + projectID + "/" + identityID)
}
func identityProjBindPrefix(projectID string) []byte {
	return []byte("kms/identities/proj/" + projectID + "/")
}

func identityTemplateKey(id string) []byte { return []byte("kms/identities/templates/" + id) }
func identityTemplateOrgIdx(orgID, id string) []byte {
	return []byte("kms/identities/templates/by-org/" + orgID + "/" + id)
}
func identityTemplateOrgPrefix(orgID string) []byte {
	return []byte("kms/identities/templates/by-org/" + orgID + "/")
}

func identityPrivKey(id string) []byte { return []byte("kms/identities/priv/" + id) }
func identityPrivIdx(projectID, identityID, id string) []byte {
	return []byte("kms/identities/priv-idx/" + projectID + "/" + identityID + "/" + id)
}
func identityPrivPrefix(projectID, identityID string) []byte {
	return []byte("kms/identities/priv-idx/" + projectID + "/" + identityID + "/")
}

// ── entities ───────────────────────────────────────────────────────────────

type identityMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	ID    string `json:"id"`
}

type identity struct {
	ID                  string         `json:"id"`
	Name                string         `json:"name"`
	OrgID               string         `json:"orgId"`
	ProjectID           string         `json:"projectId,omitempty"`
	HasDeleteProtection bool           `json:"hasDeleteProtection"`
	AuthMethods         []string       `json:"authMethods"`
	Metadata            []identityMeta `json:"metadata"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
}

type identityTemplate struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	OrgID          string         `json:"organizationId"`
	AuthMethod     string         `json:"authMethod"`
	TemplateFields map[string]any `json:"templateFields"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
}

type identityPrivilege struct {
	ID          string         `json:"id"`
	Slug        string         `json:"slug"`
	ProjectID   string         `json:"projectId"`
	IdentityID  string         `json:"identityId"`
	Type        string         `json:"type,omitempty"`
	Permissions []any          `json:"permissions"`
	IsTemporary bool           `json:"isTemporary"`
	Extra       map[string]any `json:"-"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

// identityJSON renders the SPA Identity shape (fields the UI reads).
func identityJSON(it *identity) map[string]any {
	meta := make([]map[string]any, 0, len(it.Metadata))
	for _, m := range it.Metadata {
		meta = append(meta, map[string]any{"key": m.Key, "value": m.Value, "id": m.ID})
	}
	am := it.AuthMethods
	if am == nil {
		am = []string{}
	}
	out := map[string]any{
		"id": it.ID, "name": it.Name, "orgId": it.OrgID,
		"hasDeleteProtection": it.HasDeleteProtection,
		"authMethods":         am, "activeLockoutAuthMethods": []string{},
		"metadata": meta, "createdAt": it.CreatedAt, "updatedAt": it.UpdatedAt,
	}
	if it.ProjectID != "" {
		out["projectId"] = it.ProjectID
	}
	return out
}

// identityMembershipOrgJSON wraps an identity as an org-membership record (the
// shape /v1/identities/{id} and the org listings deserialize).
func identityMembershipOrgJSON(it *identity) map[string]any {
	meta := make([]map[string]any, 0, len(it.Metadata))
	for _, m := range it.Metadata {
		meta = append(meta, map[string]any{"key": m.Key, "value": m.Value, "id": m.ID})
	}
	return map[string]any{
		"id": it.ID, "identity": identityJSON(it), "organization": it.OrgID,
		"role": "admin", "metadata": meta,
		"createdAt": it.CreatedAt, "updatedAt": it.UpdatedAt,
	}
}

func identityTemplateJSON(t *identityTemplate) map[string]any {
	tf := t.TemplateFields
	if tf == nil {
		tf = map[string]any{}
	}
	return map[string]any{
		"id": t.ID, "name": t.Name, "organizationId": t.OrgID,
		"authMethod": t.AuthMethod, "templateFields": tf,
		"createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt,
	}
}

func identityPrivilegeJSON(p *identityPrivilege) map[string]any {
	perms := p.Permissions
	if perms == nil {
		perms = []any{}
	}
	out := map[string]any{
		"id": p.ID, "slug": p.Slug, "projectId": p.ProjectID, "identityId": p.IdentityID,
		"permissions": perms, "isTemporary": p.IsTemporary,
		"temporaryMode": nil, "temporaryRange": nil,
		"temporaryAccessStartTime": nil, "temporaryAccessEndTime": nil,
		"createdAt": p.CreatedAt, "updatedAt": p.UpdatedAt,
	}
	for k, v := range p.Extra {
		out[k] = v
	}
	return out
}

// identityAuthMethods is the canonical list of supported auth-method slugs; the
// SPA hits /v1/auth/{slug}-auth/identities/{id} for each.
var identityAuthMethods = []string{
	"universal", "token", "aws", "azure", "gcp", "kubernetes",
	"oidc", "jwt", "ldap", "oci", "tls-cert", "alicloud",
}

// identityAuthResponseKey maps a method slug to the JSON envelope key the SPA
// reads, e.g. "tls-cert" → "identityTlsCertAuth".
func identityAuthResponseKey(method string) string {
	camel := map[string]string{
		"universal":  "identityUniversalAuth",
		"token":      "identityTokenAuth",
		"aws":        "identityAwsAuth",
		"azure":      "identityAzureAuth",
		"gcp":        "identityGcpAuth",
		"kubernetes": "identityKubernetesAuth",
		"oidc":       "identityOidcAuth",
		"jwt":        "identityJwtAuth",
		"ldap":       "identityLdapAuth",
		"oci":        "identityOciAuth",
		"tls-cert":   "identityTlsCertAuth",
		"alicloud":   "identityAliCloudAuth",
	}
	return camel[method]
}

func registerIdentitiesAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed returns the caller's claims or writes 401 and returns nil.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── core identity CRUD ──────────────────────────────────────────────────

	// POST /v1/identities/ — create (note: SPA posts to the trailing-slash form).
	mux.HandleFunc("POST /v1/identities/", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name                string         `json:"name"`
			OrganizationID      string         `json:"organizationId"`
			Role                string         `json:"role"`
			HasDeleteProtection bool           `json:"hasDeleteProtection"`
			Metadata            []identityMeta `json:"metadata"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("identity name required"))
			return
		}
		orgID := req.OrganizationID
		if orgID == "" {
			orgID = cl.OrgID
		}
		now := time.Now().UTC()
		it := &identity{
			ID: newID(), Name: req.Name, OrgID: orgID,
			HasDeleteProtection: req.HasDeleteProtection,
			AuthMethods:         []string{}, Metadata: withIdentityMetaIDs(req.Metadata),
			CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(identityKey(it.ID), it)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(identityOrgIdx(orgID, it.ID), []byte(it.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(it)})
	})

	// GET /v1/identities/{id} — returns the org-membership shape.
	mux.HandleFunc("GET /v1/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var it identity
		if st.getJSON(identityKey(r.PathValue("id")), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityMembershipOrgJSON(&it)})
	})

	// PATCH /v1/identities/{id}
	mux.HandleFunc("PATCH /v1/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var it identity
		if st.getJSON(identityKey(r.PathValue("id")), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		var req struct {
			Name                *string        `json:"name"`
			HasDeleteProtection *bool          `json:"hasDeleteProtection"`
			Metadata            []identityMeta `json:"metadata"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			it.Name = *req.Name
		}
		if req.HasDeleteProtection != nil {
			it.HasDeleteProtection = *req.HasDeleteProtection
		}
		if req.Metadata != nil {
			it.Metadata = withIdentityMetaIDs(req.Metadata)
		}
		it.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(identityKey(it.ID), &it)
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	// DELETE /v1/identities/{id}
	mux.HandleFunc("DELETE /v1/identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("id")
		var it identity
		if st.getJSON(identityKey(id), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(identityKey(id))
			return txn.Delete(identityOrgIdx(it.OrgID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	// POST /v1/identities/search — org-scoped, paginated.
	mux.HandleFunc("POST /v1/identities/search", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}
		_ = decode(w, r, &req)
		all := identitiesForOrg(st, cl.OrgID)
		total := len(all)
		page := paginateIdentities(all, req.Offset, req.Limit)
		out := make([]any, 0, len(page))
		for _, it := range page {
			out = append(out, identityMembershipOrgJSON(it))
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": out, "totalCount": total})
	})

	// GET /v1/identities/{id}/identity-memberships — this identity's project bindings.
	mux.HandleFunc("GET /v1/identities/{id}/identity-memberships", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identityMemberships": []any{}})
	})

	// ── org identity surface (new-API listings) ─────────────────────────────

	mux.HandleFunc("GET /v1/org-identities", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		all := identitiesForOrg(st, cl.OrgID)
		out := make([]any, 0, len(all))
		for _, it := range all {
			out = append(out, identityJSON(it))
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": out, "totalCount": len(all)})
	})

	// GET /v1/org-identities/{id} — single org identity, flat {identity} shape
	// (the SPA orgIdentity getById hook reads data.identity as a flat Identity).
	// Lives under /v1/org-identities/ (not /v1/organization/identities/{id}),
	// because that org-namespaced wildcard would collide with projects'
	// "GET /v1/organization/{orgId}/my-workspaces" in Go 1.22's ServeMux.
	mux.HandleFunc("GET /v1/org-identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var it identity
		if st.getJSON(identityKey(r.PathValue("id")), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	// GET /v1/org-available-identities — identities not yet attached to
	// the membership target. Returns the slim {id,name} shape.
	mux.HandleFunc("GET /v1/org-available-identities", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		all := identitiesForOrg(st, cl.OrgID)
		out := make([]any, 0, len(all))
		for _, it := range all {
			out = append(out, map[string]any{"id": it.ID, "name": it.Name})
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": out})
	})

	// POST/DELETE /v1/org-identity-memberships/{id}
	mux.HandleFunc("POST /v1/org-identity-memberships/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"identityMembership": map[string]any{
			"id": newID(), "orgId": cl.OrgID, "identityId": id,
			"createdAt": now, "updatedAt": now,
		}})
	})
	mux.HandleFunc("DELETE /v1/org-identity-memberships/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"identityMembership": map[string]any{
			"id": newID(), "orgId": cl.OrgID, "identityId": id,
			"createdAt": now, "updatedAt": now,
		}})
	})

	// ── project identity surface ────────────────────────────────────────────

	// GET /v1/projects/{projectId}/identities — identities bound to the project.
	mux.HandleFunc("GET /v1/projects/{projectId}/identities", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		all := identitiesForProject(st, r.PathValue("projectId"))
		out := make([]any, 0, len(all))
		for _, it := range all {
			out = append(out, identityJSON(it))
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": out, "totalCount": len(all)})
	})

	// POST /v1/projects/{projectId}/identities — create a project-scoped identity.
	mux.HandleFunc("POST /v1/projects/{projectId}/identities", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		projectID := r.PathValue("projectId")
		var req struct {
			Name                string         `json:"name"`
			HasDeleteProtection bool           `json:"hasDeleteProtection"`
			Metadata            []identityMeta `json:"metadata"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("identity name required"))
			return
		}
		now := time.Now().UTC()
		it := &identity{
			ID: newID(), Name: req.Name, OrgID: cl.OrgID, ProjectID: projectID,
			HasDeleteProtection: req.HasDeleteProtection,
			AuthMethods:         []string{}, Metadata: withIdentityMetaIDs(req.Metadata),
			CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(identityKey(it.ID), it)
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Set(identityProjBindKey(projectID, it.ID), []byte(it.ID))
			return txn.Set(identityOrgIdx(cl.OrgID, it.ID), []byte(it.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(it)})
	})

	mux.HandleFunc("GET /v1/projects/{projectId}/identities/{identityId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var it identity
		if st.getJSON(identityKey(r.PathValue("identityId")), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	mux.HandleFunc("PATCH /v1/projects/{projectId}/identities/{identityId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var it identity
		if st.getJSON(identityKey(r.PathValue("identityId")), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		var req struct {
			Name                *string        `json:"name"`
			HasDeleteProtection *bool          `json:"hasDeleteProtection"`
			Metadata            []identityMeta `json:"metadata"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			it.Name = *req.Name
		}
		if req.HasDeleteProtection != nil {
			it.HasDeleteProtection = *req.HasDeleteProtection
		}
		if req.Metadata != nil {
			it.Metadata = withIdentityMetaIDs(req.Metadata)
		}
		it.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(identityKey(it.ID), &it)
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	mux.HandleFunc("DELETE /v1/projects/{projectId}/identities/{identityId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		projectID, identityID := r.PathValue("projectId"), r.PathValue("identityId")
		var it identity
		if st.getJSON(identityKey(identityID), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Delete(identityProjBindKey(projectID, identityID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"identity": identityJSON(&it)})
	})

	// GET /v1/projects/{projectId}/memberships/available-identities
	mux.HandleFunc("GET /v1/projects/{projectId}/memberships/available-identities", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		all := identitiesForOrg(st, cl.OrgID)
		out := make([]any, 0, len(all))
		for _, it := range all {
			out = append(out, map[string]any{"id": it.ID, "name": it.Name})
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": out})
	})

	// GET /v1/projects/{projectId}/memberships/identities — V2 membership list.
	mux.HandleFunc("GET /v1/projects/{projectId}/memberships/identities", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identityMemberships": []any{}, "totalCount": 0})
	})

	projMembershipUpsert := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		projectID, identityID := r.PathValue("projectId"), r.PathValue("identityId")
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(identityProjBindKey(projectID, identityID), []byte(identityID))
		})
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"identityMembership": map[string]any{
			"id": newID(), "projectId": projectID, "identityId": identityID,
			"roles": []any{}, "createdAt": now, "updatedAt": now,
		}})
	}
	mux.HandleFunc("POST /v1/projects/{projectId}/memberships/identities/{identityId}", projMembershipUpsert)
	mux.HandleFunc("PATCH /v1/projects/{projectId}/memberships/identities/{identityId}", projMembershipUpsert)
	mux.HandleFunc("DELETE /v1/projects/{projectId}/memberships/identities/{identityId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		projectID, identityID := r.PathValue("projectId"), r.PathValue("identityId")
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Delete(identityProjBindKey(projectID, identityID))
		})
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"identityMembership": map[string]any{
			"id": newID(), "projectId": projectID, "identityId": identityID,
			"createdAt": now, "updatedAt": now,
		}})
	})

	// GET single membership (V1 + V2 paths share the entity shape).
	membershipDetail := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		identityID := r.PathValue("identityId")
		var it identity
		if st.getJSON(identityKey(identityID), &it) != nil {
			writeJSON(w, http.StatusNotFound, msg("identity not found"))
			return
		}
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"identityMembership": map[string]any{
			"id": newID(), "identity": identityJSON(&it), "roles": []any{},
			"createdAt": now, "updatedAt": now,
		}})
	}
	mux.HandleFunc("GET /v1/projects/{projectId}/identity-memberships/{identityId}", membershipDetail)
	mux.HandleFunc("GET /v1/projects/{projectId}/memberships/identities/{identityId}", membershipDetail)

	// ── auth methods (12 × CRUD via one factory) ────────────────────────────

	for _, method := range identityAuthMethods {
		m := method
		respKey := identityAuthResponseKey(m)
		base := "/v1/auth/" + m + "-auth/identities/{id}"

		// upsert: persist whatever the SPA posted, stamped with identityId, and
		// record the method on the identity's authMethods.
		upsert := func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			id := r.PathValue("id")
			var body map[string]any
			_ = decode(w, r, &body)
			if body == nil {
				body = map[string]any{}
			}
			body["identityId"] = id
			defaultIdentityAuthFields(body)
			_ = st.putJSON(identityAuthKey(m, id), body)
			recordIdentityAuthMethod(st, id, m, true)
			writeJSON(w, http.StatusOK, map[string]any{respKey: body})
		}
		mux.HandleFunc("POST "+base, upsert)
		mux.HandleFunc("PATCH "+base, upsert)

		mux.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			id := r.PathValue("id")
			var body map[string]any
			if st.getJSON(identityAuthKey(m, id), &body) != nil {
				writeJSON(w, http.StatusNotFound, msg(m+"-auth not configured"))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{respKey: body})
		})

		mux.HandleFunc("DELETE "+base, func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			id := r.PathValue("id")
			var body map[string]any
			_ = st.getJSON(identityAuthKey(m, id), &body)
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(identityAuthKey(m, id)) })
			recordIdentityAuthMethod(st, id, m, false)
			if body == nil {
				body = map[string]any{"identityId": id}
			}
			writeJSON(w, http.StatusOK, map[string]any{respKey: body})
		})
	}

	// universal-auth: client-secrets list/create/revoke + clear-lockouts.
	mux.HandleFunc("GET /v1/auth/universal-auth/identities/{id}/client-secrets", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"clientSecretData": []any{}})
	})
	mux.HandleFunc("POST /v1/auth/universal-auth/identities/{id}/client-secrets", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("id")
		var req struct {
			Description  string `json:"description"`
			TTL          int    `json:"ttl"`
			NumUsesLimit int    `json:"numUsesLimit"`
		}
		_ = decode(w, r, &req)
		secretID := newID()
		secret := newID() + newID() // 64 hex chars
		now := time.Now().UTC()
		data := map[string]any{
			"id": secretID, "identityUniversalAuth": id, "isClientSecretRevoked": false,
			"description": req.Description, "clientSecretPrefix": secret[:4],
			"clientSecretNumUses": 0, "clientSecretNumUsesLimit": req.NumUsesLimit,
			"clientSecretTTL": req.TTL, "createdAt": now, "updatedAt": now,
		}
		writeJSON(w, http.StatusOK, map[string]any{"clientSecret": secret, "clientSecretData": data})
	})
	mux.HandleFunc("POST /v1/auth/universal-auth/identities/{id}/client-secrets/{secretId}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"clientSecretData": map[string]any{
			"id": r.PathValue("secretId"), "identityUniversalAuth": r.PathValue("id"),
			"isClientSecretRevoked": true, "createdAt": now, "updatedAt": now,
		}})
	})
	mux.HandleFunc("POST /v1/auth/universal-auth/identities/{id}/clear-lockouts", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": 0})
	})

	// ldap-auth: clear-lockouts.
	mux.HandleFunc("POST /v1/auth/ldap-auth/identities/{id}/clear-lockouts", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": 0})
	})

	// token-auth: tokens list/create + per-token update/revoke.
	mux.HandleFunc("GET /v1/auth/token-auth/identities/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": []any{}})
	})
	mux.HandleFunc("POST /v1/auth/token-auth/identities/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("id")
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"accessToken": newID() + newID(),
			"tokenData":   identityAccessTokenJSON(newID(), id, req.Name),
		})
	})
	mux.HandleFunc("PATCH /v1/auth/token-auth/tokens/{tokenId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"token": identityAccessTokenJSON(r.PathValue("tokenId"), "", req.Name)})
	})
	mux.HandleFunc("POST /v1/auth/token-auth/tokens/{tokenId}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("Successfully revoked access token"))
	})

	// ── identity auth templates ─────────────────────────────────────────────

	mux.HandleFunc("GET /v1/identity-templates", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		// Available-templates probe (?authMethod=...) returns a bare array.
		orgID := r.URL.Query().Get("organizationId")
		if orgID == "" {
			orgID = cl.OrgID
		}
		out := identityTemplatesArray(st, orgID)
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /v1/identity-templates", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name           string         `json:"name"`
			OrganizationID string         `json:"organizationId"`
			AuthMethod     string         `json:"authMethod"`
			TemplateFields map[string]any `json:"templateFields"`
		}
		if !decode(w, r, &req) {
			return
		}
		orgID := req.OrganizationID
		if orgID == "" {
			orgID = cl.OrgID
		}
		now := time.Now().UTC()
		t := &identityTemplate{
			ID: newID(), Name: req.Name, OrgID: orgID, AuthMethod: req.AuthMethod,
			TemplateFields: req.TemplateFields, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(identityTemplateKey(t.ID), t)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(identityTemplateOrgIdx(orgID, t.ID), []byte(t.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"template": identityTemplateJSON(t)})
	})

	// GET /v1/identity-templates/search — paginated {templates,totalCount}.
	mux.HandleFunc("GET /v1/identity-templates/search", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		orgID := r.URL.Query().Get("organizationId")
		if orgID == "" {
			orgID = cl.OrgID
		}
		out := identityTemplatesArray(st, orgID)
		writeJSON(w, http.StatusOK, map[string]any{"templates": out, "totalCount": len(out)})
	})

	mux.HandleFunc("GET /v1/identity-templates/{templateId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t identityTemplate
		if st.getJSON(identityTemplateKey(r.PathValue("templateId")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("template not found"))
			return
		}
		writeJSON(w, http.StatusOK, identityTemplateJSON(&t))
	})

	mux.HandleFunc("PATCH /v1/identity-templates/{templateId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t identityTemplate
		if st.getJSON(identityTemplateKey(r.PathValue("templateId")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("template not found"))
			return
		}
		var req struct {
			Name           *string        `json:"name"`
			TemplateFields map[string]any `json:"templateFields"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			t.Name = *req.Name
		}
		if req.TemplateFields != nil {
			t.TemplateFields = req.TemplateFields
		}
		t.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(identityTemplateKey(t.ID), &t)
		writeJSON(w, http.StatusOK, map[string]any{"template": identityTemplateJSON(&t)})
	})

	mux.HandleFunc("DELETE /v1/identity-templates/{templateId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("templateId")
		var t identityTemplate
		if st.getJSON(identityTemplateKey(id), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("template not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(identityTemplateKey(id))
			return txn.Delete(identityTemplateOrgIdx(t.OrgID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"template": identityTemplateJSON(&t)})
	})

	mux.HandleFunc("GET /v1/identity-templates/{templateId}/usage", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("POST /v1/identity-templates/{templateId}/delete-usage", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})

	// ── identity project additional privileges ──────────────────────────────

	mux.HandleFunc("GET /v1/identity-project-additional-privilege", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		q := r.URL.Query()
		out := identityPrivilegesFor(st, q.Get("projectId"), q.Get("identityId"))
		writeJSON(w, http.StatusOK, map[string]any{"privileges": out})
	})

	mux.HandleFunc("POST /v1/identity-project-additional-privilege", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			IdentityID  string `json:"identityId"`
			ProjectID   string `json:"projectId"`
			Slug        string `json:"slug"`
			Permissions []any  `json:"permissions"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		slug := req.Slug
		if slug == "" {
			slug = "privilege-" + newID()[:8]
		}
		p := &identityPrivilege{
			ID: newID(), Slug: slugify(slug), ProjectID: req.ProjectID, IdentityID: req.IdentityID,
			Permissions: req.Permissions, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(identityPrivKey(p.ID), p)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(identityPrivIdx(p.ProjectID, p.IdentityID, p.ID), []byte(p.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"privilege": identityPrivilegeJSON(p)})
	})

	mux.HandleFunc("GET /v2/identity-project-additional-privilege/{privilegeId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p identityPrivilege
		if st.getJSON(identityPrivKey(r.PathValue("privilegeId")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"privilege": identityPrivilegeJSON(&p)})
	})

	mux.HandleFunc("PATCH /v2/identity-project-additional-privilege/{privilegeId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p identityPrivilege
		if st.getJSON(identityPrivKey(r.PathValue("privilegeId")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		var req struct {
			Slug        *string `json:"slug"`
			Permissions []any   `json:"permissions"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Slug != nil && *req.Slug != "" {
			p.Slug = slugify(*req.Slug)
		}
		if req.Permissions != nil {
			p.Permissions = req.Permissions
		}
		p.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(identityPrivKey(p.ID), &p)
		writeJSON(w, http.StatusOK, map[string]any{"privilege": identityPrivilegeJSON(&p)})
	})

	mux.HandleFunc("DELETE /v2/identity-project-additional-privilege/{privilegeId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("privilegeId")
		var p identityPrivilege
		if st.getJSON(identityPrivKey(id), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(identityPrivKey(id))
			return txn.Delete(identityPrivIdx(p.ProjectID, p.IdentityID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"privilege": identityPrivilegeJSON(&p)})
	})
}

// ── helpers (area-prefixed; no collision with package helpers) ──────────────

// withIdentityMetaIDs ensures every metadata entry carries a stable id.
func withIdentityMetaIDs(in []identityMeta) []identityMeta {
	out := make([]identityMeta, 0, len(in))
	for _, m := range in {
		if m.ID == "" {
			m.ID = newID()
		}
		out = append(out, m)
	}
	return out
}

// identityAccessTokenJSON renders the IdentityAccessToken shape.
func identityAccessTokenJSON(id, identityID, name string) map[string]any {
	now := time.Now().UTC()
	var nm any
	if name != "" {
		nm = name
	}
	return map[string]any{
		"id": id, "identityId": identityID, "name": nm,
		"accessTokenTTL": 2592000, "accessTokenMaxTTL": 2592000,
		"accessTokenNumUses": 0, "accessTokenNumUsesLimit": 0,
		"accessTokenLastUsedAt": nil, "accessTokenLastRenewedAt": nil,
		"isAccessTokenRevoked": false, "identityUAClientSecretId": nil,
		"createdAt": now, "updatedAt": now,
	}
}

// defaultIdentityAuthFields fills the TTL/IP fields the SPA forms always read
// back so a freshly-posted partial config round-trips without undefined access.
func defaultIdentityAuthFields(b map[string]any) {
	setIfAbsent := func(k string, v any) {
		if _, ok := b[k]; !ok {
			b[k] = v
		}
	}
	setIfAbsent("accessTokenTTL", 2592000)
	setIfAbsent("accessTokenMaxTTL", 2592000)
	setIfAbsent("accessTokenNumUsesLimit", 0)
	setIfAbsent("accessTokenTrustedIps", []any{})
}

// recordIdentityAuthMethod adds/removes a method slug from an identity's authMethods.
func recordIdentityAuthMethod(st *webStore, identityID, method string, add bool) {
	var it identity
	if st.getJSON(identityKey(identityID), &it) != nil {
		return
	}
	kept := make([]string, 0, len(it.AuthMethods)+1)
	for _, m := range it.AuthMethods {
		if m != method {
			kept = append(kept, m)
		}
	}
	if add {
		kept = append(kept, method)
	}
	it.AuthMethods = kept
	it.UpdatedAt = time.Now().UTC()
	_ = st.putJSON(identityKey(identityID), &it)
}

// identityIDsForPrefix collects the stored id values under a badger key prefix.
func identityIDsForPrefix(st *webStore, prefix []byte) []string {
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				ids = append(ids, string(v))
				return nil
			})
		}
		return nil
	})
	return ids
}

func identitiesForOrg(st *webStore, orgID string) []*identity {
	out := []*identity{}
	if orgID == "" {
		return out
	}
	for _, id := range identityIDsForPrefix(st, identityOrgPrefix(orgID)) {
		var it identity
		if st.getJSON(identityKey(id), &it) == nil {
			out = append(out, &it)
		}
	}
	return out
}

func identitiesForProject(st *webStore, projectID string) []*identity {
	out := []*identity{}
	if projectID == "" {
		return out
	}
	for _, id := range identityIDsForPrefix(st, identityProjBindPrefix(projectID)) {
		var it identity
		if st.getJSON(identityKey(id), &it) == nil {
			out = append(out, &it)
		}
	}
	return out
}

func identityTemplatesArray(st *webStore, orgID string) []any {
	out := []any{}
	if orgID == "" {
		return out
	}
	for _, id := range identityIDsForPrefix(st, identityTemplateOrgPrefix(orgID)) {
		var t identityTemplate
		if st.getJSON(identityTemplateKey(id), &t) == nil {
			out = append(out, identityTemplateJSON(&t))
		}
	}
	return out
}

func identityPrivilegesFor(st *webStore, projectID, identityID string) []any {
	out := []any{}
	if projectID == "" || identityID == "" {
		return out
	}
	for _, id := range identityIDsForPrefix(st, identityPrivPrefix(projectID, identityID)) {
		var p identityPrivilege
		if st.getJSON(identityPrivKey(id), &p) == nil {
			out = append(out, identityPrivilegeJSON(&p))
		}
	}
	return out
}

// paginateIdentities returns the [offset, offset+limit) window (limit<=0 = all).
func paginateIdentities(in []*identity, offset, limit int) []*identity {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(in) {
		return []*identity{}
	}
	end := len(in)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return in[offset:end]
}

// keep encoding/json referenced (entity (de)serialization flows through webStore).
var _ = json.Marshal
