// Tokens — credential surfaces hung off projects/users in the SPA.
//
// Groups (frontend/src/hooks/api):
//
//	apiKeys        POST   /v1/api-key                                  {apiKeyData, apiKey}
//	               PATCH  /v3/api-key/{id}                             {apiKeyData}
//	               DELETE /v3/api-key/{id}                             {apiKeyData}
//	serviceTokens  GET    /v1/projects/{id}/service-token-data         {serviceTokenData: [...]}
//	               POST   /v1/service-token/                           {serviceToken, serviceTokenData}
//	               DELETE /v2/service-token/{id}                       {serviceTokenData}
//	bots           GET    /v1/bot/{workspaceId}                        {bot}
//	               PATCH  /v1/bot/{id}/active                          {bot}
//	assumePrivs    POST   /v1/projects/{id}/assume-privileges          {message}
//	               DELETE /v1/projects/{id}/assume-privileges          {message}
//	userProjPriv   GET    /v1/user-project-additional-privilege        {privileges: [...]}
//	               POST   /v1/user-project-additional-privilege        {privilege}
//	               GET    /v1/user-project-additional-privilege/{id}   {privilege}
//	               PATCH  /v1/user-project-additional-privilege/{id}   {privilege}
//	               DELETE /v1/user-project-additional-privilege/{id}   {privilege}
//
// Real CRUD where simple (api-keys, service-tokens, additional-privileges persist
// as JSON-KV under "kms/<area>/..."). A per-project bot is auto-materialized so the
// secrets page's useGetWorkspaceBot never 404s. assume-privileges is a no-op ack:
// the KMS session JWT model has no actor-impersonation, so it returns {message}
// without re-minting (the SPA only reads data.message). No token randomBytes/
// encryptedKey crypto is performed — the opaque token value is a server-minted id
// (the SPA appends its own client-held randomBytes for the display value).
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities (JSON-KV in ZapDB) ───────────────────────────────────────────

type apiKeyData struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	User       string    `json:"user"`
	UsageCount int       `json:"usageCount"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type serviceTokenScope struct {
	Environment string `json:"environment"`
	SecretPath  string `json:"secretPath"`
}

type serviceToken struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	ProjectID string              `json:"projectId"`
	Scopes    []serviceTokenScope `json:"scopes"`
	User      string              `json:"user"`
	ExpiresAt *time.Time          `json:"expiresAt"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
}

type userProjectPrivilege struct {
	ID                       string          `json:"id"`
	ProjectMembershipID      string          `json:"projectMembershipId"`
	Slug                     string          `json:"slug"`
	Permissions              json.RawMessage `json:"permissions"`
	IsTemporary              bool            `json:"isTemporary"`
	TemporaryMode            string          `json:"temporaryMode,omitempty"`
	TemporaryRange           string          `json:"temporaryRange,omitempty"`
	TemporaryAccessStartTime string          `json:"temporaryAccessStartTime,omitempty"`
	TemporaryAccessEndTime   string          `json:"temporaryAccessEndTime,omitempty"`
	CreatedAt                time.Time       `json:"createdAt"`
	UpdatedAt                time.Time       `json:"updatedAt"`
}

type botRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"isActive"`
	PublicKey string    `json:"publicKey"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// keys
func apiKeyKey(id string) []byte          { return []byte("kms/apikeys/" + id) }
func apiKeyUserIdx(uid, id string) []byte { return []byte("kms/apikeys/by-user/" + uid + "/" + id) }

func serviceTokenKey(id string) []byte { return []byte("kms/service-tokens/" + id) }
func serviceTokenProjIdx(projectID, id string) []byte {
	return []byte("kms/service-tokens/by-project/" + projectID + "/" + id)
}
func serviceTokenProjPrefix(projectID string) []byte {
	return []byte("kms/service-tokens/by-project/" + projectID + "/")
}

func botKey(workspaceID string) []byte { return []byte("kms/bots/" + workspaceID) }

func userPrivKey(id string) []byte { return []byte("kms/user-proj-priv/" + id) }
func userPrivMembershipIdx(membershipID, id string) []byte {
	return []byte("kms/user-proj-priv/by-membership/" + membershipID + "/" + id)
}
func userPrivMembershipPrefix(membershipID string) []byte {
	return []byte("kms/user-proj-priv/by-membership/" + membershipID + "/")
}

// ── JSON renderers (match the exact SPA-deserialized shapes) ───────────────

func apiKeyJSON(k *apiKeyData) map[string]any {
	return map[string]any{
		"id": k.ID, "name": k.Name, "user": k.User, "lastUsed": nil,
		"usageCount": k.UsageCount, "createdAt": k.CreatedAt, "updatedAt": k.UpdatedAt,
	}
}

func serviceTokenJSON(t *serviceToken) map[string]any {
	scopes := make([]map[string]any, 0, len(t.Scopes))
	for _, s := range t.Scopes {
		scopes = append(scopes, map[string]any{"environment": s.Environment, "secretPath": s.SecretPath})
	}
	var exp any
	if t.ExpiresAt != nil {
		exp = *t.ExpiresAt
	}
	return map[string]any{
		"id": t.ID, "name": t.Name, "projectId": t.ProjectID, "scopes": scopes,
		"user": t.User, "expiresAt": exp, "createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt, "__v": 0,
	}
}

func botJSON(workspaceID string, b *botRecord) map[string]any {
	return map[string]any{
		"id": b.ID, "name": b.Name, "workspace": workspaceID, "isActive": b.IsActive,
		"publicKey": b.PublicKey, "createdAt": b.CreatedAt, "updatedAt": b.UpdatedAt, "__v": 0,
	}
}

func userPrivJSON(p *userProjectPrivilege) map[string]any {
	perms := json.RawMessage("[]")
	if len(p.Permissions) > 0 {
		perms = p.Permissions
	}
	out := map[string]any{
		"id": p.ID, "projectMembershipId": p.ProjectMembershipID, "slug": p.Slug,
		"permissions": perms, "isTemporary": p.IsTemporary,
		"isLinkedToAccessApproval": false,
		"createdAt":                p.CreatedAt, "updatedAt": p.UpdatedAt,
	}
	if p.IsTemporary {
		out["temporaryMode"] = p.TemporaryMode
		out["temporaryRange"] = p.TemporaryRange
		out["temporaryAccessStartTime"] = p.TemporaryAccessStartTime
		out["temporaryAccessEndTime"] = tokensNullableStr(p.TemporaryAccessEndTime)
	} else {
		out["temporaryMode"] = nil
		out["temporaryRange"] = nil
		out["temporaryAccessStartTime"] = nil
		out["temporaryAccessEndTime"] = nil
	}
	return out
}

func tokensNullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func registerTokensAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed returns the claims, or nil after writing 401.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── apiKeys ────────────────────────────────────────────────────────────
	// POST /v1/api-key — mint a personal API key for the caller.
	mux.HandleFunc("POST /v1/api-key", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		now := time.Now().UTC()
		k := &apiKeyData{ID: newID(), Name: req.Name, User: cl.UserID, UsageCount: 0, CreatedAt: now, UpdatedAt: now}
		_ = st.putJSON(apiKeyKey(k.ID), k)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(apiKeyUserIdx(cl.UserID, k.ID), []byte(k.ID)) })
		// CreateServiceTokenDataV3Res: {apiKeyData, apiKey}. apiKey is the secret value,
		// shown once. We mint an opaque id-based token (no DB-side hashing surface here).
		writeJSON(w, http.StatusOK, map[string]any{"apiKeyData": apiKeyJSON(k), "apiKey": "ak." + k.ID + "." + newID()})
	})

	// PATCH /v3/api-key/{id} — rename.
	mux.HandleFunc("PATCH /v3/api-key/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var k apiKeyData
		if st.getJSON(apiKeyKey(r.PathValue("id")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("api key not found"))
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		if req.Name != "" {
			k.Name = req.Name
		}
		k.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(apiKeyKey(k.ID), &k)
		writeJSON(w, http.StatusOK, map[string]any{"apiKeyData": apiKeyJSON(&k)})
	})

	// DELETE /v3/api-key/{id}
	mux.HandleFunc("DELETE /v3/api-key/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var k apiKeyData
		if st.getJSON(apiKeyKey(r.PathValue("id")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("api key not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(apiKeyKey(k.ID))
			return txn.Delete(apiKeyUserIdx(k.User, k.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"apiKeyData": apiKeyJSON(&k)})
	})

	// ── serviceTokens ──────────────────────────────────────────────────────
	// GET /v1/projects/{id}/service-token-data
	mux.HandleFunc("GET /v1/projects/{id}/service-token-data", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"serviceTokenData": listServiceTokens(st, r.PathValue("id"))})
	})

	// POST /v1/service-token/  (trailing slash; {$} anchors the exact path).
	mux.HandleFunc("POST /v1/service-token/{$}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name        string              `json:"name"`
			WorkspaceID string              `json:"workspaceId"`
			Scopes      []serviceTokenScope `json:"scopes"`
			ExpiresIn   int64               `json:"expiresIn"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		t := &serviceToken{
			ID: newID(), Name: req.Name, ProjectID: req.WorkspaceID,
			Scopes: req.Scopes, User: cl.UserID, CreatedAt: now, UpdatedAt: now,
		}
		if req.ExpiresIn > 0 {
			exp := now.Add(time.Duration(req.ExpiresIn) * time.Second)
			t.ExpiresAt = &exp
		}
		_ = st.putJSON(serviceTokenKey(t.ID), t)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(serviceTokenProjIdx(t.ProjectID, t.ID), []byte(t.ID))
		})
		// CreateServiceTokenRes: {serviceToken, serviceTokenData}. The SPA appends
		// ".<randomBytes>" to serviceToken for its client-side display value.
		writeJSON(w, http.StatusOK, map[string]any{
			"serviceToken":     "st." + t.ID + "." + newID(),
			"serviceTokenData": serviceTokenJSON(t),
		})
	})

	// DELETE /v2/service-token/{id}
	mux.HandleFunc("DELETE /v2/service-token/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t serviceToken
		if st.getJSON(serviceTokenKey(r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("service token not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(serviceTokenKey(t.ID))
			return txn.Delete(serviceTokenProjIdx(t.ProjectID, t.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"serviceTokenData": serviceTokenJSON(&t)})
	})

	// ── bots ───────────────────────────────────────────────────────────────
	// GET /v1/bot/{workspaceId} — one bot per workspace, auto-materialized.
	mux.HandleFunc("GET /v1/bot/{workspaceId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		wid := r.PathValue("workspaceId")
		var b botRecord
		if st.getJSON(botKey(wid), &b) != nil {
			now := time.Now().UTC()
			b = botRecord{ID: newID(), Name: "Infisical Bot", IsActive: false, PublicKey: "", CreatedAt: now, UpdatedAt: now}
			_ = st.putJSON(botKey(wid), &b)
		}
		writeJSON(w, http.StatusOK, map[string]any{"bot": botJSON(wid, &b)})
	})

	// PATCH /v1/bot/{id}/active — toggle E2EE bot. {id} is the workspaceId here
	// (one bot per workspace; the SPA stores by workspaceId).
	mux.HandleFunc("PATCH /v1/bot/{id}/active", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		wid := r.PathValue("id")
		var b botRecord
		if st.getJSON(botKey(wid), &b) != nil {
			now := time.Now().UTC()
			b = botRecord{ID: newID(), Name: "Infisical Bot", CreatedAt: now, UpdatedAt: now}
		}
		var req struct {
			IsActive bool `json:"isActive"`
		}
		_ = decode(w, r, &req)
		b.IsActive = req.IsActive
		b.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(botKey(wid), &b)
		writeJSON(w, http.StatusOK, map[string]any{"bot": botJSON(wid, &b)})
	})

	// ── assumePrivileges ─────────────────────────────────────────────────────
	// POST /v1/projects/{id}/assume-privileges — ack only (no impersonation in the
	// KMS session model). The SPA reads only data.message.
	mux.HandleFunc("POST /v1/projects/{id}/assume-privileges", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("Successfully assumed privileges"))
	})
	// DELETE /v1/projects/{id}/assume-privileges — exit assumed session.
	mux.HandleFunc("DELETE /v1/projects/{id}/assume-privileges", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("Successfully exited assumed privileges"))
	})

	// ── projectUserAdditionalPrivilege ───────────────────────────────────────
	// GET /v1/user-project-additional-privilege ?projectMembershipId
	mux.HandleFunc("GET /v1/user-project-additional-privilege", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		mid := r.URL.Query().Get("projectMembershipId")
		writeJSON(w, http.StatusOK, map[string]any{"privileges": listUserPrivs(st, mid)})
	})

	// POST /v1/user-project-additional-privilege
	mux.HandleFunc("POST /v1/user-project-additional-privilege", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			ProjectMembershipID string          `json:"projectMembershipId"`
			Slug                string          `json:"slug"`
			Permissions         json.RawMessage `json:"permissions"`
			Type                struct {
				IsTemporary              bool   `json:"isTemporary"`
				TemporaryMode            string `json:"temporaryMode"`
				TemporaryRange           string `json:"temporaryRange"`
				TemporaryAccessStartTime string `json:"temporaryAccessStartTime"`
			} `json:"type"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		slug := req.Slug
		if slug == "" {
			slug = "privilege-" + newID()[:8]
		}
		p := &userProjectPrivilege{
			ID: newID(), ProjectMembershipID: req.ProjectMembershipID, Slug: slugify(slug),
			Permissions: req.Permissions, IsTemporary: req.Type.IsTemporary,
			TemporaryMode: req.Type.TemporaryMode, TemporaryRange: req.Type.TemporaryRange,
			TemporaryAccessStartTime: req.Type.TemporaryAccessStartTime, CreatedAt: now, UpdatedAt: now,
		}
		if p.IsTemporary && p.TemporaryAccessStartTime != "" && p.TemporaryRange != "" {
			if start, err := time.Parse(time.RFC3339, p.TemporaryAccessStartTime); err == nil {
				if d, derr := time.ParseDuration(p.TemporaryRange); derr == nil {
					p.TemporaryAccessEndTime = start.Add(d).Format(time.RFC3339)
				}
			}
		}
		_ = st.putJSON(userPrivKey(p.ID), p)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(userPrivMembershipIdx(p.ProjectMembershipID, p.ID), []byte(p.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"privilege": userPrivJSON(p)})
	})

	// GET /v1/user-project-additional-privilege/{id}
	mux.HandleFunc("GET /v1/user-project-additional-privilege/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p userProjectPrivilege
		if st.getJSON(userPrivKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"privilege": userPrivJSON(&p)})
	})

	// PATCH /v1/user-project-additional-privilege/{id}
	mux.HandleFunc("PATCH /v1/user-project-additional-privilege/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p userProjectPrivilege
		if st.getJSON(userPrivKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		var req struct {
			Slug        *string         `json:"slug"`
			Permissions json.RawMessage `json:"permissions"`
			Type        *struct {
				IsTemporary              bool   `json:"isTemporary"`
				TemporaryMode            string `json:"temporaryMode"`
				TemporaryRange           string `json:"temporaryRange"`
				TemporaryAccessStartTime string `json:"temporaryAccessStartTime"`
			} `json:"type"`
		}
		_ = decode(w, r, &req)
		if req.Slug != nil && *req.Slug != "" {
			p.Slug = slugify(*req.Slug)
		}
		if len(req.Permissions) > 0 {
			p.Permissions = req.Permissions
		}
		if req.Type != nil {
			p.IsTemporary = req.Type.IsTemporary
			p.TemporaryMode = req.Type.TemporaryMode
			p.TemporaryRange = req.Type.TemporaryRange
			p.TemporaryAccessStartTime = req.Type.TemporaryAccessStartTime
			p.TemporaryAccessEndTime = ""
			if p.IsTemporary && p.TemporaryAccessStartTime != "" && p.TemporaryRange != "" {
				if start, err := time.Parse(time.RFC3339, p.TemporaryAccessStartTime); err == nil {
					if d, derr := time.ParseDuration(p.TemporaryRange); derr == nil {
						p.TemporaryAccessEndTime = start.Add(d).Format(time.RFC3339)
					}
				}
			}
		}
		p.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(userPrivKey(p.ID), &p)
		writeJSON(w, http.StatusOK, map[string]any{"privilege": userPrivJSON(&p)})
	})

	// DELETE /v1/user-project-additional-privilege/{id}
	mux.HandleFunc("DELETE /v1/user-project-additional-privilege/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var p userProjectPrivilege
		if st.getJSON(userPrivKey(r.PathValue("id")), &p) != nil {
			writeJSON(w, http.StatusNotFound, msg("privilege not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(userPrivKey(p.ID))
			return txn.Delete(userPrivMembershipIdx(p.ProjectMembershipID, p.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"privilege": userPrivJSON(&p)})
	})
}

// ── list helpers (prefix-iterate the secondary index, then load records) ───

func listServiceTokens(st *webStore, projectID string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	var ids []string
	pfx := serviceTokenProjPrefix(projectID)
	_ = st.db.View(func(txn *badger.Txn) error {
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
		var t serviceToken
		if st.getJSON(serviceTokenKey(id), &t) == nil {
			out = append(out, serviceTokenJSON(&t))
		}
	}
	return out
}

func listUserPrivs(st *webStore, membershipID string) []any {
	out := []any{}
	if membershipID == "" {
		return out
	}
	var ids []string
	pfx := userPrivMembershipPrefix(membershipID)
	_ = st.db.View(func(txn *badger.Txn) error {
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
		var p userProjectPrivilege
		if st.getJSON(userPrivKey(id), &p) == nil {
			out = append(out, userPrivJSON(&p))
		}
	}
	return out
}
