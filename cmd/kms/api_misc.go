// Misc web-UI API — the long tail of org/instance settings + small CRUD
// surfaces the SPA touches outside the secrets core. All ZapDB-backed JSON-KV
// (prefix kms/<area>/...), session-JWT authed, no Postgres/Redis/Node.
//
// Groups covered (frontend/src/hooks/api/<group>):
//
//	gateways         GET   /v1/gateways                                   {gateways: []}
//	                 PATCH /v1/gateways/{id}                              {gateway}
//	                 DELETE/v1/gateways/{id}
//	gateways-v2      DELETE/v2/gateways/{id}
//	relays           GET   /v1/relays                                     []
//	                 DELETE/v1/relays/{id}
//	rateLimit        GET   /v1/rate-limit                                 {rateLimit}
//	                 PUT   /v1/rate-limit                                 {rateLimit}
//	upgradePath      GET   /v1/upgrade-path/versions                      {versions: []}
//	                 POST  /v1/upgrade-path/calculate                     UpgradePathResult
//	projectTemplates GET/POST       /v1/project-templates                 {projectTemplates|projectTemplate}
//	                 GET/PATCH/DELETE/v1/project-templates/{id}           {projectTemplate}
//	notifications    GET   /v1/notifications/user                         {notifications: []}
//	                 POST  /v1/notifications/user/mark-as-read
//	                 PATCH/DELETE   /v1/notifications/user/{id}           {notification}
//	userActions      GET/POST       /v1/user-action                       {userAction}
//	userEngagement   POST  /v1/user-engagement/me/wish                    {}
//	secretSharing    GET/POST       /v1/secret-sharing/shared|requests    + branding + public reveal
//	migration        GET   /v3/external-migration/custom-migration-enabled/{provider}
//	                 vault configs CRUD + introspection (empty for external Vault calls)
//	inviteOrg        POST  /v1/invite-org/signup|signup-resend|verify
//
// CRUD is real for the simple entities (gateways/relays/rate-limit/
// project-templates/notifications/user-action/secret-sharing/vault-configs).
// External-system introspection (HashiCorp Vault namespaces/policies/mounts/
// roles, env-key import) returns the correctly-shaped EMPTY response so the
// migration wizard renders without erroring — there is no live Vault to call.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── shared per-area key helpers ─────────────────────────────────────────────

func miscKey(area, id string) []byte { return []byte("kms/" + area + "/" + id) }
func miscIdx(area, orgID, id string) []byte {
	return []byte("kms/" + area + "/by-org/" + orgID + "/" + id)
}
func miscPrefix(area, orgID string) []byte { return []byte("kms/" + area + "/by-org/" + orgID + "/") }

// miscList iterates the by-org index for an area and decodes each entity via fn.
func miscList(st *webStore, area, orgID string, fn func(raw []byte)) {
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = miscPrefix(area, orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := miscPrefix(area, orgID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		_ = st.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(miscKey(area, id))
			if err != nil {
				return nil
			}
			return item.Value(func(v []byte) error { fn(v); return nil })
		})
	}
}

func miscPut(st *webStore, area, orgID, id string, v any) error {
	if err := st.putJSON(miscKey(area, id), v); err != nil {
		return err
	}
	return st.db.Update(func(txn *badger.Txn) error { return txn.Set(miscIdx(area, orgID, id), []byte(id)) })
}

func miscDelete(st *webStore, area, orgID, id string) {
	_ = st.db.Update(func(txn *badger.Txn) error {
		_ = txn.Delete(miscKey(area, id))
		return txn.Delete(miscIdx(area, orgID, id))
	})
}

func registerMiscAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed resolves the session claim once; nil response already written on 401.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	registerGatewaysAPI(mux, st, authed)
	registerRelaysAPI(mux, st, authed)
	registerRateLimitAPI(mux, st, authed)
	registerUpgradePathAPI(mux, authed)
	registerProjectTemplatesAPI(mux, st, authed)
	registerNotificationsAPI(mux, st, authed)
	registerUserActionAPI(mux, st, authed)
	registerUserEngagementAPI(mux, st, authed)
	registerSecretSharingAPI(mux, st, authed)
	registerMigrationAPI(mux, st, authed)
	registerInviteOrgAPI(mux, st)
}

// authFn is the closure shape shared by all sub-registrars.
type authFn = func(w http.ResponseWriter, r *http.Request) *webClaims

// ── gateways (v1) + gateways-v2 ─────────────────────────────────────────────

type miscGateway struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"orgId"`
	IdentityID string    `json:"identityId"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Heartbeat  time.Time `json:"heartbeat"`
}

func gatewayJSON(g *miscGateway) map[string]any {
	return map[string]any{
		"id": g.ID, "identityId": g.IdentityID, "name": g.Name,
		"createdAt": g.CreatedAt, "updatedAt": g.UpdatedAt,
		"issuedAt": g.CreatedAt, "serialNumber": g.ID, "heartbeat": g.Heartbeat,
		"identity": map[string]any{"id": g.IdentityID, "name": g.Name},
	}
}

func registerGatewaysAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	// GET /v1/gateways — the SPA Promise.all's this with an array-typed read; the
	// documented body is {gateways: [...]}. Empty until a gateway is registered
	// (gateway enrolment is a relay/identity certificate flow, not wired here).
	mux.HandleFunc("GET /v1/gateways", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		miscList(st, "gateways", cl.OrgID, func(raw []byte) {
			var g miscGateway
			if json.Unmarshal(raw, &g) == nil {
				out = append(out, gatewayJSON(&g))
			}
		})
		writeJSON(w, http.StatusOK, map[string]any{"gateways": out})
	})

	mux.HandleFunc("PATCH /v1/gateways/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var g miscGateway
		if st.getJSON(miscKey("gateways", r.PathValue("id")), &g) != nil {
			writeJSON(w, http.StatusNotFound, msg("gateway not found"))
			return
		}
		var req struct{ Name string }
		_ = decode(w, r, &req)
		if req.Name != "" {
			g.Name = req.Name
		}
		g.UpdatedAt = time.Now().UTC()
		_ = miscPut(st, "gateways", g.OrgID, g.ID, &g)
		writeJSON(w, http.StatusOK, map[string]any{"gateway": gatewayJSON(&g)})
	})

	mux.HandleFunc("DELETE /v1/gateways/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		miscDelete(st, "gateways", cl.OrgID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// gateways-v2: same store, distinct delete path the SPA uses for v2 rows.
	mux.HandleFunc("DELETE /v2/gateways/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		miscDelete(st, "gateways", cl.OrgID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, msg("deleted"))
	})
}

// ── relays ──────────────────────────────────────────────────────────────────

type miscRelay struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"orgId"`
	IdentityID string    `json:"identityId"`
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Heartbeat  time.Time `json:"heartbeat"`
}

func relayJSON(rl *miscRelay) map[string]any {
	return map[string]any{
		"id": rl.ID, "orgId": rl.OrgID, "identityId": rl.IdentityID,
		"name": rl.Name, "host": rl.Host,
		"createdAt": rl.CreatedAt, "updatedAt": rl.UpdatedAt, "heartbeat": rl.Heartbeat,
	}
}

func registerRelaysAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	// GET /v1/relays — bare array body (TRelay[]).
	mux.HandleFunc("GET /v1/relays", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		miscList(st, "relays", cl.OrgID, func(raw []byte) {
			var rl miscRelay
			if json.Unmarshal(raw, &rl) == nil {
				out = append(out, relayJSON(&rl))
			}
		})
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("DELETE /v1/relays/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		miscDelete(st, "relays", cl.OrgID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, msg("deleted"))
	})
}

// ── rate limit (instance-wide singleton) ────────────────────────────────────

type miscRateLimit struct {
	ReadRateLimit       int `json:"readRateLimit"`
	WriteRateLimit      int `json:"writeRateLimit"`
	SecretsRateLimit    int `json:"secretsRateLimit"`
	AuthRateLimit       int `json:"authRateLimit"`
	InviteUserRateLimit int `json:"inviteUserRateLimit"`
	MfaRateLimit        int `json:"mfaRateLimit"`
	PublicEndpointLimit int `json:"publicEndpointLimit"`
}

func defaultRateLimit() miscRateLimit {
	return miscRateLimit{
		ReadRateLimit: 600, WriteRateLimit: 200, SecretsRateLimit: 60,
		AuthRateLimit: 60, InviteUserRateLimit: 30, MfaRateLimit: 20, PublicEndpointLimit: 30,
	}
}

func registerRateLimitAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	const key = "kms/rate-limit/singleton"

	mux.HandleFunc("GET /v1/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		rl := defaultRateLimit()
		_ = st.getJSON([]byte(key), &rl)
		writeJSON(w, http.StatusOK, map[string]any{"rateLimit": rl})
	})

	mux.HandleFunc("PUT /v1/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		rl := defaultRateLimit()
		if !decode(w, r, &rl) {
			return
		}
		_ = st.putJSON([]byte(key), &rl)
		writeJSON(w, http.StatusOK, map[string]any{"rateLimit": rl})
	})
}

// ── upgrade path ────────────────────────────────────────────────────────────

func registerUpgradePathAPI(mux *http.ServeMux, authed authFn) {
	// GET /v1/upgrade-path/versions — release feed (GitHub-sourced upstream).
	// No outbound fetch from KMS; the UI degrades to "no versions" on empty.
	mux.HandleFunc("GET /v1/upgrade-path/versions", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": []any{}})
	})

	// POST /v1/upgrade-path/calculate — UpgradePathResult shell (no breaking
	// changes / no migration between unknown versions).
	mux.HandleFunc("POST /v1/upgrade-path/calculate", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct{ FromVersion, ToVersion string }
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"path":            []any{},
			"breakingChanges": []any{},
			"features":        []any{},
			"hasDbMigration":  false,
			"config":          map[string]any{},
		})
	})
}

// ── project templates ───────────────────────────────────────────────────────

type miscProjectTemplate struct {
	ID           string           `json:"id"`
	OrgID        string           `json:"orgId"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Type         string           `json:"type"`
	Roles        []any            `json:"roles"`
	Environments []map[string]any `json:"environments"`
	CreatedAt    time.Time        `json:"createdAt"`
	UpdatedAt    time.Time        `json:"updatedAt"`
}

func projectTemplateJSON(t *miscProjectTemplate) map[string]any {
	roles := t.Roles
	if roles == nil {
		roles = []any{}
	}
	envs := t.Environments
	if envs == nil {
		envs = []map[string]any{}
	}
	typ := t.Type
	if typ == "" {
		typ = "secret-manager"
	}
	return map[string]any{
		"id": t.ID, "name": t.Name, "description": t.Description, "type": typ,
		"roles": roles, "environments": envs,
		"createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt,
	}
}

func registerProjectTemplatesAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	mux.HandleFunc("GET /v1/project-templates", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		miscList(st, "project-templates", cl.OrgID, func(raw []byte) {
			var t miscProjectTemplate
			if json.Unmarshal(raw, &t) == nil {
				out = append(out, projectTemplateJSON(&t))
			}
		})
		writeJSON(w, http.StatusOK, map[string]any{"projectTemplates": out})
	})

	mux.HandleFunc("POST /v1/project-templates", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Type        string `json:"type"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		t := &miscProjectTemplate{
			ID: newID(), OrgID: cl.OrgID, Name: req.Name, Description: req.Description,
			Type: req.Type, Roles: []any{}, Environments: []map[string]any{},
			CreatedAt: now, UpdatedAt: now,
		}
		_ = miscPut(st, "project-templates", cl.OrgID, t.ID, t)
		writeJSON(w, http.StatusOK, map[string]any{"projectTemplate": projectTemplateJSON(t)})
	})

	mux.HandleFunc("GET /v1/project-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t miscProjectTemplate
		if st.getJSON(miscKey("project-templates", r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("project template not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"projectTemplate": projectTemplateJSON(&t)})
	})

	mux.HandleFunc("PATCH /v1/project-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t miscProjectTemplate
		if st.getJSON(miscKey("project-templates", r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("project template not found"))
			return
		}
		var req struct {
			Name         *string          `json:"name"`
			Description  *string          `json:"description"`
			Roles        []any            `json:"roles"`
			Environments []map[string]any `json:"environments"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			t.Name = *req.Name
		}
		if req.Description != nil {
			t.Description = *req.Description
		}
		if req.Roles != nil {
			t.Roles = req.Roles
		}
		if req.Environments != nil {
			t.Environments = req.Environments
		}
		t.UpdatedAt = time.Now().UTC()
		_ = miscPut(st, "project-templates", t.OrgID, t.ID, &t)
		writeJSON(w, http.StatusOK, map[string]any{"projectTemplate": projectTemplateJSON(&t)})
	})

	mux.HandleFunc("DELETE /v1/project-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t miscProjectTemplate
		if st.getJSON(miscKey("project-templates", r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("project template not found"))
			return
		}
		miscDelete(st, "project-templates", t.OrgID, t.ID)
		writeJSON(w, http.StatusOK, map[string]any{"projectTemplate": projectTemplateJSON(&t)})
	})
}

// ── notifications (per-user) ────────────────────────────────────────────────

type miscNotification struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Link      string    `json:"link"`
	IsRead    bool      `json:"isRead"`
	CreatedAt time.Time `json:"createdAt"`
}

func notificationJSON(n *miscNotification) map[string]any {
	return map[string]any{
		"id": n.ID, "userId": n.UserID, "type": n.Type, "title": n.Title,
		"body": n.Body, "link": n.Link, "isRead": n.IsRead, "createdAt": n.CreatedAt,
	}
}

func registerNotificationsAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	// Per-user index (userId, not orgId) so notifications follow the principal.
	notifList := func(userID string, fn func(raw []byte)) {
		miscList(st, "notifications", userID, fn)
	}

	mux.HandleFunc("GET /v1/notifications/user", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		notifList(cl.UserID, func(raw []byte) {
			var n miscNotification
			if json.Unmarshal(raw, &n) == nil {
				out = append(out, notificationJSON(&n))
			}
		})
		writeJSON(w, http.StatusOK, map[string]any{"notifications": out})
	})

	mux.HandleFunc("POST /v1/notifications/user/mark-as-read", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var ids []string
		notifList(cl.UserID, func(raw []byte) {
			var n miscNotification
			if json.Unmarshal(raw, &n) == nil {
				ids = append(ids, n.ID)
			}
		})
		for _, id := range ids {
			var n miscNotification
			if st.getJSON(miscKey("notifications", id), &n) == nil && !n.IsRead {
				n.IsRead = true
				_ = miscPut(st, "notifications", n.UserID, n.ID, &n)
			}
		}
		writeJSON(w, http.StatusOK, msg("ok"))
	})

	mux.HandleFunc("PATCH /v1/notifications/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var n miscNotification
		if st.getJSON(miscKey("notifications", r.PathValue("id")), &n) != nil {
			writeJSON(w, http.StatusNotFound, msg("notification not found"))
			return
		}
		var req struct {
			IsRead *bool `json:"isRead"`
		}
		_ = decode(w, r, &req)
		if req.IsRead != nil {
			n.IsRead = *req.IsRead
		}
		_ = miscPut(st, "notifications", n.UserID, n.ID, &n)
		writeJSON(w, http.StatusOK, map[string]any{"notification": notificationJSON(&n)})
	})

	mux.HandleFunc("DELETE /v1/notifications/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		miscDelete(st, "notifications", cl.UserID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, msg("deleted"))
	})
}

// ── user actions (dismissed-banner flags, keyed per user+action) ────────────

func registerUserActionAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	actKey := func(userID, action string) []byte {
		return []byte("kms/user-action/" + userID + "/" + action)
	}

	// GET /v1/user-action?action=... — echoes the stored action string ("" if
	// never taken). The SPA only checks truthiness.
	mux.HandleFunc("GET /v1/user-action", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		action := r.URL.Query().Get("action")
		var stored string
		_ = st.getJSON(actKey(cl.UserID, action), &stored)
		writeJSON(w, http.StatusOK, map[string]any{"userAction": stored})
	})

	mux.HandleFunc("POST /v1/user-action", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		if !decode(w, r, &req) {
			return
		}
		_ = st.putJSON(actKey(cl.UserID, req.Action), req.Action)
		writeJSON(w, http.StatusOK, map[string]any{"userAction": req.Action})
	})
}

// ── user engagement (feature wishes) ────────────────────────────────────────

func registerUserEngagementAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	mux.HandleFunc("POST /v1/user-engagement/me/wish", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Text string `json:"text"`
		}
		_ = decode(w, r, &req)
		id := newID()
		_ = st.putJSON(miscKey("user-wishes", cl.UserID+"/"+id), map[string]any{
			"id": id, "userId": cl.UserID, "text": req.Text, "createdAt": time.Now().UTC(),
		})
		writeJSON(w, http.StatusOK, map[string]any{})
	})
}

// ── secret sharing ──────────────────────────────────────────────────────────

type miscSharedSecret struct {
	ID                string    `json:"id"`
	UserID            string    `json:"userId"`
	OrgID             string    `json:"orgId"`
	Name              string    `json:"name"`
	EncryptedValue    string    `json:"encryptedValue"`
	SecretValue       string    `json:"secretValue"`
	AccessType        string    `json:"accessType"`
	ExpiresAt         time.Time `json:"expiresAt"`
	ExpiresAfterViews *int      `json:"expiresAfterViews"`
	IsRequest         bool      `json:"isRequest"`
	IsValueSet        bool      `json:"isValueSet"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func sharedSecretJSON(s *miscSharedSecret) map[string]any {
	at := s.AccessType
	if at == "" {
		at = "organization"
	}
	return map[string]any{
		"id": s.ID, "userId": s.UserID, "orgId": s.OrgID, "name": s.Name,
		"accessType": at, "expiresAt": s.ExpiresAt, "expiresAfterViews": s.ExpiresAfterViews,
		"encryptedValue": s.EncryptedValue, "encryptedSecret": "", "iv": "", "tag": "",
		"createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
}

func registerSecretSharingAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	listBy := func(orgID string, request bool) []any {
		out := []any{}
		miscList(st, "secret-sharing", orgID, func(raw []byte) {
			var s miscSharedSecret
			if json.Unmarshal(raw, &s) == nil && s.IsRequest == request {
				out = append(out, sharedSecretJSON(&s))
			}
		})
		return out
	}

	mux.HandleFunc("GET /v1/secret-sharing/shared", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		secs := listBy(cl.OrgID, false)
		writeJSON(w, http.StatusOK, map[string]any{"secrets": secs, "totalCount": len(secs)})
	})
	mux.HandleFunc("GET /v1/secret-sharing/requests", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		secs := listBy(cl.OrgID, true)
		writeJSON(w, http.StatusOK, map[string]any{"secrets": secs, "totalCount": len(secs)})
	})

	create := func(isRequest bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cl := authed(w, r)
			if cl == nil {
				return
			}
			var req struct {
				Name              string `json:"name"`
				SecretValue       string `json:"secretValue"`
				AccessType        string `json:"accessType"`
				ExpiresAfterViews *int   `json:"expiresAfterViews"`
			}
			_ = decode(w, r, &req)
			now := time.Now().UTC()
			s := &miscSharedSecret{
				ID: newID(), UserID: cl.UserID, OrgID: cl.OrgID, Name: req.Name,
				EncryptedValue: req.SecretValue, SecretValue: req.SecretValue,
				AccessType: req.AccessType, ExpiresAfterViews: req.ExpiresAfterViews,
				IsRequest: isRequest, IsValueSet: !isRequest && req.SecretValue != "",
				CreatedAt: now, UpdatedAt: now,
			}
			_ = miscPut(st, "secret-sharing", cl.OrgID, s.ID, s)
			writeJSON(w, http.StatusOK, map[string]any{"id": s.ID})
		}
	}
	mux.HandleFunc("POST /v1/secret-sharing/shared", create(false))
	mux.HandleFunc("POST /v1/secret-sharing/shared/public", create(false))
	mux.HandleFunc("POST /v1/secret-sharing/requests", create(true))

	mux.HandleFunc("GET /v1/secret-sharing/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var s miscSharedSecret
		if st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret request not found"))
			return
		}
		at := s.AccessType
		if at == "" {
			at = "organization"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"request": map[string]any{
				"id": s.ID, "orgId": s.OrgID, "accessType": at,
				"requester": map[string]any{"organizationName": "", "username": ""},
			},
			"isSecretValueSet": s.IsValueSet,
		})
	})

	mux.HandleFunc("POST /v1/secret-sharing/requests/{id}/set-value", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s miscSharedSecret
		if st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret request not found"))
			return
		}
		var req struct {
			SecretValue string `json:"secretValue"`
		}
		_ = decode(w, r, &req)
		s.SecretValue = req.SecretValue
		s.EncryptedValue = req.SecretValue
		s.IsValueSet = true
		s.UpdatedAt = time.Now().UTC()
		_ = miscPut(st, "secret-sharing", s.OrgID, s.ID, &s)
		writeJSON(w, http.StatusOK, sharedSecretJSON(&s))
	})

	mux.HandleFunc("POST /v1/secret-sharing/requests/{id}/reveal-value", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s miscSharedSecret
		if st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret request not found"))
			return
		}
		out := sharedSecretJSON(&s)
		out["secretValue"] = s.SecretValue
		writeJSON(w, http.StatusOK, map[string]any{"secretRequest": out})
	})

	// Public reveal — value is served plaintext (sealed at rest under the REK).
	mux.HandleFunc("POST /v1/secret-sharing/shared/public/{id}", func(w http.ResponseWriter, r *http.Request) {
		var s miscSharedSecret
		if st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusOK, map[string]any{"isPasswordProtected": false, "error": "not found"})
			return
		}
		at := s.AccessType
		if at == "" {
			at = "organization"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"isPasswordProtected": false,
			"secret": map[string]any{
				"secretValue": s.SecretValue, "encryptedValue": s.EncryptedValue,
				"iv": "", "tag": "", "accessType": at, "expiresAt": s.ExpiresAt,
				"expiresAfterViews": s.ExpiresAfterViews,
			},
		})
	})

	mux.HandleFunc("DELETE /v1/secret-sharing/shared/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var s miscSharedSecret
		_ = st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s)
		miscDelete(st, "secret-sharing", cl.OrgID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, sharedSecretJSON(&s))
	})
	mux.HandleFunc("DELETE /v1/secret-sharing/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var s miscSharedSecret
		_ = st.getJSON(miscKey("secret-sharing", r.PathValue("id")), &s)
		miscDelete(st, "secret-sharing", cl.OrgID, r.PathValue("id"))
		writeJSON(w, http.StatusOK, sharedSecretJSON(&s))
	})

	// Branding config + asset upload/delete (org self-service share page).
	brandKey := func(orgID string) []byte { return miscKey("secret-sharing-branding", orgID) }
	mux.HandleFunc("GET /v1/secret-sharing/shared/branding", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		cfg := map[string]any{"hasLogo": false, "hasFavicon": false}
		_ = st.getJSON(brandKey(cl.OrgID), &cfg)
		writeJSON(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("POST /v1/secret-sharing/shared/branding/{assetType}", func(w http.ResponseWriter, r *http.Request) {
		// Multipart asset upload; binary storage is out of scope — record the flag.
		cl := authed(w, r)
		if cl == nil {
			return
		}
		cfg := map[string]any{"hasLogo": false, "hasFavicon": false}
		_ = st.getJSON(brandKey(cl.OrgID), &cfg)
		switch r.PathValue("assetType") {
		case "brand-logo":
			cfg["hasLogo"] = true
		case "brand-favicon":
			cfg["hasFavicon"] = true
		}
		_ = st.putJSON(brandKey(cl.OrgID), &cfg)
		writeJSON(w, http.StatusOK, msg("uploaded"))
	})
	mux.HandleFunc("DELETE /v1/secret-sharing/shared/branding/{assetType}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		cfg := map[string]any{"hasLogo": false, "hasFavicon": false}
		_ = st.getJSON(brandKey(cl.OrgID), &cfg)
		switch r.PathValue("assetType") {
		case "brand-logo":
			cfg["hasLogo"] = false
		case "brand-favicon":
			cfg["hasFavicon"] = false
		}
		_ = st.putJSON(brandKey(cl.OrgID), &cfg)
		writeJSON(w, http.StatusOK, msg("deleted"))
	})
}

// ── external migration (HashiCorp Vault / EnvKey) ───────────────────────────

type miscVaultConfig struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"orgId"`
	Namespace    string    `json:"namespace"`
	ConnectionID string    `json:"connectionId"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func vaultConfigJSON(c *miscVaultConfig) map[string]any {
	return map[string]any{
		"id": c.ID, "orgId": c.OrgID, "namespace": c.Namespace,
		"connectionId": c.ConnectionID, "createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func registerMigrationAPI(mux *http.ServeMux, st *webStore, authed authFn) {
	// GET /v3/external-migration/custom-migration-enabled/{provider}
	mux.HandleFunc("GET /v3/external-migration/custom-migration-enabled/{provider}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
	})

	// Vault external-migration configs — real CRUD (the persisted connection
	// pointer); secret import itself talks to a live Vault, which KMS does not.
	mux.HandleFunc("GET /v1/external-migration/vault/configs", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		miscList(st, "vault-config", cl.OrgID, func(raw []byte) {
			var c miscVaultConfig
			if json.Unmarshal(raw, &c) == nil {
				out = append(out, vaultConfigJSON(&c))
			}
		})
		writeJSON(w, http.StatusOK, map[string]any{"configs": out})
	})
	mux.HandleFunc("POST /v1/external-migration/vault/configs", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			ConnectionID string `json:"connectionId"`
			Namespace    string `json:"namespace"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		c := &miscVaultConfig{
			ID: newID(), OrgID: cl.OrgID, Namespace: req.Namespace,
			ConnectionID: req.ConnectionID, CreatedAt: now, UpdatedAt: now,
		}
		_ = miscPut(st, "vault-config", cl.OrgID, c.ID, c)
		writeJSON(w, http.StatusOK, map[string]any{"config": vaultConfigJSON(c)})
	})
	mux.HandleFunc("PUT /v3/external-migration/vault/configs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var c miscVaultConfig
		if st.getJSON(miscKey("vault-config", r.PathValue("id")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("vault config not found"))
			return
		}
		var req struct {
			ConnectionID string `json:"connectionId"`
			Namespace    string `json:"namespace"`
		}
		_ = decode(w, r, &req)
		if req.ConnectionID != "" {
			c.ConnectionID = req.ConnectionID
		}
		if req.Namespace != "" {
			c.Namespace = req.Namespace
		}
		c.UpdatedAt = time.Now().UTC()
		_ = miscPut(st, "vault-config", c.OrgID, c.ID, &c)
		writeJSON(w, http.StatusOK, map[string]any{"config": vaultConfigJSON(&c)})
	})
	mux.HandleFunc("DELETE /v3/external-migration/vault/configs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var c miscVaultConfig
		if st.getJSON(miscKey("vault-config", r.PathValue("id")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("vault config not found"))
			return
		}
		miscDelete(st, "vault-config", c.OrgID, c.ID)
		writeJSON(w, http.StatusOK, map[string]any{"config": vaultConfigJSON(&c)})
	})

	// Vault introspection — these proxy a live Vault the KMS cannot reach, so
	// each returns its correctly-keyed empty body (UI shows "nothing found").
	emptyKey := func(path, key string) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{key: []any{}})
		})
	}
	emptyKey("/v1/external-migration/vault/namespaces", "namespaces")
	emptyKey("/v1/external-migration/vault/policies", "policies")
	emptyKey("/v1/external-migration/vault/mounts", "mounts")
	emptyKey("/v1/external-migration/vault/auth-mounts", "mounts")
	emptyKey("/v1/external-migration/vault/secret-paths", "secretPaths")
	emptyKey("/v1/external-migration/vault/auth-roles/kubernetes", "roles")
	emptyKey("/v1/external-migration/vault/kubernetes-roles", "roles")
	emptyKey("/v1/external-migration/vault/database-roles", "roles")
	emptyKey("/v1/external-migration/vault/ldap-roles", "roles")

	// Import triggers — accepted + acknowledged; no live source to pull from.
	mux.HandleFunc("POST /v1/external-migration/vault/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("import queued"))
	})
	mux.HandleFunc("POST /v1/external-migration/vault/import-secrets", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "imported"})
	})
	mux.HandleFunc("POST /v1/external-migration/env-key/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("import queued"))
	})
}

// ── invite-org (org member invitations) ─────────────────────────────────────

func registerInviteOrgAPI(mux *http.ServeMux, st *webStore) {
	auth := newWebAuth(webAuthSecret(st.db))

	// POST /v1/invite-org/signup — invite emails to an org. SMTP is not wired,
	// so no mail is sent and completeInviteLinks is empty; the membership-pending
	// records persist so the members table reflects the invite.
	mux.HandleFunc("POST /v1/invite-org/signup", func(w http.ResponseWriter, r *http.Request) {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		var req struct {
			InviteeEmails        []string `json:"inviteeEmails"`
			OrganizationRoleSlug string   `json:"organizationRoleSlug"`
			OrganizationID       string   `json:"organizationId"`
		}
		_ = decode(w, r, &req)
		orgID := req.OrganizationID
		if orgID == "" {
			orgID = cl.OrgID
		}
		for _, email := range req.InviteeEmails {
			email = strings.ToLower(strings.TrimSpace(email))
			if email == "" {
				continue
			}
			id := newID()
			_ = st.putJSON(miscKey("org-invite", orgID+"/"+id), map[string]any{
				"id": id, "orgId": orgID, "email": email,
				"role": req.OrganizationRoleSlug, "status": "invited",
				"createdAt": time.Now().UTC(),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":             "Successfully invited user to organization",
			"completeInviteLinks": []any{},
		})
	})

	// POST /v1/invite-org/signup-resend — re-issue an invite. No SMTP → no link.
	mux.HandleFunc("POST /v1/invite-org/signup-resend", func(w http.ResponseWriter, r *http.Request) {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		var req struct {
			MembershipID string `json:"membershipId"`
		}
		_ = decode(w, r, &req)
		// signupToken omitted (no email delivery) — UI handles its absence.
		writeJSON(w, http.StatusOK, map[string]any{})
	})

	// POST /v1/invite-org/verify — verify an invite code (public, pre-auth).
	mux.HandleFunc("POST /v1/invite-org/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email          string `json:"email"`
			Code           string `json:"code"`
			OrganizationID string `json:"organizationId"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "Successfully verified invite",
			"user":    map[string]any{"email": strings.ToLower(strings.TrimSpace(req.Email))},
		})
	})
}
