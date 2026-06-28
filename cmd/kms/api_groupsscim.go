// Groups + SCIM provisioning surface (org-level access groups & directory sync).
//
// groups (/v1/groups):
//
//	GET    /v1/groups/{id}                                  {...group}
//	POST   /v1/groups                                       {...group}
//	PATCH  /v1/groups/{id}                                  {...group}
//	DELETE /v1/groups/{id}                                  {...group}
//	GET    /v1/groups/{id}/users                            {users, totalCount}
//	GET    /v1/groups/{id}/members                          {members, totalCount}
//	GET    /v1/groups/{id}/machine-identities              {machineIdentities, totalCount}
//	GET    /v1/groups/{id}/projects                         {projects, totalCount}
//	POST/DELETE /v1/groups/{id}/users/{username}            {...group}
//	POST/DELETE /v1/groups/{id}/machine-identities/{identityId} {id,name}
//	GET    /v1/organization/{organizationId}/groups         {groups: [...]}
//
// externalGroupOrgRoleMappings (SCIM IdP-group → org-role bindings):
//
//	GET/PUT /v1/scim/group-org-role-mappings               [...mappings]
//
// githubOrgSyncConfig (GitHub-team → KMS-group directory sync):
//
//	GET/POST/PATCH/DELETE /v1/github-org-sync-config        {githubOrgSyncConfig}
//	POST /v1/github-org-sync-config/sync-all-teams          {sync summary}
//
// scim (SCIM 2.0 provisioning tokens + audit events):
//
//	GET/POST /v1/scim/scim-tokens                           {scimTokens|scimToken}
//	DELETE   /v1/scim/scim-tokens/{scimTokenId}             {ok}
//	GET      /v1/scim/scim-events                           {scimEvents: [...]}
//
// All entities persist as JSON-KV in ZapDB under "kms/groups/…",
// "kms/group-mappings/…", "kms/github-sync/…", "kms/scim-tokens/…".
// Group user/identity memberships live inline on the group entity.
//
// Stubs (config persisted, heavy logic not implemented): GitHub team sync
// (sync-all-teams returns an empty plausible summary — no live GitHub API
// walk); SCIM events list (returns []; the SCIM 2.0 /scim/v2 provisioning
// protocol itself is a separate IdP-facing surface, out of scope here).
package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── domain entities ───────────────────────────────────────────────────────

// groupMember is an inline membership row (user or machine identity).
type groupMember struct {
	ID        string    `json:"id"`        // user-id or identity-id
	Name      string    `json:"name"`      // identity name (machine) / display (user)
	Email     string    `json:"email"`     // user only
	Username  string    `json:"username"`  // user only
	FirstName string    `json:"firstName"` // user only
	LastName  string    `json:"lastName"`  // user only
	JoinedAt  time.Time `json:"joinedGroupAt"`
}

type group struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Slug       string        `json:"slug"`
	OrgID      string        `json:"orgId"`
	Role       string        `json:"role"`
	RoleID     string        `json:"roleId"`
	Users      []groupMember `json:"users"`
	Identities []groupMember `json:"identities"`
	CreatedAt  time.Time     `json:"createdAt"`
	UpdatedAt  time.Time     `json:"updatedAt"`
}

func groupKeyID(id string) []byte { return []byte("kms/groups/" + id) }
func groupOrgIdx(orgID, id string) []byte {
	return []byte("kms/groups/by-org/" + orgID + "/" + id)
}
func groupOrgPrefix(orgID string) []byte { return []byte("kms/groups/by-org/" + orgID + "/") }

// externalGroupMapping binds an IdP group name to an org role slug.
type externalGroupMapping struct {
	ID        string    `json:"id"`
	GroupName string    `json:"groupName"`
	Role      string    `json:"role"`
	RoleID    string    `json:"roleId"`
	OrgID     string    `json:"orgId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func groupMappingKey(orgID string) []byte { return []byte("kms/group-mappings/" + orgID) }

type githubSyncConfig struct {
	ID                   string    `json:"id"`
	OrgID                string    `json:"orgId"`
	GithubOrgName        string    `json:"githubOrgName"`
	GithubOrgAccessToken string    `json:"githubOrgAccessToken,omitempty"`
	IsActive             bool      `json:"isActive"`
	CreatedAt            time.Time `json:"createdAt"`
}

func githubSyncKey(orgID string) []byte { return []byte("kms/github-sync/" + orgID) }

type scimToken struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"orgId"`
	Description string    `json:"description"`
	TTLDays     int       `json:"ttlDays"`
	TokenSuffix string    `json:"tokenSuffix"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func scimTokenKey(id string) []byte { return []byte("kms/scim-tokens/" + id) }
func scimTokenOrgIdx(orgID, id string) []byte {
	return []byte("kms/scim-tokens/by-org/" + orgID + "/" + id)
}
func scimTokenOrgPrefix(orgID string) []byte {
	return []byte("kms/scim-tokens/by-org/" + orgID + "/")
}

// groupscimQuery reads an int query param with a fallback.
func groupscimQuery(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func registerGroupsScimAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed resolves the web session; writes 401 and returns nil if absent.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── groups CRUD ───────────────────────────────────────────────────────

	loadGroup := func(id string) (*group, bool) {
		var g group
		if st.getJSON(groupKeyID(id), &g) != nil {
			return nil, false
		}
		return &g, true
	}
	saveGroup := func(g *group) error {
		g.UpdatedAt = time.Now().UTC()
		if err := st.putJSON(groupKeyID(g.ID), g); err != nil {
			return err
		}
		return st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(groupOrgIdx(g.OrgID, g.ID), []byte(g.ID))
		})
	}

	// GET /v1/groups/{id}
	mux.HandleFunc("GET /v1/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		writeJSON(w, http.StatusOK, groupJSON(g))
	})

	// POST /v1/groups
	mux.HandleFunc("POST /v1/groups", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct{ Name, Slug, Role string }
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("group name required"))
			return
		}
		if req.Slug == "" {
			req.Slug = slugify(req.Name)
		}
		role := req.Role
		if role == "" {
			role = "no-access"
		}
		now := time.Now().UTC()
		g := &group{
			ID: newID(), Name: req.Name, Slug: req.Slug, OrgID: cl.OrgID,
			Role: role, Users: []groupMember{}, Identities: []groupMember{},
			CreatedAt: now, UpdatedAt: now,
		}
		if err := saveGroup(g); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, groupJSON(g))
	})

	// PATCH /v1/groups/{id}
	mux.HandleFunc("PATCH /v1/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		var req struct{ Name, Slug, Role string }
		_ = decode(w, r, &req)
		if req.Name != "" {
			g.Name = req.Name
		}
		if req.Slug != "" {
			g.Slug = req.Slug
		}
		if req.Role != "" {
			g.Role = req.Role
		}
		_ = saveGroup(g)
		writeJSON(w, http.StatusOK, groupJSON(g))
	})

	// DELETE /v1/groups/{id}
	mux.HandleFunc("DELETE /v1/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(groupKeyID(g.ID))
			return txn.Delete(groupOrgIdx(g.OrgID, g.ID))
		})
		writeJSON(w, http.StatusOK, groupJSON(g))
	})

	// ── group membership lists (paginated, search-filtered in memory) ──────

	// GET /v1/groups/{id}/users
	mux.HandleFunc("GET /v1/groups/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{"users": []any{}, "totalCount": 0})
			return
		}
		rows := filterMembers(g.Users, r.URL.Query().Get("search"))
		page := pageMembers(rows, groupscimQuery(r, "offset", 0), groupscimQuery(r, "limit", 10))
		out := make([]any, 0, len(page))
		for _, m := range page {
			out = append(out, groupUserJSON(m))
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out, "totalCount": len(rows)})
	})

	// GET /v1/groups/{id}/machine-identities
	mux.HandleFunc("GET /v1/groups/{id}/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{"machineIdentities": []any{}, "totalCount": 0})
			return
		}
		rows := filterMembers(g.Identities, r.URL.Query().Get("search"))
		page := pageMembers(rows, groupscimQuery(r, "offset", 0), groupscimQuery(r, "limit", 10))
		out := make([]any, 0, len(page))
		for _, m := range page {
			out = append(out, map[string]any{"id": m.ID, "name": m.Name, "joinedGroupAt": m.JoinedAt})
		}
		writeJSON(w, http.StatusOK, map[string]any{"machineIdentities": out, "totalCount": len(rows)})
	})

	// GET /v1/groups/{id}/members — unified user+identity view.
	mux.HandleFunc("GET /v1/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{"members": []any{}, "totalCount": 0})
			return
		}
		all := make([]map[string]any, 0, len(g.Users)+len(g.Identities))
		search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
		matches := func(s string) bool { return search == "" || strings.Contains(strings.ToLower(s), search) }
		for _, m := range g.Users {
			if matches(m.Username) || matches(m.Email) || matches(m.FirstName) || matches(m.LastName) {
				all = append(all, map[string]any{
					"id": m.ID, "joinedGroupAt": m.JoinedAt, "type": "user",
					"user": map[string]any{
						"email": m.Email, "username": m.Username,
						"firstName": m.FirstName, "lastName": m.LastName,
					},
				})
			}
		}
		for _, m := range g.Identities {
			if matches(m.Name) {
				all = append(all, map[string]any{
					"id": m.ID, "joinedGroupAt": m.JoinedAt, "type": "machineIdentity",
					"machineIdentity": map[string]any{"id": m.ID, "name": m.Name},
				})
			}
		}
		offset, limit := groupscimQuery(r, "offset", 0), groupscimQuery(r, "limit", 10)
		total := len(all)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if limit <= 0 || end > total {
			end = total
		}
		writeJSON(w, http.StatusOK, map[string]any{"members": all[offset:end], "totalCount": total})
	})

	// GET /v1/groups/{id}/projects — group's project assignments (empty until
	// project-group bindings are implemented; correct wrapper so the tab loads).
	mux.HandleFunc("GET /v1/groups/{id}/projects", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"projects": []any{}, "totalCount": 0})
	})

	// ── group user membership add/remove ──────────────────────────────────

	addUser := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		username := r.PathValue("username")
		// Resolve user details if a local user exists; else store username only.
		m := groupMember{ID: username, Username: username, JoinedAt: time.Now().UTC()}
		if u, err := st.UserByEmail(username); err == nil {
			m = groupMember{
				ID: u.ID, Username: u.Username, Email: u.Email,
				FirstName: u.FirstName, LastName: u.LastName, JoinedAt: time.Now().UTC(),
			}
		}
		if !hasMember(g.Users, m.ID) && !hasMemberByUsername(g.Users, username) {
			g.Users = append(g.Users, m)
			_ = saveGroup(g)
		}
		writeJSON(w, http.StatusOK, groupJSON(g))
	}
	removeUser := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		username := r.PathValue("username")
		kept := g.Users[:0]
		for _, m := range g.Users {
			if m.ID != username && m.Username != username {
				kept = append(kept, m)
			}
		}
		g.Users = kept
		_ = saveGroup(g)
		writeJSON(w, http.StatusOK, groupJSON(g))
	}
	mux.HandleFunc("POST /v1/groups/{id}/users/{username}", addUser)
	mux.HandleFunc("DELETE /v1/groups/{id}/users/{username}", removeUser)

	// ── group machine-identity membership add/remove ──────────────────────

	addIdentity := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		iid := r.PathValue("identityId")
		if !hasMember(g.Identities, iid) {
			g.Identities = append(g.Identities, groupMember{ID: iid, Name: iid, JoinedAt: time.Now().UTC()})
			_ = saveGroup(g)
		}
		var found2 groupMember
		for _, m := range g.Identities {
			if m.ID == iid {
				found2 = m
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": found2.ID, "name": found2.Name})
	}
	removeIdentity := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		g, found := loadGroup(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("group not found"))
			return
		}
		iid := r.PathValue("identityId")
		kept := g.Identities[:0]
		for _, m := range g.Identities {
			if m.ID != iid {
				kept = append(kept, m)
			}
		}
		g.Identities = kept
		_ = saveGroup(g)
		writeJSON(w, http.StatusOK, map[string]any{"id": iid, "name": iid})
	}
	mux.HandleFunc("POST /v1/groups/{id}/machine-identities/{identityId}", addIdentity)
	mux.HandleFunc("DELETE /v1/groups/{id}/machine-identities/{identityId}", removeIdentity)

	// GET /v1/organization/{organizationId}/groups — all groups in an org.
	mux.HandleFunc("GET /v1/organization/{organizationId}/groups", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		out := make([]any, 0)
		for _, g := range groupsForOrg(st, r.PathValue("organizationId")) {
			out = append(out, groupJSON(g))
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": out})
	})

	// ── externalGroupOrgRoleMappings ──────────────────────────────────────

	// GET /v1/scim/group-org-role-mappings
	mux.HandleFunc("GET /v1/scim/group-org-role-mappings", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		writeJSON(w, http.StatusOK, loadGroupMappings(st, cl.OrgID))
	})

	// PUT /v1/scim/group-org-role-mappings — full replace.
	mux.HandleFunc("PUT /v1/scim/group-org-role-mappings", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Mappings []struct {
				GroupName string `json:"groupName"`
				RoleSlug  string `json:"roleSlug"`
			} `json:"mappings"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		out := make([]externalGroupMapping, 0, len(req.Mappings))
		for _, m := range req.Mappings {
			out = append(out, externalGroupMapping{
				ID: newID(), GroupName: m.GroupName, Role: m.RoleSlug, RoleID: m.RoleSlug,
				OrgID: cl.OrgID, CreatedAt: now, UpdatedAt: now,
			})
		}
		_ = st.putJSON(groupMappingKey(cl.OrgID), out)
		writeJSON(w, http.StatusOK, loadGroupMappings(st, cl.OrgID))
	})

	// ── githubOrgSyncConfig ───────────────────────────────────────────────

	// GET /v1/github-org-sync-config
	mux.HandleFunc("GET /v1/github-org-sync-config", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var c githubSyncConfig
		if st.getJSON(githubSyncKey(cl.OrgID), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("github org sync config not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"githubOrgSyncConfig": githubSyncJSON(&c)})
	})

	// POST /v1/github-org-sync-config
	mux.HandleFunc("POST /v1/github-org-sync-config", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			GithubOrgName        string `json:"githubOrgName"`
			GithubOrgAccessToken string `json:"githubOrgAccessToken"`
			IsActive             *bool  `json:"isActive"`
		}
		if !decode(w, r, &req) {
			return
		}
		c := githubSyncConfig{
			ID: newID(), OrgID: cl.OrgID, GithubOrgName: req.GithubOrgName,
			GithubOrgAccessToken: req.GithubOrgAccessToken, IsActive: req.IsActive != nil && *req.IsActive,
			CreatedAt: time.Now().UTC(),
		}
		_ = st.putJSON(githubSyncKey(cl.OrgID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"githubOrgSyncConfig": githubSyncJSON(&c)})
	})

	// PATCH /v1/github-org-sync-config
	mux.HandleFunc("PATCH /v1/github-org-sync-config", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var c githubSyncConfig
		if st.getJSON(githubSyncKey(cl.OrgID), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("github org sync config not found"))
			return
		}
		var req struct {
			GithubOrgName        *string `json:"githubOrgName"`
			GithubOrgAccessToken *string `json:"githubOrgAccessToken"`
			IsActive             *bool   `json:"isActive"`
		}
		_ = decode(w, r, &req)
		if req.GithubOrgName != nil {
			c.GithubOrgName = *req.GithubOrgName
		}
		if req.GithubOrgAccessToken != nil {
			c.GithubOrgAccessToken = *req.GithubOrgAccessToken
		}
		if req.IsActive != nil {
			c.IsActive = *req.IsActive
		}
		_ = st.putJSON(githubSyncKey(cl.OrgID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"githubOrgSyncConfig": githubSyncJSON(&c)})
	})

	// DELETE /v1/github-org-sync-config
	mux.HandleFunc("DELETE /v1/github-org-sync-config", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(githubSyncKey(cl.OrgID)) })
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// POST /v1/github-org-sync-config/sync-all-teams — STUB: persisting the
	// config is real, but walking the live GitHub org/teams API and
	// reconciling memberships is not implemented. Returns a zeroed, correctly
	// shaped summary so the UI flow completes without error.
	mux.HandleFunc("POST /v1/github-org-sync-config/sync-all-teams", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"totalUsers": 0, "errors": []string{}, "createdTeams": []string{},
			"updatedTeams": []string{}, "removedMemberships": 0, "syncDuration": 0,
		})
	})

	// ── scim tokens + events ──────────────────────────────────────────────

	// GET /v1/scim/scim-tokens?organizationId=
	mux.HandleFunc("GET /v1/scim/scim-tokens", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		orgID := r.URL.Query().Get("organizationId")
		if orgID == "" {
			orgID = cl.OrgID
		}
		out := make([]any, 0)
		for _, t := range scimTokensForOrg(st, orgID) {
			out = append(out, scimTokenJSON(t))
		}
		writeJSON(w, http.StatusOK, map[string]any{"scimTokens": out})
	})

	// POST /v1/scim/scim-tokens — mints an opaque bearer (returned ONCE).
	mux.HandleFunc("POST /v1/scim/scim-tokens", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			OrganizationID string `json:"organizationId"`
			Description    string `json:"description"`
			TTLDays        int    `json:"ttlDays"`
		}
		_ = decode(w, r, &req)
		orgID := req.OrganizationID
		if orgID == "" {
			orgID = cl.OrgID
		}
		secret := newID() + newID() // 32-byte opaque token
		now := time.Now().UTC()
		t := &scimToken{
			ID: newID(), OrgID: orgID, Description: req.Description, TTLDays: req.TTLDays,
			TokenSuffix: secret[len(secret)-4:], CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(scimTokenKey(t.ID), t)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(scimTokenOrgIdx(orgID, t.ID), []byte(t.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"scimToken": "scim_" + secret})
	})

	// DELETE /v1/scim/scim-tokens/{scimTokenId}
	mux.HandleFunc("DELETE /v1/scim/scim-tokens/{scimTokenId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var t scimToken
		if st.getJSON(scimTokenKey(r.PathValue("scimTokenId")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("scim token not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(scimTokenKey(t.ID))
			return txn.Delete(scimTokenOrgIdx(t.OrgID, t.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"scimToken": scimTokenJSON(&t)})
	})

	// GET /v1/scim/scim-events — SCIM provisioning audit log. Empty until the
	// SCIM 2.0 IdP-facing surface emits events.
	mux.HandleFunc("GET /v1/scim/scim-events", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"scimEvents": []any{}})
	})
}

// ── helpers (area-prefixed; unique) ───────────────────────────────────────

func groupsForOrg(st *webStore, orgID string) []*group {
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = groupOrgPrefix(orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := groupOrgPrefix(orgID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	out := make([]*group, 0, len(ids))
	for _, id := range ids {
		var g group
		if st.getJSON(groupKeyID(id), &g) == nil {
			out = append(out, &g)
		}
	}
	return out
}

func scimTokensForOrg(st *webStore, orgID string) []*scimToken {
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = scimTokenOrgPrefix(orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := scimTokenOrgPrefix(orgID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	out := make([]*scimToken, 0, len(ids))
	for _, id := range ids {
		var t scimToken
		if st.getJSON(scimTokenKey(id), &t) == nil {
			out = append(out, &t)
		}
	}
	return out
}

func loadGroupMappings(st *webStore, orgID string) []any {
	var rows []externalGroupMapping
	_ = st.getJSON(groupMappingKey(orgID), &rows)
	out := make([]any, 0, len(rows))
	for _, m := range rows {
		out = append(out, map[string]any{
			"id": m.ID, "groupName": m.GroupName, "role": m.Role, "roleId": m.RoleID,
			"orgId": m.OrgID, "createdAt": m.CreatedAt, "updatedAt": m.UpdatedAt,
		})
	}
	return out
}

func filterMembers(in []groupMember, search string) []groupMember {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return in
	}
	out := make([]groupMember, 0, len(in))
	for _, m := range in {
		hay := strings.ToLower(m.Username + " " + m.Email + " " + m.FirstName + " " + m.LastName + " " + m.Name)
		if strings.Contains(hay, search) {
			out = append(out, m)
		}
	}
	return out
}

func pageMembers(in []groupMember, offset, limit int) []groupMember {
	total := len(in)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	return in[offset:end]
}

func hasMember(in []groupMember, id string) bool {
	for _, m := range in {
		if m.ID == id {
			return true
		}
	}
	return false
}

func hasMemberByUsername(in []groupMember, username string) bool {
	for _, m := range in {
		if m.Username == username {
			return true
		}
	}
	return false
}

func groupJSON(g *group) map[string]any {
	return map[string]any{
		"id": g.ID, "name": g.Name, "slug": g.Slug, "orgId": g.OrgID,
		"role": g.Role, "roleId": g.RoleID,
		"createdAt": g.CreatedAt, "updatedAt": g.UpdatedAt,
	}
}

func groupUserJSON(m groupMember) map[string]any {
	return map[string]any{
		"id": m.ID, "email": m.Email, "username": m.Username,
		"firstName": m.FirstName, "lastName": m.LastName, "joinedGroupAt": m.JoinedAt,
	}
}

func githubSyncJSON(c *githubSyncConfig) map[string]any {
	return map[string]any{
		"id": c.ID, "orgId": c.OrgID, "githubOrgName": c.GithubOrgName,
		"isActive": c.IsActive, "createdAt": c.CreatedAt,
	}
}

func scimTokenJSON(t *scimToken) map[string]any {
	return map[string]any{
		"id": t.ID, "ttlDays": t.TTLDays, "description": t.Description,
		"tokenSuffix": t.TokenSuffix, "orgId": t.OrgID,
		"createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt,
	}
}
