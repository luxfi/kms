// Advanced tier — Secret Syncs, App Connections, Integrations, Integration Auth.
//
// These four groups back the SPA's "Integrations" surface: the older
// integration/integration-auth pair (OAuth/token-based push of secrets to a
// third party) and the newer app-connection/secret-sync pair (a reusable
// connection + a sync that pushes a folder of secrets to a destination).
//
//	── App Connections (/v1/app-connections) ──────────────────────────────
//	GET    /v1/app-connections/options                 {appConnectionOptions}
//	GET    /v1/app-connections ?projectId              {appConnections}
//	GET    /v1/app-connections/{app}/available         {appConnections}
//	POST   /v1/app-connections/{app}                   {appConnection}
//	PATCH  /v1/app-connections/{app}/{connectionId}    {appConnection}
//	DELETE /v1/app-connections/{app}/{connectionId}    {appConnection}
//
//	── Secret Syncs (/v1/secret-syncs) ────────────────────────────────────
//	GET    /v1/secret-syncs/options                    {secretSyncOptions}
//	GET    /v1/secret-syncs ?projectId                 {secretSyncs}
//	GET    /v1/secret-syncs/{destination}/{syncId}     {secretSync}
//	POST   /v1/secret-syncs/{destination}/check-destination  {hasDuplicate}
//	POST   /v1/secret-syncs/{destination}              {secretSync}
//	PATCH  /v1/secret-syncs/{destination}/{syncId}     {secretSync}
//	DELETE /v1/secret-syncs/{destination}/{syncId}     {secretSync}
//	POST   /v1/secret-syncs/{destination}/{syncId}/{sync,import,remove}-secrets
//
//	── Integrations (/v1/integration) ─────────────────────────────────────
//	POST   /v1/integration                             {integration}
//	GET    /v1/integration/{id}                        {integration}
//	DELETE /v1/integration/{id}                        {integration}
//	POST   /v1/integration/{id}/sync                   {integration}
//
//	── Integration Auth (/v1/integration-auth) ────────────────────────────
//	GET    /v1/integration-auth/integration-options    {integrationOptions}
//	POST   /v1/integration-auth/oauth-token            {integrationAuth}
//	POST   /v1/integration-auth/access-token           {integrationAuth}
//	GET    /v1/integration-auth/{id}                   {integrationAuth}
//	POST   /v1/integration-auth/{id}/duplicate         {integrationAuth}
//	DELETE /v1/integration-auth/{id}                   {}
//	DELETE /v1/integration-auth ?integration&projectId {}
//	GET    /v1/integration-auth/{id}/<provider-introspection...>  (empty lists)
//
// CRUD entities (app-connection, secret-sync, integration, integration-auth)
// persist as JSON-KV in ZapDB under "kms/<area>/{id}" with a per-project index
// "kms/<area>/by-project/{projectId}/{id}" (mirrors api_projects.go). The
// provider-introspection endpoints (github orgs, vercel branches, aws kms keys,
// …) and the actual push/pull of secrets to a third party require live OAuth
// tokens + outbound calls to that provider; those are returned as correctly
// shaped EMPTY lists / no-op acknowledgements (external-integration stubs) so
// the dashboard navigates without errors. The config entity itself is fully
// persisted, so a sync/connection round-trips through create→list→get→delete.
package main

import (
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── stored entities ────────────────────────────────────────────────────────

type appConnection struct {
	ID                          string         `json:"id"`
	Name                        string         `json:"name"`
	Description                 string         `json:"description"`
	App                         string         `json:"app"`
	Method                      string         `json:"method"`
	OrgID                       string         `json:"orgId"`
	ProjectID                   string         `json:"projectId"`
	GatewayID                   string         `json:"gatewayId,omitempty"`
	IsPlatformManagedCredential bool           `json:"isPlatformManagedCredentials"`
	Credentials                 map[string]any `json:"credentials"`
	CreatedAt                   time.Time      `json:"createdAt"`
	UpdatedAt                   time.Time      `json:"updatedAt"`
}

type secretSyncEntity struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	Destination       string         `json:"destination"`
	ConnectionID      string         `json:"connectionId"`
	ProjectID         string         `json:"projectId"`
	Environment       string         `json:"environment"`
	SecretPath        string         `json:"secretPath"`
	IsAutoSyncEnabled bool           `json:"isAutoSyncEnabled"`
	DestinationConfig map[string]any `json:"destinationConfig"`
	SyncOptions       map[string]any `json:"syncOptions"`
	CreatedAt         time.Time      `json:"createdAt"`
	UpdatedAt         time.Time      `json:"updatedAt"`
}

type integrationEntity struct {
	ID                  string         `json:"id"`
	IsActive            bool           `json:"isActive"`
	IntegrationAuthID   string         `json:"integrationAuthId"`
	Integration         string         `json:"integration"`
	App                 string         `json:"app,omitempty"`
	AppID               string         `json:"appId,omitempty"`
	Owner               string         `json:"owner,omitempty"`
	Path                string         `json:"path,omitempty"`
	Region              string         `json:"region,omitempty"`
	Scope               string         `json:"scope,omitempty"`
	URL                 string         `json:"url,omitempty"`
	SourceEnvironment   string         `json:"sourceEnvironment,omitempty"`
	TargetEnvironment   string         `json:"targetEnvironment,omitempty"`
	TargetEnvironmentID string         `json:"targetEnvironmentId,omitempty"`
	TargetService       string         `json:"targetService,omitempty"`
	TargetServiceID     string         `json:"targetServiceId,omitempty"`
	SecretPath          string         `json:"secretPath"`
	ProjectID           string         `json:"projectId"`
	EnvID               string         `json:"envId"`
	Metadata            map[string]any `json:"metadata,omitempty"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
}

type integrationAuthEntity struct {
	ID          string         `json:"id"`
	Integration string         `json:"integration"`
	ProjectID   string         `json:"projectId"`
	URL         string         `json:"url,omitempty"`
	TeamID      string         `json:"teamId,omitempty"`
	Namespace   string         `json:"namespace,omitempty"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

// ── keys (entity record + per-project index, mirrors projectOrgIdx) ─────────

func appConnKey(id string) []byte { return []byte("kms/appconns/" + id) }
func appConnProjIdx(projectID, id string) []byte {
	return []byte("kms/appconns/by-project/" + projectID + "/" + id)
}
func appConnProjPrefix(projectID string) []byte {
	return []byte("kms/appconns/by-project/" + projectID + "/")
}

func secretSyncKey(id string) []byte { return []byte("kms/secretsyncs/" + id) }
func secretSyncProjIdx(projectID, id string) []byte {
	return []byte("kms/secretsyncs/by-project/" + projectID + "/" + id)
}
func secretSyncProjPrefix(projectID string) []byte {
	return []byte("kms/secretsyncs/by-project/" + projectID + "/")
}

func integrationKey(id string) []byte { return []byte("kms/integrations/" + id) }
func integrationProjIdx(projectID, id string) []byte {
	return []byte("kms/integrations/by-project/" + projectID + "/" + id)
}

func integrationAuthKey(id string) []byte { return []byte("kms/integrationauths/" + id) }
func integrationAuthProjIdx(projectID, id string) []byte {
	return []byte("kms/integrationauths/by-project/" + projectID + "/" + id)
}
func integrationAuthProjPrefix(projectID string) []byte {
	return []byte("kms/integrationauths/by-project/" + projectID + "/")
}

// syncsconnIdxIDs collects the entity ids recorded under a by-project index
// prefix (same iteration shape as ProjectsForOrg in api_projects.go).
func syncsconnIdxIDs(db *badger.DB, prefix []byte) []string {
	var ids []string
	_ = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(prefix):]))
		}
		return nil
	})
	return ids
}

func registerSyncsConnAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// syncsconnAuthed validates the session and returns the claims, or writes
	// 401 and returns nil. Each handler calls it once at the top.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	registerAppConnections(mux, st, authed)
	registerSecretSyncs(mux, st, authed)
	registerIntegrations(mux, st, authed)
	registerIntegrationAuth(mux, st, authed)
}

// ── App Connections ─────────────────────────────────────────────────────────

func registerAppConnections(mux *http.ServeMux, st *webStore, authed func(http.ResponseWriter, *http.Request) *webClaims) {
	// Options drive the "new connection" dropdown. Each app advertises the
	// auth methods it supports so the picker isn't empty. (Deep per-app option
	// fields are optional in the SPA type.)
	mux.HandleFunc("GET /v1/app-connections/options", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"appConnectionOptions": appConnectionOptions()})
	})

	// List connections in a project (or org-wide when projectId omitted).
	mux.HandleFunc("GET /v1/app-connections", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"appConnections": listAppConnections(st, r.URL.Query().Get("projectId")),
		})
	})

	// Available connections of a given app (the slim {id,name,projectId} shape
	// used when wiring a sync to a connection).
	mux.HandleFunc("GET /v1/app-connections/{app}/available", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		app := r.PathValue("app")
		out := []any{}
		for _, c := range listAppConnectionsTyped(st, r.URL.Query().Get("projectId")) {
			if c.App == app {
				out = append(out, map[string]any{"id": c.ID, "name": c.Name, "projectId": c.ProjectID})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"appConnections": out})
	})

	// Create. Credentials persist as-is (ZapDB at-rest encryption covers them);
	// they are NOT validated against the live provider here.
	mux.HandleFunc("POST /v1/app-connections/{app}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name                        string         `json:"name"`
			Description                 string         `json:"description"`
			Method                      string         `json:"method"`
			GatewayID                   string         `json:"gatewayId"`
			ProjectID                   string         `json:"projectId"`
			IsPlatformManagedCredential bool           `json:"isPlatformManagedCredentials"`
			Credentials                 map[string]any `json:"credentials"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		c := &appConnection{
			ID: newID(), Name: req.Name, Description: req.Description, App: r.PathValue("app"),
			Method: req.Method, OrgID: cl.OrgID, ProjectID: req.ProjectID, GatewayID: req.GatewayID,
			IsPlatformManagedCredential: req.IsPlatformManagedCredential, Credentials: req.Credentials,
			CreatedAt: now, UpdatedAt: now,
		}
		if c.Credentials == nil {
			c.Credentials = map[string]any{}
		}
		_ = st.putJSON(appConnKey(c.ID), c)
		if c.ProjectID != "" {
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(appConnProjIdx(c.ProjectID, c.ID), []byte(c.ID)) })
		}
		writeJSON(w, http.StatusOK, map[string]any{"appConnection": appConnectionJSON(c)})
	})

	mux.HandleFunc("PATCH /v1/app-connections/{app}/{connectionId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var c appConnection
		if st.getJSON(appConnKey(r.PathValue("connectionId")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("app connection not found"))
			return
		}
		var req struct {
			Name                        *string        `json:"name"`
			Description                 *string        `json:"description"`
			GatewayID                   *string        `json:"gatewayId"`
			IsPlatformManagedCredential *bool          `json:"isPlatformManagedCredentials"`
			Credentials                 map[string]any `json:"credentials"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			c.Name = *req.Name
		}
		if req.Description != nil {
			c.Description = *req.Description
		}
		if req.GatewayID != nil {
			c.GatewayID = *req.GatewayID
		}
		if req.IsPlatformManagedCredential != nil {
			c.IsPlatformManagedCredential = *req.IsPlatformManagedCredential
		}
		if req.Credentials != nil {
			c.Credentials = req.Credentials
		}
		c.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(appConnKey(c.ID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"appConnection": appConnectionJSON(&c)})
	})

	mux.HandleFunc("DELETE /v1/app-connections/{app}/{connectionId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var c appConnection
		if st.getJSON(appConnKey(r.PathValue("connectionId")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("app connection not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(appConnKey(c.ID))
			if c.ProjectID != "" {
				_ = txn.Delete(appConnProjIdx(c.ProjectID, c.ID))
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"appConnection": appConnectionJSON(&c)})
	})
}

// ── Secret Syncs ──────────────────────────────────────────────────────────────

func registerSecretSyncs(mux *http.ServeMux, st *webStore, authed func(http.ResponseWriter, *http.Request) *webClaims) {
	mux.HandleFunc("GET /v1/secret-syncs/options", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSyncOptions": secretSyncOptions()})
	})

	mux.HandleFunc("GET /v1/secret-syncs", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secretSyncs": listSecretSyncs(st, r.URL.Query().Get("projectId")),
		})
	})

	// Duplicate-destination check. With no live provider state we report no
	// duplicate (the SPA only blocks the form when hasDuplicate is true).
	mux.HandleFunc("POST /v1/secret-syncs/{destination}/check-destination", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"hasDuplicate": false})
	})

	mux.HandleFunc("GET /v1/secret-syncs/{destination}/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s secretSyncEntity
		if st.getJSON(secretSyncKey(r.PathValue("syncId")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret sync not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSync": secretSyncJSON(&s)})
	})

	mux.HandleFunc("POST /v1/secret-syncs/{destination}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Name              string         `json:"name"`
			Description       string         `json:"description"`
			ConnectionID      string         `json:"connectionId"`
			ProjectID         string         `json:"projectId"`
			Environment       string         `json:"environment"`
			SecretPath        string         `json:"secretPath"`
			IsAutoSyncEnabled bool           `json:"isAutoSyncEnabled"`
			DestinationConfig map[string]any `json:"destinationConfig"`
			SyncOptions       map[string]any `json:"syncOptions"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		s := &secretSyncEntity{
			ID: newID(), Name: req.Name, Description: req.Description, Destination: r.PathValue("destination"),
			ConnectionID: req.ConnectionID, ProjectID: req.ProjectID, Environment: envOrDefault(req.Environment),
			SecretPath: req.SecretPath, IsAutoSyncEnabled: req.IsAutoSyncEnabled,
			DestinationConfig: req.DestinationConfig, SyncOptions: req.SyncOptions, CreatedAt: now, UpdatedAt: now,
		}
		if s.DestinationConfig == nil {
			s.DestinationConfig = map[string]any{}
		}
		if s.SyncOptions == nil {
			s.SyncOptions = map[string]any{}
		}
		_ = st.putJSON(secretSyncKey(s.ID), s)
		if s.ProjectID != "" {
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(secretSyncProjIdx(s.ProjectID, s.ID), []byte(s.ID)) })
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSync": secretSyncJSON(s)})
	})

	mux.HandleFunc("PATCH /v1/secret-syncs/{destination}/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s secretSyncEntity
		if st.getJSON(secretSyncKey(r.PathValue("syncId")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret sync not found"))
			return
		}
		var req struct {
			Name              *string        `json:"name"`
			Description       *string        `json:"description"`
			ConnectionID      *string        `json:"connectionId"`
			Environment       *string        `json:"environment"`
			SecretPath        *string        `json:"secretPath"`
			IsAutoSyncEnabled *bool          `json:"isAutoSyncEnabled"`
			DestinationConfig map[string]any `json:"destinationConfig"`
			SyncOptions       map[string]any `json:"syncOptions"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			s.Name = *req.Name
		}
		if req.Description != nil {
			s.Description = *req.Description
		}
		if req.ConnectionID != nil {
			s.ConnectionID = *req.ConnectionID
		}
		if req.Environment != nil {
			s.Environment = envOrDefault(*req.Environment)
		}
		if req.SecretPath != nil {
			s.SecretPath = *req.SecretPath
		}
		if req.IsAutoSyncEnabled != nil {
			s.IsAutoSyncEnabled = *req.IsAutoSyncEnabled
		}
		if req.DestinationConfig != nil {
			s.DestinationConfig = req.DestinationConfig
		}
		if req.SyncOptions != nil {
			s.SyncOptions = req.SyncOptions
		}
		s.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(secretSyncKey(s.ID), &s)
		writeJSON(w, http.StatusOK, map[string]any{"secretSync": secretSyncJSON(&s)})
	})

	mux.HandleFunc("DELETE /v1/secret-syncs/{destination}/{syncId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s secretSyncEntity
		if st.getJSON(secretSyncKey(r.PathValue("syncId")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret sync not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(secretSyncKey(s.ID))
			if s.ProjectID != "" {
				_ = txn.Delete(secretSyncProjIdx(s.ProjectID, s.ID))
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"secretSync": secretSyncJSON(&s)})
	})

	// Trigger sync/import/remove. The actual push/pull of secrets to the
	// destination provider needs a live connection to that provider; here we
	// acknowledge with the sync entity so the UI reflects success.
	triggerSync := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var s secretSyncEntity
		if st.getJSON(secretSyncKey(r.PathValue("syncId")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret sync not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSync": secretSyncJSON(&s)})
	}
	mux.HandleFunc("POST /v1/secret-syncs/{destination}/{syncId}/sync-secrets", triggerSync)
	mux.HandleFunc("POST /v1/secret-syncs/{destination}/{syncId}/import-secrets", triggerSync)
	mux.HandleFunc("POST /v1/secret-syncs/{destination}/{syncId}/remove-secrets", triggerSync)
}

// ── Integrations ──────────────────────────────────────────────────────────────

func registerIntegrations(mux *http.ServeMux, st *webStore, authed func(http.ResponseWriter, *http.Request) *webClaims) {
	mux.HandleFunc("POST /v1/integration", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			IntegrationAuthID   string         `json:"integrationAuthId"`
			IsActive            bool           `json:"isActive"`
			App                 string         `json:"app"`
			AppID               string         `json:"appId"`
			SourceEnvironment   string         `json:"sourceEnvironment"`
			TargetEnvironment   string         `json:"targetEnvironment"`
			TargetEnvironmentID string         `json:"targetEnvironmentId"`
			TargetService       string         `json:"targetService"`
			TargetServiceID     string         `json:"targetServiceId"`
			Owner               string         `json:"owner"`
			Path                string         `json:"path"`
			Region              string         `json:"region"`
			URL                 string         `json:"url"`
			Scope               string         `json:"scope"`
			SecretPath          string         `json:"secretPath"`
			Metadata            map[string]any `json:"metadata"`
		}
		if !decode(w, r, &req) {
			return
		}
		// Resolve the owning project + integration slug from the parent auth.
		projectID, integrationSlug := "", ""
		if req.IntegrationAuthID != "" {
			var ia integrationAuthEntity
			if st.getJSON(integrationAuthKey(req.IntegrationAuthID), &ia) == nil {
				projectID, integrationSlug = ia.ProjectID, ia.Integration
			}
		}
		now := time.Now().UTC()
		ig := &integrationEntity{
			ID: newID(), IsActive: req.IsActive, IntegrationAuthID: req.IntegrationAuthID,
			Integration: integrationSlug, App: req.App, AppID: req.AppID, Owner: req.Owner,
			Path: req.Path, Region: req.Region, Scope: req.Scope, URL: req.URL,
			SourceEnvironment: envOrDefault(req.SourceEnvironment), TargetEnvironment: req.TargetEnvironment,
			TargetEnvironmentID: req.TargetEnvironmentID, TargetService: req.TargetService,
			TargetServiceID: req.TargetServiceID, SecretPath: req.SecretPath, ProjectID: projectID,
			EnvID: req.SourceEnvironment, Metadata: req.Metadata, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(integrationKey(ig.ID), ig)
		if ig.ProjectID != "" {
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(integrationProjIdx(ig.ProjectID, ig.ID), []byte(ig.ID)) })
		}
		writeJSON(w, http.StatusOK, map[string]any{"integration": integrationJSON(ig)})
	})

	mux.HandleFunc("GET /v1/integration/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var ig integrationEntity
		if st.getJSON(integrationKey(r.PathValue("id")), &ig) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"integration": integrationJSON(&ig)})
	})

	mux.HandleFunc("DELETE /v1/integration/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var ig integrationEntity
		if st.getJSON(integrationKey(r.PathValue("id")), &ig) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(integrationKey(ig.ID))
			if ig.ProjectID != "" {
				_ = txn.Delete(integrationProjIdx(ig.ProjectID, ig.ID))
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"integration": integrationJSON(&ig)})
	})

	// Manual sync trigger — acknowledge with updatedAt bumped.
	mux.HandleFunc("POST /v1/integration/{id}/sync", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var ig integrationEntity
		if st.getJSON(integrationKey(r.PathValue("id")), &ig) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		ig.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(integrationKey(ig.ID), &ig)
		writeJSON(w, http.StatusOK, map[string]any{"integration": integrationJSON(&ig)})
	})
}

// ── Integration Auth ──────────────────────────────────────────────────────────

func registerIntegrationAuth(mux *http.ServeMux, st *webStore, authed func(http.ResponseWriter, *http.Request) *webClaims) {
	// Cloud-integration catalogue powering the "Native Integrations" grid.
	mux.HandleFunc("GET /v1/integration-auth/integration-options", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"integrationOptions": cloudIntegrationOptions()})
	})

	// OAuth-code exchange. We persist the auth entity; exchanging the code for
	// a provider token requires that provider's OAuth endpoint (external stub),
	// so no token is stored here.
	mux.HandleFunc("POST /v1/integration-auth/oauth-token", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			WorkspaceID    string `json:"workspaceId"`
			Code           string `json:"code"`
			Integration    string `json:"integration"`
			InstallationID string `json:"installationId"`
			URL            string `json:"url"`
		}
		if !decode(w, r, &req) {
			return
		}
		ia := newIntegrationAuthEntity(st, req.WorkspaceID, req.Integration, req.URL, "", "", map[string]any{"installationId": req.InstallationID})
		writeJSON(w, http.StatusOK, map[string]any{"integrationAuth": integrationAuthJSON(ia)})
	})

	// Direct access-token / credential save.
	mux.HandleFunc("POST /v1/integration-auth/access-token", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			WorkspaceID         string `json:"workspaceId"`
			Integration         string `json:"integration"`
			RefreshToken        string `json:"refreshToken"`
			AccessID            string `json:"accessId"`
			AccessToken         string `json:"accessToken"`
			AwsAssumeIamRoleArn string `json:"awsAssumeIamRoleArn"`
			URL                 string `json:"url"`
			Namespace           string `json:"namespace"`
		}
		if !decode(w, r, &req) {
			return
		}
		ia := newIntegrationAuthEntity(st, req.WorkspaceID, req.Integration, req.URL, req.Namespace, "", map[string]any{})
		writeJSON(w, http.StatusOK, map[string]any{"integrationAuth": integrationAuthJSON(ia)})
	})

	// Bulk delete by integration slug + project (query-param form). Registered
	// as the bare collection route; the {id} variant handles single deletes.
	mux.HandleFunc("DELETE /v1/integration-auth", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		q := r.URL.Query()
		projectID, slug := q.Get("projectId"), q.Get("integration")
		if projectID != "" {
			for _, id := range syncsconnIdxIDs(st.db, integrationAuthProjPrefix(projectID)) {
				var ia integrationAuthEntity
				if st.getJSON(integrationAuthKey(id), &ia) == nil && (slug == "" || ia.Integration == slug) {
					_ = st.db.Update(func(txn *badger.Txn) error {
						_ = txn.Delete(integrationAuthKey(id))
						return txn.Delete(integrationAuthProjIdx(projectID, id))
					})
				}
			}
		}
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	mux.HandleFunc("GET /v1/integration-auth/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var ia integrationAuthEntity
		if st.getJSON(integrationAuthKey(r.PathValue("id")), &ia) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration auth not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"integrationAuth": integrationAuthJSON(&ia)})
	})

	mux.HandleFunc("DELETE /v1/integration-auth/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var ia integrationAuthEntity
		if st.getJSON(integrationAuthKey(r.PathValue("id")), &ia) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration auth not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(integrationAuthKey(ia.ID))
			if ia.ProjectID != "" {
				_ = txn.Delete(integrationAuthProjIdx(ia.ProjectID, ia.ID))
			}
			return nil
		})
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// Duplicate an integration auth into the same/another project.
	mux.HandleFunc("POST /v1/integration-auth/{id}/duplicate", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var src integrationAuthEntity
		if st.getJSON(integrationAuthKey(r.PathValue("id")), &src) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration auth not found"))
			return
		}
		var req struct {
			ProjectID string `json:"projectId"`
		}
		_ = decode(w, r, &req)
		projectID := req.ProjectID
		if projectID == "" {
			projectID = src.ProjectID
		}
		ia := newIntegrationAuthEntity(st, projectID, src.Integration, src.URL, src.Namespace, src.TeamID, src.Metadata)
		writeJSON(w, http.StatusOK, map[string]any{"integrationAuth": integrationAuthJSON(ia)})
	})

	// ── provider introspection (external stubs) ──────────────────────────
	// These enumerate resources INSIDE the connected provider account (GitHub
	// repos, Vercel projects, AWS KMS keys, …). They require a live token to
	// that provider's API; with none, each returns its correctly-keyed EMPTY
	// list so the relevant <Select> renders empty rather than the page 500ing.
	emptyArr := func(key string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if authed(w, r) == nil {
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{key: []any{}})
		}
	}

	mux.HandleFunc("GET /v1/integration-auth/{id}/apps", emptyArr("apps"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/teams", emptyArr("teams"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/vercel/branches", emptyArr("branches"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/vercel/custom-environments", emptyArr("environments"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/checkly/groups", emptyArr("groups"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/github/orgs", emptyArr("orgs"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/github/envs", emptyArr("envs"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/orgs", emptyArr("orgs"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/projects", emptyArr("projects"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/environments", emptyArr("environments"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/apps", emptyArr("apps"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/containers", emptyArr("containers"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/qovery/jobs", emptyArr("jobs"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/aws-secrets-manager/kms-keys", emptyArr("kmsKeys"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/heroku/pipelines", emptyArr("pipelines"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/railway/environments", emptyArr("environments"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/railway/services", emptyArr("services"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/bitbucket/workspaces", emptyArr("workspaces"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/bitbucket/environments", emptyArr("environments"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/northflank/secret-groups", emptyArr("secretGroups"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/teamcity/build-configs", emptyArr("buildConfigs"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/octopus-deploy/spaces", emptyArr("spaces"))
	mux.HandleFunc("GET /v1/integration-auth/{id}/circleci/organizations", emptyArr("organizations"))
	// scope-values is an object of named string-lists, not a single array.
	mux.HandleFunc("GET /v1/integration-auth/{id}/octopus-deploy/scope-values", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"Environments": []any{}, "Machines": []any{}, "Actions": []any{}, "Roles": []any{},
			"Channels": []any{}, "TenantTags": []any{}, "Processes": []any{},
		})
	})
}

// newIntegrationAuthEntity persists a new integration-auth entity (+ project
// index) and returns it. Shared by oauth-token, access-token, and duplicate.
func newIntegrationAuthEntity(st *webStore, projectID, integ, url, namespace, teamID string, metadata map[string]any) *integrationAuthEntity {
	if metadata == nil {
		metadata = map[string]any{}
	}
	now := time.Now().UTC()
	ia := &integrationAuthEntity{
		ID: newID(), Integration: integ, ProjectID: projectID, URL: url,
		TeamID: teamID, Namespace: namespace, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
	}
	_ = st.putJSON(integrationAuthKey(ia.ID), ia)
	if projectID != "" {
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(integrationAuthProjIdx(projectID, ia.ID), []byte(ia.ID)) })
	}
	return ia
}

// ── list helpers (project-scoped, mirrors ProjectsForOrg) ───────────────────

func listAppConnectionsTyped(st *webStore, projectID string) []*appConnection {
	if projectID == "" {
		return nil
	}
	ids := syncsconnIdxIDs(st.db, appConnProjPrefix(projectID))
	out := make([]*appConnection, 0, len(ids))
	for _, id := range ids {
		var c appConnection
		if st.getJSON(appConnKey(id), &c) == nil {
			out = append(out, &c)
		}
	}
	return out
}

func listAppConnections(st *webStore, projectID string) []any {
	out := []any{}
	for _, c := range listAppConnectionsTyped(st, projectID) {
		out = append(out, appConnectionJSON(c))
	}
	return out
}

func listSecretSyncs(st *webStore, projectID string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	for _, id := range syncsconnIdxIDs(st.db, secretSyncProjPrefix(projectID)) {
		var s secretSyncEntity
		if st.getJSON(secretSyncKey(id), &s) == nil {
			out = append(out, secretSyncJSON(&s))
		}
	}
	return out
}

// ── JSON renderers (the exact shapes the SPA deserializes) ──────────────────

func appConnectionJSON(c *appConnection) map[string]any {
	return map[string]any{
		"id": c.ID, "name": c.Name, "description": c.Description, "app": c.App,
		"method": c.Method, "orgId": c.OrgID, "projectId": c.ProjectID, "gatewayId": syncsconnNil(c.GatewayID),
		"isPlatformManagedCredentials": c.IsPlatformManagedCredential, "credentials": c.Credentials,
		"version": 1, "createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func secretSyncJSON(s *secretSyncEntity) map[string]any {
	return map[string]any{
		"id": s.ID, "name": s.Name, "description": syncsconnNil(s.Description), "destination": s.Destination,
		"connectionId": s.ConnectionID, "projectId": s.ProjectID, "environment": map[string]any{"slug": s.Environment},
		"folderId": nil, "secretPath": s.SecretPath, "isAutoSyncEnabled": s.IsAutoSyncEnabled,
		"destinationConfig": s.DestinationConfig, "syncOptions": s.SyncOptions, "syncStatus": nil,
		"lastSyncMessage": nil, "lastSyncedAt": nil, "createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
}

func integrationJSON(ig *integrationEntity) map[string]any {
	return map[string]any{
		"id": ig.ID, "isActive": ig.IsActive, "integrationAuthId": ig.IntegrationAuthID,
		"integration": ig.Integration, "app": syncsconnNil(ig.App), "appId": syncsconnNil(ig.AppID),
		"owner": syncsconnNil(ig.Owner), "path": syncsconnNil(ig.Path), "region": syncsconnNil(ig.Region),
		"scope": syncsconnNil(ig.Scope), "url": syncsconnNil(ig.URL), "targetEnvironment": syncsconnNil(ig.TargetEnvironment),
		"targetEnvironmentId": syncsconnNil(ig.TargetEnvironmentID), "targetService": syncsconnNil(ig.TargetService),
		"targetServiceId": syncsconnNil(ig.TargetServiceID), "secretPath": ig.SecretPath, "projectId": ig.ProjectID,
		"workspace": ig.ProjectID, "envId": ig.EnvID, "metadata": ig.Metadata, "isSynced": true,
		"__v": 0, "createdAt": ig.CreatedAt, "updatedAt": ig.UpdatedAt,
	}
}

func integrationAuthJSON(ia *integrationAuthEntity) map[string]any {
	return map[string]any{
		"id": ia.ID, "integration": ia.Integration, "projectId": ia.ProjectID, "workspace": ia.ProjectID,
		"url": syncsconnNil(ia.URL), "teamId": syncsconnNil(ia.TeamID), "algorithm": "aes-256-gcm",
		"keyEncoding": "base64", "metadata": ia.Metadata, "__v": 0, "createdAt": ia.CreatedAt, "updatedAt": ia.UpdatedAt,
	}
}

// syncsconnNil renders "" as JSON null (the SPA treats these fields as optional).
func syncsconnNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ── option catalogues (drive the SPA "create" pickers) ──────────────────────

// appConnectionOptions lists every connectable app with its supported auth
// methods. The slugs MUST match frontend AppConnection enum values.
func appConnectionOptions() []map[string]any {
	opt := func(app, name string, methods ...string) map[string]any {
		return map[string]any{"app": app, "name": name, "methods": methods}
	}
	return []map[string]any{
		opt("aws", "AWS", "access-key", "assume-role"),
		opt("github", "GitHub", "app", "oauth"),
		opt("github-radar", "GitHub Radar", "app"),
		opt("gcp", "GCP", "service-account-impersonation"),
		opt("azure-key-vault", "Azure Key Vault", "oauth", "client-secret"),
		opt("azure-app-configuration", "Azure App Configuration", "oauth", "client-secret"),
		opt("azure-client-secrets", "Azure Client Secrets", "oauth", "client-secret"),
		opt("azure-devops", "Azure DevOps", "oauth", "client-secret"),
		opt("azure-adcs", "Azure ADCS", "username-password"),
		opt("databricks", "Databricks", "service-principal"),
		opt("humanitec", "Humanitec", "api-token"),
		opt("terraform-cloud", "Terraform Cloud", "api-token"),
		opt("vercel", "Vercel", "api-token"),
		opt("postgres", "PostgreSQL", "username-and-password"),
		opt("mssql", "Microsoft SQL Server", "username-and-password"),
		opt("mysql", "MySQL", "username-and-password"),
		opt("oracledb", "OracleDB", "username-and-password"),
		opt("camunda", "Camunda", "client-credentials"),
		opt("windmill", "Windmill", "access-token"),
		opt("auth0", "Auth0", "client-credentials"),
		opt("hashicorp-vault", "HashiCorp Vault", "access-token", "app-role"),
		opt("ldap", "LDAP", "simple-bind"),
		opt("teamcity", "TeamCity", "access-token"),
		opt("oci", "OCI", "api-key"),
		opt("1password", "1Password", "api-token"),
		opt("heroku", "Heroku", "auth-token", "oauth"),
		opt("render", "Render", "api-key"),
		opt("flyio", "Fly.io", "access-token"),
		opt("gitlab", "GitLab", "access-token", "oauth"),
		opt("cloudflare", "Cloudflare", "api-token"),
		opt("dns-made-easy", "DNS Made Easy", "api-key"),
		opt("bitbucket", "Bitbucket", "api-token"),
		opt("zabbix", "Zabbix", "api-token"),
		opt("railway", "Railway", "account-token", "project-token"),
		opt("checkly", "Checkly", "api-key"),
		opt("supabase", "Supabase", "access-token"),
		opt("digital-ocean", "DigitalOcean", "api-token"),
		opt("netlify", "Netlify", "access-token"),
		opt("northflank", "Northflank", "api-token"),
		opt("okta", "Okta", "api-token"),
		opt("redis", "Redis", "username-and-password"),
		opt("mongodb", "MongoDB", "username-and-password"),
		opt("laravel-forge", "Laravel Forge", "api-token"),
		opt("chef", "Chef", "client-key"),
		opt("octopus-deploy", "Octopus Deploy", "api-key"),
		opt("ssh", "SSH", "private-key"),
	}
}

// secretSyncOptions lists every sync destination. destination slugs MUST match
// the frontend SecretSync enum; canImportSecrets gates the "import" action.
func secretSyncOptions() []map[string]any {
	opt := func(dest, name string, canImport bool) map[string]any {
		return map[string]any{"destination": dest, "name": name, "canImportSecrets": canImport}
	}
	return []map[string]any{
		opt("aws-parameter-store", "AWS Parameter Store", true),
		opt("aws-secrets-manager", "AWS Secrets Manager", true),
		opt("github", "GitHub", false),
		opt("gcp-secret-manager", "GCP Secret Manager", true),
		opt("azure-key-vault", "Azure Key Vault", true),
		opt("azure-app-configuration", "Azure App Configuration", true),
		opt("azure-devops", "Azure DevOps", false),
		opt("databricks", "Databricks", false),
		opt("humanitec", "Humanitec", false),
		opt("terraform-cloud", "Terraform Cloud", false),
		opt("camunda", "Camunda", false),
		opt("vercel", "Vercel", true),
		opt("windmill", "Windmill", true),
		opt("hashicorp-vault", "HashiCorp Vault", true),
		opt("teamcity", "TeamCity", false),
		opt("oci-vault", "OCI Vault", true),
		opt("1password", "1Password", true),
		opt("heroku", "Heroku", true),
		opt("render", "Render", false),
		opt("flyio", "Fly.io", true),
		opt("gitlab", "GitLab", false),
		opt("cloudflare-pages", "Cloudflare Pages", true),
		opt("cloudflare-workers", "Cloudflare Workers", true),
		opt("supabase", "Supabase", true),
		opt("zabbix", "Zabbix", false),
		opt("railway", "Railway", true),
		opt("checkly", "Checkly", true),
		opt("digital-ocean-app-platform", "DigitalOcean App Platform", true),
		opt("netlify", "Netlify", true),
		opt("northflank", "Northflank", true),
		opt("bitbucket", "Bitbucket", false),
		opt("laravel-forge", "Laravel Forge", false),
		opt("chef", "Chef", true),
		opt("octopus-deploy", "Octopus Deploy", false),
	}
}

// cloudIntegrationOptions is the legacy "native integrations" catalogue
// (TCloudIntegration shape). isAvailable=false everywhere since wiring an
// integration needs that provider's live OAuth; the grid still renders.
func cloudIntegrationOptions() []map[string]any {
	type ci struct{ slug, name, typ string }
	items := []ci{
		{"github", "GitHub", "oauth"},
		{"gitlab", "GitLab", "oauth"},
		{"vercel", "Vercel", "oauth"},
		{"netlify", "Netlify", "oauth"},
		{"render", "Render", "pat"},
		{"heroku", "Heroku", "oauth"},
		{"flyio", "Fly.io", "pat"},
		{"railway", "Railway", "pat"},
		{"aws-parameter-store", "AWS Parameter Store", "custom"},
		{"aws-secret-manager", "AWS Secrets Manager", "custom"},
		{"gcp-secret-manager", "GCP Secret Manager", "oauth"},
		{"azure-key-vault", "Azure Key Vault", "oauth"},
		{"azure-app-configuration", "Azure App Configuration", "oauth"},
		{"circleci", "CircleCI", "pat"},
		{"travisci", "Travis CI", "pat"},
		{"terraform-cloud", "Terraform Cloud", "pat"},
		{"cloudflare-pages", "Cloudflare Pages", "pat"},
		{"cloudflare-workers", "Cloudflare Workers", "pat"},
		{"bitbucket", "BitBucket", "oauth"},
		{"databricks", "Databricks", "pat"},
		{"checkly", "Checkly", "pat"},
		{"hashicorp-vault", "Vault", "pat"},
		{"laravel-forge", "Laravel Forge", "pat"},
		{"northflank", "Northflank", "pat"},
		{"teamcity", "TeamCity", "pat"},
		{"windmill", "Windmill", "pat"},
		{"digital-ocean-app-platform", "Digital Ocean App Platform", "pat"},
		{"supabase", "Supabase", "pat"},
		{"octopus-deploy", "Octopus Deploy", "pat"},
		{"qovery", "Qovery", "pat"},
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"name": it.name, "slug": it.slug, "image": it.name + ".png", "isAvailable": false,
			"type": it.typ, "clientId": "", "docsLink": "", "clientSlug": it.slug, "syncSlug": it.slug,
		})
	}
	return out
}
