// Audit + scanning surface — audit logs, audit-log streams, secret scanning
// (v1 git-risk + v2 data-source/finding model), webhooks, and workflow
// integrations (Slack / Microsoft Teams).
//
// What's REAL CRUD (JSON-KV in ZapDB under kms/<area>/...):
//   - audit-log-streams        (config entities — the sink credentials are
//                               persisted; nothing is actually streamed to
//                               Datadog/Splunk/etc. — delivery is a stub)
//   - secret-scanning v2 data sources  (config entities; the git/SCM scan
//                                       engine itself is stubbed — resources,
//                                       scans, and findings list empty)
//   - webhooks                 (config entities; firing/test-delivery stubbed)
//   - workflow-integrations    (Slack + Teams config entities; the OAuth
//                               install dance, channel enumeration, and message
//                               delivery are stubbed)
//
// What's an empty-but-correctly-shaped list / plausible response (dashboard
// tabs that must render without erroring; the heavy machinery behind them is
// out of scope):
//   - audit-logs + actor filters
//   - secret-scanning v1 git risks + installation status + export
//   - secret-scanning v2 findings / resources / scans / unresolved-count
//
// Every handler is org-scoped via the KMS web session (newWebAuth). Entities
// that belong to an org are indexed under kms/<area>/by-org/{orgId}/{id};
// project-scoped entities (webhooks, scanning data sources, configs) under
// kms/<area>/by-project/{projectId}/{id}, mirroring api_projects.go.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── generic per-area index iteration ──────────────────────────────────────
// auditscanList collects every JSON entity stored under the given key prefix.
func auditscanList[T any](ws *webStore, prefix []byte) []T {
	out := []T{}
	_ = ws.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var e T
				if json.Unmarshal(v, &e) == nil {
					out = append(out, e)
				}
				return nil
			})
		}
		return nil
	})
	return out
}

func auditscanDelete(ws *webStore, keys ...[]byte) {
	_ = ws.db.Update(func(txn *badger.Txn) error {
		for _, k := range keys {
			_ = txn.Delete(k)
		}
		return nil
	})
}

// auditscanTitle upper-cases the first rune (provider/source label display).
func auditscanTitle(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// auditscanNullable renders "" as JSON null, else the string.
func auditscanNullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// auditscanSlashPath returns a leading-slash-normalized secret path.
func auditscanSlashPath(p string) string {
	c := cleanPath(p)
	if c == "" {
		return "/"
	}
	return "/" + c
}

// ── entity shapes (on-disk + wire) ─────────────────────────────────────────

type auditLogStream struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"orgId"`
	Provider    string         `json:"provider"`
	Credentials map[string]any `json:"credentials"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

func auditLogStreamKey(orgID, id string) []byte {
	return []byte("kms/audit-log-streams/by-org/" + orgID + "/" + id)
}
func auditLogStreamPrefix(orgID string) []byte {
	return []byte("kms/audit-log-streams/by-org/" + orgID + "/")
}

func auditLogStreamJSON(s *auditLogStream) map[string]any {
	return map[string]any{
		"id": s.ID, "orgId": s.OrgID, "provider": s.Provider,
		"credentials": s.Credentials, "createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
}

type webhookEntity struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	Type        string    `json:"type"`
	Environment string    `json:"environment"`
	SecretPath  string    `json:"secretPath"`
	URL         string    `json:"url"`
	IsDisabled  bool      `json:"isDisabled"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func webhookKey(projectID, id string) []byte {
	return []byte("kms/webhooks/by-project/" + projectID + "/" + id)
}
func webhookPrefix(projectID string) []byte {
	return []byte("kms/webhooks/by-project/" + projectID + "/")
}
func webhookByID(id string) []byte { return []byte("kms/webhooks/id/" + id) }

func webhookJSON(h *webhookEntity) map[string]any {
	typ := h.Type
	if typ == "" {
		typ = "general"
	}
	return map[string]any{
		"id": h.ID, "type": typ, "projectId": h.ProjectID,
		"environment": map[string]any{"slug": h.Environment, "name": h.Environment, "id": h.Environment},
		"envId":       h.Environment, "secretPath": h.SecretPath, "url": h.URL,
		"lastStatus": "success", "isDisabled": h.IsDisabled,
		"createdAt": h.CreatedAt, "updatedAt": h.UpdatedAt,
	}
}

type scanDataSource struct {
	ID                string         `json:"id"`
	ProjectID         string         `json:"projectId"`
	Type              string         `json:"type"`
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	ConnectionID      string         `json:"connectionId"`
	IsAutoScanEnabled bool           `json:"isAutoScanEnabled"`
	Config            map[string]any `json:"config"`
	CreatedAt         time.Time      `json:"createdAt"`
	UpdatedAt         time.Time      `json:"updatedAt"`
}

func scanDataSourceKey(projectID, id string) []byte {
	return []byte("kms/secret-scanning/data-sources/by-project/" + projectID + "/" + id)
}
func scanDataSourcePrefix(projectID string) []byte {
	return []byte("kms/secret-scanning/data-sources/by-project/" + projectID + "/")
}
func scanDataSourceByID(id string) []byte {
	return []byte("kms/secret-scanning/data-sources/id/" + id)
}

func scanDataSourceJSON(d *scanDataSource) map[string]any {
	cfg := d.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	return map[string]any{
		"id": d.ID, "name": d.Name, "description": d.Description,
		"connectionId": auditscanNullable(d.ConnectionID), "createdAt": d.CreatedAt, "updatedAt": d.UpdatedAt,
		"projectId": d.ProjectID, "type": d.Type, "isAutoScanEnabled": d.IsAutoScanEnabled,
		"isDisconnected": false, "config": cfg, "connection": nil,
		// list-with-details fields (data-sources-dashboard reads these too):
		"lastScannedAt": nil, "lastScanStatus": nil, "lastScanStatusMessage": nil,
		"unresolvedFindings": 0,
	}
}

type scanConfig struct {
	ProjectID string `json:"projectId"`
	Content   string `json:"content"`
}

func scanConfigKey(projectID string) []byte {
	return []byte("kms/secret-scanning/configs/" + projectID)
}

// workflowIntegration covers both Slack and Microsoft Teams config entities.
type workflowIntegration struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"orgId"`
	Integration string    `json:"integration"` // "slack" | "microsoft-teams"
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	TeamName    string    `json:"teamName"`
	TenantID    string    `json:"tenantId"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func workflowIntegrationKey(orgID, id string) []byte {
	return []byte("kms/workflow-integrations/by-org/" + orgID + "/" + id)
}
func workflowIntegrationPrefix(orgID string) []byte {
	return []byte("kms/workflow-integrations/by-org/" + orgID + "/")
}
func workflowIntegrationByID(id string) []byte {
	return []byte("kms/workflow-integrations/id/" + id)
}

func workflowIntegrationJSON(w *workflowIntegration) map[string]any {
	st := w.Status
	if st == "" {
		st = "installed"
	}
	return map[string]any{
		"id": w.ID, "slug": w.Slug, "description": w.Description,
		"status": st, "integration": w.Integration,
	}
}

// registerAuditScanAPI wires the audit + scanning + webhooks + workflow surface.
func registerAuditScanAPI(mux *http.ServeMux, db *badger.DB) {
	ws := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// claims returns the caller's session claims, or nil after writing 401.
	claims := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}
	ok := func(w http.ResponseWriter, r *http.Request) bool { return claims(w, r) != nil }

	// ════════════════════════════════════════════════════════════════════
	// auditLogs — list + actor filters. Audit capture isn't implemented, so
	// these render the (empty) shapes the dashboard infinite-query expects.
	// ════════════════════════════════════════════════════════════════════
	mux.HandleFunc("GET /v1/organization/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"auditLogs": []any{}})
	})
	mux.HandleFunc("GET /v1/projects/{id}/audit-logs/filters/actors", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"actors": []any{}})
	})

	// ════════════════════════════════════════════════════════════════════
	// auditLogStreams — REAL CRUD. Sink config (provider + credentials) is
	// persisted per-org; actual log delivery to the provider is a stub.
	// ════════════════════════════════════════════════════════════════════
	mux.HandleFunc("GET /v1/audit-log-streams/options", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		providers := []string{"azure", "cribl", "custom", "datadog", "splunk", "qradar"}
		opts := make([]any, 0, len(providers))
		for _, p := range providers {
			opts = append(opts, map[string]any{"provider": p, "name": auditscanTitle(p)})
		}
		writeJSON(w, http.StatusOK, map[string]any{"providerOptions": opts})
	})
	mux.HandleFunc("GET /v1/audit-log-streams", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		streams := auditscanList[auditLogStream](ws, auditLogStreamPrefix(cl.OrgID))
		out := make([]any, 0, len(streams))
		for i := range streams {
			out = append(out, auditLogStreamJSON(&streams[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"auditLogStreams": out})
	})
	mux.HandleFunc("GET /v1/audit-log-streams/{provider}/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s auditLogStream
		if ws.getJSON(auditLogStreamKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("audit log stream not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"auditLogStream": auditLogStreamJSON(&s)})
	})
	mux.HandleFunc("POST /v1/audit-log-streams/{provider}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Credentials map[string]any `json:"credentials"`
		}
		_ = decode(w, r, &req)
		now := time.Now().UTC()
		s := &auditLogStream{
			ID: newID(), OrgID: cl.OrgID, Provider: r.PathValue("provider"),
			Credentials: req.Credentials, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(auditLogStreamKey(cl.OrgID, s.ID), s)
		writeJSON(w, http.StatusOK, map[string]any{"auditLogStream": auditLogStreamJSON(s)})
	})
	mux.HandleFunc("PATCH /v1/audit-log-streams/{provider}/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s auditLogStream
		if ws.getJSON(auditLogStreamKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("audit log stream not found"))
			return
		}
		var req struct {
			Credentials map[string]any `json:"credentials"`
		}
		_ = decode(w, r, &req)
		if req.Credentials != nil {
			s.Credentials = req.Credentials
		}
		s.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(auditLogStreamKey(cl.OrgID, s.ID), &s)
		writeJSON(w, http.StatusOK, map[string]any{"auditLogStream": auditLogStreamJSON(&s)})
	})
	mux.HandleFunc("DELETE /v1/audit-log-streams/{provider}/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s auditLogStream
		if ws.getJSON(auditLogStreamKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("audit log stream not found"))
			return
		}
		auditscanDelete(ws, auditLogStreamKey(cl.OrgID, s.ID))
		writeJSON(w, http.StatusOK, map[string]any{"auditLogStream": auditLogStreamJSON(&s)})
	})

	// ════════════════════════════════════════════════════════════════════
	// secretScanning (v1) — legacy git-risk model. The GitHub-app scan
	// engine is not implemented; these return empty/plausible shapes so the
	// org "Secret Scanning" page renders.
	// ════════════════════════════════════════════════════════════════════
	mux.HandleFunc("GET /v1/secret-scanning/installation-status/organization/{orgId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"appInstallationCompleted": false})
	})
	mux.HandleFunc("GET /v1/secret-scanning/organization/{orgId}/risks", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"risks": []any{}, "totalCount": 0, "repos": []string{}})
	})
	mux.HandleFunc("GET /v1/secret-scanning/organization/{orgId}/risks/export", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"risks": []any{}})
	})
	mux.HandleFunc("POST /v1/secret-scanning/organization/{orgId}/risks/{riskId}/status", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("riskId"), "status": req.Status})
	})
	mux.HandleFunc("POST /v1/secret-scanning/create-installation-session/organization", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessionId": newID(), "gitAppSlug": "lux-kms-scanner"})
	})
	mux.HandleFunc("POST /v1/secret-scanning/link-installation", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var req struct {
			SessionID, InstallationID string
		}
		_ = decode(w, r, &req)
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{
			"id": newID(), "installationId": req.InstallationID, "userId": cl.UserID,
			"orgId": cl.OrgID, "createdAt": now, "updatedAt": now,
		})
	})

	// ════════════════════════════════════════════════════════════════════
	// secretScanningV2 — data sources are REAL CRUD (config persisted per
	// project). The scan engine is stubbed: resources/scans/findings list
	// empty, the unresolved count is 0, triggering a scan is a no-op that
	// echoes the data source.
	// ════════════════════════════════════════════════════════════════════
	mux.HandleFunc("GET /v1/secret-scanning/data-sources/options", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		sources := []string{"github", "bitbucket", "gitlab"}
		opts := make([]any, 0, len(sources))
		for _, s := range sources {
			opts = append(opts, map[string]any{"name": auditscanTitle(s), "type": s})
		}
		writeJSON(w, http.StatusOK, map[string]any{"dataSourceOptions": opts})
	})
	mux.HandleFunc("GET /v1/secret-scanning/data-sources-dashboard", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		sources := auditscanList[scanDataSource](ws, scanDataSourcePrefix(pid))
		out := make([]any, 0, len(sources))
		for i := range sources {
			out = append(out, scanDataSourceJSON(&sources[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"dataSources": out})
	})
	mux.HandleFunc("GET /v1/secret-scanning/unresolved-findings-count", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"unresolvedFindings": 0})
	})
	mux.HandleFunc("GET /v1/secret-scanning/findings", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": []any{}})
	})
	mux.HandleFunc("GET /v1/secret-scanning/configs", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		var c scanConfig
		if ws.getJSON(scanConfigKey(pid), &c) != nil {
			c = scanConfig{ProjectID: pid}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"config": map[string]any{"projectId": pid, "content": auditscanNullable(c.Content)},
		})
	})
	mux.HandleFunc("PATCH /v2/secret-scanning/configs", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		var req struct {
			Content string `json:"content"`
		}
		_ = decode(w, r, &req)
		c := scanConfig{ProjectID: pid, Content: req.Content}
		_ = ws.putJSON(scanConfigKey(pid), &c)
		writeJSON(w, http.StatusOK, map[string]any{
			"config": map[string]any{"projectId": pid, "content": auditscanNullable(c.Content)},
		})
	})

	// v2 data-source item routes ({type}/{id}…). loadDS resolves the by-id
	// pointer then loads the project-scoped record.
	loadDS := func(id string) (*scanDataSource, bool) {
		var pid string
		if ws.getJSON(scanDataSourceByID(id), &pid) != nil {
			return nil, false
		}
		var d scanDataSource
		if ws.getJSON(scanDataSourceKey(pid, id), &d) != nil {
			return nil, false
		}
		return &d, true
	}
	mux.HandleFunc("GET /v2/secret-scanning/data-sources/{type}/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		d, found := loadDS(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("data source not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dataSource": scanDataSourceJSON(d)})
	})
	mux.HandleFunc("GET /v2/secret-scanning/data-sources/{type}/{id}/resources-dashboard", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resources": []any{}})
	})
	mux.HandleFunc("GET /v2/secret-scanning/data-sources/{type}/{id}/scans-dashboard", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"scans": []any{}})
	})
	mux.HandleFunc("POST /v2/secret-scanning/data-sources/{type}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			Name, Description, ConnectionID string
			ProjectID                       string
			IsAutoScanEnabled               bool
			Config                          map[string]any
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		d := &scanDataSource{
			ID: newID(), ProjectID: req.ProjectID, Type: r.PathValue("type"),
			Name: req.Name, Description: req.Description, ConnectionID: req.ConnectionID,
			IsAutoScanEnabled: req.IsAutoScanEnabled, Config: req.Config,
			CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(scanDataSourceKey(d.ProjectID, d.ID), d)
		_ = ws.putJSON(scanDataSourceByID(d.ID), d.ProjectID)
		writeJSON(w, http.StatusOK, map[string]any{"dataSource": scanDataSourceJSON(d)})
	})
	mux.HandleFunc("PATCH /v2/secret-scanning/data-sources/{type}/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		d, found := loadDS(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("data source not found"))
			return
		}
		var req struct {
			Name, Description *string
			IsAutoScanEnabled *bool
			Config            map[string]any
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			d.Name = *req.Name
		}
		if req.Description != nil {
			d.Description = *req.Description
		}
		if req.IsAutoScanEnabled != nil {
			d.IsAutoScanEnabled = *req.IsAutoScanEnabled
		}
		if req.Config != nil {
			d.Config = req.Config
		}
		d.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(scanDataSourceKey(d.ProjectID, d.ID), d)
		writeJSON(w, http.StatusOK, map[string]any{"dataSource": scanDataSourceJSON(d)})
	})
	mux.HandleFunc("DELETE /v2/secret-scanning/data-sources/{type}/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		d, found := loadDS(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("data source not found"))
			return
		}
		auditscanDelete(ws, scanDataSourceKey(d.ProjectID, d.ID), scanDataSourceByID(d.ID))
		writeJSON(w, http.StatusOK, map[string]any{"dataSource": scanDataSourceJSON(d)})
	})
	// Trigger scan (data-source-wide or per-resource) — stub: echo the source.
	triggerScan := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		d, found := loadDS(r.PathValue("id"))
		if !found {
			writeJSON(w, http.StatusNotFound, msg("data source not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dataSource": scanDataSourceJSON(d)})
	}
	mux.HandleFunc("POST /v2/secret-scanning/data-sources/{type}/{id}/scan", triggerScan)
	mux.HandleFunc("POST /v2/secret-scanning/data-sources/{type}/{id}/resources/{resourceId}/scan", triggerScan)
	// Finding status updates (single + bulk) — stub: echo a finding shell.
	mux.HandleFunc("PATCH /v2/secret-scanning/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			Status  string `json:"status"`
			Remarks any    `json:"remarks"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"finding": map[string]any{"id": r.PathValue("id"), "status": req.Status, "remarks": req.Remarks},
		})
	})
	mux.HandleFunc("PATCH /v1/secret-scanning/findings", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"finding": map[string]any{}})
	})

	// ════════════════════════════════════════════════════════════════════
	// webhooks — REAL CRUD. Project-scoped config; firing/test delivery stub.
	// ════════════════════════════════════════════════════════════════════
	mux.HandleFunc("GET /v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		hooks := auditscanList[webhookEntity](ws, webhookPrefix(pid))
		out := make([]any, 0, len(hooks))
		for i := range hooks {
			out = append(out, webhookJSON(&hooks[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
	})
	mux.HandleFunc("POST /v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, Environment, WebhookURL, SecretPath, Type string
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		h := &webhookEntity{
			ID: newID(), ProjectID: req.ProjectID, Type: req.Type,
			Environment: envOrDefault(req.Environment), SecretPath: auditscanSlashPath(req.SecretPath),
			URL: req.WebhookURL, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(webhookKey(h.ProjectID, h.ID), h)
		_ = ws.putJSON(webhookByID(h.ID), h)
		writeJSON(w, http.StatusOK, map[string]any{"webhook": webhookJSON(h)})
	})
	mux.HandleFunc("POST /v1/webhooks/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h webhookEntity
		if ws.getJSON(webhookByID(r.PathValue("id")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("webhook not found"))
			return
		}
		// delivery stubbed; report the last known status.
		writeJSON(w, http.StatusOK, map[string]any{"webhook": webhookJSON(&h)})
	})
	mux.HandleFunc("PATCH /v1/webhooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h webhookEntity
		if ws.getJSON(webhookByID(r.PathValue("id")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("webhook not found"))
			return
		}
		var req struct {
			IsDisabled *bool `json:"isDisabled"`
		}
		_ = decode(w, r, &req)
		if req.IsDisabled != nil {
			h.IsDisabled = *req.IsDisabled
		}
		h.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(webhookKey(h.ProjectID, h.ID), &h)
		_ = ws.putJSON(webhookByID(h.ID), &h)
		writeJSON(w, http.StatusOK, map[string]any{"webhook": webhookJSON(&h)})
	})
	mux.HandleFunc("DELETE /v1/webhooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h webhookEntity
		if ws.getJSON(webhookByID(r.PathValue("id")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("webhook not found"))
			return
		}
		auditscanDelete(ws, webhookKey(h.ProjectID, h.ID), webhookByID(h.ID))
		writeJSON(w, http.StatusOK, map[string]any{"webhook": webhookJSON(&h)})
	})

	// ════════════════════════════════════════════════════════════════════
	// workflowIntegrations — Slack + Microsoft Teams. Config entities are
	// REAL CRUD (per-org). The OAuth install dance, channel/team
	// enumeration, and message delivery are stubbed (return install URLs /
	// empty lists), since they require live Slack/Graph API credentials.
	// ════════════════════════════════════════════════════════════════════

	// all integrations (both platforms)
	mux.HandleFunc("GET /v1/workflow-integrations", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		ints := auditscanList[workflowIntegration](ws, workflowIntegrationPrefix(cl.OrgID))
		out := make([]any, 0, len(ints))
		for i := range ints {
			out = append(out, workflowIntegrationJSON(&ints[i]))
		}
		writeJSON(w, http.StatusOK, out)
	})

	// ── Slack ──
	mux.HandleFunc("GET /v1/workflow-integrations/slack/install", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		// OAuth stub: a real deployment redirects to Slack's authorize URL.
		writeJSON(w, http.StatusOK, "https://slack.com/oauth/v2/authorize")
	})
	mux.HandleFunc("GET /v1/workflow-integrations/slack/reinstall", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, "https://slack.com/oauth/v2/authorize")
	})
	mux.HandleFunc("GET /v1/workflow-integrations/slack", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		ints := auditscanList[workflowIntegration](ws, workflowIntegrationPrefix(cl.OrgID))
		out := make([]any, 0)
		for i := range ints {
			if ints[i].Integration == "slack" {
				out = append(out, map[string]any{
					"id": ints[i].ID, "slug": ints[i].Slug,
					"description": ints[i].Description, "teamName": ints[i].TeamName,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v1/workflow-integrations/slack/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s workflowIntegration
		if ws.getJSON(workflowIntegrationKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": s.ID, "slug": s.Slug, "description": s.Description, "teamName": s.TeamName,
		})
	})
	mux.HandleFunc("GET /v1/workflow-integrations/slack/{id}/channels", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("PATCH /v1/workflow-integrations/slack/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		auditscanPatchIntegration(w, r, ws, cl)
	})
	mux.HandleFunc("DELETE /v1/workflow-integrations/slack/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		auditscanDeleteIntegration(w, r, ws, cl)
	})

	// ── Microsoft Teams ──
	mux.HandleFunc("GET /v1/workflow-integrations/microsoft-teams/client-id", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"clientId": envOr("MS_TEAMS_CLIENT_ID", "")})
	})
	mux.HandleFunc("GET /v1/workflow-integrations/microsoft-teams", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		ints := auditscanList[workflowIntegration](ws, workflowIntegrationPrefix(cl.OrgID))
		out := make([]any, 0)
		for i := range ints {
			if ints[i].Integration == "microsoft-teams" {
				out = append(out, map[string]any{
					"id": ints[i].ID, "slug": ints[i].Slug,
					"description": ints[i].Description, "tenantId": ints[i].TenantID,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v1/workflow-integrations/microsoft-teams/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s workflowIntegration
		if ws.getJSON(workflowIntegrationKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": s.ID, "slug": s.Slug, "description": s.Description, "tenantId": s.TenantID,
		})
	})
	mux.HandleFunc("GET /v1/workflow-integrations/microsoft-teams/{id}/teams", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("POST /v1/workflow-integrations/microsoft-teams", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Code, TenantID, Slug, Description, RedirectURI string
		}
		_ = decode(w, r, &req)
		now := time.Now().UTC()
		s := &workflowIntegration{
			ID: newID(), OrgID: cl.OrgID, Integration: "microsoft-teams",
			Slug: req.Slug, Description: req.Description, TenantID: req.TenantID,
			Status: "installed", CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(workflowIntegrationKey(cl.OrgID, s.ID), s)
		_ = ws.putJSON(workflowIntegrationByID(s.ID), cl.OrgID)
		writeJSON(w, http.StatusOK, workflowIntegrationJSON(s))
	})
	mux.HandleFunc("PATCH /v1/workflow-integrations/microsoft-teams/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		auditscanPatchIntegration(w, r, ws, cl)
	})
	mux.HandleFunc("DELETE /v1/workflow-integrations/microsoft-teams/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		auditscanDeleteIntegration(w, r, ws, cl)
	})
	mux.HandleFunc("POST /v1/workflow-integrations/microsoft-teams/{id}/installation-status", func(w http.ResponseWriter, r *http.Request) {
		cl := claims(w, r)
		if cl == nil {
			return
		}
		var s workflowIntegration
		if ws.getJSON(workflowIntegrationKey(cl.OrgID, r.PathValue("id")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("integration not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "installed"})
	})
}

// auditscanPatchIntegration updates a Slack/Teams config's slug+description.
func auditscanPatchIntegration(w http.ResponseWriter, r *http.Request, ws *webStore, cl *webClaims) {
	var s workflowIntegration
	if ws.getJSON(workflowIntegrationKey(cl.OrgID, r.PathValue("id")), &s) != nil {
		writeJSON(w, http.StatusNotFound, msg("integration not found"))
		return
	}
	var req struct {
		Slug, Description *string
	}
	_ = decode(w, r, &req)
	if req.Slug != nil {
		s.Slug = *req.Slug
	}
	if req.Description != nil {
		s.Description = *req.Description
	}
	s.UpdatedAt = time.Now().UTC()
	_ = ws.putJSON(workflowIntegrationKey(cl.OrgID, s.ID), &s)
	writeJSON(w, http.StatusOK, workflowIntegrationJSON(&s))
}

// auditscanDeleteIntegration removes a Slack/Teams config (both index keys).
func auditscanDeleteIntegration(w http.ResponseWriter, r *http.Request, ws *webStore, cl *webClaims) {
	id := r.PathValue("id")
	var s workflowIntegration
	if ws.getJSON(workflowIntegrationKey(cl.OrgID, id), &s) != nil {
		writeJSON(w, http.StatusNotFound, msg("integration not found"))
		return
	}
	auditscanDelete(ws, workflowIntegrationKey(cl.OrgID, id), workflowIntegrationByID(id))
	writeJSON(w, http.StatusOK, workflowIntegrationJSON(&s))
}
