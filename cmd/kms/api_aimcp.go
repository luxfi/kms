// AI / MCP surface — the project-scoped Model-Context-Protocol console.
//
// Three SPA groups (frontend/src/hooks/api/aiMcp{Servers,Endpoints,ActivityLogs}):
//
//	aiMcpServers     /v1/ai/mcp/servers           — upstream MCP servers a project trusts
//	aiMcpEndpoints   /v1/ai/mcp/endpoints         — composed endpoints (server fan-in + tool gating)
//	aiMcpActivityLogs/v1/ai/mcp/activity-logs     — tool-call audit trail
//
// Servers/endpoints persist as JSON-KV in ZapDB under kms/aimcp/{servers,endpoints}/...,
// project-indexed (kms/aimcp/<kind>/by-proj/<projectId>/<id>) so the project list
// query is a prefix scan — same shape as api_projects.go ProjectsForOrg.
//
// REAL CRUD: create/get/list/update/delete of servers and endpoints, and the
// per-endpoint tool-enable map (tools live inline on the endpoint). STUBBED
// (return a plausible-shaped payload, no live network): MCP tool discovery
// (servers/tools, tools/sync — would speak the MCP wire to the upstream URL),
// the OAuth dance against an external MCP server (initiate/status/finalize/
// verify-token/credentials). The activity-log list returns the correct wrapper
// with an empty array (the audit pipeline is not wired) so the dashboard tab
// navigates without erroring.
package main

import (
	"net/http"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities ──────────────────────────────────────────────────────────────

type aimcpServer struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	Description    string            `json:"description"`
	Status         string            `json:"status"`
	CredentialMode string            `json:"credentialMode"`
	AuthMethod     string            `json:"authMethod"`
	ProjectID      string            `json:"projectId"`
	Tools          []aimcpServerTool `json:"tools"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      time.Time         `json:"updatedAt"`
}

type aimcpServerTool struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type aimcpEndpoint struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Description  string              `json:"description"`
	Status       string              `json:"status"`
	PiiFiltering bool                `json:"piiFiltering"`
	ProjectID    string              `json:"projectId"`
	ServerIDs    []string            `json:"serverIds"`
	ToolConfigs  []aimcpEndpointTool `json:"toolConfigs"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
}

type aimcpEndpointTool struct {
	ID           string `json:"id"`
	ServerToolID string `json:"serverToolId"`
	IsEnabled    bool   `json:"isEnabled"`
}

// ── keys (entity + project index) ────────────────────────────────────────

func aimcpServerKey(id string) []byte   { return []byte("kms/aimcp/servers/" + id) }
func aimcpEndpointKey(id string) []byte { return []byte("kms/aimcp/endpoints/" + id) }

func aimcpServerIdx(projectID, id string) []byte {
	return []byte("kms/aimcp/servers/by-proj/" + projectID + "/" + id)
}
func aimcpServerPrefix(projectID string) []byte {
	return []byte("kms/aimcp/servers/by-proj/" + projectID + "/")
}
func aimcpEndpointIdx(projectID, id string) []byte {
	return []byte("kms/aimcp/endpoints/by-proj/" + projectID + "/" + id)
}
func aimcpEndpointPrefix(projectID string) []byte {
	return []byte("kms/aimcp/endpoints/by-proj/" + projectID + "/")
}

// ── JSON renderers (match the SPA TAiMcp* shapes exactly) ────────────────

func aimcpServerJSON(s *aimcpServer) map[string]any {
	status := s.Status
	if status == "" {
		status = "uninitialized"
	}
	return map[string]any{
		"id": s.ID, "name": s.Name, "url": s.URL, "description": s.Description,
		"status": status, "credentialMode": s.CredentialMode, "authMethod": s.AuthMethod,
		"projectId": s.ProjectID, "toolsCount": len(s.Tools),
		"createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
}

func aimcpServerToolJSON(serverID string, t aimcpServerTool) map[string]any {
	return map[string]any{
		"id": t.ID, "name": t.Name, "description": t.Description,
		"inputSchema": t.InputSchema, "aiMcpServerId": serverID,
	}
}

// aimcpEndpointJSON renders TAiMcpEndpoint; withServers adds serverIds for the
// detail view (TAiMcpEndpointWithServerIds).
func aimcpEndpointJSON(e *aimcpEndpoint, withServers bool) map[string]any {
	active := 0
	for _, t := range e.ToolConfigs {
		if t.IsEnabled {
			active++
		}
	}
	out := map[string]any{
		"id": e.ID, "name": e.Name, "description": aimcpNilIfEmpty(e.Description),
		"status": aimcpNilIfEmpty(e.Status), "piiFiltering": e.PiiFiltering, "projectId": e.ProjectID,
		"connectedServers": len(e.ServerIDs), "activeTools": active,
		"createdAt": e.CreatedAt, "updatedAt": e.UpdatedAt,
	}
	if withServers {
		ids := e.ServerIDs
		if ids == nil {
			ids = []string{}
		}
		out["serverIds"] = ids
	}
	return out
}

func aimcpEndpointToolJSON(endpointID string, t aimcpEndpointTool) map[string]any {
	return map[string]any{
		"id": t.ID, "aiMcpEndpointId": endpointID,
		"aiMcpServerToolId": t.ServerToolID, "isEnabled": t.IsEnabled,
	}
}

func aimcpNilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ── register ──────────────────────────────────────────────────────────────

func registerAiMcpAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// store helpers (closures over st) ────────────────────────────────────
	getServer := func(id string) (*aimcpServer, error) {
		var s aimcpServer
		if err := st.getJSON(aimcpServerKey(id), &s); err != nil {
			return nil, err
		}
		return &s, nil
	}
	saveServer := func(s *aimcpServer) error {
		s.UpdatedAt = time.Now().UTC()
		if err := st.putJSON(aimcpServerKey(s.ID), s); err != nil {
			return err
		}
		return st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(aimcpServerIdx(s.ProjectID, s.ID), []byte(s.ID))
		})
	}
	getEndpoint := func(id string) (*aimcpEndpoint, error) {
		var e aimcpEndpoint
		if err := st.getJSON(aimcpEndpointKey(id), &e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	saveEndpoint := func(e *aimcpEndpoint) error {
		e.UpdatedAt = time.Now().UTC()
		if err := st.putJSON(aimcpEndpointKey(e.ID), e); err != nil {
			return err
		}
		return st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(aimcpEndpointIdx(e.ProjectID, e.ID), []byte(e.ID))
		})
	}
	idsForPrefix := func(pfx []byte) []string {
		var ids []string
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
		return ids
	}

	// ══ aiMcpServers ═════════════════════════════════════════════════════

	// GET /v1/ai/mcp/servers?projectId — {servers, totalCount}
	mux.HandleFunc("GET /v1/ai/mcp/servers", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		pid := r.URL.Query().Get("projectId")
		out := make([]any, 0)
		for _, id := range idsForPrefix(aimcpServerPrefix(pid)) {
			if s, err := getServer(id); err == nil {
				out = append(out, aimcpServerJSON(s))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"servers": out, "totalCount": len(out)})
	})

	// POST /v1/ai/mcp/servers — {server}
	mux.HandleFunc("POST /v1/ai/mcp/servers", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			ProjectID, Name, URL, Description, CredentialMode, AuthMethod string
		}
		if !decode(w, r, &req) {
			return
		}
		if req.ProjectID == "" || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("projectId and name required"))
			return
		}
		now := time.Now().UTC()
		s := &aimcpServer{
			ID: newID(), Name: req.Name, URL: req.URL, Description: req.Description,
			Status: "uninitialized", CredentialMode: req.CredentialMode, AuthMethod: req.AuthMethod,
			ProjectID: req.ProjectID, Tools: []aimcpServerTool{}, CreatedAt: now, UpdatedAt: now,
		}
		if err := saveServer(s); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"server": aimcpServerJSON(s)})
	})

	// GET /v1/ai/mcp/servers/{serverId} — {server}
	mux.HandleFunc("GET /v1/ai/mcp/servers/{serverId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		s, err := getServer(r.PathValue("serverId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("server not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"server": aimcpServerJSON(s)})
	})

	// PATCH /v1/ai/mcp/servers/{serverId} — {server}
	mux.HandleFunc("PATCH /v1/ai/mcp/servers/{serverId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		s, err := getServer(r.PathValue("serverId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("server not found"))
			return
		}
		var req struct {
			Name, Description *string
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
		if err := saveServer(s); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"server": aimcpServerJSON(s)})
	})

	// DELETE /v1/ai/mcp/servers/{serverId} — {server}
	mux.HandleFunc("DELETE /v1/ai/mcp/servers/{serverId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("serverId")
		s, err := getServer(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("server not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(aimcpServerKey(id))
			return txn.Delete(aimcpServerIdx(s.ProjectID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"server": aimcpServerJSON(s)})
	})

	// GET /v1/ai/mcp/servers/{serverId}/tools — {tools}
	// Tools are discovered by speaking the MCP wire to the upstream URL; we
	// persist whatever a prior sync stored (empty until then).
	mux.HandleFunc("GET /v1/ai/mcp/servers/{serverId}/tools", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("serverId")
		out := make([]any, 0)
		if s, err := getServer(id); err == nil {
			for _, t := range s.Tools {
				out = append(out, aimcpServerToolJSON(id, t))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": out})
	})

	// POST /v1/ai/mcp/servers/{serverId}/tools/sync — {tools}
	// STUB: real impl initialises an MCP session to the server and lists tools.
	// We mark the server active and return its (currently persisted) tool set.
	mux.HandleFunc("POST /v1/ai/mcp/servers/{serverId}/tools/sync", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("serverId")
		s, err := getServer(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("server not found"))
			return
		}
		s.Status = "active"
		_ = saveServer(s)
		out := make([]any, 0)
		for _, t := range s.Tools {
			out = append(out, aimcpServerToolJSON(id, t))
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": out})
	})

	// POST /v1/ai/mcp/servers/oauth/initiate — {authUrl, sessionId}
	// STUB: returns a session id; the real flow redirects the browser to the
	// upstream server's OAuth authorize URL.
	mux.HandleFunc("POST /v1/ai/mcp/servers/oauth/initiate", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct{ ProjectID, URL, ClientID, ClientSecret string }
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"authUrl": req.URL, "sessionId": newID()})
	})

	// GET /v1/ai/mcp/servers/oauth/status/{sessionId} — TOAuthStatusResponse
	// STUB: polled by the UI during the OAuth popup; reports not-yet-authorized.
	mux.HandleFunc("GET /v1/ai/mcp/servers/oauth/status/{sessionId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorized": false})
	})

	// ══ aiMcpEndpoints ═══════════════════════════════════════════════════

	// GET /v1/ai/mcp/endpoints?projectId — {endpoints, totalCount}
	mux.HandleFunc("GET /v1/ai/mcp/endpoints", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		pid := r.URL.Query().Get("projectId")
		out := make([]any, 0)
		for _, id := range idsForPrefix(aimcpEndpointPrefix(pid)) {
			if e, err := getEndpoint(id); err == nil {
				out = append(out, aimcpEndpointJSON(e, false))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": out, "totalCount": len(out)})
	})

	// POST /v1/ai/mcp/endpoints — {endpoint}
	mux.HandleFunc("POST /v1/ai/mcp/endpoints", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			ProjectID, Name, Description string
			ServerIDs                    []string `json:"serverIds"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.ProjectID == "" || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("projectId and name required"))
			return
		}
		now := time.Now().UTC()
		if req.ServerIDs == nil {
			req.ServerIDs = []string{}
		}
		e := &aimcpEndpoint{
			ID: newID(), Name: req.Name, Description: req.Description, Status: "active",
			ProjectID: req.ProjectID, ServerIDs: req.ServerIDs, ToolConfigs: []aimcpEndpointTool{},
			CreatedAt: now, UpdatedAt: now,
		}
		if err := saveEndpoint(e); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoint": aimcpEndpointJSON(e, false)})
	})

	// GET /v1/ai/mcp/endpoints/{endpointId} — {endpoint} (with serverIds)
	mux.HandleFunc("GET /v1/ai/mcp/endpoints/{endpointId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		e, err := getEndpoint(r.PathValue("endpointId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoint": aimcpEndpointJSON(e, true)})
	})

	// PATCH /v1/ai/mcp/endpoints/{endpointId} — {endpoint}
	mux.HandleFunc("PATCH /v1/ai/mcp/endpoints/{endpointId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		e, err := getEndpoint(r.PathValue("endpointId"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		var req struct {
			Name, Description *string
			ServerIDs         *[]string `json:"serverIds"`
			PiiFiltering      *bool     `json:"piiFiltering"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			e.Name = *req.Name
		}
		if req.Description != nil {
			e.Description = *req.Description
		}
		if req.ServerIDs != nil {
			e.ServerIDs = *req.ServerIDs
		}
		if req.PiiFiltering != nil {
			e.PiiFiltering = *req.PiiFiltering
		}
		if err := saveEndpoint(e); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoint": aimcpEndpointJSON(e, true)})
	})

	// DELETE /v1/ai/mcp/endpoints/{endpointId} — {endpoint}
	mux.HandleFunc("DELETE /v1/ai/mcp/endpoints/{endpointId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("endpointId")
		e, err := getEndpoint(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(aimcpEndpointKey(id))
			return txn.Delete(aimcpEndpointIdx(e.ProjectID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"endpoint": aimcpEndpointJSON(e, false)})
	})

	// GET /v1/ai/mcp/endpoints/{endpointId}/tools — {tools}
	mux.HandleFunc("GET /v1/ai/mcp/endpoints/{endpointId}/tools", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		id := r.PathValue("endpointId")
		out := make([]any, 0)
		if e, err := getEndpoint(id); err == nil {
			for _, t := range e.ToolConfigs {
				out = append(out, aimcpEndpointToolJSON(id, t))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": out})
	})

	// POST /v1/ai/mcp/endpoints/{endpointId}/tools/{serverToolId} — enable a tool — {tool}
	mux.HandleFunc("POST /v1/ai/mcp/endpoints/{endpointId}/tools/{serverToolId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		eid, stid := r.PathValue("endpointId"), r.PathValue("serverToolId")
		e, err := getEndpoint(eid)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		tc := aimcpSetTool(e, stid, true)
		_ = saveEndpoint(e)
		writeJSON(w, http.StatusOK, map[string]any{"tool": aimcpEndpointToolJSON(eid, tc)})
	})

	// DELETE /v1/ai/mcp/endpoints/{endpointId}/tools/{serverToolId} — disable a tool
	mux.HandleFunc("DELETE /v1/ai/mcp/endpoints/{endpointId}/tools/{serverToolId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		eid, stid := r.PathValue("endpointId"), r.PathValue("serverToolId")
		e, err := getEndpoint(eid)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		_ = aimcpSetTool(e, stid, false)
		_ = saveEndpoint(e)
		writeJSON(w, http.StatusOK, msg("disabled"))
	})

	// PATCH /v1/ai/mcp/endpoints/{endpointId}/tools/bulk — {tools}
	mux.HandleFunc("PATCH /v1/ai/mcp/endpoints/{endpointId}/tools/bulk", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		eid := r.PathValue("endpointId")
		e, err := getEndpoint(eid)
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("endpoint not found"))
			return
		}
		var req struct {
			Tools []struct {
				ServerToolID string `json:"serverToolId"`
				IsEnabled    bool   `json:"isEnabled"`
			} `json:"tools"`
		}
		if !decode(w, r, &req) {
			return
		}
		for _, t := range req.Tools {
			_ = aimcpSetTool(e, t.ServerToolID, t.IsEnabled)
		}
		_ = saveEndpoint(e)
		out := make([]any, 0, len(e.ToolConfigs))
		for _, t := range e.ToolConfigs {
			out = append(out, aimcpEndpointToolJSON(eid, t))
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": out})
	})

	// GET /v1/ai/mcp/endpoints/{endpointId}/servers-requiring-auth — {servers}
	// Personal-credential mode: which of the endpoint's servers still need the
	// caller to supply credentials. With shared/no-auth servers this is empty.
	mux.HandleFunc("GET /v1/ai/mcp/endpoints/{endpointId}/servers-requiring-auth", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}})
	})

	// POST /v1/ai/mcp/endpoints/{endpointId}/oauth/finalize — {callbackUrl}
	// STUB: completes the MCP-side OAuth authorization-code exchange.
	mux.HandleFunc("POST /v1/ai/mcp/endpoints/{endpointId}/oauth/finalize", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			RedirectURI string `json:"redirect_uri"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"callbackUrl": req.RedirectURI})
	})

	// POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/oauth/initiate — {authUrl, sessionId}
	// STUB: per-server personal OAuth start.
	mux.HandleFunc("POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/oauth/initiate", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		sid := r.PathValue("serverId")
		authURL := ""
		if s, err := getServer(sid); err == nil {
			authURL = s.URL
		}
		writeJSON(w, http.StatusOK, map[string]any{"authUrl": authURL, "sessionId": newID()})
	})

	// POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/verify-token — {valid, message?}
	// STUB: a real impl probes the upstream MCP server with the bearer token.
	mux.HandleFunc("POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/verify-token", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			AccessToken string `json:"accessToken"`
		}
		_ = decode(w, r, &req)
		valid := strings.TrimSpace(req.AccessToken) != ""
		writeJSON(w, http.StatusOK, map[string]any{"valid": valid})
	})

	// POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/credentials — {success}
	// STUB: persisting a caller's personal credential for a server would store it
	// in the per-secret envelope; we acknowledge so the UI advances.
	mux.HandleFunc("POST /v1/ai/mcp/endpoints/{endpointId}/servers/{serverId}/credentials", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	})

	// ══ aiMcpActivityLogs ════════════════════════════════════════════════

	// GET /v1/ai/mcp/activity-logs — {activityLogs}
	// Empty page: the tool-call audit pipeline is not wired. Correct wrapper +
	// 200 so the infinite-scroll table renders an empty state, never a 404.
	mux.HandleFunc("GET /v1/ai/mcp/activity-logs", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"activityLogs": []any{}})
	})
}

// aimcpSetTool flips (or inserts) the enable-flag for a server-tool on an
// endpoint, returning the resulting config row. Endpoint tool-gating is real
// CRUD (config persisted inline); the underlying tool catalog is the stubbed
// part (it comes from MCP discovery).
func aimcpSetTool(e *aimcpEndpoint, serverToolID string, enabled bool) aimcpEndpointTool {
	for i := range e.ToolConfigs {
		if e.ToolConfigs[i].ServerToolID == serverToolID {
			e.ToolConfigs[i].IsEnabled = enabled
			return e.ToolConfigs[i]
		}
	}
	tc := aimcpEndpointTool{ID: newID(), ServerToolID: serverToolID, IsEnabled: enabled}
	e.ToolConfigs = append(e.ToolConfigs, tc)
	return tc
}
