package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// aimcpTestServer wires core + ai/mcp APIs and returns a logged-in, org-scoped
// session token to drive the flow.
func aimcpTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	registerCoreAPI(mux, db, "")
	registerAiMcpAPI(mux, db)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if code, _ := do(t, "POST", srv.URL+"/v1/admin/signup", "", map[string]any{
		"email": "z@lux.network", "password": "S3cret-pw!", "organizationName": "Lux",
	}); code != 200 {
		t.Fatalf("signup: %d", code)
	}
	_, login := do(t, "POST", srv.URL+"/v1/auth/login", "", map[string]any{"email": "z@lux.network", "password": "S3cret-pw!"})
	_, sel := do(t, "POST", srv.URL+"/v1/auth/select-organization", login["accessToken"].(string), map[string]any{})
	return srv, sel["token"].(string)
}

// TestAiMcpServerFlow: create → list → get → patch → tools → sync → delete.
func TestAiMcpServerFlow(t *testing.T) {
	srv, tok := aimcpTestServer(t)
	const pid = "proj-1"

	code, cs := do(t, "POST", srv.URL+"/v1/ai/mcp/servers", tok, map[string]any{
		"projectId": pid, "name": "GitHub MCP", "url": "https://mcp.example/sse",
		"credentialMode": "shared", "authMethod": "bearer",
	})
	if code != 200 {
		t.Fatalf("create server: %d %v", code, cs)
	}
	s := cs["server"].(map[string]any)
	sid := s["id"].(string)
	if s["status"] != "uninitialized" {
		t.Fatalf("status: %v", s["status"])
	}

	_, ls := do(t, "GET", srv.URL+"/v1/ai/mcp/servers?projectId="+pid, tok, nil)
	if len(ls["servers"].([]any)) != 1 {
		t.Fatalf("list servers != 1: %v", ls)
	}
	if ls["totalCount"].(float64) != 1 {
		t.Fatalf("totalCount != 1")
	}

	_, gs := do(t, "GET", srv.URL+"/v1/ai/mcp/servers/"+sid, tok, nil)
	if gs["server"].(map[string]any)["name"] != "GitHub MCP" {
		t.Fatalf("get name: %v", gs)
	}

	_, ps := do(t, "PATCH", srv.URL+"/v1/ai/mcp/servers/"+sid, tok, map[string]any{"name": "GH MCP"})
	if ps["server"].(map[string]any)["name"] != "GH MCP" {
		t.Fatalf("patch name: %v", ps)
	}

	_, gt := do(t, "GET", srv.URL+"/v1/ai/mcp/servers/"+sid+"/tools", tok, nil)
	if len(gt["tools"].([]any)) != 0 {
		t.Fatalf("tools != empty")
	}
	_, _ = do(t, "POST", srv.URL+"/v1/ai/mcp/servers/"+sid+"/tools/sync", tok, nil)
	_, gs2 := do(t, "GET", srv.URL+"/v1/ai/mcp/servers/"+sid, tok, nil)
	if gs2["server"].(map[string]any)["status"] != "active" {
		t.Fatalf("post-sync status: %v", gs2)
	}

	if code, _ := do(t, "DELETE", srv.URL+"/v1/ai/mcp/servers/"+sid, tok, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	_, ls2 := do(t, "GET", srv.URL+"/v1/ai/mcp/servers?projectId="+pid, tok, nil)
	if len(ls2["servers"].([]any)) != 0 {
		t.Fatalf("list after delete != 0")
	}
}

// TestAiMcpEndpointFlow: create → list → get(serverIds) → tool gate → patch → delete.
func TestAiMcpEndpointFlow(t *testing.T) {
	srv, tok := aimcpTestServer(t)
	const pid = "proj-2"

	code, ce := do(t, "POST", srv.URL+"/v1/ai/mcp/endpoints", tok, map[string]any{
		"projectId": pid, "name": "Agent EP", "serverIds": []string{"srv-a", "srv-b"},
	})
	if code != 200 {
		t.Fatalf("create endpoint: %d %v", code, ce)
	}
	e := ce["endpoint"].(map[string]any)
	eid := e["id"].(string)
	if e["connectedServers"].(float64) != 2 {
		t.Fatalf("connectedServers: %v", e["connectedServers"])
	}
	if e["activeTools"].(float64) != 0 {
		t.Fatalf("activeTools: %v", e["activeTools"])
	}

	_, le := do(t, "GET", srv.URL+"/v1/ai/mcp/endpoints?projectId="+pid, tok, nil)
	if len(le["endpoints"].([]any)) != 1 {
		t.Fatalf("list endpoints != 1")
	}

	_, ge := do(t, "GET", srv.URL+"/v1/ai/mcp/endpoints/"+eid, tok, nil)
	if ids := ge["endpoint"].(map[string]any)["serverIds"].([]any); len(ids) != 2 {
		t.Fatalf("serverIds on detail: %v", ids)
	}

	// enable a tool, confirm activeTools reflects it
	_, et := do(t, "POST", srv.URL+"/v1/ai/mcp/endpoints/"+eid+"/tools/tool-1", tok, nil)
	if et["tool"].(map[string]any)["isEnabled"] != true {
		t.Fatalf("enable tool: %v", et)
	}
	_, gt := do(t, "GET", srv.URL+"/v1/ai/mcp/endpoints/"+eid+"/tools", tok, nil)
	if len(gt["tools"].([]any)) != 1 {
		t.Fatalf("endpoint tools != 1")
	}
	_, ge2 := do(t, "GET", srv.URL+"/v1/ai/mcp/endpoints/"+eid, tok, nil)
	if ge2["endpoint"].(map[string]any)["activeTools"].(float64) != 1 {
		t.Fatalf("activeTools after enable: %v", ge2)
	}

	// disable it
	if code, _ := do(t, "DELETE", srv.URL+"/v1/ai/mcp/endpoints/"+eid+"/tools/tool-1", tok, nil); code != 200 {
		t.Fatalf("disable tool: %d", code)
	}
	_, ge3 := do(t, "GET", srv.URL+"/v1/ai/mcp/endpoints/"+eid, tok, nil)
	if ge3["endpoint"].(map[string]any)["activeTools"].(float64) != 0 {
		t.Fatalf("activeTools after disable: %v", ge3)
	}

	// bulk enable two
	_, bt := do(t, "PATCH", srv.URL+"/v1/ai/mcp/endpoints/"+eid+"/tools/bulk", tok, map[string]any{
		"tools": []map[string]any{
			{"serverToolId": "tool-1", "isEnabled": true},
			{"serverToolId": "tool-2", "isEnabled": true},
		},
	})
	if len(bt["tools"].([]any)) != 2 {
		t.Fatalf("bulk tools != 2: %v", bt)
	}

	// patch endpoint metadata
	_, pe := do(t, "PATCH", srv.URL+"/v1/ai/mcp/endpoints/"+eid, tok, map[string]any{
		"name": "Agent EP v2", "piiFiltering": true,
	})
	if pe["endpoint"].(map[string]any)["name"] != "Agent EP v2" {
		t.Fatalf("patch name: %v", pe)
	}
	if pe["endpoint"].(map[string]any)["piiFiltering"] != true {
		t.Fatalf("piiFiltering: %v", pe)
	}

	if code, _ := do(t, "DELETE", srv.URL+"/v1/ai/mcp/endpoints/"+eid, tok, nil); code != 200 {
		t.Fatalf("delete endpoint: %d", code)
	}
}

// TestAiMcpActivityLogsEmpty: the audit tab returns the wrapper with an empty
// array (never a 404) so the UI renders an empty state.
func TestAiMcpActivityLogsEmpty(t *testing.T) {
	srv, tok := aimcpTestServer(t)
	code, out := do(t, "GET", srv.URL+"/v1/ai/mcp/activity-logs?projectId=p&limit=20", tok, nil)
	if code != 200 {
		t.Fatalf("activity-logs: %d", code)
	}
	if logs, ok := out["activityLogs"].([]any); !ok || len(logs) != 0 {
		t.Fatalf("activityLogs not empty array: %v", out)
	}
}

// TestAiMcpUnauthorized: list routes 401 without a session.
func TestAiMcpUnauthorized(t *testing.T) {
	srv, _ := aimcpTestServer(t)
	for _, u := range []string{
		"/v1/ai/mcp/servers?projectId=p",
		"/v1/ai/mcp/endpoints?projectId=p",
		"/v1/ai/mcp/activity-logs?projectId=p",
	} {
		if code, _ := do(t, "GET", srv.URL+u, "", nil); code != 401 {
			t.Fatalf("%s want 401 got %d", u, code)
		}
	}
}
