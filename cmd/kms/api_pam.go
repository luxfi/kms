// PAM — Privileged Access Management (resources, accounts, folders, sessions).
//
//	GET    /v1/pam/resources/options                       {resourceOptions: [...]}
//	GET    /v1/pam/resources ?projectId&...                {resources, totalCount}
//	POST   /v1/pam/resources/{resourceType}                {resource}
//	GET    /v1/pam/resources/{resourceType}/{resourceId}   {resource}
//	PATCH  /v1/pam/resources/{resourceType}/{resourceId}   {resource}
//	DELETE /v1/pam/resources/{resourceType}/{resourceId}   {resource}
//	GET    /v1/pam/accounts ?projectId&accountPath&...     {accounts, folders, totalCount, folderPaths}
//	POST   /v1/pam/accounts/{resourceType}                 {account}
//	PATCH  /v1/pam/accounts/{resourceType}/{accountId}     {account}
//	DELETE /v1/pam/accounts/{resourceType}/{accountId}     {account}
//	POST   /v1/pam/accounts/access                         {sessionId, ...}   (session-broker STUB)
//	POST   /v1/pam/folders                                 {folder}
//	PATCH  /v1/pam/folders/{folderId}                      {folder}
//	DELETE /v1/pam/folders/{folderId}                      {folder}
//	GET    /v1/pam/sessions ?projectId                     {sessions: [...]}
//	GET    /v1/pam/sessions/{sessionId}                    {session}
//
// Resources/accounts/folders/sessions persist as JSON-KV in ZapDB. The
// per-resource-type connectionDetails / credentials blobs are stored verbatim
// (json.RawMessage) since their shape varies by driver (SQL, SSH, k8s, AWS-IAM …).
// Credentials are sensitive: they are persisted but NEVER echoed back to the SPA
// (the list/get shapes omit them, matching how the UI treats password fields).
// Session brokering (relay/gateway cert minting, console-URL issuance) is a STUB:
// the access call records a session entity and returns a plausible-shaped response
// without minting real relay/gateway certificates or leasing dynamic credentials.
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

type pamResource struct {
	ID                string          `json:"id"`
	ProjectID         string          `json:"projectId"`
	Name              string          `json:"name"`
	ResourceType      string          `json:"resourceType"`
	GatewayID         string          `json:"gatewayId"`
	ConnectionDetails json.RawMessage `json:"connectionDetails,omitempty"`
	CreatedAt         time.Time       `json:"createdAt"`
	UpdatedAt         time.Time       `json:"updatedAt"`
}

type pamAccount struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"projectId"`
	FolderID     string          `json:"folderId,omitempty"`
	ResourceID   string          `json:"resourceId"`
	ResourceType string          `json:"resourceType"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	RequireMfa   bool            `json:"requireMfa"`
	Credentials  json.RawMessage `json:"-"` // sensitive: stored, never returned
	CreatedAt    time.Time       `json:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}

type pamFolder struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	ParentID    string    `json:"parentId,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type pamSession struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"projectId"`
	AccountID      string    `json:"accountId,omitempty"`
	ResourceType   string    `json:"resourceType"`
	ResourceName   string    `json:"resourceName"`
	AccountName    string    `json:"accountName"`
	UserID         string    `json:"userId,omitempty"`
	ActorName      string    `json:"actorName"`
	ActorEmail     string    `json:"actorEmail"`
	ActorIP        string    `json:"actorIp"`
	ActorUserAgent string    `json:"actorUserAgent"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expiresAt"`
	StartedAt      time.Time `json:"startedAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func pamResourceKey(id string) []byte     { return []byte("kms/pam/resources/" + id) }
func pamResourcePrefix(pid string) []byte { return []byte("kms/pam/by-project/" + pid + "/resources/") }
func pamResourceIdx(pid, id string) []byte {
	return []byte("kms/pam/by-project/" + pid + "/resources/" + id)
}

func pamAccountKey(id string) []byte     { return []byte("kms/pam/accounts/" + id) }
func pamAccountPrefix(pid string) []byte { return []byte("kms/pam/by-project/" + pid + "/accounts/") }
func pamAccountIdx(pid, id string) []byte {
	return []byte("kms/pam/by-project/" + pid + "/accounts/" + id)
}

func pamFolderKey(id string) []byte     { return []byte("kms/pam/folders/" + id) }
func pamFolderPrefix(pid string) []byte { return []byte("kms/pam/by-project/" + pid + "/folders/") }
func pamFolderIdx(pid, id string) []byte {
	return []byte("kms/pam/by-project/" + pid + "/folders/" + id)
}

func pamSessionKey(id string) []byte     { return []byte("kms/pam/sessions/" + id) }
func pamSessionPrefix(pid string) []byte { return []byte("kms/pam/by-project/" + pid + "/sessions/") }
func pamSessionIdx(pid, id string) []byte {
	return []byte("kms/pam/by-project/" + pid + "/sessions/" + id)
}

// pamListIDs collects entity IDs for a project from a by-project index prefix.
func pamListIDs(ws *webStore, prefix []byte) []string {
	var ids []string
	_ = ws.db.View(func(txn *badger.Txn) error {
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

// pamResourceJSON renders the SPA TPamResource shape (credentials never echoed).
func pamResourceJSON(rsc *pamResource) map[string]any {
	var cd any = map[string]any{}
	if len(rsc.ConnectionDetails) > 0 {
		_ = json.Unmarshal(rsc.ConnectionDetails, &cd)
	}
	return map[string]any{
		"id": rsc.ID, "projectId": rsc.ProjectID, "name": rsc.Name,
		"resourceType": rsc.ResourceType, "gatewayId": rsc.GatewayID,
		"connectionDetails": cd, "rotationAccountCredentials": nil,
		"createdAt": rsc.CreatedAt, "updatedAt": rsc.UpdatedAt,
	}
}

// pamAccountJSON renders the SPA TPamAccount shape. credentials is intentionally
// absent from the response; the embedded `resource` summary is filled when known.
func pamAccountJSON(acct *pamAccount, rsc *pamResource) map[string]any {
	resSummary := map[string]any{
		"id": acct.ResourceID, "name": "", "resourceType": acct.ResourceType,
		"rotationCredentialsConfigured": false,
	}
	if rsc != nil {
		resSummary["name"] = rsc.Name
		resSummary["resourceType"] = rsc.ResourceType
	}
	var fid any
	if acct.FolderID != "" {
		fid = acct.FolderID
	}
	return map[string]any{
		"id": acct.ID, "projectId": acct.ProjectID, "folderId": fid,
		"resourceId": acct.ResourceID, "resource": resSummary,
		"name": acct.Name, "description": acct.Description,
		"rotationEnabled": false, "requireMfa": acct.RequireMfa,
		"lastRotatedAt": nil, "lastRotationMessage": nil, "rotationStatus": nil,
		"createdAt": acct.CreatedAt, "updatedAt": acct.UpdatedAt,
	}
}

func pamFolderJSON(f *pamFolder) map[string]any {
	var pid any
	if f.ParentID != "" {
		pid = f.ParentID
	}
	return map[string]any{
		"id": f.ID, "projectId": f.ProjectID, "parentId": pid,
		"name": f.Name, "description": f.Description,
		"createdAt": f.CreatedAt, "updatedAt": f.UpdatedAt,
	}
}

func pamSessionJSON(s *pamSession) map[string]any {
	out := map[string]any{
		"id": s.ID, "projectId": s.ProjectID, "resourceType": s.ResourceType,
		"resourceName": s.ResourceName, "accountName": s.AccountName,
		"actorName": s.ActorName, "actorEmail": s.ActorEmail, "actorIp": s.ActorIP,
		"actorUserAgent": s.ActorUserAgent, "status": s.Status, "logs": []any{},
		"createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
	if s.AccountID != "" {
		out["accountId"] = s.AccountID
	} else {
		out["accountId"] = nil
	}
	if s.UserID != "" {
		out["userId"] = s.UserID
	} else {
		out["userId"] = nil
	}
	if !s.ExpiresAt.IsZero() {
		out["expiresAt"] = s.ExpiresAt
	}
	if !s.StartedAt.IsZero() {
		out["startedAt"] = s.StartedAt
	}
	return out
}

func registerPamAPI(mux *http.ServeMux, db *badger.DB) {
	ws := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth.fromRequest(r) == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return false
		}
		return true
	}

	// ── resources ────────────────────────────────────────────────────────

	// GET /v1/pam/resources/options — drivers the SPA can create resources for.
	// (Literal "options" segment outranks the {resourceType} wildcard on this
	// path, so no ServeMux conflict.)
	mux.HandleFunc("GET /v1/pam/resources/options", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		opts := []map[string]any{
			{"name": "PostgreSQL", "resource": "postgres"},
		}
		writeJSON(w, http.StatusOK, map[string]any{"resourceOptions": opts})
	})

	// GET /v1/pam/resources — resources in a project.
	mux.HandleFunc("GET /v1/pam/resources", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		out := []any{}
		for _, id := range pamListIDs(ws, pamResourcePrefix(pid)) {
			var rsc pamResource
			if ws.getJSON(pamResourceKey(id), &rsc) == nil {
				out = append(out, pamResourceJSON(&rsc))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"resources": out, "totalCount": len(out)})
	})

	// POST /v1/pam/resources/{resourceType}
	mux.HandleFunc("POST /v1/pam/resources/{resourceType}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID         string          `json:"projectId"`
			Name              string          `json:"name"`
			GatewayID         string          `json:"gatewayId"`
			ConnectionDetails json.RawMessage `json:"connectionDetails"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		rsc := &pamResource{
			ID: newID(), ProjectID: req.ProjectID, Name: req.Name,
			ResourceType: r.PathValue("resourceType"), GatewayID: req.GatewayID,
			ConnectionDetails: req.ConnectionDetails, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(pamResourceKey(rsc.ID), rsc)
		_ = ws.db.Update(func(txn *badger.Txn) error {
			return txn.Set(pamResourceIdx(rsc.ProjectID, rsc.ID), []byte(rsc.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"resource": pamResourceJSON(rsc)})
	})

	// GET /v1/pam/resources/{resourceType}/{resourceId}
	mux.HandleFunc("GET /v1/pam/resources/{resourceType}/{resourceId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rsc pamResource
		if ws.getJSON(pamResourceKey(r.PathValue("resourceId")), &rsc) != nil {
			writeJSON(w, http.StatusNotFound, msg("resource not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource": pamResourceJSON(&rsc)})
	})

	// PATCH /v1/pam/resources/{resourceType}/{resourceId}
	mux.HandleFunc("PATCH /v1/pam/resources/{resourceType}/{resourceId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rsc pamResource
		if ws.getJSON(pamResourceKey(r.PathValue("resourceId")), &rsc) != nil {
			writeJSON(w, http.StatusNotFound, msg("resource not found"))
			return
		}
		var req struct {
			Name              *string         `json:"name"`
			GatewayID         *string         `json:"gatewayId"`
			ConnectionDetails json.RawMessage `json:"connectionDetails"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			rsc.Name = *req.Name
		}
		if req.GatewayID != nil {
			rsc.GatewayID = *req.GatewayID
		}
		if len(req.ConnectionDetails) > 0 {
			rsc.ConnectionDetails = req.ConnectionDetails
		}
		rsc.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(pamResourceKey(rsc.ID), &rsc)
		writeJSON(w, http.StatusOK, map[string]any{"resource": pamResourceJSON(&rsc)})
	})

	// DELETE /v1/pam/resources/{resourceType}/{resourceId}
	mux.HandleFunc("DELETE /v1/pam/resources/{resourceType}/{resourceId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		id := r.PathValue("resourceId")
		var rsc pamResource
		if ws.getJSON(pamResourceKey(id), &rsc) != nil {
			writeJSON(w, http.StatusNotFound, msg("resource not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(pamResourceKey(id))
			return txn.Delete(pamResourceIdx(rsc.ProjectID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"resource": pamResourceJSON(&rsc)})
	})

	// ── accounts ─────────────────────────────────────────────────────────

	// GET /v1/pam/accounts — accounts + folders in a project (the accounts tab).
	mux.HandleFunc("GET /v1/pam/accounts", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		accounts := []any{}
		for _, id := range pamListIDs(ws, pamAccountPrefix(pid)) {
			var acct pamAccount
			if ws.getJSON(pamAccountKey(id), &acct) == nil {
				var rsc pamResource
				var rp *pamResource
				if acct.ResourceID != "" && ws.getJSON(pamResourceKey(acct.ResourceID), &rsc) == nil {
					rp = &rsc
				}
				accounts = append(accounts, pamAccountJSON(&acct, rp))
			}
		}
		folders := []any{}
		folderPaths := map[string]any{}
		for _, id := range pamListIDs(ws, pamFolderPrefix(pid)) {
			var f pamFolder
			if ws.getJSON(pamFolderKey(id), &f) == nil {
				folders = append(folders, pamFolderJSON(&f))
				folderPaths[f.ID] = "/" + f.Name
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"accounts": accounts, "folders": folders,
			"totalCount": len(accounts), "folderPaths": folderPaths,
		})
	})

	// POST /v1/pam/accounts/access — session-broker STUB. Records a session
	// entity and returns a plausible-shaped access response WITHOUT minting real
	// relay/gateway certificates or leasing dynamic credentials.
	// (Literal "access" outranks the {resourceType} wildcard for POST.)
	mux.HandleFunc("POST /v1/pam/accounts/access", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			AccountID   string `json:"accountId"`
			AccountPath string `json:"accountPath"`
			ProjectID   string `json:"projectId"`
			Duration    string `json:"duration"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		resourceType := ""
		accountName := ""
		resourceName := ""
		var acct pamAccount
		if req.AccountID != "" && ws.getJSON(pamAccountKey(req.AccountID), &acct) == nil {
			resourceType = acct.ResourceType
			accountName = acct.Name
			var rsc pamResource
			if acct.ResourceID != "" && ws.getJSON(pamResourceKey(acct.ResourceID), &rsc) == nil {
				resourceName = rsc.Name
			}
		}
		dur := time.Hour
		if d, err := time.ParseDuration(req.Duration); err == nil && d > 0 {
			dur = d
		}
		sess := &pamSession{
			ID: newID(), ProjectID: req.ProjectID, AccountID: req.AccountID,
			ResourceType: resourceType, ResourceName: resourceName, AccountName: accountName,
			Status: "starting", StartedAt: now, ExpiresAt: now.Add(dur),
			CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(pamSessionKey(sess.ID), sess)
		_ = ws.db.Update(func(txn *badger.Txn) error {
			return txn.Set(pamSessionIdx(sess.ProjectID, sess.ID), []byte(sess.ID))
		})
		// Shape matches TAccessPamAccountResponse; cert/relay fields omitted (stub).
		writeJSON(w, http.StatusOK, map[string]any{
			"sessionId": sess.ID, "resourceType": resourceType,
			"metadata": map[string]any{},
		})
	})

	// POST /v1/pam/accounts/{resourceType}
	mux.HandleFunc("POST /v1/pam/accounts/{resourceType}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID   string          `json:"projectId"`
			ResourceID  string          `json:"resourceId"`
			FolderID    string          `json:"folderId"`
			Name        string          `json:"name"`
			Description string          `json:"description"`
			RequireMfa  bool            `json:"requireMfa"`
			Credentials json.RawMessage `json:"credentials"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		acct := &pamAccount{
			ID: newID(), ProjectID: req.ProjectID, ResourceID: req.ResourceID,
			FolderID: req.FolderID, ResourceType: r.PathValue("resourceType"),
			Name: req.Name, Description: req.Description, RequireMfa: req.RequireMfa,
			Credentials: req.Credentials, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(pamAccountKey(acct.ID), acct)
		_ = ws.db.Update(func(txn *badger.Txn) error {
			return txn.Set(pamAccountIdx(acct.ProjectID, acct.ID), []byte(acct.ID))
		})
		var rsc pamResource
		var rp *pamResource
		if acct.ResourceID != "" && ws.getJSON(pamResourceKey(acct.ResourceID), &rsc) == nil {
			rp = &rsc
		}
		writeJSON(w, http.StatusOK, map[string]any{"account": pamAccountJSON(acct, rp)})
	})

	// PATCH /v1/pam/accounts/{resourceType}/{accountId}
	mux.HandleFunc("PATCH /v1/pam/accounts/{resourceType}/{accountId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var acct pamAccount
		if ws.getJSON(pamAccountKey(r.PathValue("accountId")), &acct) != nil {
			writeJSON(w, http.StatusNotFound, msg("account not found"))
			return
		}
		var req struct {
			Name        *string         `json:"name"`
			Description *string         `json:"description"`
			RequireMfa  *bool           `json:"requireMfa"`
			Credentials json.RawMessage `json:"credentials"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			acct.Name = *req.Name
		}
		if req.Description != nil {
			acct.Description = *req.Description
		}
		if req.RequireMfa != nil {
			acct.RequireMfa = *req.RequireMfa
		}
		// Only overwrite credentials when a real (non-sentinel) value is supplied.
		if len(req.Credentials) > 0 && string(req.Credentials) != "null" &&
			!pamCredentialsUnchanged(req.Credentials) {
			acct.Credentials = req.Credentials
		}
		acct.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(pamAccountKey(acct.ID), &acct)
		var rsc pamResource
		var rp *pamResource
		if acct.ResourceID != "" && ws.getJSON(pamResourceKey(acct.ResourceID), &rsc) == nil {
			rp = &rsc
		}
		writeJSON(w, http.StatusOK, map[string]any{"account": pamAccountJSON(&acct, rp)})
	})

	// DELETE /v1/pam/accounts/{resourceType}/{accountId}
	mux.HandleFunc("DELETE /v1/pam/accounts/{resourceType}/{accountId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		id := r.PathValue("accountId")
		var acct pamAccount
		if ws.getJSON(pamAccountKey(id), &acct) != nil {
			writeJSON(w, http.StatusNotFound, msg("account not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(pamAccountKey(id))
			return txn.Delete(pamAccountIdx(acct.ProjectID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"account": pamAccountJSON(&acct, nil)})
	})

	// ── folders ──────────────────────────────────────────────────────────

	// POST /v1/pam/folders
	mux.HandleFunc("POST /v1/pam/folders", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID   string `json:"projectId"`
			ParentID    string `json:"parentId"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		f := &pamFolder{
			ID: newID(), ProjectID: req.ProjectID, ParentID: req.ParentID,
			Name: req.Name, Description: req.Description, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(pamFolderKey(f.ID), f)
		_ = ws.db.Update(func(txn *badger.Txn) error {
			return txn.Set(pamFolderIdx(f.ProjectID, f.ID), []byte(f.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"folder": pamFolderJSON(f)})
	})

	// PATCH /v1/pam/folders/{folderId}
	mux.HandleFunc("PATCH /v1/pam/folders/{folderId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var f pamFolder
		if ws.getJSON(pamFolderKey(r.PathValue("folderId")), &f) != nil {
			writeJSON(w, http.StatusNotFound, msg("folder not found"))
			return
		}
		var req struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name != nil {
			f.Name = *req.Name
		}
		if req.Description != nil {
			f.Description = *req.Description
		}
		f.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(pamFolderKey(f.ID), &f)
		writeJSON(w, http.StatusOK, map[string]any{"folder": pamFolderJSON(&f)})
	})

	// DELETE /v1/pam/folders/{folderId}
	mux.HandleFunc("DELETE /v1/pam/folders/{folderId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		id := r.PathValue("folderId")
		var f pamFolder
		if ws.getJSON(pamFolderKey(id), &f) != nil {
			writeJSON(w, http.StatusNotFound, msg("folder not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(pamFolderKey(id))
			return txn.Delete(pamFolderIdx(f.ProjectID, id))
		})
		writeJSON(w, http.StatusOK, map[string]any{"folder": pamFolderJSON(&f)})
	})

	// ── sessions ─────────────────────────────────────────────────────────

	// GET /v1/pam/sessions — sessions recorded for a project.
	mux.HandleFunc("GET /v1/pam/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.URL.Query().Get("projectId")
		out := []any{}
		for _, id := range pamListIDs(ws, pamSessionPrefix(pid)) {
			var s pamSession
			if ws.getJSON(pamSessionKey(id), &s) == nil {
				out = append(out, pamSessionJSON(&s))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
	})

	// GET /v1/pam/sessions/{sessionId}
	mux.HandleFunc("GET /v1/pam/sessions/{sessionId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var s pamSession
		if ws.getJSON(pamSessionKey(r.PathValue("sessionId")), &s) != nil {
			writeJSON(w, http.StatusNotFound, msg("session not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"session": pamSessionJSON(&s)})
	})
}

// pamCredentialsUnchanged reports whether the supplied credentials blob is the
// "unchanged password" sentinel the SPA sends to keep stored credentials intact.
func pamCredentialsUnchanged(raw json.RawMessage) bool {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	if pw, ok := m["password"].(string); ok && pw == "__KMS_UNCHANGED__" {
		return true
	}
	return false
}
