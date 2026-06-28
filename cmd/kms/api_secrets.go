// Tier 3 — folders + secrets CRUD (the secrets-manager's actual job).
//
//	GET  /v1/folders ?projectId&environment&path        {folders}
//	POST /v1/folders {projectId,environment,name,path}   {folder}
//	PATCH/DELETE /v2/folders/{id} {projectId,environment,path,name?}
//	GET  /v1/secrets ?projectId&environment&secretPath   {secrets, imports}
//	GET  /v1/dashboard/secrets-details / secrets-overview / secret-value
//	POST/PATCH/DELETE /v4/secrets/{key} {projectId,environment,secretPath,secretValue}
//
// Secrets reuse pkg/store.SecretStore (same store the /v1/kms/orgs surface uses),
// project-scoped: storePath = "<projectID>[/<folder>]", name = secretKey,
// env = environment slug. Folders are JSON-KV entities. ZapDB-at-rest encryption
// protects values (matches the existing handler's storage model).
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

// cleanPath normalizes an Infisical secretPath ("/", "/myapp/db") to a slash-free
// relative path ("", "myapp/db").
func cleanPath(p string) string { return strings.Trim(strings.TrimSpace(p), "/") }

// storePath maps (project, secretPath) → the SecretStore path key.
func storePath(projectID, secretPath string) string {
	cp := cleanPath(secretPath)
	if cp == "" {
		return projectID
	}
	return projectID + "/" + cp
}

type folder struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ProjectID   string    `json:"projectId"`
	Env         string    `json:"env"`
	Path        string    `json:"path"` // parent path, slash-free
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

func folderKey(projectID, env, path, name string) []byte {
	return []byte("kms/folders/" + projectID + "/" + env + "/" + path + "|" + name)
}
func folderPrefix(projectID, env, path string) []byte {
	return []byte("kms/folders/" + projectID + "/" + env + "/" + path + "|")
}
func folderByID(id string) []byte { return []byte("kms/folder-id/" + id) }

func registerSecretsAPI(mux *http.ServeMux, db *badger.DB) {
	ws := newWebStore(db)
	secStore := store.NewSecretStore(db)
	auth := newWebAuth(webAuthSecret(db))
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth.fromRequest(r) == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return false
		}
		return true
	}

	// ── folders ──────────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/folders", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		writeJSON(w, http.StatusOK, map[string]any{
			"folders": listFolders(ws, q.Get("projectId"), envOrDefault(q.Get("environment")), cleanPath(q.Get("path"))),
		})
	})
	mux.HandleFunc("POST /v1/folders", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, Environment, Name, Path, Description string
		}
		if !decode(w, r, &req) {
			return
		}
		f := &folder{
			ID: newID(), Name: req.Name, ProjectID: req.ProjectID, Env: envOrDefault(req.Environment),
			Path: cleanPath(req.Path), Description: req.Description, CreatedAt: time.Now().UTC(),
		}
		_ = ws.putJSON(folderKey(f.ProjectID, f.Env, f.Path, f.Name), f)
		_ = ws.putJSON(folderByID(f.ID), f)
		writeJSON(w, http.StatusOK, map[string]any{"folder": folderJSON(f)})
	})
	patchFolder := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var f folder
		if ws.getJSON(folderByID(r.PathValue("id")), &f) != nil {
			writeJSON(w, http.StatusNotFound, msg("folder not found"))
			return
		}
		var req struct{ Name string }
		_ = decode(w, r, &req)
		if req.Name != "" {
			_ = ws.db.Update(func(txn *badger.Txn) error { return txn.Delete(folderKey(f.ProjectID, f.Env, f.Path, f.Name)) })
			f.Name = req.Name
			_ = ws.putJSON(folderKey(f.ProjectID, f.Env, f.Path, f.Name), &f)
			_ = ws.putJSON(folderByID(f.ID), &f)
		}
		writeJSON(w, http.StatusOK, map[string]any{"folder": folderJSON(&f)})
	}
	deleteFolder := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var f folder
		if ws.getJSON(folderByID(r.PathValue("id")), &f) != nil {
			writeJSON(w, http.StatusNotFound, msg("folder not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(folderKey(f.ProjectID, f.Env, f.Path, f.Name))
			return txn.Delete(folderByID(f.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"folder": folderJSON(&f)})
	}
	mux.HandleFunc("PATCH /v2/folders/{id}", patchFolder)
	mux.HandleFunc("DELETE /v2/folders/{id}", deleteFolder)

	// ── secrets ──────────────────────────────────────────────────────────
	listSecretsHandler := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		secs := listSecrets(secStore, q.Get("projectId"), envOrDefault(q.Get("environment")), q.Get("secretPath"))
		writeJSON(w, http.StatusOK, map[string]any{"secrets": secs, "imports": []any{}})
	}
	mux.HandleFunc("GET /v1/secrets", listSecretsHandler)

	// dashboard endpoints the secrets page actually calls
	mux.HandleFunc("GET /v1/dashboard/secrets-details", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		pid, env, sp := q.Get("projectId"), envOrDefault(q.Get("environment")), q.Get("secretPath")
		secs := listSecrets(secStore, pid, env, sp)
		folders := listFolders(ws, pid, env, cleanPath(sp))
		writeJSON(w, http.StatusOK, map[string]any{
			"secrets": secs, "folders": folders, "imports": []any{},
			"dynamicSecrets": []any{}, "secretRotations": []any{}, "totalCount": len(secs) + len(folders),
		})
	})
	mux.HandleFunc("GET /v1/dashboard/secrets-overview", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secrets": []any{}, "folders": []any{}, "dynamicSecrets": []any{},
			"secretRotations": []any{}, "imports": []any{},
			"totalUniqueSecretsInPage": 0, "totalUniqueFoldersInPage": 0, "totalCount": 0,
		})
	})
	mux.HandleFunc("GET /v1/dashboard/secret-value", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		sec, err := secStore.Get(storePath(q.Get("projectId"), q.Get("secretPath")), q.Get("secretKey"), envOrDefault(q.Get("environment")))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("secret not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretValue": string(sec.Ciphertext)})
	})

	// POST/PATCH/DELETE /v4/secrets/{key}
	upsertSecret := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		key := r.PathValue("key")
		var req struct {
			ProjectID, Environment, SecretPath, SecretValue, SecretComment string
		}
		if !decode(w, r, &req) {
			return
		}
		env := envOrDefault(req.Environment)
		sp := storePath(req.ProjectID, req.SecretPath)
		sec := &store.Secret{Name: key, Path: sp, Env: env, Ciphertext: []byte(req.SecretValue)}
		if err := secStore.Put(sec); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secret": secretJSON(req.ProjectID, env, req.SecretPath, key, req.SecretValue)})
	}
	mux.HandleFunc("POST /v4/secrets/{key}", upsertSecret)
	mux.HandleFunc("PATCH /v4/secrets/{key}", upsertSecret)
	mux.HandleFunc("DELETE /v4/secrets/{key}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		key := r.PathValue("key")
		var req struct{ ProjectID, Environment, SecretPath string }
		_ = decode(w, r, &req)
		_ = secStore.Delete(storePath(req.ProjectID, req.SecretPath), key, envOrDefault(req.Environment))
		writeJSON(w, http.StatusOK, map[string]any{"secret": map[string]any{"secretKey": key}})
	})
}

func envOrDefault(e string) string {
	if e == "" {
		return "default"
	}
	return e
}

func listFolders(ws *webStore, projectID, env, path string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	pfx := folderPrefix(projectID, env, path)
	_ = ws.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var f folder
				if json.Unmarshal(v, &f) == nil {
					out = append(out, folderJSON(&f))
				}
				return nil
			})
		}
		return nil
	})
	return out
}

func listSecrets(secStore *store.SecretStore, projectID, env, secretPath string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	sp := storePath(projectID, secretPath)
	secs, err := secStore.List(sp, env)
	if err != nil {
		return out
	}
	for _, s := range secs {
		// List() strips ciphertext to slim the payload; fetch each value so the
		// SPA dashboard can render it (viewSecretValue).
		val := ""
		if full, gerr := secStore.Get(sp, s.Name, env); gerr == nil {
			val = string(full.Ciphertext)
		}
		out = append(out, secretJSON(projectID, env, secretPath, s.Name, val))
	}
	return out
}

func folderJSON(f *folder) map[string]any {
	return map[string]any{"id": f.ID, "name": f.Name, "description": f.Description, "parentId": nil, "createdAt": f.CreatedAt, "updatedAt": f.CreatedAt, "version": 1}
}

func secretJSON(projectID, env, secretPath, key, value string) map[string]any {
	sp := "/" + cleanPath(secretPath)
	now := time.Now().UTC()
	return map[string]any{
		"id": projectID + ":" + env + ":" + cleanPath(secretPath) + ":" + key, "_id": key,
		"project": projectID, "environment": env, "version": 1, "type": "shared",
		"secretValueHidden": false, "secretKey": key, "secretPath": sp,
		"secretValue": value, "secretComment": "", "tags": []any{}, "metadata": map[string]any{},
		"createdAt": now, "updatedAt": now,
	}
}
