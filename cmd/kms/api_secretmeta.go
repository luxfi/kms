// SecretMeta — the metadata that decorates secrets: tags, imports, reminders,
// trusted-IP allow-lists, plus the history surfaces (PIT folder-commits and
// secret-snapshots).
//
//	tags             GET/POST  /v1/projects/{id}/tags ; DELETE /v1/projects/{id}/tags/{tagId}
//	secretImports    GET/POST  /v1/secret-imports ; PATCH/DELETE /v2/secret-imports/{id}
//	                 POST      /v2/secret-imports/{id}/replication-resync ; GET /v1/dashboard/secret-imports
//	reminders        GET/POST/DELETE /v1/reminders/secrets/{secretId}
//	trustedIps       GET/POST  /v1/projects/{id}/trusted-ips ; PATCH/DELETE /v1/projects/{id}/trusted-ips/{ipId}
//	secretSnapshots  GET /v1/projects/{id}/secret-snapshots{,/count} ; GET /v1/secret-snapshot/{id}
//	                 POST /v1/secret-snapshot/{id}/rollback
//	folderCommits    GET /v1/pit/commits{,/count,/{id}/changes,/{id}/compare} ; POST .../rollback,/revert
//
// tags / imports / reminders / trusted-ips are real CRUD entities persisted as
// JSON-KV in ZapDB (kms/secretmeta/...). The history surfaces (PIT commits and
// snapshots) are NOT backed by a real version graph here — they return the
// correctly-shaped empty/zero responses (200, never 404) so the UI's history
// tabs render cleanly; a rollback/revert against no history is a no-op success.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entity types ─────────────────────────────────────────────────────────────

type wsTag struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Color     string    `json:"color"`
	ProjectID string    `json:"projectId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type secretImport struct {
	ID            string    `json:"id"`
	ProjectID     string    `json:"projectId"`
	Environment   string    `json:"environment"`
	Path          string    `json:"path"`
	ImportEnv     string    `json:"importEnv"`
	ImportPath    string    `json:"importPath"`
	Position      int       `json:"position"`
	IsReplication bool      `json:"isReplication"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type reminder struct {
	ID               string    `json:"id"`
	SecretID         string    `json:"secretId"`
	Message          string    `json:"message"`
	RepeatDays       int       `json:"repeatDays"`
	NextReminderDate *string   `json:"nextReminderDate"`
	FromDate         *string   `json:"fromDate"`
	Recipients       []string  `json:"recipients"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type trustedIP struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	IPAddress string    `json:"ipAddress"`
	Type      string    `json:"type"`
	Prefix    *int      `json:"prefix"`
	IsActive  bool      `json:"isActive"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ── key helpers (unique kms/secretmeta/ prefix) ──────────────────────────────

func smTagKey(projectID, id string) []byte {
	return []byte("kms/secretmeta/tags/" + projectID + "/" + id)
}
func smTagPrefix(projectID string) []byte {
	return []byte("kms/secretmeta/tags/" + projectID + "/")
}

func smImportKey(id string) []byte { return []byte("kms/secretmeta/imports/byid/" + id) }
func smImportIdx(projectID, env, path, id string) []byte {
	return []byte("kms/secretmeta/imports/idx/" + projectID + "/" + env + "/" + path + "/" + id)
}
func smImportPrefix(projectID, env, path string) []byte {
	return []byte("kms/secretmeta/imports/idx/" + projectID + "/" + env + "/" + path + "/")
}

func smReminderKey(secretID string) []byte {
	return []byte("kms/secretmeta/reminders/" + secretID)
}

func smTrustedIPKey(projectID, id string) []byte {
	return []byte("kms/secretmeta/trusted-ips/" + projectID + "/" + id)
}
func smTrustedIPPrefix(projectID string) []byte {
	return []byte("kms/secretmeta/trusted-ips/" + projectID + "/")
}

// smIPType classifies an address (or CIDR) as ipv4 / ipv6 for the SPA badge.
func smIPType(addr string) string {
	host := addr
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// ── JSON shapes (match the SPA deserializers) ────────────────────────────────

func smTagJSON(t *wsTag) map[string]any {
	return map[string]any{
		"id": t.ID, "slug": t.Slug, "color": t.Color, "projectId": t.ProjectID,
		"createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt, "__v": 0,
	}
}

func smImportJSON(im *secretImport) map[string]any {
	return map[string]any{
		"id": im.ID, "folderId": im.ProjectID + ":" + im.Environment + ":" + cleanPath(im.Path),
		"importPath":  "/" + cleanPath(im.ImportPath),
		"importEnv":   map[string]any{"id": im.ImportEnv, "name": im.ImportEnv, "slug": im.ImportEnv},
		"position":    im.Position,
		"environment": im.Environment,
		"isReplication": im.IsReplication, "isReplicationSuccess": im.IsReplication,
		"isReserved": false, "replicationStatus": nil, "lastReplicated": nil,
		"createdAt": im.CreatedAt, "updatedAt": im.UpdatedAt,
	}
}

func smReminderJSON(rm *reminder) map[string]any {
	recipients := rm.Recipients
	if recipients == nil {
		recipients = []string{}
	}
	return map[string]any{
		"id": rm.ID, "secretId": rm.SecretID, "message": rm.Message,
		"repeatDays": rm.RepeatDays, "nextReminderDate": rm.NextReminderDate,
		"fromDate": rm.FromDate, "recipients": recipients,
		"createdAt": rm.CreatedAt, "updatedAt": rm.UpdatedAt,
	}
}

func smTrustedIPJSON(ip *trustedIP) map[string]any {
	return map[string]any{
		"id": ip.ID, "projectId": ip.ProjectID, "ipAddress": ip.IPAddress,
		"type": ip.Type, "prefix": ip.Prefix, "isActive": ip.IsActive,
		"comment": ip.Comment, "createdAt": ip.CreatedAt, "updatedAt": ip.UpdatedAt,
	}
}

// smList iterates a prefix and decodes each value into the SPA shape via render.
func smList(ws *webStore, prefix []byte, render func(v []byte) (map[string]any, bool)) []any {
	out := []any{}
	_ = ws.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				if m, ok := render(v); ok {
					out = append(out, m)
				}
				return nil
			})
		}
		return nil
	})
	return out
}

func registerSecretMetaAPI(mux *http.ServeMux, db *badger.DB) {
	ws := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth.fromRequest(r) == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return false
		}
		return true
	}

	// ── tags ─────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/projects/{id}/tags", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.PathValue("id")
		tags := smList(ws, smTagPrefix(pid), func(v []byte) (map[string]any, bool) {
			var t wsTag
			if json.Unmarshal(v, &t) != nil {
				return nil, false
			}
			return smTagJSON(&t), true
		})
		writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
	})
	mux.HandleFunc("POST /v1/projects/{id}/tags", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.PathValue("id")
		var req struct{ Color, Slug, Name string }
		if !decode(w, r, &req) {
			return
		}
		slug := req.Slug
		if slug == "" {
			slug = slugify(req.Name)
		}
		now := time.Now().UTC()
		t := &wsTag{ID: newID(), Slug: slug, Color: req.Color, ProjectID: pid, CreatedAt: now, UpdatedAt: now}
		_ = ws.putJSON(smTagKey(pid, t.ID), t)
		writeJSON(w, http.StatusOK, map[string]any{"tag": smTagJSON(t)})
	})
	mux.HandleFunc("DELETE /v1/projects/{id}/tags/{tagId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid, tid := r.PathValue("id"), r.PathValue("tagId")
		var t wsTag
		if ws.getJSON(smTagKey(pid, tid), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("tag not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error { return txn.Delete(smTagKey(pid, tid)) })
		writeJSON(w, http.StatusOK, map[string]any{"tag": smTagJSON(&t)})
	})

	// ── secret imports ─────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/secret-imports", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		pid, env, path := q.Get("projectId"), envOrDefault(q.Get("environment")), cleanPath(q.Get("path"))
		imports := []any{}
		if pid != "" {
			imports = smList(ws, smImportPrefix(pid, env, path), func(v []byte) (map[string]any, bool) {
				var im secretImport
				if json.Unmarshal(v, &im) != nil {
					return nil, false
				}
				return smImportJSON(&im), true
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretImports": imports})
	})
	mux.HandleFunc("POST /v1/secret-imports", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID     string `json:"projectId"`
			Environment   string `json:"environment"`
			Path          string `json:"path"`
			IsReplication bool   `json:"isReplication"`
			Import        struct {
				Environment string `json:"environment"`
				Path        string `json:"path"`
			} `json:"import"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		im := &secretImport{
			ID: newID(), ProjectID: req.ProjectID, Environment: envOrDefault(req.Environment),
			Path: cleanPath(req.Path), ImportEnv: req.Import.Environment, ImportPath: cleanPath(req.Import.Path),
			Position: 1, IsReplication: req.IsReplication, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(smImportKey(im.ID), im)
		_ = ws.putJSON(smImportIdx(im.ProjectID, im.Environment, im.Path, im.ID), im)
		writeJSON(w, http.StatusOK, map[string]any{"message": "success", "secretImport": smImportJSON(im)})
	})
	// dashboard imported-secrets resolution is not materialized — empty list.
	mux.HandleFunc("GET /v1/dashboard/secret-imports", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secrets": []any{}})
	})
	mux.HandleFunc("PATCH /v2/secret-imports/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var im secretImport
		if ws.getJSON(smImportKey(r.PathValue("id")), &im) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret import not found"))
			return
		}
		var req struct {
			Import struct {
				Environment string `json:"environment"`
				Path        string `json:"path"`
				Position    *int   `json:"position"`
			} `json:"import"`
		}
		_ = decode(w, r, &req)
		if req.Import.Environment != "" {
			im.ImportEnv = req.Import.Environment
		}
		if req.Import.Path != "" {
			im.ImportPath = cleanPath(req.Import.Path)
		}
		if req.Import.Position != nil {
			im.Position = *req.Import.Position
		}
		im.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(smImportKey(im.ID), &im)
		_ = ws.putJSON(smImportIdx(im.ProjectID, im.Environment, im.Path, im.ID), &im)
		writeJSON(w, http.StatusOK, map[string]any{"message": "success", "secretImport": smImportJSON(&im)})
	})
	mux.HandleFunc("DELETE /v2/secret-imports/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var im secretImport
		if ws.getJSON(smImportKey(r.PathValue("id")), &im) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret import not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(smImportKey(im.ID))
			return txn.Delete(smImportIdx(im.ProjectID, im.Environment, im.Path, im.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"message": "success", "secretImport": smImportJSON(&im)})
	})
	// Replication resync has no replication engine here — acknowledge it.
	mux.HandleFunc("POST /v2/secret-imports/{id}/replication-resync", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "success"})
	})

	// ── reminders (one per secret) ─────────────────────────────────────────
	mux.HandleFunc("GET /v1/reminders/secrets/{secretId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rm reminder
		if ws.getJSON(smReminderKey(r.PathValue("secretId")), &rm) != nil {
			// No reminder set — the SPA reads {reminder: null} and renders the
			// "create reminder" affordance.
			writeJSON(w, http.StatusOK, map[string]any{"reminder": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reminder": smReminderJSON(&rm)})
	})
	mux.HandleFunc("POST /v1/reminders/secrets/{secretId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		sid := r.PathValue("secretId")
		var req struct {
			Message          string   `json:"message"`
			RepeatDays       int      `json:"repeatDays"`
			NextReminderDate *string  `json:"nextReminderDate"`
			FromDate         *string  `json:"fromDate"`
			Recipients       []string `json:"recipients"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		recipients := req.Recipients
		if recipients == nil {
			recipients = []string{}
		}
		rm := &reminder{
			ID: newID(), SecretID: sid, Message: req.Message, RepeatDays: req.RepeatDays,
			NextReminderDate: req.NextReminderDate, FromDate: req.FromDate, Recipients: recipients,
			CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(smReminderKey(sid), rm)
		writeJSON(w, http.StatusOK, map[string]any{"reminder": smReminderJSON(rm)})
	})
	mux.HandleFunc("DELETE /v1/reminders/secrets/{secretId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		sid := r.PathValue("secretId")
		var rm reminder
		_ = ws.getJSON(smReminderKey(sid), &rm)
		_ = ws.db.Update(func(txn *badger.Txn) error { return txn.Delete(smReminderKey(sid)) })
		rm.SecretID = sid
		writeJSON(w, http.StatusOK, map[string]any{"reminder": smReminderJSON(&rm)})
	})

	// ── trusted IPs ────────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/projects/{id}/trusted-ips", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.PathValue("id")
		ips := smList(ws, smTrustedIPPrefix(pid), func(v []byte) (map[string]any, bool) {
			var ip trustedIP
			if json.Unmarshal(v, &ip) != nil {
				return nil, false
			}
			return smTrustedIPJSON(&ip), true
		})
		writeJSON(w, http.StatusOK, map[string]any{"trustedIps": ips})
	})
	mux.HandleFunc("POST /v1/projects/{id}/trusted-ips", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid := r.PathValue("id")
		var req struct {
			IPAddress string `json:"ipAddress"`
			Comment   string `json:"comment"`
			IsActive  bool   `json:"isActive"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		ip := &trustedIP{
			ID: newID(), ProjectID: pid, IPAddress: req.IPAddress, Type: smIPType(req.IPAddress),
			IsActive: req.IsActive, Comment: req.Comment, CreatedAt: now, UpdatedAt: now,
		}
		_ = ws.putJSON(smTrustedIPKey(pid, ip.ID), ip)
		writeJSON(w, http.StatusOK, map[string]any{"trustedIp": smTrustedIPJSON(ip)})
	})
	mux.HandleFunc("PATCH /v1/projects/{id}/trusted-ips/{ipId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid, iid := r.PathValue("id"), r.PathValue("ipId")
		var ip trustedIP
		if ws.getJSON(smTrustedIPKey(pid, iid), &ip) != nil {
			writeJSON(w, http.StatusNotFound, msg("trusted ip not found"))
			return
		}
		var req struct {
			IPAddress string `json:"ipAddress"`
			Comment   string `json:"comment"`
			IsActive  bool   `json:"isActive"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.IPAddress != "" {
			ip.IPAddress = req.IPAddress
			ip.Type = smIPType(req.IPAddress)
		}
		ip.Comment = req.Comment
		ip.IsActive = req.IsActive
		ip.UpdatedAt = time.Now().UTC()
		_ = ws.putJSON(smTrustedIPKey(pid, iid), &ip)
		writeJSON(w, http.StatusOK, map[string]any{"trustedIp": smTrustedIPJSON(&ip)})
	})
	mux.HandleFunc("DELETE /v1/projects/{id}/trusted-ips/{ipId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		pid, iid := r.PathValue("id"), r.PathValue("ipId")
		var ip trustedIP
		if ws.getJSON(smTrustedIPKey(pid, iid), &ip) != nil {
			writeJSON(w, http.StatusNotFound, msg("trusted ip not found"))
			return
		}
		_ = ws.db.Update(func(txn *badger.Txn) error { return txn.Delete(smTrustedIPKey(pid, iid)) })
		writeJSON(w, http.StatusOK, map[string]any{"trustedIp": smTrustedIPJSON(&ip)})
	})

	// ── secret snapshots (history; no real version graph → empty/zero) ──────
	mux.HandleFunc("GET /v1/projects/{id}/secret-snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSnapshots": []any{}})
	})
	mux.HandleFunc("GET /v1/projects/{id}/secret-snapshots/count", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0})
	})
	mux.HandleFunc("GET /v1/secret-snapshot/{snapshotId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{"secretSnapshot": map[string]any{
			"id": r.PathValue("snapshotId"), "secretVersions": []any{}, "folderVersion": []any{},
			"environment": map[string]any{"id": "", "name": "", "slug": ""},
			"createdAt":   now, "updatedAt": now,
		}})
	})
	mux.HandleFunc("POST /v1/secret-snapshot/{snapshotId}/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretSnapshot": map[string]any{"id": r.PathValue("snapshotId")}})
	})

	// ── folder commits / PIT (history; no real version graph → empty/zero) ──
	mux.HandleFunc("GET /v1/pit/commits/count", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "folderId": ""})
	})
	mux.HandleFunc("GET /v1/pit/commits", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"commits": []any{}, "total": 0, "hasMore": false})
	})
	mux.HandleFunc("GET /v1/pit/commits/{commitId}/changes", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"changes": map[string]any{
			"id": r.PathValue("commitId"), "commitId": r.PathValue("commitId"),
			"actorMetadata": map[string]any{"id": ""}, "actorType": "platform", "message": "",
			"folderId": "", "envId": "", "isLatest": true, "changes": []any{},
			"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
		}})
	})
	mux.HandleFunc("GET /v1/pit/commits/{commitId}/compare", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("POST /v1/pit/commits/{commitId}/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	})
	mux.HandleFunc("POST /v1/pit/commits/{commitId}/revert", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "reverted"})
	})
}
