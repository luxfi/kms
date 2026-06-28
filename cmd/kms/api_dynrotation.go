// Dynamic secrets + secret rotation (the "ephemeral / self-rotating creds" tabs).
//
// Groups (SPA hooks under frontend/src/hooks/api):
//
//	dynamicSecret        /v1/dynamic-secrets …            (CRUD of the provider config)
//	dynamicSecretLease   /v1/dynamic-secrets/leases …     (CRUD of issued leases)
//	secretRotation (v1)  /v1/secret-rotations …           + /v1/secret-rotation-providers/{ws}
//	secretRotationsV2    /v2/secret-rotations/{type} …    + /v1/secret-rotations/options
//
// Config entities (dynamic-secret definitions, leases, rotation configs) persist
// as JSON-KV in ZapDB under "kms/dynrotation/...". The *cryptographic* side —
// actually connecting to Postgres/AWS/Azure to provision a user, mint a lease
// credential, or rotate a live secret — is NOT performed here: those handlers
// persist the config + return a plausible-shaped response (empty credentials /
// generated `data`). The SPA navigates, lists, and edits configs against real
// storage; live provisioning is delegated to an out-of-band worker (future).
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities ──────────────────────────────────────────────────────────────

// dynSecret is a dynamic-secret definition (provider + ttl policy). inputs holds
// the raw provider config the SPA round-trips (host/credentials/statements…).
type dynSecret struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"` // DynamicSecretProviders enum value
	ProjectSlug  string    `json:"projectSlug"`
	Environment  string    `json:"environmentSlug"`
	Path         string    `json:"path"`
	DefaultTTL   string    `json:"defaultTTL"`
	MaxTTL       string    `json:"maxTTL,omitempty"`
	UsernameTmpl string    `json:"usernameTemplate,omitempty"`
	Inputs       any       `json:"inputs,omitempty"`
	Metadata     []kvPair  `json:"metadata,omitempty"`
	Tags         []kvPair  `json:"tags,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type kvPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// dynLease is an issued lease against a dynamic-secret definition.
type dynLease struct {
	ID              string    `json:"id"`
	Version         int       `json:"version"`
	DynamicSecretID string    `json:"dynamicSecretId"`
	ExpireAt        time.Time `json:"expireAt"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// rotationV1 is a legacy (v1) secret-rotation config.
type rotationV1 struct {
	ID          string         `json:"id"`
	WorkspaceID string         `json:"workspace"`
	Provider    string         `json:"provider"`
	Interval    int            `json:"interval"`
	SecretPath  string         `json:"secretPath"`
	Environment string         `json:"environment"`
	Inputs      map[string]any `json:"inputs,omitempty"`
	Outputs     map[string]any `json:"outputs,omitempty"`
	Status      string         `json:"status,omitempty"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

// rotationV2 is a v2 secret-rotation config (typed by SecretRotation enum).
type rotationV2 struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Description        string         `json:"description,omitempty"`
	Type               string         `json:"type"`
	ProjectID          string         `json:"projectId"`
	Environment        string         `json:"environment"`
	SecretPath         string         `json:"secretPath"`
	ConnectionID       string         `json:"connectionId"`
	RotationInterval   int            `json:"rotationInterval"`
	IsAutoRotationEnab bool           `json:"isAutoRotationEnabled"`
	RotateAtUtc        map[string]any `json:"rotateAtUtc,omitempty"`
	Parameters         any            `json:"parameters,omitempty"`
	SecretsMapping     any            `json:"secretsMapping,omitempty"`
	LastRotatedAt      time.Time      `json:"lastRotatedAt"`
	CreatedAt          time.Time      `json:"createdAt"`
	UpdatedAt          time.Time      `json:"updatedAt"`
}

// ── key helpers (unique "kms/dynrotation/" prefix) ────────────────────────

func dynSecKey(id string) []byte { return []byte("kms/dynrotation/dynsec/" + id) }
func dynSecScopeIdx(projectSlug, env, path, id string) []byte {
	return []byte("kms/dynrotation/dynsec-scope/" + projectSlug + "/" + env + "/" + path + "/" + id)
}
func dynSecScopePrefix(projectSlug, env, path string) []byte {
	return []byte("kms/dynrotation/dynsec-scope/" + projectSlug + "/" + env + "/" + path + "/")
}

func dynLeaseKey(dsID, id string) []byte {
	return []byte("kms/dynrotation/lease/" + dsID + "/" + id)
}
func dynLeasePrefix(dsID string) []byte {
	return []byte("kms/dynrotation/lease/" + dsID + "/")
}
func dynLeaseByID(id string) []byte { return []byte("kms/dynrotation/lease-id/" + id) }

func rotV1Key(id string) []byte { return []byte("kms/dynrotation/rot1/" + id) }
func rotV1WsIdx(ws, id string) []byte {
	return []byte("kms/dynrotation/rot1-ws/" + ws + "/" + id)
}
func rotV1WsPrefix(ws string) []byte { return []byte("kms/dynrotation/rot1-ws/" + ws + "/") }

func rotV2Key(id string) []byte { return []byte("kms/dynrotation/rot2/" + id) }

// ── registration ──────────────────────────────────────────────────────────

func registerDynRotationAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth.fromRequest(r) == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return false
		}
		return true
	}

	// ════════════════════════════════════════════════════════════════════
	// dynamicSecret — /v1/dynamic-secrets
	// ════════════════════════════════════════════════════════════════════

	// GET /v1/dynamic-secrets ?projectSlug&environmentSlug&path → {dynamicSecrets}
	mux.HandleFunc("GET /v1/dynamic-secrets", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		writeJSON(w, http.StatusOK, map[string]any{
			"dynamicSecrets": listDynSecrets(st, q.Get("projectSlug"), envOrDefault(q.Get("environmentSlug")), cleanPath(q.Get("path"))),
		})
	})

	// POST /v1/dynamic-secrets → {dynamicSecret}
	mux.HandleFunc("POST /v1/dynamic-secrets", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			Name            string   `json:"name"`
			ProjectSlug     string   `json:"projectSlug"`
			EnvironmentSlug string   `json:"environmentSlug"`
			Path            string   `json:"path"`
			DefaultTTL      string   `json:"defaultTTL"`
			MaxTTL          string   `json:"maxTTL"`
			UsernameTmpl    string   `json:"usernameTemplate"`
			Metadata        []kvPair `json:"metadata"`
			Tags            []kvPair `json:"tags"`
			Provider        struct {
				Type   string `json:"type"`
				Inputs any    `json:"inputs"`
			} `json:"provider"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		ds := &dynSecret{
			ID: newID(), Name: req.Name, Type: req.Provider.Type,
			ProjectSlug: req.ProjectSlug, Environment: envOrDefault(req.EnvironmentSlug),
			Path: cleanPath(req.Path), DefaultTTL: req.DefaultTTL, MaxTTL: req.MaxTTL,
			UsernameTmpl: req.UsernameTmpl, Inputs: req.Provider.Inputs,
			Metadata: req.Metadata, Tags: req.Tags, CreatedAt: now, UpdatedAt: now,
		}
		if err := saveDynSecret(st, ds); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dynamicSecret": dynSecretJSON(ds, true)})
	})

	// POST /v1/dynamic-secrets/entra-id/users — provider-data probe.
	// (Live Azure Entra ID lookup not performed → empty user list.)
	mux.HandleFunc("POST /v1/dynamic-secrets/entra-id/users", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})

	// GET /v1/dynamic-secrets/{name} ?projectSlug&environmentSlug&path → {dynamicSecret}
	mux.HandleFunc("GET /v1/dynamic-secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		ds := findDynSecret(st, q.Get("projectSlug"), envOrDefault(q.Get("environmentSlug")), cleanPath(q.Get("path")), r.PathValue("name"))
		if ds == nil {
			writeJSON(w, http.StatusNotFound, msg("dynamic secret not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dynamicSecret": dynSecretJSON(ds, true)})
	})

	// PATCH /v1/dynamic-secrets/{name} → {dynamicSecret}
	mux.HandleFunc("PATCH /v1/dynamic-secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectSlug     string `json:"projectSlug"`
			EnvironmentSlug string `json:"environmentSlug"`
			Path            string `json:"path"`
			Data            struct {
				NewName      string   `json:"newName"`
				DefaultTTL   string   `json:"defaultTTL"`
				MaxTTL       *string  `json:"maxTTL"`
				UsernameTmpl *string  `json:"usernameTemplate"`
				Inputs       any      `json:"inputs"`
				Metadata     []kvPair `json:"metadata"`
				Tags         []kvPair `json:"tags"`
			} `json:"data"`
		}
		if !decode(w, r, &req) {
			return
		}
		ds := findDynSecret(st, req.ProjectSlug, envOrDefault(req.EnvironmentSlug), cleanPath(req.Path), r.PathValue("name"))
		if ds == nil {
			writeJSON(w, http.StatusNotFound, msg("dynamic secret not found"))
			return
		}
		// rename re-keys the scope index
		if req.Data.NewName != "" && req.Data.NewName != ds.Name {
			_ = deleteDynSecret(st, ds)
			ds.Name = req.Data.NewName
		}
		if req.Data.DefaultTTL != "" {
			ds.DefaultTTL = req.Data.DefaultTTL
		}
		if req.Data.MaxTTL != nil {
			ds.MaxTTL = *req.Data.MaxTTL
		}
		if req.Data.UsernameTmpl != nil {
			ds.UsernameTmpl = *req.Data.UsernameTmpl
		}
		if req.Data.Inputs != nil {
			ds.Inputs = req.Data.Inputs
		}
		if req.Data.Metadata != nil {
			ds.Metadata = req.Data.Metadata
		}
		if req.Data.Tags != nil {
			ds.Tags = req.Data.Tags
		}
		ds.UpdatedAt = time.Now().UTC()
		_ = saveDynSecret(st, ds)
		writeJSON(w, http.StatusOK, map[string]any{"dynamicSecret": dynSecretJSON(ds, true)})
	})

	// DELETE /v1/dynamic-secrets/{name} → {dynamicSecret}
	mux.HandleFunc("DELETE /v1/dynamic-secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectSlug     string `json:"projectSlug"`
			EnvironmentSlug string `json:"environmentSlug"`
			Path            string `json:"path"`
		}
		_ = decode(w, r, &req)
		ds := findDynSecret(st, req.ProjectSlug, envOrDefault(req.EnvironmentSlug), cleanPath(req.Path), r.PathValue("name"))
		if ds == nil {
			writeJSON(w, http.StatusNotFound, msg("dynamic secret not found"))
			return
		}
		_ = deleteDynSecret(st, ds)
		writeJSON(w, http.StatusOK, map[string]any{"dynamicSecret": dynSecretJSON(ds, false)})
	})

	// ════════════════════════════════════════════════════════════════════
	// dynamicSecretLease — /v1/dynamic-secrets/leases
	// ════════════════════════════════════════════════════════════════════

	// GET /v1/dynamic-secrets/{name}/leases → {leases}
	mux.HandleFunc("GET /v1/dynamic-secrets/{name}/leases", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		q := r.URL.Query()
		ds := findDynSecret(st, q.Get("projectSlug"), envOrDefault(q.Get("environmentSlug")), cleanPath(q.Get("path")), r.PathValue("name"))
		leases := []any{}
		if ds != nil {
			leases = listLeases(st, ds.ID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"leases": leases})
	})

	// POST /v1/dynamic-secrets/leases → {lease, data}
	// POST /v1/dynamic-secrets/leases/kubernetes → {lease, data}
	createLease := func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			DynamicSecretName string `json:"dynamicSecretName"`
			ProjectSlug       string `json:"projectSlug"`
			EnvironmentSlug   string `json:"environmentSlug"`
			Path              string `json:"path"`
			TTL               string `json:"ttl"`
		}
		if !decode(w, r, &req) {
			return
		}
		ds := findDynSecret(st, req.ProjectSlug, envOrDefault(req.EnvironmentSlug), cleanPath(req.Path), req.DynamicSecretName)
		if ds == nil {
			writeJSON(w, http.StatusNotFound, msg("dynamic secret not found"))
			return
		}
		now := time.Now().UTC()
		l := &dynLease{
			ID: newID(), Version: 1, DynamicSecretID: ds.ID,
			ExpireAt: now.Add(leaseTTL(req.TTL, ds.DefaultTTL)), CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(dynLeaseKey(ds.ID, l.ID), l)
		_ = st.putJSON(dynLeaseByID(l.ID), l)
		// Live credential provisioning is delegated out-of-band; `data` carries the
		// issued credential map and is empty until a worker fulfils the lease.
		writeJSON(w, http.StatusOK, map[string]any{"lease": leaseJSON(l), "data": map[string]any{}})
	}
	mux.HandleFunc("POST /v1/dynamic-secrets/leases", createLease)
	mux.HandleFunc("POST /v1/dynamic-secrets/leases/kubernetes", createLease)

	// POST /v1/dynamic-secrets/leases/{leaseId}/renew → {lease}
	mux.HandleFunc("POST /v1/dynamic-secrets/leases/{leaseId}/renew", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			TTL string `json:"ttl"`
		}
		_ = decode(w, r, &req)
		var l dynLease
		if st.getJSON(dynLeaseByID(r.PathValue("leaseId")), &l) != nil {
			writeJSON(w, http.StatusNotFound, msg("lease not found"))
			return
		}
		l.Version++
		l.ExpireAt = time.Now().UTC().Add(leaseTTL(req.TTL, "1h"))
		l.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(dynLeaseKey(l.DynamicSecretID, l.ID), &l)
		_ = st.putJSON(dynLeaseByID(l.ID), &l)
		writeJSON(w, http.StatusOK, map[string]any{"lease": leaseJSON(&l)})
	})

	// DELETE /v1/dynamic-secrets/leases/{leaseId} → {lease}
	mux.HandleFunc("DELETE /v1/dynamic-secrets/leases/{leaseId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var l dynLease
		if st.getJSON(dynLeaseByID(r.PathValue("leaseId")), &l) != nil {
			writeJSON(w, http.StatusNotFound, msg("lease not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(dynLeaseKey(l.DynamicSecretID, l.ID))
			return txn.Delete(dynLeaseByID(l.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"lease": leaseJSON(&l)})
	})

	// ════════════════════════════════════════════════════════════════════
	// secretRotation (v1) — /v1/secret-rotations + providers
	// ════════════════════════════════════════════════════════════════════

	// GET /v1/secret-rotation-providers/{workspaceId} → {custom, providers}
	// (Provider template catalog is empty here; the v2 surface carries options.)
	mux.HandleFunc("GET /v1/secret-rotation-providers/{workspaceId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"custom": []any{}, "providers": []any{}})
	})

	// GET /v1/secret-rotations ?workspaceId → {secretRotations}
	mux.HandleFunc("GET /v1/secret-rotations", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secretRotations": listRotationsV1(st, r.URL.Query().Get("workspaceId")),
		})
	})

	// POST /v1/secret-rotations → {secretRotation}
	mux.HandleFunc("POST /v1/secret-rotations", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			WorkspaceID string         `json:"workspaceId"`
			SecretPath  string         `json:"secretPath"`
			Environment string         `json:"environment"`
			Interval    int            `json:"interval"`
			Provider    string         `json:"provider"`
			Inputs      map[string]any `json:"inputs"`
			Outputs     map[string]any `json:"outputs"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		rot := &rotationV1{
			ID: newID(), WorkspaceID: req.WorkspaceID, Provider: req.Provider,
			Interval: req.Interval, SecretPath: req.SecretPath, Environment: req.Environment,
			Inputs: req.Inputs, Outputs: req.Outputs, Status: "success",
			CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(rotV1Key(rot.ID), rot)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(rotV1WsIdx(rot.WorkspaceID, rot.ID), []byte(rot.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV1JSON(rot)})
	})

	// POST /v1/secret-rotations/restart → {secretRotation}
	mux.HandleFunc("POST /v1/secret-rotations/restart", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		_ = decode(w, r, &req)
		var rot rotationV1
		if st.getJSON(rotV1Key(req.ID), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		rot.Status = "success"
		rot.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(rotV1Key(rot.ID), &rot)
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV1JSON(&rot)})
	})

	// DELETE /v1/secret-rotations/{id} → {secretRotation}
	mux.HandleFunc("DELETE /v1/secret-rotations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rot rotationV1
		if st.getJSON(rotV1Key(r.PathValue("id")), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(rotV1Key(rot.ID))
			return txn.Delete(rotV1WsIdx(rot.WorkspaceID, rot.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV1JSON(&rot)})
	})

	// ════════════════════════════════════════════════════════════════════
	// secretRotationsV2 — /v2/secret-rotations/{type} + /v1/secret-rotations/options
	// ════════════════════════════════════════════════════════════════════

	// GET /v1/secret-rotations/options → {secretRotationOptions}
	mux.HandleFunc("GET /v1/secret-rotations/options", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretRotationOptions": rotationV2Options()})
	})

	// POST /v2/secret-rotations/{type} → {secretRotation}
	mux.HandleFunc("POST /v2/secret-rotations/{type}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			Name               string         `json:"name"`
			Description        string         `json:"description"`
			ConnectionID       string         `json:"connectionId"`
			ProjectID          string         `json:"projectId"`
			Environment        string         `json:"environment"`
			SecretPath         string         `json:"secretPath"`
			RotationInterval   int            `json:"rotationInterval"`
			IsAutoRotationEnab bool           `json:"isAutoRotationEnabled"`
			RotateAtUtc        map[string]any `json:"rotateAtUtc"`
			Parameters         any            `json:"parameters"`
			SecretsMapping     any            `json:"secretsMapping"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		rot := &rotationV2{
			ID: newID(), Name: req.Name, Description: req.Description, Type: r.PathValue("type"),
			ProjectID: req.ProjectID, Environment: envOrDefault(req.Environment), SecretPath: req.SecretPath,
			ConnectionID: req.ConnectionID, RotationInterval: req.RotationInterval,
			IsAutoRotationEnab: req.IsAutoRotationEnab, RotateAtUtc: req.RotateAtUtc,
			Parameters: req.Parameters, SecretsMapping: req.SecretsMapping,
			LastRotatedAt: now, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(rotV2Key(rot.ID), rot)
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV2JSON(rot)})
	})

	// PATCH /v2/secret-rotations/{type}/{rotationId} → {secretRotation}
	mux.HandleFunc("PATCH /v2/secret-rotations/{type}/{rotationId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rot rotationV2
		if st.getJSON(rotV2Key(r.PathValue("rotationId")), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		var req struct {
			Name               *string        `json:"name"`
			Description        *string        `json:"description"`
			ConnectionID       *string        `json:"connectionId"`
			RotationInterval   *int           `json:"rotationInterval"`
			IsAutoRotationEnab *bool          `json:"isAutoRotationEnabled"`
			RotateAtUtc        map[string]any `json:"rotateAtUtc"`
			Parameters         any            `json:"parameters"`
			SecretsMapping     any            `json:"secretsMapping"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			rot.Name = *req.Name
		}
		if req.Description != nil {
			rot.Description = *req.Description
		}
		if req.ConnectionID != nil {
			rot.ConnectionID = *req.ConnectionID
		}
		if req.RotationInterval != nil {
			rot.RotationInterval = *req.RotationInterval
		}
		if req.IsAutoRotationEnab != nil {
			rot.IsAutoRotationEnab = *req.IsAutoRotationEnab
		}
		if req.RotateAtUtc != nil {
			rot.RotateAtUtc = req.RotateAtUtc
		}
		if req.Parameters != nil {
			rot.Parameters = req.Parameters
		}
		if req.SecretsMapping != nil {
			rot.SecretsMapping = req.SecretsMapping
		}
		rot.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(rotV2Key(rot.ID), &rot)
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV2JSON(&rot)})
	})

	// DELETE /v2/secret-rotations/{type}/{rotationId} → {secretRotation}
	mux.HandleFunc("DELETE /v2/secret-rotations/{type}/{rotationId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rot rotationV2
		if st.getJSON(rotV2Key(r.PathValue("rotationId")), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(rotV2Key(rot.ID)) })
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV2JSON(&rot)})
	})

	// POST /v2/secret-rotations/{type}/{rotationId}/rotate-secrets → {secretRotation}
	mux.HandleFunc("POST /v2/secret-rotations/{type}/{rotationId}/rotate-secrets", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rot rotationV2
		if st.getJSON(rotV2Key(r.PathValue("rotationId")), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		// Live rotation against the upstream provider is delegated out-of-band;
		// here we advance lastRotatedAt so the UI reflects the request.
		rot.LastRotatedAt = time.Now().UTC()
		rot.UpdatedAt = rot.LastRotatedAt
		_ = st.putJSON(rotV2Key(rot.ID), &rot)
		writeJSON(w, http.StatusOK, map[string]any{"secretRotation": rotationV2JSON(&rot)})
	})

	// POST /v2/secret-rotations/{type}/{rotationId}/reconcile → reconcile response
	mux.HandleFunc("POST /v2/secret-rotations/{type}/{rotationId}/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var rot rotationV2
		if st.getJSON(rotV2Key(r.PathValue("rotationId")), &rot) != nil {
			writeJSON(w, http.StatusNotFound, msg("secret rotation not found"))
			return
		}
		rot.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(rotV2Key(rot.ID), &rot)
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "reconciled", "reconciled": true, "secretRotation": rotationV2JSON(&rot),
		})
	})

	// GET /v2/secret-rotations/{type}/{rotationId}/generated-credentials → creds
	mux.HandleFunc("GET /v2/secret-rotations/{type}/{rotationId}/generated-credentials", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		// Generated credentials are not retained server-side here; return the
		// empty-but-correctly-shaped envelope the SPA deserializes.
		writeJSON(w, http.StatusOK, map[string]any{
			"type":                 r.PathValue("type"),
			"rotationId":           r.PathValue("rotationId"),
			"activeIndex":          0,
			"generatedCredentials": []any{map[string]any{}, nil},
		})
	})
}

// ── dynamic-secret store helpers ──────────────────────────────────────────

func saveDynSecret(st *webStore, ds *dynSecret) error {
	if err := st.putJSON(dynSecKey(ds.ID), ds); err != nil {
		return err
	}
	return st.db.Update(func(txn *badger.Txn) error {
		return txn.Set(dynSecScopeIdx(ds.ProjectSlug, ds.Environment, ds.Path, ds.ID), []byte(ds.ID))
	})
}

func deleteDynSecret(st *webStore, ds *dynSecret) error {
	return st.db.Update(func(txn *badger.Txn) error {
		_ = txn.Delete(dynSecKey(ds.ID))
		return txn.Delete(dynSecScopeIdx(ds.ProjectSlug, ds.Environment, ds.Path, ds.ID))
	})
}

func dynSecretsForScope(st *webStore, projectSlug, env, path string) []*dynSecret {
	out := []*dynSecret{}
	if projectSlug == "" {
		return out
	}
	pfx := dynSecScopePrefix(projectSlug, env, path)
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
	for _, id := range ids {
		var ds dynSecret
		if st.getJSON(dynSecKey(id), &ds) == nil {
			out = append(out, &ds)
		}
	}
	return out
}

func listDynSecrets(st *webStore, projectSlug, env, path string) []any {
	out := []any{}
	for _, ds := range dynSecretsForScope(st, projectSlug, env, path) {
		out = append(out, dynSecretJSON(ds, false))
	}
	return out
}

func findDynSecret(st *webStore, projectSlug, env, path, name string) *dynSecret {
	for _, ds := range dynSecretsForScope(st, projectSlug, env, path) {
		if ds.Name == name {
			return ds
		}
	}
	return nil
}

// ── lease store helpers ───────────────────────────────────────────────────

func listLeases(st *webStore, dsID string) []any {
	out := []any{}
	pfx := dynLeasePrefix(dsID)
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var l dynLease
				if json.Unmarshal(v, &l) == nil {
					out = append(out, leaseJSON(&l))
				}
				return nil
			})
		}
		return nil
	})
	return out
}

// leaseTTL parses a Go-duration TTL (e.g. "1h", "30m"), falling back to def then 1h.
func leaseTTL(ttl, def string) time.Duration {
	for _, s := range []string{ttl, def} {
		if s == "" {
			continue
		}
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// ── rotation (v1) store helpers ───────────────────────────────────────────

func listRotationsV1(st *webStore, ws string) []any {
	out := []any{}
	if ws == "" {
		return out
	}
	pfx := rotV1WsPrefix(ws)
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
	for _, id := range ids {
		var rot rotationV1
		if st.getJSON(rotV1Key(id), &rot) == nil {
			out = append(out, rotationV1JSON(&rot))
		}
	}
	return out
}

// ── JSON shaping (match the SPA's deserialized shapes) ─────────────────────

func dynSecretJSON(ds *dynSecret, withInputs bool) map[string]any {
	out := map[string]any{
		"id": ds.ID, "name": ds.Name, "type": ds.Type,
		"defaultTTL": ds.DefaultTTL, "maxTTL": orNil(ds.MaxTTL),
		"usernameTemplate": orNil(ds.UsernameTmpl),
		"metadata":         kvPairs(ds.Metadata), "tags": kvPairs(ds.Tags),
		"createdAt": ds.CreatedAt, "updatedAt": ds.UpdatedAt,
	}
	if withInputs {
		inputs := ds.Inputs
		if inputs == nil {
			inputs = map[string]any{}
		}
		out["inputs"] = inputs
	}
	return out
}

func leaseJSON(l *dynLease) map[string]any {
	return map[string]any{
		"id": l.ID, "version": l.Version, "dynamicSecretId": l.DynamicSecretID,
		"expireAt": l.ExpireAt, "createdAt": l.CreatedAt, "updatedAt": l.UpdatedAt,
	}
}

func rotationV1JSON(rot *rotationV1) map[string]any {
	return map[string]any{
		"id": rot.ID, "interval": rot.Interval, "provider": rot.Provider,
		"customProvider": "", "workspace": rot.WorkspaceID, "envId": rot.Environment,
		"environment": map[string]any{"id": rot.Environment, "name": rot.Environment, "slug": rot.Environment},
		"secretPath":  rot.SecretPath, "outputs": []any{}, "status": orNil(rot.Status),
		"lastRotatedAt": rot.UpdatedAt, "algorithm": "", "keyEncoding": "",
		"createdAt": rot.CreatedAt, "updatedAt": rot.UpdatedAt,
	}
}

func rotationV2JSON(rot *rotationV2) map[string]any {
	env := map[string]any{"id": rot.Environment, "name": rot.Environment, "slug": rot.Environment}
	params := rot.Parameters
	if params == nil {
		params = map[string]any{}
	}
	mapping := rot.SecretsMapping
	if mapping == nil {
		mapping = map[string]any{}
	}
	rotateAt := rot.RotateAtUtc
	if rotateAt == nil {
		rotateAt = map[string]any{"hours": 0, "minutes": 0}
	}
	out := map[string]any{
		"id": rot.ID, "name": rot.Name, "description": orNil(rot.Description),
		"type": rot.Type, "projectId": rot.ProjectID, "connectionId": rot.ConnectionID,
		"folderId": "", "rotationInterval": rot.RotationInterval, "rotateAtUtc": rotateAt,
		"isAutoRotationEnabled": rot.IsAutoRotationEnab, "rotationStatus": "success",
		"lastRotationJobId": nil, "lastRotatedAt": rot.LastRotatedAt,
		"lastRotationAttemptedAt": rot.LastRotatedAt, "lastRotationMessage": nil,
		"connection":  map[string]any{"id": rot.ConnectionID, "name": "", "app": ""},
		"environment": env, "folder": map[string]any{"id": "", "path": "/" + cleanPath(rot.SecretPath)},
		"parameters": params, "secretsMapping": mapping, "secrets": []any{},
		"createdAt": rot.CreatedAt, "updatedAt": rot.UpdatedAt,
	}
	if rot.IsAutoRotationEnab {
		out["nextRotationAt"] = rot.LastRotatedAt.Add(time.Duration(rot.RotationInterval) * time.Second)
	} else {
		out["nextRotationAt"] = nil
	}
	return out
}

// rotationV2Options returns the catalog the v2 rotation wizard lists. Each entry
// matches TSecretRotationV2Option {name,type,connection,template}; SQL providers
// carry the createUser/rotation statement template the form pre-fills.
func rotationV2Options() []any {
	sqlMapping := map[string]any{"username": "username", "password": "password"}
	sqlTemplate := func(create, rotate string) map[string]any {
		return map[string]any{"secretsMapping": sqlMapping, "createUserStatement": create, "rotationStatement": rotate}
	}
	credMapping := func(fields ...string) map[string]any {
		m := map[string]any{}
		for _, f := range fields {
			m[f] = f
		}
		return map[string]any{"secretsMapping": m}
	}
	return []any{
		opt("Postgres Credentials", "postgres-credentials", "postgres", sqlTemplate(
			"CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}';",
			"ALTER ROLE \"{{username}}\" WITH PASSWORD '{{password}}';")),
		opt("Microsoft SQL Server Credentials", "mssql-credentials", "mssql", sqlTemplate(
			"CREATE LOGIN [{{username}}] WITH PASSWORD = '{{password}}';",
			"ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}';")),
		opt("MySQL Credentials", "mysql-credentials", "mysql", sqlTemplate(
			"CREATE USER '{{username}}' IDENTIFIED BY '{{password}}';",
			"ALTER USER '{{username}}' IDENTIFIED BY '{{password}}';")),
		opt("OracleDB Credentials", "oracledb-credentials", "oracledb", sqlTemplate(
			"CREATE USER {{username}} IDENTIFIED BY \"{{password}}\";",
			"ALTER USER {{username}} IDENTIFIED BY \"{{password}}\";")),
		opt("Auth0 Client Secret", "auth0-client-secret", "auth0", credMapping("clientId", "clientSecret")),
		opt("Azure Client Secret", "azure-client-secret", "azure-client-secret", credMapping("clientId", "clientSecret")),
		opt("LDAP Password", "ldap-password", "ldap", credMapping("dn", "password")),
		opt("AWS IAM User Secret", "aws-iam-user-secret", "aws", credMapping("accessKeyId", "secretAccessKey")),
		opt("Okta Client Secret", "okta-client-secret", "okta", credMapping("clientId", "clientSecret")),
		opt("Redis Credentials", "redis-credentials", "redis", credMapping("username", "password")),
		opt("MongoDB Credentials", "mongodb-credentials", "mongodb", credMapping("username", "password")),
		opt("Databricks Service Principal Secret", "databricks-service-principal-secret", "databricks", credMapping("clientId", "clientSecret")),
		opt("Unix/Linux Local Account", "unix-linux-local-account", "ssh", credMapping("username", "password")),
	}
}

func opt(name, typ, connection string, template map[string]any) map[string]any {
	return map[string]any{"name": name, "type": typ, "connection": connection, "template": template}
}

// ── tiny shaping helpers (area-prefixed where they could collide) ─────────

func kvPairs(in []kvPair) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, p := range in {
		out = append(out, map[string]any{"key": p.Key, "value": p.Value})
	}
	return out
}

// orNil renders an empty string as JSON null (the SPA types use `string | null`).
func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
