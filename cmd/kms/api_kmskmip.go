// Advanced KMS surface — CMEK transit, KMIP, and external-KMS connectors.
//
// CMEK (customer-managed encryption keys, Infisical's "/v1/kms/keys" transit):
//
//	GET    /v1/cmek/keys ?projectId&offset&limit&search&orderBy&orderDirection  {keys, totalCount}
//	POST   /v1/cmek/keys {projectId,name,description,keyUsage,encryptionAlgorithm}  {key}
//	PATCH  /v1/cmek/keys/{keyId} {name,description,isDisabled}                       {key}
//	DELETE /v1/cmek/keys/{keyId}                                                     {key}
//	GET    /v1/cmek/keys/{keyId}/public-key   {publicKey}     (asymmetric — stub)
//	GET    /v1/cmek/keys/{keyId}/private-key  {privateKey}    (asymmetric — stub)
//	POST   /v1/cmek/keys/{keyId}/encrypt {plaintext}          {ciphertext}   (real AES-256-GCM)
//	POST   /v1/cmek/keys/{keyId}/decrypt {ciphertext}         {plaintext}    (real AES-256-GCM)
//	POST   /v1/cmek/keys/{keyId}/sign   {data,signingAlgorithm}   {signature,keyId,signingAlgorithm}   (stub)
//	POST   /v1/cmek/keys/{keyId}/verify {data,signature,signingAlgorithm}  {signatureValid,...}        (stub)
//
// NOTE — PATH REMAP: the SPA's cmeks hooks call /v1/kms/keys[/...], but those
// patterns are already owned by the validator/MPC key-set routes in main.go
// (registering them here would PANIC the ServeMux on duplicate). The CMEK
// transit surface is therefore served under the distinct /v1/cmek/* prefix.
// Symmetric encrypt/decrypt is implemented for real (per-key AES-256-GCM, key
// material stored at rest under the entity); asymmetric sign/verify and
// public/private-key export are plausible-shaped stubs.
//
// KMIP (per-org PKI gateway for KMIP clients):
//
//	GET    /v1/kmip                                    {serverCertificateChain, clientCertificateChain}
//	POST   /v1/kmip {caKeyAlgorithm}                   (setup org KMIP — cert stub)
//	GET    /v1/kmip/clients ?projectId&...             {kmipClients, totalCount}
//	POST   /v1/kmip/clients {projectId,name,description,permissions}  {kmipClient}
//	PATCH  /v1/kmip/clients/{id} {name,description,permissions}        {kmipClient}
//	DELETE /v1/kmip/clients/{id}                                       {kmipClient}
//	POST   /v1/kmip/clients/{clientId}/certificates {keyAlgorithm,ttl}  {certificate...}  (cert stub)
//
// External KMS (AWS/GCP connector config + per-project KMS selection):
//
//	GET    /v1/external-kms                            {externalKmsList}
//	POST   /v1/external-kms/{provider} {name,description,configuration}  {externalKms}
//	GET    /v1/external-kms/{provider}/{kmsId}         {id,name,description,orgId,externalKms}
//	PATCH  /v1/external-kms/{provider}/{kmsId} {name,description,configuration}  {externalKms}
//	DELETE /v1/external-kms/{provider}/{kmsId}         {externalKms}
//	POST   /v1/external-kms/gcp/keys {authMethod,region,...}  {keys}    (connector probe — empty)
//	GET    /v1/projects/{id}/kms                       {secretManagerKmsKey}
//	PATCH  /v1/projects/{id}/kms {kms:{type,kmsId?}}   {secretManagerKmsKey}
//	GET    /v1/projects/{id}/kms/backup               {secretManager}    (backup blob — stub)
//	POST   /v1/projects/{id}/kms/backup {backup}      {secretManagerKmsKey}
//
// All entities persist as JSON-KV in ZapDB under "kms/cmek/...", "kms/kmip/...",
// "kms/extkms/...". Deep KMIP/PKI cert issuance and cloud-KMS round-trips are
// out of scope — those handlers persist the config entity and return a
// plausible-shaped response so the SPA navigates cleanly.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities ────────────────────────────────────────────────────────────────

type cmekKey struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	KeyUsage            string    `json:"keyUsage"`
	EncryptionAlgorithm string    `json:"encryptionAlgorithm"`
	ProjectID           string    `json:"projectId"`
	OrgID               string    `json:"orgId"`
	IsDisabled          bool      `json:"isDisabled"`
	IsReserved          bool      `json:"isReserved"`
	Version             int       `json:"version"`
	Material            []byte    `json:"material"` // 32B symmetric key (at rest, not exported)
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type kmipClient struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	ProjectID   string    `json:"projectId"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type kmipOrgConfig struct {
	OrgID                  string `json:"orgId"`
	CaKeyAlgorithm         string `json:"caKeyAlgorithm"`
	ServerCertificateChain string `json:"serverCertificateChain"`
	ClientCertificateChain string `json:"clientCertificateChain"`
}

type externalKms struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	OrgID         string         `json:"orgId"`
	Provider      string         `json:"provider"`
	IsDisabled    bool           `json:"isDisabled"`
	Status        string         `json:"status"`
	StatusDetails string         `json:"statusDetails"`
	Configuration map[string]any `json:"configuration"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

// projectKmsSel records which KMS a project's secret manager uses.
type projectKmsSel struct {
	ProjectID string `json:"projectId"`
	Type      string `json:"type"`  // internal | external
	KmsID     string `json:"kmsId"` // external KMS id when Type==external
}

// ── key helpers (unique area-prefixed names; do NOT collide with package) ─────

func cmekEntKey(id string) []byte { return []byte("kms/cmek/" + id) }
func cmekProjIdx(projectID, id string) []byte {
	return []byte("kms/cmek-by-project/" + projectID + "/" + id)
}
func cmekProjPrefix(projectID string) []byte {
	return []byte("kms/cmek-by-project/" + projectID + "/")
}

func kmipClientKey(id string) []byte { return []byte("kms/kmip/client/" + id) }
func kmipClientProjIdx(projectID, id string) []byte {
	return []byte("kms/kmip/by-project/" + projectID + "/" + id)
}
func kmipClientProjPrefix(projectID string) []byte {
	return []byte("kms/kmip/by-project/" + projectID + "/")
}
func kmipOrgKey(orgID string) []byte { return []byte("kms/kmip/org/" + orgID) }

func extKmsKey(id string) []byte { return []byte("kms/extkms/" + id) }
func extKmsOrgIdx(orgID, id string) []byte {
	return []byte("kms/extkms-by-org/" + orgID + "/" + id)
}
func extKmsOrgPrefix(orgID string) []byte { return []byte("kms/extkms-by-org/" + orgID + "/") }

func projectKmsKey(projectID string) []byte { return []byte("kms/project-kms/" + projectID) }

// ── JSON shapers (match the SPA deserialization shapes) ──────────────────────

func cmekJSON(k *cmekKey) map[string]any {
	return map[string]any{
		"id": k.ID, "name": k.Name, "description": k.Description,
		"keyUsage": k.KeyUsage, "encryptionAlgorithm": k.EncryptionAlgorithm,
		"projectId": k.ProjectID, "orgId": k.OrgID,
		"isDisabled": k.IsDisabled, "isReserved": k.IsReserved, "version": k.Version,
		"createdAt": k.CreatedAt, "updatedAt": k.UpdatedAt,
	}
}

func kmipClientJSON(c *kmipClient) map[string]any {
	perms := c.Permissions
	if perms == nil {
		perms = []string{}
	}
	return map[string]any{
		"id": c.ID, "name": c.Name, "description": c.Description,
		"permissions": perms, "projectId": c.ProjectID,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func extKmsListJSON(k *externalKms) map[string]any {
	return map[string]any{
		"id": k.ID, "description": k.Description, "isDisabled": k.IsDisabled,
		"createdAt": k.CreatedAt, "updatedAt": k.UpdatedAt, "name": k.Name,
		"externalKms": map[string]any{
			"provider": k.Provider, "status": k.Status, "statusDetails": k.StatusDetails,
		},
	}
}

func extKmsJSON(k *externalKms) map[string]any {
	cfg := k.Configuration
	if cfg == nil {
		cfg = map[string]any{}
	}
	return map[string]any{
		"id": k.ID, "description": k.Description, "orgId": k.OrgID, "name": k.Name,
		"externalKms": map[string]any{
			"id": k.ID, "status": k.Status, "statusDetails": k.StatusDetails,
			"provider": k.Provider, "configuration": cfg,
		},
	}
}

func projectKmsJSON(sel *projectKmsSel) map[string]any {
	id := "internal"
	name := "Internal KMS"
	isExternal := false
	if sel != nil && sel.Type == "external" && sel.KmsID != "" {
		id = sel.KmsID
		name = "External KMS"
		isExternal = true
	}
	return map[string]any{"id": id, "name": name, "isExternal": isExternal}
}

// ── transit AES-256-GCM (real symmetric encrypt/decrypt for CMEK) ─────────────

func cmekSeal(material, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func cmekOpen(material []byte, ciphertextB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, body := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

// ── registration ─────────────────────────────────────────────────────────────

func registerKmsKmipAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	cl := func(w http.ResponseWriter, r *http.Request) *webClaims {
		c := auth.fromRequest(r)
		if c == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return c
	}

	// ── CMEK transit (remapped to /v1/cmek/*) ───────────────────────────────
	mux.HandleFunc("GET /v1/cmek/keys", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		pid := r.URL.Query().Get("projectId")
		keys := listCmeks(st, pid)
		writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "totalCount": len(keys)})
	})

	mux.HandleFunc("POST /v1/cmek/keys", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		var req struct {
			ProjectID, Name, Description, KeyUsage, EncryptionAlgorithm string
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" || req.ProjectID == "" {
			writeJSON(w, http.StatusBadRequest, msg("projectId and name required"))
			return
		}
		usage := req.KeyUsage
		if usage == "" {
			usage = "encrypt-decrypt"
		}
		alg := req.EncryptionAlgorithm
		if alg == "" {
			alg = "aes-256-gcm"
		}
		material := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, material); err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		now := time.Now().UTC()
		k := &cmekKey{
			ID: newID(), Name: req.Name, Description: req.Description, KeyUsage: usage,
			EncryptionAlgorithm: alg, ProjectID: req.ProjectID, OrgID: c.OrgID,
			Version: 1, Material: material, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(cmekEntKey(k.ID), k)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(cmekProjIdx(k.ProjectID, k.ID), []byte(k.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"key": cmekJSON(k)})
	})

	mux.HandleFunc("PATCH /v1/cmek/keys/{keyId}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k cmekKey
		if st.getJSON(cmekEntKey(r.PathValue("keyId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		var req struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
			IsDisabled  *bool   `json:"isDisabled"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			k.Name = *req.Name
		}
		if req.Description != nil {
			k.Description = *req.Description
		}
		if req.IsDisabled != nil {
			k.IsDisabled = *req.IsDisabled
		}
		k.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(cmekEntKey(k.ID), &k)
		writeJSON(w, http.StatusOK, map[string]any{"key": cmekJSON(&k)})
	})

	mux.HandleFunc("DELETE /v1/cmek/keys/{keyId}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k cmekKey
		if st.getJSON(cmekEntKey(r.PathValue("keyId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(cmekEntKey(k.ID))
			return txn.Delete(cmekProjIdx(k.ProjectID, k.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"key": cmekJSON(&k)})
	})

	// Asymmetric key export — stub (no asymmetric material is generated yet).
	mux.HandleFunc("GET /v1/cmek/keys/{keyId}/public-key", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		if !cmekExists(st, r.PathValue("keyId")) {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"publicKey": ""})
	})
	mux.HandleFunc("GET /v1/cmek/keys/{keyId}/private-key", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		if !cmekExists(st, r.PathValue("keyId")) {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"privateKey": ""})
	})

	// Encrypt/decrypt — real AES-256-GCM round-trip on the key's material.
	mux.HandleFunc("POST /v1/cmek/keys/{keyId}/encrypt", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k cmekKey
		if st.getJSON(cmekEntKey(r.PathValue("keyId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		var req struct{ Plaintext string }
		if !decode(w, r, &req) {
			return
		}
		// The SPA always sends base64-encoded plaintext.
		pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			pt = []byte(req.Plaintext)
		}
		ct, err := cmekSeal(k.Material, pt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ciphertext": ct})
	})
	mux.HandleFunc("POST /v1/cmek/keys/{keyId}/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k cmekKey
		if st.getJSON(cmekEntKey(r.PathValue("keyId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		var req struct{ Ciphertext string }
		if !decode(w, r, &req) {
			return
		}
		pt, err := cmekOpen(k.Material, req.Ciphertext)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, msg("decrypt failed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)})
	})

	// Sign/verify — stub (asymmetric signing delegates to MPC; not wired here).
	mux.HandleFunc("POST /v1/cmek/keys/{keyId}/sign", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		keyID := r.PathValue("keyId")
		if !cmekExists(st, keyID) {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		var req struct{ Data, SigningAlgorithm string }
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"signature": "", "keyId": keyID, "signingAlgorithm": req.SigningAlgorithm,
		})
	})
	mux.HandleFunc("POST /v1/cmek/keys/{keyId}/verify", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		keyID := r.PathValue("keyId")
		if !cmekExists(st, keyID) {
			writeJSON(w, http.StatusNotFound, msg("key not found"))
			return
		}
		var req struct{ Data, Signature, SigningAlgorithm string }
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"signatureValid": false, "keyId": keyID, "signingAlgorithm": req.SigningAlgorithm,
		})
	})

	// ── KMIP ─────────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/kmip", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		var cfg kmipOrgConfig
		if st.getJSON(kmipOrgKey(c.OrgID), &cfg) != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"serverCertificateChain": "", "clientCertificateChain": "",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"serverCertificateChain": cfg.ServerCertificateChain,
			"clientCertificateChain": cfg.ClientCertificateChain,
		})
	})

	mux.HandleFunc("POST /v1/kmip", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		var req struct{ CaKeyAlgorithm string }
		_ = decode(w, r, &req)
		cfg := &kmipOrgConfig{OrgID: c.OrgID, CaKeyAlgorithm: req.CaKeyAlgorithm}
		_ = st.putJSON(kmipOrgKey(c.OrgID), cfg)
		writeJSON(w, http.StatusOK, map[string]any{
			"serverCertificateChain": "", "clientCertificateChain": "",
		})
	})

	mux.HandleFunc("GET /v1/kmip/clients", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		pid := r.URL.Query().Get("projectId")
		clients := listKmipClients(st, pid)
		writeJSON(w, http.StatusOK, map[string]any{"kmipClients": clients, "totalCount": len(clients)})
	})

	mux.HandleFunc("POST /v1/kmip/clients", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var req struct {
			ProjectID, Name, Description string
			Permissions                  []string
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" || req.ProjectID == "" {
			writeJSON(w, http.StatusBadRequest, msg("projectId and name required"))
			return
		}
		now := time.Now().UTC()
		cli := &kmipClient{
			ID: newID(), Name: req.Name, Description: req.Description,
			Permissions: req.Permissions, ProjectID: req.ProjectID,
			CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(kmipClientKey(cli.ID), cli)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(kmipClientProjIdx(cli.ProjectID, cli.ID), []byte(cli.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"kmipClient": kmipClientJSON(cli)})
	})

	mux.HandleFunc("PATCH /v1/kmip/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var cli kmipClient
		if st.getJSON(kmipClientKey(r.PathValue("id")), &cli) != nil {
			writeJSON(w, http.StatusNotFound, msg("kmip client not found"))
			return
		}
		var req struct {
			Name        *string  `json:"name"`
			Description *string  `json:"description"`
			Permissions []string `json:"permissions"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			cli.Name = *req.Name
		}
		if req.Description != nil {
			cli.Description = *req.Description
		}
		if req.Permissions != nil {
			cli.Permissions = req.Permissions
		}
		cli.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(kmipClientKey(cli.ID), &cli)
		writeJSON(w, http.StatusOK, map[string]any{"kmipClient": kmipClientJSON(&cli)})
	})

	mux.HandleFunc("DELETE /v1/kmip/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var cli kmipClient
		if st.getJSON(kmipClientKey(r.PathValue("id")), &cli) != nil {
			writeJSON(w, http.StatusNotFound, msg("kmip client not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(kmipClientKey(cli.ID))
			return txn.Delete(kmipClientProjIdx(cli.ProjectID, cli.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"kmipClient": kmipClientJSON(&cli)})
	})

	// Client certificate issuance — stub (KMIP CA signing not implemented).
	mux.HandleFunc("POST /v1/kmip/clients/{clientId}/certificates", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var existing kmipClient
		if st.getJSON(kmipClientKey(r.PathValue("clientId")), &existing) != nil {
			writeJSON(w, http.StatusNotFound, msg("kmip client not found"))
			return
		}
		var req struct{ KeyAlgorithm, Ttl string }
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"serialNumber": newID(), "certificate": "", "certificateChain": "", "privateKey": "",
		})
	})

	// ── external KMS ───────────────────────────────────────────────────────────
	mux.HandleFunc("GET /v1/external-kms", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"externalKmsList": listExtKms(st, c.OrgID)})
	})

	mux.HandleFunc("POST /v1/external-kms/{provider}", func(w http.ResponseWriter, r *http.Request) {
		c := cl(w, r)
		if c == nil {
			return
		}
		provider := r.PathValue("provider")
		var req struct {
			Name, Description string
			Configuration     map[string]any
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("name required"))
			return
		}
		now := time.Now().UTC()
		k := &externalKms{
			ID: newID(), Name: req.Name, Description: req.Description, OrgID: c.OrgID,
			Provider: provider, Status: "active", StatusDetails: "",
			Configuration: req.Configuration, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(extKmsKey(k.ID), k)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(extKmsOrgIdx(k.OrgID, k.ID), []byte(k.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"externalKms": extKmsJSON(k)})
	})

	mux.HandleFunc("GET /v1/external-kms/{provider}/{kmsId}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k externalKms
		if st.getJSON(extKmsKey(r.PathValue("kmsId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("external kms not found"))
			return
		}
		writeJSON(w, http.StatusOK, extKmsJSON(&k))
	})

	mux.HandleFunc("PATCH /v1/external-kms/{provider}/{kmsId}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k externalKms
		if st.getJSON(extKmsKey(r.PathValue("kmsId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("external kms not found"))
			return
		}
		var req struct {
			Name          *string        `json:"name"`
			Description   *string        `json:"description"`
			Configuration map[string]any `json:"configuration"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			k.Name = *req.Name
		}
		if req.Description != nil {
			k.Description = *req.Description
		}
		if req.Configuration != nil {
			k.Configuration = req.Configuration
		}
		k.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(extKmsKey(k.ID), &k)
		writeJSON(w, http.StatusOK, map[string]any{"externalKms": extKmsJSON(&k)})
	})

	mux.HandleFunc("DELETE /v1/external-kms/{provider}/{kmsId}", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var k externalKms
		if st.getJSON(extKmsKey(r.PathValue("kmsId")), &k) != nil {
			writeJSON(w, http.StatusNotFound, msg("external kms not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(extKmsKey(k.ID))
			return txn.Delete(extKmsOrgIdx(k.OrgID, k.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"externalKms": extKmsJSON(&k)})
	})

	// GCP key discovery — connector probe; no cloud round-trip, return empty set.
	mux.HandleFunc("POST /v1/external-kms/gcp/keys", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": []string{}})
	})

	// ── per-project KMS selection ──────────────────────────────────────────────
	mux.HandleFunc("GET /v1/projects/{id}/kms", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var sel projectKmsSel
		if st.getJSON(projectKmsKey(r.PathValue("id")), &sel) != nil {
			writeJSON(w, http.StatusOK, map[string]any{"secretManagerKmsKey": projectKmsJSON(nil)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretManagerKmsKey": projectKmsJSON(&sel)})
	})

	mux.HandleFunc("PATCH /v1/projects/{id}/kms", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var req struct {
			Kms struct {
				Type  string `json:"type"`
				KmsID string `json:"kmsId"`
			} `json:"kms"`
		}
		if !decode(w, r, &req) {
			return
		}
		sel := &projectKmsSel{ProjectID: r.PathValue("id"), Type: req.Kms.Type, KmsID: req.Kms.KmsID}
		_ = st.putJSON(projectKmsKey(sel.ProjectID), sel)
		writeJSON(w, http.StatusOK, map[string]any{"secretManagerKmsKey": projectKmsJSON(sel)})
	})

	mux.HandleFunc("GET /v1/projects/{id}/kms/backup", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secretManager": ""})
	})

	mux.HandleFunc("POST /v1/projects/{id}/kms/backup", func(w http.ResponseWriter, r *http.Request) {
		if cl(w, r) == nil {
			return
		}
		var req struct{ Backup string }
		_ = decode(w, r, &req)
		var sel projectKmsSel
		_ = st.getJSON(projectKmsKey(r.PathValue("id")), &sel)
		writeJSON(w, http.StatusOK, map[string]any{"secretManagerKmsKey": projectKmsJSON(&sel)})
	})
}

// ── list helpers (badger prefix-scan → JSON arrays) ──────────────────────────

func cmekExists(st *webStore, id string) bool {
	var k cmekKey
	return st.getJSON(cmekEntKey(id), &k) == nil
}

func listCmeks(st *webStore, projectID string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	var ids []string
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = cmekProjPrefix(projectID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := cmekProjPrefix(projectID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		var k cmekKey
		if st.getJSON(cmekEntKey(id), &k) == nil {
			out = append(out, cmekJSON(&k))
		}
	}
	return out
}

func listKmipClients(st *webStore, projectID string) []any {
	out := []any{}
	if projectID == "" {
		return out
	}
	pfx := kmipClientProjPrefix(projectID)
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			id := string(it.Item().Key()[len(pfx):])
			var cli kmipClient
			if st.getJSON(kmipClientKey(id), &cli) == nil {
				out = append(out, kmipClientJSON(&cli))
			}
		}
		return nil
	})
	return out
}

func listExtKms(st *webStore, orgID string) []any {
	out := []any{}
	if orgID == "" {
		return out
	}
	pfx := extKmsOrgPrefix(orgID)
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			id := string(it.Item().Key()[len(pfx):])
			var k externalKms
			if st.getJSON(extKmsKey(id), &k) == nil {
				out = append(out, extKmsListJSON(&k))
			}
		}
		return nil
	})
	return out
}
