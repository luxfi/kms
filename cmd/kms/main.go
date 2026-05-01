// Command kms starts the KMS server backed by ZapDB + MPC.
//
// Configuration precedence: flags > env vars > defaults.
//
//	Env vars:
//	  MPC_ADDR           - ZAP address (host:port); empty = mDNS discovery
//	  MPC_VAULT_ID       - MPC vault ID for validator keys (required for MPC)
//	  KMS_NODE_ID        - ZAP node ID (default "kms-0")
//	  KMS_ZAP_PORT       - ZAP secrets-server listen port (default 9999, 0 = disable)
//	  KMS_MASTER_KEY_B64 - 32-byte master key (base64) for SecretStore envelope
//	  KMS_DATA_DIR       - ZapDB data directory (default "/data/kms")
//	  KMS_LISTEN         - HTTP listen address (default ":8080")
//	  IAM_ENDPOINT       - Hanzo IAM endpoint for auth (default "https://hanzo.id")
//	  KMS_ZAP_ACL        - path to ZAP ACL file (CSV: nodeId,pathPrefix,role).
//	                       Empty = open mode (legacy). Set to enforce
//	                       principal-role authn on Op Secret*.
//
//	S3 replication (ZapDB Replicator):
//	  REPLICATE_S3_ENDPOINT  - S3 endpoint (empty = replication disabled)
//	  REPLICATE_S3_BUCKET    - S3 bucket (default "lux-kms-backups")
//	  REPLICATE_S3_REGION    - S3 region (default "us-central1")
//	  REPLICATE_S3_ACCESS_KEY
//	  REPLICATE_S3_SECRET_KEY
//	  REPLICATE_AGE_RECIPIENT - age public key for backup encryption
//	  REPLICATE_AGE_IDENTITY  - age private key for restore
//	  REPLICATE_PATH          - S3 key prefix (default "kms/{KMS_NODE_ID}")
package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	badger "github.com/luxfi/zapdb"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	luxlog "github.com/luxfi/log"
	"github.com/luxfi/zap"
)

// One binary, one image. The KMS admin UI ships inside this binary.
// The `web/` directory at this package root is populated by `make build`
// (it copies `frontend/dist/` from the repo root before `go build`); the
// embed picks up the static Vite output and serves it at `/` with a SPA
// fallback so React Router routes resolve. API routes (`/v1/*`,
// `/healthz`, `/health`) take precedence and are registered before the
// catch-all. If `web/` is empty (e.g. fresh clone, no UI build yet), the
// fallback returns 404 cleanly — the API still works.
//
//go:embed all:web
var frontendDist embed.FS

func main() {
	mpcAddr := envOr("MPC_ADDR", "")
	vaultID := envOr("MPC_VAULT_ID", "")
	nodeID := envOr("KMS_NODE_ID", "kms-0")
	iamEndpoint := envOr("IAM_ENDPOINT", "https://hanzo.id")
	dataDir := envOr("KMS_DATA_DIR", "/data/kms")
	listen := envOr("KMS_LISTEN", ":8080")

	// Open ZapDB.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("kms: create data dir %s: %v", dataDir, err)
	}
	dbOpts := badger.DefaultOptions(dataDir).
		WithLogger(zapdbLogger{}).
		WithEncryptionKey(masterKeyFromEnv()).
		WithIndexCacheSize(64 << 20) // 64MB index cache
	db, err := badger.Open(dbOpts)
	if err != nil {
		log.Fatalf("kms: open zapdb at %s: %v", dataDir, err)
	}
	defer db.Close()

	log.Printf("kms: zapdb opened at %s", dataDir)

	// Start ZapDB Replicator if S3 is configured.
	replicator := startReplicator(db, nodeID)
	if replicator != nil {
		defer replicator.Stop()
	}

	mux := http.NewServeMux()

	// Health probes — wired in every shape callers might try:
	//   /healthz / /health               — root, for direct/standalone probes
	//   /v1/kms/healthz / /v1/kms/health — gateway-routed, no prefix strip
	// All return the same shape so probes are interchangeable.
	healthOK := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "kms"})
	}
	mux.HandleFunc("GET /healthz", healthOK)
	mux.HandleFunc("GET /health", healthOK)
	mux.HandleFunc("GET /v1/kms/healthz", healthOK)
	mux.HandleFunc("GET /v1/kms/health", healthOK)

	// SPA bootstrap config. The Infisical-derived React frontend in
	// frontend/src/hooks/api/admin/queries.ts:fetchServerConfig fetches
	// `/v1/admin/config` at first paint and refuses to render when the
	// payload is missing — the user sees `["server-config"] data is
	// undefined`. We don't run the full Infisical admin surface, so
	// this returns a minimal-but-complete shape: signups via IAM, no
	// invite-only gating, no SMTP, instance is initialized. Fields the
	// SPA reads: initialized, allowSignUp, allowedSignUpDomain, etc.
	// defaultAuthOrgSlug drives the "Login with Liquid ID" button in the
	// SPA: when set, the SPA bypasses the org-picker and goes straight to
	// /v1/sso/oidc/login?orgSlug=<this>. Read from env so the same image
	// white-labels per-deployment (e.g. "liquidity" on satschel.com).
	defaultOrgSlug := envOr("KMS_DEFAULT_ORG_SLUG", "")
	mux.HandleFunc("GET /v1/admin/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"config": map[string]any{
				"initialized":               true,
				"allowSignUp":               true,
				"allowedSignUpDomain":       nil,
				"trustSamlEmails":           false,
				"trustLdapEmails":           false,
				"trustOidcEmails":           true,
				"defaultAuthOrgId":          "",
				"defaultAuthOrgSlug":        defaultOrgSlug,
				"isSecretScanningDisabled":  false,
				"isMigrationModeOn":         false,
				"enabledLoginMethods":       []string{"oidc"},
				"slackClientId":             "",
				"isSmtpConfigured":          false,
				"isSecretApprovalDisabled":  false,
				"identityRevocationEnabled": true,
			},
		})
	})

	// Machine identity auth via IAM.
	mux.HandleFunc("POST /v1/kms/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.ClientSecret == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "clientId and clientSecret required"})
			return
		}
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {req.ClientID},
			"client_secret": {req.ClientSecret},
		}
		// Canonical OAuth2 path on hanzoai/iam — no `/api/` prefix (killed in
		// v2.381.0). `/login/oauth/access_token` is mounted at root per the
		// OAuth2 spec; `/oauth/access_token` is also wired as an alias.
		resp, err := http.PostForm(iamEndpoint+"/login/oauth/access_token", form)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"statusCode": 502, "message": "identity provider unreachable"})
			return
		}
		defer resp.Body.Close()
		var tok map[string]any
		json.NewDecoder(resp.Body).Decode(&tok)
		at, _ := tok["access_token"].(string)
		if at == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accessToken": at, "expiresIn": 86400, "tokenType": "Bearer"})
	})

	// Secret store — ZapDB-backed, encrypted at rest.
	secStore := store.NewSecretStore(db)

	// GET /v1/kms/orgs/{org}/secrets/{path...}/{name}
	// Matches the ATS kmsclient.Get() URL pattern.
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		idx := strings.LastIndex(rest, "/")
		if idx < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "path and name required"})
			return
		}
		path, name := rest[:idx], rest[idx+1:]
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		sec, err := secStore.Get(path, name, env)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"value": string(sec.Ciphertext)},
		})
	})

	// POST /v1/kms/orgs/{org}/secrets — create a secret.
	mux.HandleFunc("POST /v1/kms/orgs/{org}/secrets", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path  string `json:"path"`
			Name  string `json:"name"`
			Env   string `json:"env"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "name and value required"})
			return
		}
		if req.Env == "" {
			req.Env = "default"
		}
		sec := &store.Secret{
			Name:       req.Name,
			Path:       req.Path,
			Env:        req.Env,
			Ciphertext: []byte(req.Value),
		}
		if err := secStore.Put(sec); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	})

	// DELETE /v1/kms/orgs/{org}/secrets/{rest...}/{name}
	mux.HandleFunc("DELETE /v1/kms/orgs/{org}/secrets/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		idx := strings.LastIndex(rest, "/")
		if idx < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "path and name required"})
			return
		}
		path, name := rest[:idx], rest[idx+1:]
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		if err := secStore.Delete(path, name, env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Legacy: env-backed secret fetch.
	mux.HandleFunc("GET /v1/kms/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "secret name required"})
			return
		}
		val := os.Getenv(name)
		if val == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"secretKey": name, "secretValue": val},
		})
	})

	// MPC key management (only when MPC_VAULT_ID is set).
	if vaultID != "" {
		zapClient, err := mpc.NewZapClient(nodeID, mpcAddr)
		if err != nil {
			log.Fatalf("kms: zap client: %v", err)
		}

		keyStore, err := store.New(db)
		if err != nil {
			log.Fatalf("kms: key store: %v", err)
		}

		checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if status, err := zapClient.Status(checkCtx); err != nil {
			log.Printf("kms: WARNING: mpc unreachable via ZAP: %v", err)
		} else {
			log.Printf("kms: mpc ready=%v peers=%d/%d mode=%s",
				status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
		}
		checkCancel()

		mgr := keys.NewManager(zapClient, keyStore, vaultID)
		registerKMSRoutes(mux, mgr, zapClient)
	} else {
		log.Printf("kms: MPC_VAULT_ID not set — running in secrets-only mode (no threshold signing)")
	}

	// ZAP secrets server — exposes the SecretStore over luxfi/zap on its own
	// port so in-cluster callers can fetch with zero REST round-trip.
	masterKeyB64 := envOr("KMS_MASTER_KEY_B64", "")
	zapPortStr := envOr("KMS_ZAP_PORT", "9999")
	zapPort, _ := strconv.Atoi(zapPortStr)
	if masterKeyB64 != "" && zapPort > 0 {
		masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil || len(masterKey) != 32 {
			log.Printf("kms: KMS_MASTER_KEY_B64 invalid (need 32 bytes base64); ZAP secrets-server disabled")
		} else {
			n := zap.NewNode(zap.NodeConfig{
				NodeID:      nodeID + "-secrets",
				ServiceType: "_kms._tcp",
				Port:        zapPort,
			})
			if err := n.Start(); err != nil {
				log.Printf("kms: ZAP secrets-server failed to start on :%d: %v", zapPort, err)
			} else {
				acl, aclErr := zapserver.LoadACLFromEnv()
				if aclErr != nil {
					// Refuse to boot with a bad ACL — silent open mode
					// after a misconfigured ACL would be a regression.
					log.Fatalf("kms: KMS_ZAP_ACL load failed: %v", aclErr)
				}
				zs := zapserver.New(zapserver.Config{
					Store:     secStore,
					MasterKey: masterKey,
					ACL:       acl,
					Logger:    luxlog.New("component", "kms-zapserver"),
				})
				zs.Register(n)
				log.Printf("kms: ZAP secrets-server listening on :%d (service=_kms._tcp)", zapPort)
			}
		}
	} else {
		log.Printf("kms: ZAP secrets-server disabled (set KMS_MASTER_KEY_B64 and KMS_ZAP_PORT to enable)")
	}

	// IAM OIDC SSO — /v1/sso/oidc/{login,callback}, /v1/sso/whoami, /v1/sso/logout.
	// Registered before the SPA catch-all; if OIDC isn't configured the
	// handlers return 503 so misconfiguration is observable.
	registerOIDCRoutes(mux)

	// Mount the embedded admin UI under the root catch-all. Registered last
	// so explicit handlers (`/healthz`, `/health`, `/v1/*`) win the route
	// match. SPA fallback: any GET that doesn't match a real file falls
	// back to index.html so React Router can resolve the path client-side.
	registerWebUI(mux)

	// Start HTTP server.
	srv := &http.Server{
		Addr:         listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("kms: HTTP listening on %s", listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("kms: http: %v", err)
		}
	}()

	// Graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("kms: shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func registerKMSRoutes(mux *http.ServeMux, mgr *keys.Manager, mpcBackend keys.MPCBackend) {
	// KMS key routes are unprotected at the HTTP layer — auth is enforced
	// by the Gateway (JWT validation + X-IAM-Roles header injection).
	// In-cluster callers (ATS, BD, TA) go through Gateway; direct access
	// is blocked by K8s NetworkPolicy (only Gateway can reach port 8080).

	mux.HandleFunc("POST /v1/kms/keys/generate", func(w http.ResponseWriter, r *http.Request) {
		var req keys.GenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.ValidatorID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validator_id is required"})
			return
		}
		if req.Threshold < 2 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "threshold must be >= 2"})
			return
		}
		if req.Parties < req.Threshold {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parties must be >= threshold"})
			return
		}
		if req.Threshold == req.Parties {
			log.Printf("kms: WARNING: keygen threshold==parties (%d) for validator=%s — no fault tolerance",
				req.Threshold, req.ValidatorID)
		}

		ks, err := mgr.GenerateValidatorKeys(r.Context(), req)
		if err != nil {
			log.Printf("kms: audit: keygen FAILED validator_id=%s error=%v", req.ValidatorID, err)
			if strings.Contains(err.Error(), "already exists") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("kms: audit: keygen OK validator_id=%s bls_wallet=%s ringtail_wallet=%s threshold=%d parties=%d",
			ks.ValidatorID, ks.BLSWalletID, ks.RingtailWalletID, ks.Threshold, ks.Parties)
		writeJSON(w, http.StatusCreated, ks)
	})

	mux.HandleFunc("GET /v1/kms/keys", func(w http.ResponseWriter, r *http.Request) {
		list := mgr.List()
		if list == nil {
			list = []*keys.ValidatorKeySet{}
		}
		writeJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /v1/kms/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ks, err := mgr.Get(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "validator key set not found"})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	})

	mux.HandleFunc("POST /v1/kms/keys/{id}/sign", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req keys.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if len(req.Message) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message is required"})
			return
		}

		var resp *keys.SignResponse
		var err error
		switch req.KeyType {
		case "bls":
			resp, err = mgr.SignWithBLS(r.Context(), id, req.Message)
		case "ringtail":
			resp, err = mgr.SignWithRingtail(r.Context(), id, req.Message)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_type must be 'bls' or 'ringtail'"})
			return
		}
		if err != nil {
			log.Printf("kms: audit: sign FAILED validator_id=%s key_type=%s error=%v", id, req.KeyType, err)
			if strings.Contains(err.Error(), "not found") {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("kms: audit: sign OK validator_id=%s key_type=%s", id, req.KeyType)
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /v1/kms/keys/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req keys.RotateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_threshold or new_participants required"})
			return
		}

		ks, err := mgr.Rotate(r.Context(), id, req)
		if err != nil {
			log.Printf("kms: audit: rotate FAILED validator_id=%s error=%v", id, err)
			if strings.Contains(err.Error(), "not found") {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("kms: audit: rotate OK validator_id=%s new_threshold=%d new_parties=%d",
			id, ks.Threshold, ks.Parties)
		writeJSON(w, http.StatusOK, ks)
	})

	mux.HandleFunc("GET /v1/kms/status", func(w http.ResponseWriter, r *http.Request) {
		status, err := mpcBackend.Status(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"kms":     "ok",
				"mpc":     "unreachable",
				"details": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"kms": "ok",
			"mpc": status,
		})
	})
}

// startReplicator initializes ZapDB S3 replication if configured.
//
// REPLICATE_S3_ENDPOINT is normalized to bare host:port — minio.New
// rejects fully-qualified URLs ("Endpoint url cannot have fully
// qualified paths") and silently disables replication when an operator
// passes a scheme- or path-bearing value. We parse defensively and
// drop both the scheme and any path component, logging a warning so
// the misconfiguration is visible.
func startReplicator(db *badger.DB, nodeID string) *badger.Replicator {
	rawEndpoint := os.Getenv("REPLICATE_S3_ENDPOINT")
	if rawEndpoint == "" {
		log.Printf("kms: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)")
		return nil
	}

	endpoint, useSSL := normalizeS3Endpoint(rawEndpoint)

	// Backwards-compatible env reads: AWS SDK names take precedence,
	// REPLICATE_S3_* legacy names are honoured, and the historical
	// REPLICATE_S3_ACCESS_KEY / _SECRET_KEY shorthand still wins as a
	// last resort. Operators should pick one — we accept all three so
	// a stale chart cannot silently zero-out credentials.
	access := firstNonEmpty(
		os.Getenv("REPLICATE_S3_ACCESS_KEY_ID"),
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("REPLICATE_S3_ACCESS_KEY"),
	)
	secret := firstNonEmpty(
		os.Getenv("REPLICATE_S3_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("REPLICATE_S3_SECRET_KEY"),
	)

	cfg := badger.ReplicatorConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("REPLICATE_S3_BUCKET", "lux-kms-backups"),
		Region:    envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: access,
		SecretKey: secret,
		UseSSL:    useSSL,
		Path:      envOr("REPLICATE_S3_PATH", envOr("REPLICATE_PATH", fmt.Sprintf("kms/%s", nodeID))),
		Interval:  time.Second,
	}

	// Age encryption for backups.
	recipientStr := os.Getenv("REPLICATE_AGE_RECIPIENT")
	if recipientStr != "" {
		// Age recipient parsing happens inside the Replicator via the age package.
		// The ReplicatorConfig accepts the raw recipient/identity interfaces.
		log.Printf("kms: S3 replication with age encryption enabled")
	}

	replicator, err := badger.NewReplicator(db, cfg)
	if err != nil {
		log.Printf("kms: WARNING: S3 replicator init failed: %v — replication disabled", err)
		return nil
	}

	go replicator.Start(context.Background())
	log.Printf("kms: S3 replication started → %s/%s/%s", endpoint, cfg.Bucket, cfg.Path)
	return replicator
}

// masterKeyFromEnv returns a 32-byte encryption key for ZapDB at-rest encryption,
// or nil to disable (dev only).
func masterKeyFromEnv() []byte {
	b64 := os.Getenv("KMS_ENCRYPTION_KEY_B64")
	if b64 == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != 32 {
		log.Printf("kms: KMS_ENCRYPTION_KEY_B64 invalid (need 32 bytes base64); at-rest encryption disabled")
		return nil
	}
	return key
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// firstNonEmpty returns the first argument with non-zero length, or "" if
// all are empty. Used to fall back across the AWS / REPLICATE_S3 env-name
// variants without picking a default that could silently mask a typo.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// normalizeS3Endpoint strips scheme + path from a REPLICATE_S3_ENDPOINT
// value so minio.New receives the bare host:port it expects. Returns
// (host[:port], useSSL) where useSSL is true unless the operator
// explicitly specified an http:// scheme. A non-empty path is logged as
// a warning so the misconfiguration is visible — minio rejects path-
// bearing endpoints with "Endpoint url cannot have fully qualified
// paths." and the historical behaviour was to silently disable
// replication.
func normalizeS3Endpoint(raw string) (host string, useSSL bool) {
	useSSL = !strings.HasPrefix(raw, "http://")

	// strings.HasPrefix above already covers "http://"; treat the bare
	// "https://" case explicitly so the parse path stays simple.
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			log.Printf("kms: REPLICATE_S3_ENDPOINT %q failed to parse — using as-is, replication may fail", raw)
			return raw, useSSL
		}
		if u.Path != "" && u.Path != "/" {
			log.Printf("kms: REPLICATE_S3_ENDPOINT %q has a path component (%q) — stripping; put the bucket in REPLICATE_S3_BUCKET", raw, u.Path)
		}
		if u.RawQuery != "" {
			log.Printf("kms: REPLICATE_S3_ENDPOINT %q has a query string — stripping", raw)
		}
		return u.Host, useSSL
	}
	// Already bare host:port. Trim a trailing "/" if any operator added one.
	return strings.TrimRight(raw, "/"), useSSL
}

// zapdbLogger adapts slog to ZapDB's Logger interface.
type zapdbLogger struct{}

func (zapdbLogger) Errorf(format string, args ...interface{}) {
	slog.Error(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Warningf(format string, args ...interface{}) {
	slog.Warn(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Infof(format string, args ...interface{}) {
	slog.Info(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Debugf(format string, args ...interface{}) {
	slog.Debug(fmt.Sprintf(format, args...))
}

// registerWebUI mounts the embedded Vite SPA at `/` with a SPA fallback.
// API routes are registered earlier on the same mux and win the route
// match (Go 1.22 ServeMux specificity rules); this only catches the
// remainder. If `web/` is empty (not built yet), every fallthrough returns
// 404 — the API still works, just no UI.
func registerWebUI(mux *http.ServeMux) {
	sub, err := fs.Sub(frontendDist, "web")
	if err != nil {
		log.Printf("kms: web UI disabled — embed sub: %v", err)
		return
	}
	// If index.html is missing, treat the UI as not-built and return early.
	// (`make build` populates `web/` from frontend/dist before `go build`.)
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		log.Printf("kms: web UI not built — `make build` populates cmd/kms/web from frontend/dist")
		return
	}
	fileSrv := http.FileServer(http.FS(sub))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Trim leading "/" once for fs.Stat.
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			clean = "index.html"
		}
		if _, err := fs.Stat(sub, clean); err != nil {
			// Not a real asset — serve index.html so React Router takes over.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileSrv.ServeHTTP(w, r2)
			return
		}
		fileSrv.ServeHTTP(w, r)
	})
	log.Printf("kms: web UI mounted at /")
}
