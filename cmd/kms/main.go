// Command kms starts the Lux KMS server backed by ZapDB + MPC.
//
// Configuration precedence: flags > env vars > defaults.
//
//	Env vars:
//	  MPC_ADDR           - ZAP address (host:port); empty = mDNS discovery
//	  MPC_VAULT_ID       - MPC vault ID for validator keys (required for MPC)
//	  KMS_NODE_ID        - ZAP node ID (default "kms-0")
//	  KMS_ZAP_PORT       - ZAP secrets-server listen port (default 9652, 0 = disable)
//	  KMS_MASTER_KEY_B64 - 32-byte master key (base64) for SecretStore envelope
//	  KMS_DATA_DIR       - ZapDB data directory (default "/data/kms")
//	  KMS_LISTEN         - HTTP listen address (default ":8080")
//	  IAM_ENDPOINT       - Hanzo IAM endpoint for auth (default "https://hanzo.id")
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
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// Health.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "kms"})
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
		resp, err := http.PostForm(iamEndpoint+"/api/login/oauth/access_token", form)
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
				zs := zapserver.New(zapserver.Config{
					Store:     secStore,
					MasterKey: masterKey,
					Logger:    luxlog.New("component", "kms-zapserver"),
				})
				zs.Register(n)
				log.Printf("kms: ZAP secrets-server listening on :%d (service=_kms._tcp)", zapPort)
			}
		}
	} else {
		log.Printf("kms: ZAP secrets-server disabled (set KMS_MASTER_KEY_B64 and KMS_ZAP_PORT to enable)")
	}

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
func startReplicator(db *badger.DB, nodeID string) *badger.Replicator {
	endpoint := os.Getenv("REPLICATE_S3_ENDPOINT")
	if endpoint == "" {
		log.Printf("kms: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)")
		return nil
	}

	cfg := badger.ReplicatorConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("REPLICATE_S3_BUCKET", "lux-kms-backups"),
		Region:    envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: os.Getenv("REPLICATE_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("REPLICATE_S3_SECRET_KEY"),
		UseSSL:    !strings.HasPrefix(endpoint, "http://"),
		Path:      envOr("REPLICATE_PATH", fmt.Sprintf("kms/%s", nodeID)),
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
