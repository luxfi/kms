// Command kms starts the KMS server backed by ZapDB + MPC.
//
// Configuration precedence: flags > env vars > defaults.
//
// Boot is fail-open: if MPC_VAULT_ID is set but the MPC daemon is
// unreachable, KMS logs a warning and continues in secrets-only mode.
// /healthz reports `status=degraded` and any /v1/kms/keys/* request
// returns 503 with body `{"error":"mpc unreachable","mode":"secrets-only"}`.
// Each request re-probes MPC, so the same pod recovers transparently
// once MPC comes back up — no restart required.
//
//	Env vars:
//	  MPC_ADDR           - ZAP address (host:port); empty = mDNS discovery
//	  MPC_VAULT_ID       - MPC vault ID for validator keys (required for MPC)
//	  KMS_NODE_ID        - ZAP node ID (default "kms-0")
//	  ZAP_PORT           - ZAP secrets-server listen port (default 9999, 0 = disable)
//	  MPC_REK_ENDPOINT   - MPC ZAP CSV for threshold-rooted Root Encryption Key
//	                       fetch. kmsd refuses to start unless the ring returns
//	                       a 32-byte REK. The only source of a root key.
//	  MPC_REK_KEY_ID     - MPC-side identifier of the wrapped REK record
//	                       (default "kms/rek/v1"). Bump alongside reshare.
//	  MPC_REK_TIMEOUT    - REK bootstrap timeout (Go duration, default "10s").
//	  KMS_MASTER_KEY_B64 - REFUSED. A root in the environment is a root in a
//	                       Secret, readable by whatever reads Secrets. Setting it
//	                       stops the boot rather than being ignored.
//	  KMS_DATA_DIR       - ZapDB data directory (default "/data/kms")
//	  KMS_LISTEN         - HTTP listen address (default ":8080")
//	  IAM_ENDPOINT       - Hanzo IAM endpoint for auth (default "https://hanzo.id")
//	  KMS_CONSENSUS_VALIDATORS - newline-separated NodeIDs of the validator
//	                             authority (consensus read set). Required for
//	                             ZAP. Format: one cb58 NodeID per line.
//	  KMS_CONSENSUS_OPERATORS  - newline-separated NodeIDs of the operator
//	                             authority (consensus write set). Required
//	                             for ZAP. Same format.
//	  KMS_CONSENSUS_FILE       - optional file path supplying the same two
//	                             sets (JSON: {"validators":[...],"operators":[...]}).
//	                             When set, env vars above are ignored.
//	  KMS_CONSENSUS_TTL        - per-authority refresh TTL (Go duration,
//	                             default 30s). The kms-operator re-applies
//	                             the snapshot at this cadence.
//	  KMS_NONCE_LEDGER_TTL     - anti-replay nonce TTL (Go duration,
//	                             default MaxClockSkew+1m=6m). Captured
//	                             envelopes are rejected as replays while
//	                             their (NodeID,Nonce) tuple is in the
//	                             ledger; after TTL they fail clock-skew
//	                             anyway. Tune up only if MaxClockSkew is
//	                             tuned up.
//	  KMS_NONCE_LEDGER_GC      - background GC sweep cadence (Go duration,
//	                             default TTL/4 = 90s). Smaller values
//	                             reduce peak memory; larger values reduce
//	                             CPU burn. The ledger correctness does
//	                             NOT depend on this — it's a memory/CPU
//	                             trade only.
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
	"errors"
	"fmt"
	"github.com/luxfi/age"
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

	"github.com/luxfi/kms/pkg/atrest"
	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/sdksign"
	"github.com/luxfi/kms/pkg/secret"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/store/mpcrek"
	"github.com/luxfi/kms/pkg/zapserver"
	luxlog "github.com/luxfi/log"
	"github.com/luxfi/zap"
)

// One binary, one image. The KMS admin UI ships inside this binary.

func main() {
	mpcAddr := envOr("MPC_ADDR", "")
	vaultID := envOr("MPC_VAULT_ID", "")
	nodeID := envOr("KMS_NODE_ID", "kms-0")
	iamEndpoint := envOr("IAM_ENDPOINT", "https://hanzo.id")
	// Canonical OAuth2 token endpoint on hanzoai/iam. The API moved under
	// the `/v1/iam` prefix; the legacy root `/login/oauth/access_token`
	// route is now a frontend redirect, not the token API. Env-overridable
	// so a future path move needs no rebuild — one knob, one default.
	iamTokenPath := envOr("IAM_TOKEN_PATH", "/v1/iam/oauth/token")
	dataDir := envOr("KMS_DATA_DIR", "/data/kms")
	listen := envOr("KMS_LISTEN", ":8080")

	// Open ZapDB. At-rest encryption is a precondition, not a preference: a
	// store opened without a key holds every credential in the fleet in
	// cleartext on the PVC and in the S3 replica, and no gate in front of it
	// changes that. So a missing or malformed key stops the boot here rather
	// than degrading to a plaintext store behind one scrolled-past log line.
	atRest, err := atrest.KeyFromEnv()
	if err != nil {
		log.Fatalf("kms: %v", err)
	}
	db, err := atrest.Open(dataDir, atRest, zapdbLogger{})
	if err != nil {
		log.Fatalf("kms: %v", err)
	}
	defer db.Close()

	log.Printf("kms: zapdb opened at %s (at-rest encryption on)", dataDir)

	// Start ZapDB Replicator if S3 is configured.
	replicator := startReplicator(db, nodeID)
	if replicator != nil {
		defer replicator.Stop()
	}

	mux := http.NewServeMux()

	// MPC availability flag. Flips to true after a successful ZAP probe at
	// boot. Read by /healthz to surface degraded mode and by the keys
	// routes to short-circuit with 503 when MPC is unreachable. The
	// pointer-to-bool is set once in main and read concurrently — atomic
	// load isn't necessary because the value never changes after boot.
	var mpcAvailable bool

	// Health probes — wired in every shape callers might try:
	//   /healthz / /health               — root, for direct/standalone probes
	//   /v1/kms/healthz / /v1/kms/health — gateway-routed, no prefix strip
	// All return the same shape so probes are interchangeable.
	healthOK := healthHandler(vaultID, &mpcAvailable)
	mux.HandleFunc("GET /healthz", healthOK)
	mux.HandleFunc("GET /health", healthOK)
	mux.HandleFunc("GET /v1/kms/healthz", healthOK)
	mux.HandleFunc("GET /v1/kms/health", healthOK)

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
		// Canonical OAuth2 token endpoint on hanzoai/iam, under the `/v1/iam`
		// API prefix (default IAM_TOKEN_PATH=/v1/iam/oauth/token). The legacy
		// root `/login/oauth/access_token` is a frontend redirect, not the API.
		resp, err := http.PostForm(iamEndpoint+iamTokenPath, form)
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

	// JWT-backed authorization for the secrets surface. Every request to
	// /v1/kms/orgs/{org}/secrets/* must carry an IAM-signed bearer token
	// whose `owner` claim equals {org} (or whose roles include
	// kms-admin). Public endpoints (health, /v1/kms/auth/login, OIDC
	// SSO, the SPA) are NOT wrapped — they remain reachable without a
	// token. See auth.go.
	//
	// JWKS is fetched from KMS_IAM_URL (in-cluster) and the JWT `iss`
	// claim is validated against KMS_EXPECTED_ISSUER (public hostname).
	// When the deployment uses a single URL for both, fall through to
	// IAM_ENDPOINT.
	jwksFrom := envOr("KMS_IAM_URL", iamEndpoint)
	expectedIss := envOr("KMS_EXPECTED_ISSUER", iamEndpoint)
	auth := newOrgJWTAuth(jwksFrom, expectedIss)

	// KMS_HOME_ORG binds this deployment's flat secret store to the org that
	// owns it. Without it the store authorizes any valid IAM token from any of
	// the shared issuer's orgs — every brand, every app — through the org-less
	// door or through its own /orgs/{self} door, because the URL org proves only
	// that the caller named itself honestly (see authorizesHome). Fail closed:
	// refuse to boot rather than serve the store ungated. A stalled rollout
	// leaves the prior pod serving; a running pod is never open.
	auth.homeOrgs = parseHomeOrgs(envOr("KMS_HOME_ORG", ""))
	if err := requireHomeOrgConfig(auth.homeOrgs); err != nil {
		log.Fatalf("kms: %v", err)
	}

	// Secret CRUD surface — org-scoped, JWT-gated, ZapDB-backed. Extracted
	// into one named registrar (mirrors registerKMSRoutes / registerOIDCRoutes
	// ) so the exact route set the server exposes is testable
	// in isolation. There is deliberately NO env-var fetch route: the KMS
	// process environment (KMS_MASTER_KEY_B64 root REK, MPC_TOKEN, S3 keys) is
	// never reachable over HTTP. Secrets flow ONLY through these org-scoped
	// routes and the ZAP wire. Regression: TestSecretRoutes_NoEnvVarLeak.
	// The REK is resolved BEFORE the routes, because the HTTP door seals with it
	// exactly as the ZAP door does. It used to load further down, after these
	// routes were built, which is why this door had no key and wrote what it was
	// given.
	masterKey := loadREK()
	defer mpcrek.Zero(masterKey)

	registerSecretRoutes(mux, auth, secStore, masterKey)

	// MPC key management (only when MPC_VAULT_ID is set).
	//
	// Boot is fail-open: every error path here logs a warning and degrades
	// to secrets-only mode instead of exiting. The previous behaviour
	// (log.Fatalf on any ZAP init or status failure) meant a transient MPC
	// outage took down KMS too — the secrets surface is independent and
	// must keep serving. Routes that require MPC return 503 via the
	// mpcAvailable flag wired into healthOK / registerKMSRoutes.
	//
	// signBackend, when non-nil, enables the OpSign/OpVerify ops on the
	// /v1/sdk surface. It wraps the MPC-backed key Manager; the KMS holds
	// no full key material. nil ⇒ sign/verify return "signing not
	// configured".
	var signBackend zapserver.SignBackend
	if vaultID != "" {
		// Trust at the network boundary (NetworkPolicy + ZAP wire).
		zapClient, err := mpc.NewZapClient(nodeID, mpcAddr)
		switch {
		case err != nil:
			log.Printf("kms: WARNING: mpc zap client init failed: %v — degrading to secrets-only mode", err)
			// Even though no client could be built, the key routes must
			// still respond with a clear 503 — without this, callers see
			// 405/404 and can't distinguish "MPC down" from "wrong path"
			// or "wrong method". registerStubKMSRoutes installs handlers
			// that always 503 with the same body shape as registerKMSRoutes.
			registerStubKMSRoutes(mux, err)
		default:
			keyStore, ksErr := store.New(db)
			if ksErr != nil {
				log.Printf("kms: WARNING: mpc key store init failed: %v — degrading to secrets-only mode", ksErr)
				zapClient.Close()
				registerStubKMSRoutes(mux, ksErr)
				break
			}

			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			status, statusErr := zapClient.Status(checkCtx)
			checkCancel()
			if statusErr != nil {
				log.Printf("kms: WARNING: mpc unreachable via ZAP: %v — degrading to secrets-only mode", statusErr)
				// Keep the client + key routes wired even though the probe
				// failed: MPC may come up later in the same pod lifetime
				// (e.g. NetworkPolicy applied after KMS started). Routes
				// re-probe on every call; if MPC is up by then they
				// succeed transparently.
			} else {
				log.Printf("kms: mpc ready=%v peers=%d/%d mode=%s",
					status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
				mpcAvailable = true
			}
			mgr := keys.NewManager(zapClient, keyStore, vaultID)
			// Enable /v1/sdk sign/verify over the same MPC-backed manager.
			signBackend = sdksign.New(mgr)
			registerKMSRoutes(mux, auth, mgr, zapClient, &mpcAvailable)
		}
	}
	if vaultID == "" {
		log.Printf("kms: MPC_VAULT_ID not set — running in secrets-only mode (no threshold signing)")
	}

	// ZAP secrets server — exposes the SecretStore over luxfi/zap on its own
	// port so in-cluster callers can fetch with zero REST round-trip.
	//
	// The master key (Root Encryption Key) protecting every per-secret DEK is
	// resolved by loadREK below. The only source is a luxfi/mpc threshold ring
	// (MPC_REK_ENDPOINT), and a fetch that fails stops the boot: the point of
	// rooting in the ring is that the root is not derivable from anything on the
	// pod, and reaching for something on the pod when the ring is quiet would
	// give that away exactly when it matters.
	zapPortStr := envOr("ZAP_PORT", "9999")
	zapPort, _ := strconv.Atoi(zapPortStr)
	if masterKey != nil {
		// One authorizer + one nonce ledger back BOTH transports (the
		// in-cluster ZAP wire and the HTTP /v1/sdk surface) — one
		// verify→authorize→dispatch core, two framings. Both fail closed:
		// a misconfigured authorizer or ledger is a wire-reachable
		// security hole (open authorization / re-opened replay window),
		// so we refuse to boot rather than serve /v1/sdk without
		// consensus authorization or replay defence.
		authorizer, err := buildConsensusAuthorizer()
		if err != nil {
			log.Fatalf("kms: consensus authorizer init failed: %v", err)
		}
		nonceLedger, err := buildNonceLedger()
		if err != nil {
			log.Fatalf("kms: nonce ledger init failed: %v", err)
		}
		srv := zapserver.New(zapserver.Config{
			Store:       secStore,
			MasterKey:   masterKey,
			Authorizer:  authorizer,
			NonceLedger: nonceLedger,
			Signer:      signBackend,
			Logger:      luxlog.New("component", "kms-sdk"),
		})

		// HTTP /v1/sdk — the SDK-facing enveloped secret + threshold-sign
		// plane. Every request carries an ML-DSA-65-signed envelope;
		// authorization is consensus-native (validators read, operators
		// write). Registered before the SPA catch-all so it wins the
		// route match. Active whenever the REK is loaded, independent of
		// the ZAP wire port.
		mux.Handle("/v1/sdk/", srv.HTTPHandler())
		log.Printf("kms: /v1/sdk enveloped secrets surface mounted (sign=%v)", signBackend != nil)

		// ZAP wire transport (in-cluster binary) — the SAME Server, the
		// SAME core. Enabled unless ZAP_PORT=0.
		if zapPort > 0 {
			n := zap.NewNode(zap.NodeConfig{
				NodeID:      nodeID + "-secrets",
				ServiceType: "_kms._tcp",
				Port:        zapPort,
			})
			if err := n.Start(); err != nil {
				log.Printf("kms: ZAP secrets-server failed to start on :%d: %v", zapPort, err)
			} else {
				srv.Register(n)
				log.Printf("kms: ZAP secrets-server listening on :%d (service=_kms._tcp)", zapPort)
			}
		} else {
			log.Printf("kms: ZAP wire transport disabled (ZAP_PORT=0); /v1/sdk HTTP surface still active")
		}
	} else {
		log.Printf("kms: secrets plane disabled (set MPC_REK_ENDPOINT + MPC_REK_SEALED_B64 to enable /v1/sdk + ZAP)")
	}

	// IAM OIDC SSO — /v1/sso/oidc/{login,callback}, /v1/sso/whoami, /v1/sso/logout.
	// Registered before the SPA catch-all; if OIDC isn't configured the
	// handlers return 503 so misconfiguration is observable.
	registerOIDCRoutes(mux)

	// Mount the embedded admin UI under the root catch-all. Registered last
	// so explicit handlers (`/healthz`, `/health`, `/v1/*`) win the route
	// match. SPA fallback: any GET that doesn't match a real file falls
	// back to index.html so React Router can resolve the path client-side.

	// Start HTTP server.
	// Every route is registered by now; "/" catches the rest as JSON, and
	// jsonOnly guarantees nothing on this listener ever answers in HTML.
	mux.HandleFunc("/", notFoundJSON)
	srv := &http.Server{
		Addr:         listen,
		Handler:      jsonOnly(mux),
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

// registerSecretRoutes installs the org-scoped secret CRUD surface — the ONLY
// HTTP way to read or write secrets:
//
//	GET    /v1/kms/orgs/{org}/secrets/{path...}/{name}   read a secret value
//	POST   /v1/kms/orgs/{org}/secrets                    create/upsert (env required)
//	DELETE /v1/kms/orgs/{org}/secrets/{path...}/{name}   delete a secret
//
// Every route is wrapped in auth.requireOrgJWT: an IAM-signed bearer whose
// owner/name/tag resolves to {org} (or carries the kms-admin role) is
// mandatory, verified against IAM's JWKS. The values live in ZapDB (encrypted
// at rest) and are also reachable over the ZAP wire.
//
// There is intentionally no `GET /v1/kms/secrets/{name}` env-var route. Such a
// route once read os.Getenv of an attacker-supplied name and returned it
// UNWRAPPED — no auth middleware — leaking the KMS process environment
// (KMS_MASTER_KEY_B64 root REK, MPC_TOKEN, S3 backup keys) to anyone who
// reached :8080 past the network boundary (NetworkPolicy gap, port-forward,
// pod compromise, SSRF). It was deleted, not gated: it had zero callers (the
// kms-operator and in-cluster clients read via the org-scoped path or ZAP) and
// process env is never a secret-fetch source. Regression that keeps it gone:
// TestSecretRoutes_NoEnvVarLeak.
func registerSecretRoutes(mux *http.ServeMux, auth *orgJWTAuth, secStore *store.SecretStore, masterKey []byte) {
	listHandler := func(w http.ResponseWriter, r *http.Request) {
		q, err := parseListQuery(r.URL.Query())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
			return
		}
		refs, truncated, err := secStore.Find(q)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "list failed"})
			return
		}
		names := make([]string, 0, len(refs))
		for _, ref := range refs {
			names = append(names, ref.Name)
		}
		// `secrets` carries each record's FULL coordinate, `query` echoes the
		// filter that produced them: an empty result is then self-explaining —
		// the caller can see which path and env were actually searched instead
		// of reading "[]" as "this store is empty". `names` is the shape the
		// existing HTTP clients read and stays. `truncated` warns when the answer
		// was capped, so a caller narrows rather than trusting a partial list.
		writeJSON(w, http.StatusOK, map[string]any{
			"names":     names,
			"secrets":   refs,
			"total":     len(refs),
			"truncated": truncated,
			"query":     map[string]string{"path": q.Path, "env": q.Env},
		})
	}
	getHandler := func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		// A secret at the store root has an empty path, so `rest` is just the
		// name with no separator. List() and POST both accept path="" and the
		// store keys on (path, name) — so rejecting a slash-less rest made every
		// root-level secret unreachable while List cheerfully reported it. Split
		// on the last "/" when there is one; otherwise the whole rest is the name.
		path, name := "", rest
		if idx := strings.LastIndex(rest, "/"); idx >= 0 {
			path, name = rest[:idx], rest[idx+1:]
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "name required"})
			return
		}
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		sec, err := secStore.Get(path, name, env)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		// A sealed record carries a wrapped DEK; one written before this door
		// sealed anything does not. That difference is what tells them apart, so
		// a record from either era reads correctly here.
		//
		// A bare record is re-sealed as it is read. Nothing has to be migrated on
		// a schedule and no flag day is needed: the bare ones convert as they are
		// used, and the population only shrinks. A read that cannot re-seal still
		// answers — the value is already readable, and refusing would take a
		// working secret away to punish a write that already happened.
		value := sec.Ciphertext
		if len(sec.WrappedDEK) > 0 {
			pt, oerr := store.Open(masterKey, sec)
			if oerr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "cannot open secret"})
				return
			}
			defer mpcrek.Zero(pt)
			value = pt
		} else if len(masterKey) == 32 {
			if resealed, serr := store.Seal(masterKey, sec.Path, sec.Name, sec.Env, value); serr == nil {
				if perr := secStore.Put(resealed); perr != nil {
					log.Printf("kms: could not re-seal %s/%s: %v", sec.Path, sec.Name, perr)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"value": string(value)},
		})
	}
	deleteHandler := func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		// A secret at the store root has an empty path, so `rest` is just the
		// name with no separator. List() and POST both accept path="" and the
		// store keys on (path, name) — so rejecting a slash-less rest made every
		// root-level secret unreachable while List cheerfully reported it. Split
		// on the last "/" when there is one; otherwise the whole rest is the name.
		path, name := "", rest
		if idx := strings.LastIndex(rest, "/"); idx >= 0 {
			path, name = rest[:idx], rest[idx+1:]
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "name required"})
			return
		}
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		if err := secStore.Delete(path, name, env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}

	// GET /v1/kms/orgs/{org}/secrets[?path=&env=]  — enumerate the store.
	//
	// The ZAP wire has carried this since it was written (OpSecretList 0x0042,
	// {path, env} -> {names}); HTTP had get/put/delete and no list, so the two
	// framings of the same store disagreed about what you could ask it. A client
	// that wanted to enumerate had to either open a ZAP connection or give up —
	// the hanzo browser extension gave up. Same handler shape, same envelope as
	// ZAP returns.
	//
	// SEMANTICS (both framings, one store.Find): path is a SUBTREE root and is
	// recursive — listing "deploy" returns "deploy/ci" too — and defaults to the
	// whole store; env FILTERS and defaults to every environment. Both filters
	// therefore only ever narrow what you asked for, and a name is always
	// reported with the path and env it actually lives at.
	//
	// This surface enumerates the DEPLOYMENT's store, not one org's: the secret
	// keyspace carries no org, so {org} here is caller-chosen and scopes nothing
	// — a caller can only ever name an org its own token already authorizes.
	// What binds a request to this store is KMS_HOME_ORG (authorizesHome, run by
	// both doors). The org-KEYED plane is cloud's (apps/kms), which shards a
	// file per tenant.
	//
	// Distinct from the {rest...} pattern below: this one has no trailing
	// segment, so ServeMux routes the bare collection here and any path under it
	// there. Pinned by TestSecretRoutes_ListAndGetDoNotShadow.
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets", auth.requireOrgJWT(listHandler))

	// GET /v1/kms/orgs/{org}/secrets/{path...}/{name}
	// Matches the Go kmsclient.Get() URL pattern.
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(getHandler))

	// POST /v1/kms/orgs/{org}/secrets — create a secret. The handler is a
	// named func (putSecretHandler) so the env-required contract is unit
	// testable without standing up the full server.
	mux.HandleFunc("POST /v1/kms/orgs/{org}/secrets", auth.requireOrgJWT(putSecretHandler(secStore, masterKey)))

	// DELETE /v1/kms/orgs/{org}/secrets/{rest...}/{name}
	mux.HandleFunc("DELETE /v1/kms/orgs/{org}/secrets/{rest...}", auth.requireOrgJWT(deleteHandler))

	// ── the org-less surface ────────────────────────────────────────────────
	// /v1/kms/secrets*: the SAME four handlers, addressed without an org in the
	// URL — the shape cloud's embedded KMS and every swept client (gateway,
	// console, kms-operator) speak. There is no URL org to reconcile here, so
	// requireJWT gates on the same thing requireOrgJWT ultimately does: whether
	// the caller's own org authorizes this deployment's home org. Two doors, one
	// boundary. The org-addressed registrations above are the COMPAT surface for
	// unswept callers (the Go kmsclient, the browser extension) and are removed
	// the release after those sweep; new callers use these.
	mux.HandleFunc("GET /v1/kms/secrets", auth.requireJWT(listHandler))
	mux.HandleFunc("GET /v1/kms/secrets/{rest...}", auth.requireJWT(getHandler))
	mux.HandleFunc("POST /v1/kms/secrets", auth.requireJWT(putSecretHandler(secStore, masterKey)))
	mux.HandleFunc("DELETE /v1/kms/secrets/{rest...}", auth.requireJWT(deleteHandler))
}

// listParams maps every accepted list query parameter to the field it sets.
//
// The store has ONE name for a subtree root — `path` — and every other route on
// this surface already spells it that way (POST takes {path,name,env,value};
// GET addresses /secrets/{path}/{name}). `prefix` is that same value under the
// spelling two shipped first-party SDKs emit against THIS route: the Go
// kmsclient's httpList and the generated hanzoai Python client both send
// `?prefix=`. Translating one legacy spelling at the boundary is what turns
// their silently-empty answer into the right one, and the response echoes the
// canonical name back so there is still only one name for the value.
//
// Nothing else is accepted. `secretPath`/`environment` belong to the Infisical
// /api/v3 shape, which this server does not serve — a client sending those is
// addressing a different API and is better told so than answered.
var listParams = map[string]string{
	"path":   "path",
	"prefix": "path",
	"env":    "env",
}

// parseListQuery turns a list request's query string into a secret.Query, and
// REFUSES anything it does not understand.
//
// A silently-ignored filter is the worst failure this surface has: an unknown
// parameter used to fall through to "no filter at all", answer 200 with an empty
// list, and read to the caller as "the store holds nothing" — which is how an
// invalid deploy token sat unnoticed while every build pinned nothing. A
// misspelled question must fail loudly, not be answered as if it were a
// different question, so the refusal names the offending key AND the accepted
// vocabulary: one round trip is enough to correct it.
//
// An omitted parameter is not a silent narrowing either: no path means the
// whole store and no env means every environment (see secret.Query).
func parseListQuery(v url.Values) (secret.Query, error) {
	var q secret.Query
	set := map[string]string{}
	for key, vals := range v {
		field, ok := listParams[key]
		if !ok {
			return q, fmt.Errorf("unknown query parameter %q: this endpoint takes path (also spelled prefix) and env; omit path to list every path, omit env to list every environment", key)
		}
		val := ""
		if len(vals) > 0 {
			val = strings.TrimSpace(vals[0])
		}
		if val == "" {
			continue
		}
		if prev, dup := set[field]; dup && prev != val {
			return q, fmt.Errorf("conflicting values for %s", field)
		}
		set[field] = val
	}
	q.Path, q.Env = set["path"], set["env"]
	// env is one key segment; a '/' in it can never match a stored record, so
	// say so instead of returning an empty list that looks like an empty store.
	if q.Env != "" && !store.ValidCoord(q.Env, "x") {
		return secret.Query{}, fmt.Errorf("env must be a single segment (no '/', no control characters)")
	}
	return q, nil
}

// putSecretHandler serves POST /v1/kms/orgs/{org}/secrets (create/upsert).
//
// env is a first-class component of the storage key
// (kms/secrets/{path}/{env}/{name}); it can never be aliased. A silent
// "default" would commit the write to a bucket that project/env/path readers
// (the kms-operator, cluster syncs) never resolve — the exact split that let
// an IAM z-password land in env=default while prod kept serving the stale
// value. So a write with no env fails loud (400). Reads (GET) keep a
// backward-compatible default: a read cannot plant a value another reader
// later trusts, and legacy readers that omit env must keep working.
func putSecretHandler(secStore *store.SecretStore, masterKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if strings.TrimSpace(req.Env) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"message": `env is required — set "env" in the request body; there is no default. A silent default would split this write from the project/env/path record readers resolve.`,
			})
			return
		}
		// Sealed with the same call the ZAP door makes, under the MPC-rooted REK:
		// a fresh per-secret DEK, the value under it with path/name/env as AAD, and
		// the DEK wrapped under the REK. The field is named Ciphertext and now
		// holds ciphertext. Without a key there is nothing to seal WITH, and
		// writing the value bare is the thing being fixed, so this refuses.
		if len(masterKey) != 32 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"message": "no root key: this store cannot seal a secret, so it will not take one",
			})
			return
		}
		plaintext := []byte(req.Value)
		sec, err := store.Seal(masterKey, req.Path, req.Name, req.Env, plaintext)
		mpcrek.Zero(plaintext)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
			return
		}
		if err := secStore.Put(sec); err != nil {
			// A coordinate the key cannot encode unambiguously is the caller's
			// error, not the store's: report 400 so it is fixed at the source
			// rather than retried forever against a 500.
			code := http.StatusInternalServerError
			if errors.Is(err, store.ErrInvalidCoord) {
				code = http.StatusBadRequest
			}
			writeJSON(w, code, map[string]any{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	}
}

// registerStubKMSRoutes installs 503-only handlers for every /v1/kms/keys/*
// route. Used when the boot-time MPC client could not be constructed at
// all (e.g. dial timed out, ZAP node init failed). Without this, GET
// /v1/kms/keys/{id} fell through to the SPA catch-all and returned the
// admin UI HTML; POST returned 405 from the muxer's "no method match"
// path. Both are useless to callers — they need a single, parseable
// signal that MPC is down so retry / circuit-break logic kicks in.
//
// The body shape matches registerKMSRoutes' requireMPC 503 exactly so
// callers don't need to branch on "stub vs gated" — they see one
// `{"error":"mpc unreachable","mode":"secrets-only","detail":"..."}`
// response across both code paths.
func registerStubKMSRoutes(mux *http.ServeMux, bootErr error) {
	stub := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":  "mpc unreachable",
			"detail": bootErr.Error(),
			"mode":   "secrets-only",
		})
	}
	mux.HandleFunc("POST /v1/kms/keys/generate", stub)
	mux.HandleFunc("GET /v1/kms/keys", stub)
	mux.HandleFunc("GET /v1/kms/keys/{id}", stub)
	mux.HandleFunc("POST /v1/kms/keys/{id}/sign", stub)
	mux.HandleFunc("POST /v1/kms/keys/{id}/rotate", stub)
	mux.HandleFunc("GET /v1/kms/status", stub)
}

// healthHandler returns the /healthz handler.
//
// Health is intentionally HTTP 200 even when MPC is unreachable: the
// secrets surface (ZAP secrets-server, /v1/kms/orgs/.../secrets, IAM
// SSO, /v1/kms/auth/login) is fully functional in secrets-only mode.
// Routes that require MPC (/v1/kms/keys/*) self-report 503 instead.
// K8s readiness gating off /healthz would otherwise pull a working
// secrets-only KMS out of rotation purely because MPC is in upgrade.
//
// When MPC is enabled in spec but unreachable, the body switches to
// `{"status":"degraded","mpc":"unreachable","detail":"..."}` so probes
// that scrape the body still observe the degraded mode without
// flapping the pod out of service.
func healthHandler(vaultID string, mpcAvailable *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := map[string]string{"status": "ok", "service": "kms"}
		if vaultID != "" && (mpcAvailable == nil || !*mpcAvailable) {
			body["status"] = "degraded"
			body["mpc"] = "unreachable"
			body["detail"] = "secrets-only mode; signing routes return 503"
		}
		writeJSON(w, http.StatusOK, body)
	}
}

func registerKMSRoutes(mux *http.ServeMux, auth *orgJWTAuth, mgr *keys.Manager, mpcBackend keys.MPCBackend, mpcAvailable *bool) {
	// KMS validator-key routes (keygen / sign / rotate / metadata reads)
	// are gated by app-layer IAM JWT auth (auth.requireKeyAuth: kms-admin
	// role, fail closed). This is defense in depth BEHIND the Gateway and
	// NetworkPolicy — never a substitute for them. A caller that reaches
	// :8080 directly (NetworkPolicy gap, port-forward, pod compromise,
	// SSRF) still cannot keygen/sign/rotate without a valid IAM signature,
	// because the signature is verified here and no injected header is
	// trusted. The /v1/kms/status health probe stays open (no key
	// material; consumed by circuit-breakers that hold no token).
	//
	// requireMPC short-circuits with 503 + a re-probe attempt when the
	// boot-time MPC handshake failed. The re-probe lets KMS recover
	// transparently if MPC came up after KMS did (common during rollout
	// or NetworkPolicy reconcile races); a single 5s status call is
	// cheap relative to keygen/sign latency.
	requireMPC := func(w http.ResponseWriter, r *http.Request) bool {
		if mpcAvailable != nil && *mpcAvailable {
			return true
		}
		probeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := mpcBackend.Status(probeCtx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":  "mpc unreachable",
				"detail": err.Error(),
				"mode":   "secrets-only",
			})
			return false
		}
		if mpcAvailable != nil {
			*mpcAvailable = true
		}
		return true
	}

	mux.HandleFunc("POST /v1/kms/keys/generate", auth.requireKeyAuth(func(w http.ResponseWriter, r *http.Request) {
		if !requireMPC(w, r) {
			return
		}
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
		log.Printf("kms: audit: keygen OK validator_id=%s bls_wallet=%s corona_wallet=%s threshold=%d parties=%d",
			ks.ValidatorID, ks.BLSWalletID, ks.CoronaWalletID, ks.Threshold, ks.Parties)
		writeJSON(w, http.StatusCreated, ks)
	}))

	mux.HandleFunc("GET /v1/kms/keys", auth.requireKeyAuth(func(w http.ResponseWriter, r *http.Request) {
		list := mgr.List()
		if list == nil {
			list = []*keys.ValidatorKeySet{}
		}
		writeJSON(w, http.StatusOK, list)
	}))

	mux.HandleFunc("GET /v1/kms/keys/{id}", auth.requireKeyAuth(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ks, err := mgr.Get(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "validator key set not found"})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	}))

	mux.HandleFunc("POST /v1/kms/keys/{id}/sign", auth.requireKeyAuth(func(w http.ResponseWriter, r *http.Request) {
		if !requireMPC(w, r) {
			return
		}
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
		case "corona":
			resp, err = mgr.SignWithCorona(r.Context(), id, req.Message)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_type must be 'bls' or 'corona'"})
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
	}))

	mux.HandleFunc("POST /v1/kms/keys/{id}/rotate", auth.requireKeyAuth(func(w http.ResponseWriter, r *http.Request) {
		if !requireMPC(w, r) {
			return
		}
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
	}))

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
// REPLICATE_S3_ENDPOINT is normalized to bare host:port — s3.New
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

	// Backup interval. Default 60s — every-second backups generated
	// continuous allocation pressure (~3 KiB streamed per cycle plus
	// the encrypter's working buffers, ~150 MiB sustained heap on
	// quiet KMS pods). 60s catches up to mainnet write rate (~10
	// secret rotations/day) with plenty of headroom; operators can
	// tune via REPLICATE_INTERVAL=<go-duration>.
	intv := time.Minute
	if v := os.Getenv("REPLICATE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			intv = d
		}
	}
	cfg := badger.ReplicatorConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("REPLICATE_S3_BUCKET", "lux-kms-backups"),
		Region:    envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: access,
		SecretKey: secret,
		UseSSL:    useSSL,
		Path:      envOr("REPLICATE_S3_PATH", envOr("REPLICATE_PATH", fmt.Sprintf("kms/%s", nodeID))),
		Interval:  intv,
	}

	// Age encryption for backups. The recipient has to be parsed and handed to
	// the replicator; reading the variable does nothing on its own. It used to
	// read it, log that encryption was on, and pass nothing — so the copy left
	// unencrypted while the log said otherwise.
	//
	// Asking for encryption and not getting it is the one outcome worth refusing:
	// replication that silently ships an unencrypted copy of the store is worse
	// than no replication, because the operator believes it is protected.
	if recipientStr := strings.TrimSpace(os.Getenv("REPLICATE_AGE_RECIPIENT")); recipientStr != "" {
		recipient, err := age.ParseX25519Recipient(recipientStr)
		if err != nil {
			log.Fatalf("kms: REPLICATE_AGE_RECIPIENT is set but unusable (%v) — refusing to replicate unencrypted", err)
		}
		cfg.AgeRecipient = recipient
		log.Printf("kms: S3 replication with age encryption enabled")
	} else {
		log.Printf("kms: WARNING: S3 replication has no age recipient — the copy carries whatever the store holds")
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

// loadREK returns the 32-byte Root Encryption Key used by the ZAP secrets
// server to seal every per-secret DEK.
//
// Preference order:
//  1. MPC_REK_ENDPOINT set → fetch via mpcrek.Bootstrap. FAIL-CLOSED on
//     any error: log.Fatalf rather than silently falling back to the
//     env-var path. This is the point of MPC-rooting the REK — if the
//     pod can shrug off MPC unavailability and still come up with a
//     key, we have re-introduced the static-secret weakness we set out
//     to remove.
//  2. KMS_MASTER_KEY_B64 set → REFUSE TO START. A root key in the
//     environment is readable by whatever can read Secrets, which is the
//     reader the ring exists to keep out.
//  3. Neither set → nil (ZAP secrets-server stays disabled).
//
// The returned slice is the live REK for the process lifetime. The
// caller MUST keep it alive until shutdown and arrange to zero it via
// mpcrek.Zero on the way out (see the defer in main).
func loadREK() []byte {
	if endpoint := envOr("MPC_REK_ENDPOINT", ""); endpoint != "" {
		keyID := envOr("MPC_REK_KEY_ID", "kms/rek/v1")
		timeoutStr := envOr("MPC_REK_TIMEOUT", "10s")
		timeout, perr := time.ParseDuration(timeoutStr)
		if perr != nil {
			log.Fatalf("kms: MPC_REK_TIMEOUT %q invalid: %v", timeoutStr, perr)
		}
		nodeID := envOr("KMS_NODE_ID", "kms-0") + "-rek-bootstrap"

		// The sealed REK. Ciphertext, so it travels as ordinary configuration —
		// a config map, a file, an environment variable are all fine, because
		// the only thing that opens it is a quorum of the ring.
		sealedB64 := envOr("MPC_REK_SEALED_B64", "")
		if sealedB64 == "" {
			log.Fatalf("kms: MPC_REK_ENDPOINT is set but MPC_REK_SEALED_B64 is not; the ring holds shares, not ciphertexts")
		}
		sealed, derr := base64.StdEncoding.DecodeString(sealedB64)
		if derr != nil {
			log.Fatalf("kms: MPC_REK_SEALED_B64 is not base64: %v", derr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		log.Printf("kms: bootstrapping REK from MPC endpoint=%q keyID=%q", endpoint, keyID)
		rek, err := mpcrek.Bootstrap(ctx, mpcrek.Config{
			Endpoint: endpoint,
			KeyID:    keyID,
			NodeID:   nodeID,
			Timeout:  timeout,
			Sealed:   sealed,
		})
		if err != nil {
			// Fail-closed. The deployment asked for MPC-rooted REK and
			// MPC said no — refuse to start with a static key, that's
			// the split-brain we are escaping.
			log.Fatalf("kms: MPC REK bootstrap failed: %v", err)
		}
		log.Printf("kms: REK bootstrapped from MPC (32 bytes)")
		return rek
	}

	// There is no env-var root key. A key in the process environment is a key in
	// a Secret, and anything that can read Secrets — a cloud API token, a shell in
	// the pod, a volume snapshot — then holds the one value that opens every
	// secret this store keeps. Sealing under a root that lives beside the
	// ciphertext protects nothing from the reader who has both.
	//
	// The ring is the whole point: it holds shares, no single holder can produce
	// the root, and the sealed form travels as ordinary configuration precisely
	// because ciphertext is safe to leave lying about.
	//
	// Refusing rather than ignoring: an operator who set this believes the store
	// is protected by it, and starting quietly without a root would leave them
	// believing that while nothing was sealed.
	if envOr("KMS_MASTER_KEY_B64", "") != "" {
		log.Fatalf("kms: KMS_MASTER_KEY_B64 is set — a root key in the environment is readable by anything that reads Secrets, so it is not accepted. Set MPC_REK_ENDPOINT and MPC_REK_SEALED_B64.")
	}
	return nil
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

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
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
// value so s3.New receives the bare host:port it expects. Returns
// (host[:port], useSSL) where useSSL is true unless the operator
// explicitly specified an http:// scheme. A non-empty path is logged as
// a warning so the misconfiguration is visible — the SDK rejects path-
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
