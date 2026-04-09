// Command kms starts the Lux KMS server on Hanzo Base.
//
// Configuration precedence: flags > env vars > defaults.
//
//	Env vars:
//	  MPC_ADDR        - ZAP address (host:port); empty = mDNS discovery
//	  MPC_VAULT_ID    - MPC vault ID for validator keys (required)
//	  KMS_NODE_ID     - ZAP node ID (default "kms-0")
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/hook"
	"github.com/hanzoai/base/tools/router"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
)

func main() {
	mpcAddr := envOr("MPC_ADDR", "")
	vaultID := envOr("MPC_VAULT_ID", "")
	nodeID := envOr("KMS_NODE_ID", "kms-0")
	iamEndpoint := envOr("IAM_ENDPOINT", "https://hanzo.id")
	frontendDir := envOr("KMS_FRONTEND_DIR", "./frontend")

	app := base.New()

	// MPC key management (optional — only when MPC_VAULT_ID is set).
	if vaultID != "" {
		zapClient, err := mpc.NewZapClient(nodeID, mpcAddr)
		if err != nil {
			log.Fatalf("kms: zap client: %v", err)
		}

		app.OnServe().BindFunc(func(e *core.ServeEvent) error {
			keyStore, err := store.New(app)
			if err != nil {
				return err
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
			registerKMSRoutes(e.Router, mgr, zapClient)
			return e.Next()
		})
	} else {
		log.Printf("kms: MPC_VAULT_ID not set — running in secrets-only mode (no threshold signing)")
	}

	// Platform routes: auth, secrets, health.
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// Health
		e.Router.GET("/healthz", func(re *core.RequestEvent) error {
			return re.JSON(http.StatusOK, map[string]string{"status": "ok", "service": "kms"})
		})

		// Machine identity auth — /v2/kms/auth/login
		e.Router.POST("/v2/kms/auth/login", func(re *core.RequestEvent) error {
			var req struct {
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
			}
			if err := json.NewDecoder(re.Request.Body).Decode(&req); err != nil || req.ClientID == "" || req.ClientSecret == "" {
				return re.JSON(http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "clientId and clientSecret required"})
			}
			form := url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {req.ClientID},
				"client_secret": {req.ClientSecret},
			}
			resp, err := http.PostForm(iamEndpoint+"/api/login/oauth/access_token", form)
			if err != nil {
				return re.JSON(http.StatusBadGateway, map[string]any{"statusCode": 502, "message": "identity provider unreachable"})
			}
			defer resp.Body.Close()
			var tok map[string]any
			json.NewDecoder(resp.Body).Decode(&tok)
			at, _ := tok["access_token"].(string)
			if at == "" {
				return re.JSON(http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "invalid credentials"})
			}
			return re.JSON(http.StatusOK, map[string]any{"accessToken": at, "expiresIn": 86400, "tokenType": "Bearer"})
		})

		// Raw secret fetch — /v4/kms/secrets/{name}
		e.Router.GET("/v4/kms/secrets/{name}", func(re *core.RequestEvent) error {
			name := re.Request.PathValue("name")
			if name == "" {
				return re.JSON(http.StatusBadRequest, map[string]any{"message": "secret name required"})
			}
			val := os.Getenv(name)
			if val == "" {
				return re.JSON(http.StatusNotFound, map[string]any{"message": "not found"})
			}
			return re.JSON(http.StatusOK, map[string]any{
				"secret": map[string]any{"secretKey": name, "secretValue": val},
			})
		})

		return e.Next()
	})

	// Frontend — serve KMS UI at / (no /_/ admin panel).
	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Func: func(e *core.ServeEvent) error {
			if _, err := os.Stat(frontendDir); err == nil {
				e.Router.GET("/assets/{path...}", apis.Static(os.DirFS(frontendDir), false))
				e.Router.GET("/images/{path...}", apis.Static(os.DirFS(frontendDir), false))
				e.Router.GET("/favicon.ico", apis.Static(os.DirFS(frontendDir), false))
				e.Router.GET("/runtime-ui-env.js", apis.Static(os.DirFS(frontendDir), false))
				// SPA fallback for frontend routes
				e.Router.GET("/login", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/login/{path...}", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/signup/{path...}", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/dashboard/{path...}", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/settings/{path...}", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/org/{path...}", apis.Static(os.DirFS(frontendDir), true))
				e.Router.GET("/secret-manager/{path...}", apis.Static(os.DirFS(frontendDir), true))
				log.Printf("kms: serving frontend from %s", frontendDir)
			}
			// Root → login
			if os.Getenv("BASE_SKIP_ROOT_REDIRECT") != "" && !e.Router.HasRoute(http.MethodGet, "/") {
				e.Router.GET("/", func(re *core.RequestEvent) error {
					return re.Redirect(http.StatusTemporaryRedirect, "/login")
				})
			}
			return e.Next()
		},
		Priority: 999,
	})

	if err := app.Start(); err != nil {
		log.Fatalf("kms: %v", err)
	}
}

func registerKMSRoutes(r *router.Router[*core.RequestEvent], mgr *keys.Manager, mpcBackend keys.MPCBackend) {
	api := r.Group("/v1/kms")

	// All KMS routes require superuser authentication.
	api.BindFunc(func(e *core.RequestEvent) error {
		if !e.HasSuperuserAuth() {
			return e.UnauthorizedError("superuser auth required", nil)
		}
		return e.Next()
	})

	api.POST("/keys/generate", func(e *core.RequestEvent) error {
		var req keys.GenerateRequest
		if err := e.BindBody(&req); err != nil {
			return e.BadRequestError("invalid request body", nil)
		}
		if req.ValidatorID == "" {
			return e.BadRequestError("validator_id is required", nil)
		}
		if req.Threshold < 2 {
			return e.BadRequestError("threshold must be >= 2", nil)
		}
		if req.Parties < req.Threshold {
			return e.BadRequestError("parties must be >= threshold", nil)
		}
		if req.Threshold == req.Parties {
			log.Printf("kms: WARNING: keygen threshold==parties (%d) for validator=%s — no fault tolerance, any single node failure blocks signing",
				req.Threshold, req.ValidatorID)
		}

		ks, err := mgr.GenerateValidatorKeys(e.Request.Context(), req)
		if err != nil {
			log.Printf("kms: audit: keygen FAILED validator_id=%s error=%v", req.ValidatorID, err)
			if strings.Contains(err.Error(), "already exists") {
				return e.JSON(409, map[string]string{"error": err.Error()})
			}
			return e.InternalServerError("", err)
		}
		log.Printf("kms: audit: keygen OK validator_id=%s bls_wallet=%s ringtail_wallet=%s threshold=%d parties=%d",
			ks.ValidatorID, ks.BLSWalletID, ks.RingtailWalletID, ks.Threshold, ks.Parties)
		return e.JSON(201, ks)
	})

	api.GET("/keys", func(e *core.RequestEvent) error {
		list := mgr.List()
		if list == nil {
			list = []*keys.ValidatorKeySet{}
		}
		return e.JSON(200, list)
	})

	api.GET("/keys/{id}", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		ks, err := mgr.Get(id)
		if err != nil {
			return e.NotFoundError("validator key set not found", nil)
		}
		return e.JSON(200, ks)
	})

	api.POST("/keys/{id}/sign", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		var req keys.SignRequest
		if err := e.BindBody(&req); err != nil {
			return e.BadRequestError("invalid request body", nil)
		}
		if len(req.Message) == 0 {
			return e.BadRequestError("message is required", nil)
		}

		var resp *keys.SignResponse
		var err error
		switch req.KeyType {
		case "bls":
			resp, err = mgr.SignWithBLS(e.Request.Context(), id, req.Message)
		case "ringtail":
			resp, err = mgr.SignWithRingtail(e.Request.Context(), id, req.Message)
		default:
			return e.BadRequestError("key_type must be 'bls' or 'ringtail'", nil)
		}
		if err != nil {
			log.Printf("kms: audit: sign FAILED validator_id=%s key_type=%s error=%v", id, req.KeyType, err)
			if strings.Contains(err.Error(), "not found") {
				return e.NotFoundError(err.Error(), nil)
			}
			return e.InternalServerError("", err)
		}
		log.Printf("kms: audit: sign OK validator_id=%s key_type=%s", id, req.KeyType)
		return e.JSON(200, resp)
	})

	api.POST("/keys/{id}/rotate", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		var req keys.RotateRequest
		if err := e.BindBody(&req); err != nil {
			return e.BadRequestError("invalid request body", nil)
		}
		if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
			return e.BadRequestError("new_threshold or new_participants required", nil)
		}

		ks, err := mgr.Rotate(e.Request.Context(), id, req)
		if err != nil {
			log.Printf("kms: audit: rotate FAILED validator_id=%s error=%v", id, err)
			if strings.Contains(err.Error(), "not found") {
				return e.NotFoundError(err.Error(), nil)
			}
			return e.InternalServerError("", err)
		}
		log.Printf("kms: audit: rotate OK validator_id=%s new_threshold=%d new_parties=%d",
			id, ks.Threshold, ks.Parties)
		return e.JSON(200, ks)
	})

	api.GET("/status", func(e *core.RequestEvent) error {
		status, err := mpcBackend.Status(e.Request.Context())
		if err != nil {
			return e.JSON(200, map[string]string{
				"kms":     "ok",
				"mpc":     "unreachable",
				"details": err.Error(),
			})
		}
		return e.JSON(200, map[string]interface{}{
			"kms": "ok",
			"mpc": status,
		})
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
