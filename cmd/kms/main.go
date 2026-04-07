// Command kms starts the Lux KMS server on Hanzo Base.
//
// Configuration precedence: flags > env vars > defaults.
//
//	Env vars:
//	  MPC_URL         - MPC daemon base URL
//	  MPC_TOKEN       - MPC API auth token
//	  MPC_VAULT_ID    - MPC vault ID for validator keys
//	  KMS_STORE_PATH  - Path to key metadata store
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
)

func main() {
	mpcURL := envOr("MPC_URL", "http://mpc-api.lux-mpc.svc.cluster.local:8081")
	mpcToken := envOr("MPC_TOKEN", "")
	vaultID := envOr("MPC_VAULT_ID", "")

	if vaultID == "" {
		log.Fatal("kms: MPC_VAULT_ID is required")
	}

	mpcClient := mpc.NewClient(mpcURL, mpcToken)

	app := base.New()

	// Store uses Base's built-in DB (SQLite local, Postgres prod).
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		keyStore, err := store.New(app)
		if err != nil {
			return err
		}

		// Verify MPC reachability.
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if status, err := mpcClient.Status(checkCtx); err != nil {
			log.Printf("kms: WARNING: mpc unreachable: %v", err)
		} else {
			log.Printf("kms: mpc ready=%v peers=%d/%d mode=%s",
				status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
		}
		checkCancel()

		mgr := keys.NewManager(mpcClient, keyStore, vaultID)
		registerKMSRoutes(e.Router, mgr, mpcClient)
		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatalf("kms: %v", err)
	}
}

func registerKMSRoutes(r *router.Router[*core.RequestEvent], mgr *keys.Manager, mpcClient *mpc.Client) {
	api := r.Group("/v1")

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

		ks, err := mgr.GenerateValidatorKeys(e.Request.Context(), req)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				return e.JSON(409, map[string]string{"error": err.Error()})
			}
			return e.InternalServerError("", err)
		}
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
			if strings.Contains(err.Error(), "not found") {
				return e.NotFoundError(err.Error(), nil)
			}
			return e.InternalServerError("", err)
		}
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
			if strings.Contains(err.Error(), "not found") {
				return e.NotFoundError(err.Error(), nil)
			}
			return e.InternalServerError("", err)
		}
		return e.JSON(200, ks)
	})

	api.GET("/status", func(e *core.RequestEvent) error {
		status, err := mpcClient.Status(e.Request.Context())
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

// writeJSON is kept for test compatibility.
func writeJSON(w interface{ Write([]byte) (int, error) }, _ int, v interface{}) {
	json.NewEncoder(w).Encode(v)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
