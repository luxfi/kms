// Command kms starts the Lux KMS HTTP server.
//
// Configuration precedence: flags > env vars > defaults.
//
//	Env vars:
//	  KMS_LISTEN      - HTTP listen address (default ":8080")
//	  MPC_URL         - MPC daemon base URL
//	  MPC_TOKEN       - MPC API auth token
//	  MPC_VAULT_ID    - MPC vault ID for validator keys
//	  KMS_STORE_PATH  - Path to key metadata store
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/server"
	"github.com/luxfi/kms/pkg/store"
)

func main() {
	var (
		listenAddr = flag.String("listen", envOr("KMS_LISTEN", ":8080"), "HTTP listen address")
		mpcURL     = flag.String("mpc-url", envOr("MPC_URL", "http://mpc-api.lux-mpc.svc.cluster.local:8081"), "MPC daemon base URL")
		mpcToken   = flag.String("mpc-token", envOr("MPC_TOKEN", ""), "MPC API auth token")
		vaultID    = flag.String("vault-id", envOr("MPC_VAULT_ID", ""), "MPC vault ID for validator keys")
		storePath  = flag.String("store", envOr("KMS_STORE_PATH", "/data/kms/keys.json"), "Path to key metadata store")
	)
	flag.Parse()

	if *vaultID == "" {
		log.Fatal("kms: --vault-id or MPC_VAULT_ID is required")
	}

	// Ensure store directory exists.
	if dir := filepath.Dir(*storePath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("kms: create store dir %s: %v", dir, err)
		}
	}

	// Initialize store.
	keyStore, err := store.New(*storePath)
	if err != nil {
		log.Fatalf("kms: failed to open store: %v", err)
	}

	// Initialize MPC client.
	mpcClient := mpc.NewClient(*mpcURL, *mpcToken)

	// Startup health check: verify MPC reachability (warn, don't crash).
	log.Printf("kms: mpc backend: %s", *mpcURL)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if status, err := mpcClient.Status(checkCtx); err != nil {
		log.Printf("kms: WARNING: mpc unreachable at startup: %v", err)
		log.Printf("kms: the server will start but key operations will fail until mpc is available")
	} else {
		log.Printf("kms: mpc cluster ready=%v peers=%d/%d mode=%s",
			status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
	}
	checkCancel()

	// Initialize key manager.
	mgr := keys.NewManager(mpcClient, keyStore, *vaultID)

	// Initialize and start HTTP server.
	srv := server.New(mgr, mpcClient, *listenAddr)
	httpSrv, errCh := srv.Start()

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("kms: received %s, shutting down", sig)
	case err := <-errCh:
		log.Printf("kms: server error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("kms: shutdown error: %v", err)
	}
	log.Println("kms: stopped")
}

// envOr returns the value of the environment variable named key,
// or fallback if the variable is not set or empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
