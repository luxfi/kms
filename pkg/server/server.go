// Package server provides the HTTP API for the Lux KMS.
package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
)

// Server is the Lux KMS HTTP server.
type Server struct {
	manager *keys.Manager
	mpc     *mpc.Client
	router  chi.Router
	server  *http.Server
}

// New creates a new KMS server.
func New(manager *keys.Manager, mpcClient *mpc.Client, listenAddr string) *Server {
	s := &Server{
		manager: manager,
		mpc:     mpcClient,
	}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(120 * time.Second))

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/keys/generate", s.handleGenerate)
		r.Get("/keys", s.handleList)
		r.Get("/keys/{id}", s.handleGet)
		r.Post("/keys/{id}/sign", s.handleSign)
		r.Post("/keys/{id}/rotate", s.handleRotate)
	})

	r.Get("/api/v1/status", s.handleStatus)
	r.Get("/healthz", s.handleHealthz)

	s.router = r
	s.server = &http.Server{
		Addr:         listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening. Returns the http.Server and an error channel.
func (s *Server) Start() (*http.Server, <-chan error) {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("kms: listening on %s", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	return s.server, errCh
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Router returns the chi.Router for testing.
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req keys.GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ValidatorID == "" {
		writeError(w, http.StatusBadRequest, "validator_id is required")
		return
	}
	if req.Threshold < 2 {
		writeError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}
	if req.Parties < req.Threshold {
		writeError(w, http.StatusBadRequest, "parties must be >= threshold")
		return
	}

	ks, err := s.manager.GenerateValidatorKeys(r.Context(), req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, ks)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	list := s.manager.List()
	if list == nil {
		list = []*keys.ValidatorKeySet{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ks, err := s.manager.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req keys.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Message) == 0 {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	var (
		resp *keys.SignResponse
		err  error
	)

	switch req.KeyType {
	case "bls":
		resp, err = s.manager.SignWithBLS(r.Context(), id, req.Message)
	case "ringtail":
		resp, err = s.manager.SignWithRingtail(r.Context(), id, req.Message)
	default:
		writeError(w, http.StatusBadRequest, "key_type must be 'bls' or 'ringtail'")
		return
	}

	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req keys.RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
		writeError(w, http.StatusBadRequest, "new_threshold or new_participants required")
		return
	}

	ks, err := s.manager.Rotate(r.Context(), id, req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ks)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.mpc.Status(r.Context())
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
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

