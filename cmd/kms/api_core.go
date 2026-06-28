// Core web-UI API: the minimum surface for the SPA to render, sign up the
// first admin, log in, pick an org, and identify the current user. Backed by
// the ZapDB webStore + KMS-local session JWT (webAuth). No Postgres/Redis.
//
// Shapes mirror what frontend/src/hooks/api expects:
//   GET  /v1/status                     -> ServerStatus
//   GET  /v1/admin/config               -> {config: TServerConfig}  (initialized reflects user count)
//   POST /v1/admin/signup               -> {user, token, organization}   (first-run only)
//   POST /v1/auth/login                 -> {accessToken, mfaEnabled}      (LoginV3Res)
//   POST /v1/auth/select-organization   -> {token, isMfaEnabled}
//   POST /v1/auth/logout                -> {message}
//   GET  /v1/user, /v1/users/me         -> {user: User & UserEnc}
//   GET  /v1/organization               -> {organizations: [...]}
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

const webSessionTTL = 24 * time.Hour

// registerCoreAPI wires the core web-UI endpoints onto mux. defaultOrgSlug is
// the same value main.go computes for the OIDC button (kept consistent).
func registerCoreAPI(mux *http.ServeMux, db *badger.DB, defaultOrgSlug string) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// GET /v1/status — login page + banners.
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"date":                     time.Now().UTC().Format(time.RFC3339),
			"message":                  "ok",
			"emailConfigured":          false,
			"secretScanningConfigured": false,
			"redisConfigured":          false,
			"samlDefaultOrgSlug":       defaultOrgSlug,
			"auditLogStorageDisabled":  true,
		})
	})

	// GET /v1/admin/config — Suspense render-gate. initialized=false until the
	// first admin signs up, which makes the SPA show the admin-signup screen.
	mux.HandleFunc("GET /v1/admin/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"config": map[string]any{
				"initialized":               st.CountUsers() > 0,
				"allowSignUp":               true,
				"allowedSignUpDomain":       nil,
				"trustSamlEmails":           false,
				"trustLdapEmails":           false,
				"trustOidcEmails":           true,
				"defaultAuthOrgId":          "",
				"defaultAuthOrgSlug":        defaultOrgSlug,
				"defaultAuthOrgAuthMethod":  nil,
				"isSecretScanningDisabled":  false,
				"isMigrationModeOn":         false,
				"fipsEnabled":               false,
				"invalidatingCache":         false,
				"enabledLoginMethods":       []string{"email", "oidc"},
				"slackClientId":             "",
				"isSmtpConfigured":          false,
				"isSecretApprovalDisabled":  false,
				"identityRevocationEnabled": true,
			},
		})
	})

	// POST /v1/admin/signup — create the first super-admin + default org.
	mux.HandleFunc("POST /v1/admin/signup", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email, Password, FirstName, LastName string
			OrganizationName                     string `json:"organizationName"`
		}
		if !decode(w, r, &req) {
			return
		}
		if st.CountUsers() > 0 {
			writeJSON(w, http.StatusForbidden, msg("instance already initialized"))
			return
		}
		u, err := st.CreateUser(req.Email, req.Password, req.FirstName, req.LastName, true)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, msg(err.Error()))
			return
		}
		orgName := req.OrganizationName
		if orgName == "" {
			orgName = "default"
		}
		org, _ := st.CreateOrg(orgName)
		_ = st.AddMembership(u.ID, org.ID, "admin")
		token, _ := auth.mint(u.ID, org.ID, webSessionTTL)
		writeJSON(w, http.StatusOK, map[string]any{
			"user":         userJSON(u),
			"token":        token,
			"organization": orgJSON(org),
		})
	})

	// POST /v1/auth/login — loginV3 (single-step email+password).
	mux.HandleFunc("POST /v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Email, Password string }
		if !decode(w, r, &req) {
			return
		}
		u, err := st.UserByEmail(strings.ToLower(strings.TrimSpace(req.Email)))
		if err != nil || !verifyPassword(req.Password, u.PasswordHash) {
			writeJSON(w, http.StatusUnauthorized, msg("invalid credentials"))
			return
		}
		token, _ := auth.mint(u.ID, "", webSessionTTL) // pre-org token
		writeJSON(w, http.StatusOK, map[string]any{"accessToken": token, "mfaEnabled": false})
	})

	// POST /v1/auth/select-organization — mint an org-scoped token.
	mux.HandleFunc("POST /v1/auth/select-organization", func(w http.ResponseWriter, r *http.Request) {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		var req struct {
			OrganizationID string `json:"organizationId"`
		}
		_ = decode(w, r, &req)
		orgID := req.OrganizationID
		if orgID == "" {
			if orgs, _ := st.OrgsForUser(cl.UserID); len(orgs) > 0 {
				orgID = orgs[0].ID
			}
		}
		token, _ := auth.mint(cl.UserID, orgID, webSessionTTL)
		writeJSON(w, http.StatusOK, map[string]any{"token": token, "isMfaEnabled": false})
	})

	// POST /v1/auth/logout — stateless JWT; client drops the token.
	mux.HandleFunc("POST /v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, msg("Successfully logged out"))
	})

	// GET /v1/user and /v1/users/me — current principal.
	currentUser := func(w http.ResponseWriter, r *http.Request) {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		u, err := st.UserByID(cl.UserID)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u)})
	}
	mux.HandleFunc("GET /v1/user", currentUser)
	mux.HandleFunc("GET /v1/users/me", currentUser)

	// GET /v1/organization — orgs the current user belongs to.
	mux.HandleFunc("GET /v1/organization", func(w http.ResponseWriter, r *http.Request) {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return
		}
		orgs, _ := st.OrgsForUser(cl.UserID)
		out := make([]any, 0, len(orgs))
		for _, o := range orgs {
			out = append(out, orgJSON(o))
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": out})
	})
}

// fromRequest extracts + verifies the session JWT from the Authorization header.
func (a *webAuth) fromRequest(r *http.Request) *webClaims {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	cl, err := a.verify(strings.TrimPrefix(h, "Bearer "))
	if err != nil {
		return nil
	}
	return cl
}

// userJSON renders the SPA's User & UserEnc shape (no e2e crypto in v3 — enc
// fields are empty; secrets are server-sealed under the REK, served plaintext).
func userJSON(u *webUser) map[string]any {
	return map[string]any{
		"id":               u.ID,
		"email":            u.Email,
		"username":         u.Username,
		"firstName":        u.FirstName,
		"lastName":         u.LastName,
		"superAdmin":       u.SuperAdmin,
		"authProvider":     nil,
		"authMethods":      []string{"email"},
		"isMfaEnabled":     false,
		"mfaMethods":       []string{},
		"seenIps":          []string{},
		"createdAt":        u.CreatedAt,
		"updatedAt":        u.UpdatedAt,
		"publicKey":        "",
		"encryptionVersion": 2,
	}
}

func orgJSON(o *webOrg) map[string]any {
	return map[string]any{"id": o.ID, "name": o.Name, "slug": o.Slug, "createdAt": o.CreatedAt}
}

// decode reads a JSON body; writes 400 + returns false on failure.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("invalid request body"))
		return false
	}
	return true
}

func msg(m string) map[string]any { return map[string]any{"message": m} }

// webAuthSecret returns a stable HS256 signing key: KMS_WEB_AUTH_SECRET if set,
// else a random key generated once and persisted in ZapDB so sessions survive
// restarts without operator config.
func webAuthSecret(db *badger.DB) []byte {
	if s := envOr("KMS_WEB_AUTH_SECRET", ""); s != "" {
		return []byte(s)
	}
	const key = "kms/config/web-auth-secret"
	var secret []byte
	_ = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error { secret = append([]byte{}, v...); return nil })
	})
	if len(secret) >= 32 {
		return secret
	}
	secret = make([]byte, 32)
	_, _ = rand.Read(secret)
	_ = db.Update(func(txn *badger.Txn) error { return txn.Set([]byte(key), secret) })
	_ = hex.EncodeToString // keep import if unused elsewhere
	return secret
}
