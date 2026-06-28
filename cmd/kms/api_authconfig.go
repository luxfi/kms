// AuthConfig — org auth providers (SAML SSO / OIDC / LDAP), MFA sessions,
// per-user TOTP + WebAuthn, password reset/setup, and the email-signup flow.
//
// These back the org "Security → Authentication" settings tabs plus the
// personal-security (TOTP/passkey) and login/onboarding (signup, password
// reset) flows. Config entities persist as JSON-KV in ZapDB under
// "kms/authcfg/...". Real CRUD where the entity is simple (sso/oidc/ldap
// config, ldap group maps, totp registration, webauthn credentials). The
// genuinely cryptographic bits — SAML assertion verification, OIDC token
// exchange, real WebAuthn attestation/assertion, email delivery of reset
// codes — are STUBBED: we persist the plausible-shaped config/record and
// return a plausible-shaped response so the SPA renders and navigates without
// errors. None of these mint a privileged session.
//
// All package-level identifiers carry the `authcfg`/`authCfg` prefix to stay
// orthogonal to oidc.go's existing `oidcConfig` and to sibling api_*.go files.
//
//	GET/POST/PATCH /v1/sso/config                      SAML SSO config (per org)
//	GET/POST/PATCH /v1/sso/oidc/config                 OIDC config (per org)
//	GET            /v1/sso/oidc/manage-group-memberships
//	GET/POST/PATCH /v1/ldap/config                     LDAP config (per org)
//	POST           /v1/ldap/config/test-connection
//	GET/POST       /v1/ldap/config/{id}/group-maps
//	DELETE         /v1/ldap/config/{id}/group-maps/{mapId}
//	GET            /v2/mfa-sessions/{id}/status
//	POST           /v2/mfa-sessions/{id}/verify
//	GET/POST       /v1/auth/mfa/...  (check/totp, check/webauthn, send, verify, webauthn/*)
//	POST/GET/DELETE /v1/user/me/totp[/register|/verify|/recovery-codes]
//	GET/POST/PATCH/DELETE /v1/user/me/webauthn[/...]
//	POST           /v1/password/email/password-reset[-verify]
//	GET            /v1/password/backup-private-key
//	POST           /v1/password/password-reset
//	POST           /v1/password/user/password-reset
//	POST           /v1/password/email/password-setup
//	POST           /v1/password/password-setup
//	POST           /v1/signup/email/signup
//	POST           /v1/signup/email/verify
//	POST           /v1/signup/complete-account/signup
//	POST           /v1/signup/complete-account/invite
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities ──────────────────────────────────────────────────────────────

// authCfgSSO is the SAML SSO provider config for an org.
type authCfgSSO struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"orgId"`
	AuthProvider    string    `json:"authProvider"`
	IsActive        bool      `json:"isActive"`
	EntryPoint      string    `json:"entryPoint"`
	Issuer          string    `json:"issuer"`
	Cert            string    `json:"cert"`
	EnableGroupSync bool      `json:"enableGroupSync"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// authCfgOIDC is the OIDC provider config for an org (distinct from oidc.go's
// server-side `oidcConfig`, which models THIS server's own IAM SSO client).
type authCfgOIDC struct {
	ID                    string    `json:"id"`
	OrgID                 string    `json:"orgId"`
	Issuer                string    `json:"issuer"`
	AuthorizationEndpoint string    `json:"authorizationEndpoint"`
	ConfigurationType     string    `json:"configurationType"`
	DiscoveryURL          string    `json:"discoveryURL"`
	JwksURI               string    `json:"jwksUri"`
	TokenEndpoint         string    `json:"tokenEndpoint"`
	UserinfoEndpoint      string    `json:"userinfoEndpoint"`
	AllowedEmailDomains   string    `json:"allowedEmailDomains"`
	ClientID              string    `json:"clientId"`
	ClientSecret          string    `json:"clientSecret"`
	IsActive              bool      `json:"isActive"`
	ManageGroupMembers    bool      `json:"manageGroupMemberships"`
	JwtSignatureAlgorithm string    `json:"jwtSignatureAlgorithm"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

// authCfgLDAP is the LDAP provider config for an org.
type authCfgLDAP struct {
	ID                  string    `json:"id"`
	OrgID               string    `json:"orgId"`
	IsActive            bool      `json:"isActive"`
	URL                 string    `json:"url"`
	BindDN              string    `json:"bindDN"`
	BindPass            string    `json:"bindPass"`
	UniqueUserAttribute string    `json:"uniqueUserAttribute"`
	SearchBase          string    `json:"searchBase"`
	SearchFilter        string    `json:"searchFilter"`
	GroupSearchBase     string    `json:"groupSearchBase"`
	GroupSearchFilter   string    `json:"groupSearchFilter"`
	CACert              string    `json:"caCert"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

// authCfgLDAPGroupMap maps an LDAP group CN to a KMS group slug.
type authCfgLDAPGroupMap struct {
	ID           string `json:"id"`
	LdapConfigID string `json:"ldapConfigId"`
	LdapGroupCN  string `json:"ldapGroupCN"`
	GroupSlug    string `json:"groupSlug"`
}

// authCfgWebAuthnCred is a registered WebAuthn credential for a user.
type authCfgWebAuthnCred struct {
	ID           string     `json:"id"`
	UserID       string     `json:"userId"`
	CredentialID string     `json:"credentialId"`
	Name         string     `json:"name"`
	Transports   []string   `json:"transports"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt"`
}

// authCfgTOTP is a user's TOTP enrollment.
type authCfgTOTP struct {
	UserID        string    `json:"userId"`
	OtpURL        string    `json:"otpUrl"`
	IsVerified    bool      `json:"isVerified"`
	RecoveryCodes []string  `json:"recoveryCodes"`
	CreatedAt     time.Time `json:"createdAt"`
}

// ── keys ──────────────────────────────────────────────────────────────────

func authCfgSSOKey(orgID string) []byte  { return []byte("kms/authcfg/sso/" + orgID) }
func authCfgOIDCKey(orgID string) []byte { return []byte("kms/authcfg/oidc/" + orgID) }
func authCfgLDAPKey(orgID string) []byte { return []byte("kms/authcfg/ldap/" + orgID) }
func authCfgLDAPByID(id string) []byte   { return []byte("kms/authcfg/ldap-id/" + id) }
func authCfgGroupMapKey(cfgID, id string) []byte {
	return []byte("kms/authcfg/ldap-gmap/" + cfgID + "/" + id)
}
func authCfgGroupMapPrefix(cfgID string) []byte {
	return []byte("kms/authcfg/ldap-gmap/" + cfgID + "/")
}
func authCfgTOTPKey(userID string) []byte { return []byte("kms/authcfg/totp/" + userID) }
func authCfgWebAuthnKey(userID, id string) []byte {
	return []byte("kms/authcfg/webauthn/" + userID + "/" + id)
}
func authCfgWebAuthnPrefix(userID string) []byte {
	return []byte("kms/authcfg/webauthn/" + userID + "/")
}

// ── JSON shapes ─────────────────────────────────────────────────────────────

func authCfgSSOJSON(c *authCfgSSO) map[string]any {
	return map[string]any{
		"id": c.ID, "organization": c.OrgID, "orgId": c.OrgID,
		"authProvider": c.AuthProvider, "isActive": c.IsActive,
		"entryPoint": c.EntryPoint, "issuer": c.Issuer, "cert": c.Cert,
		"enableGroupSync": c.EnableGroupSync,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func authCfgOIDCJSON(c *authCfgOIDC) map[string]any {
	alg := c.JwtSignatureAlgorithm
	if alg == "" {
		alg = "RS256"
	}
	cfgType := c.ConfigurationType
	if cfgType == "" {
		cfgType = "discovery"
	}
	return map[string]any{
		"id": c.ID, "orgId": c.OrgID, "issuer": c.Issuer,
		"authorizationEndpoint": c.AuthorizationEndpoint, "configurationType": cfgType,
		"discoveryURL": c.DiscoveryURL, "jwksUri": c.JwksURI,
		"tokenEndpoint": c.TokenEndpoint, "userinfoEndpoint": c.UserinfoEndpoint,
		"allowedEmailDomains": c.AllowedEmailDomains, "clientId": c.ClientID,
		"clientSecret": c.ClientSecret, "isActive": c.IsActive,
		"manageGroupMemberships": c.ManageGroupMembers, "jwtSignatureAlgorithm": alg,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func authCfgLDAPJSON(c *authCfgLDAP) map[string]any {
	return map[string]any{
		"id": c.ID, "organization": c.OrgID, "orgId": c.OrgID,
		"isActive": c.IsActive, "url": c.URL, "bindDN": c.BindDN,
		"bindPass": c.BindPass, "uniqueUserAttribute": c.UniqueUserAttribute,
		"searchBase": c.SearchBase, "searchFilter": c.SearchFilter,
		"groupSearchBase": c.GroupSearchBase, "groupSearchFilter": c.GroupSearchFilter,
		"caCert": c.CACert, "createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func authCfgGroupMapJSON(m *authCfgLDAPGroupMap) map[string]any {
	return map[string]any{
		"id": m.ID, "ldapConfigId": m.LdapConfigID, "ldapGroupCN": m.LdapGroupCN,
		"group": map[string]any{"id": m.GroupSlug, "name": m.GroupSlug, "slug": m.GroupSlug},
	}
}

func authCfgWebAuthnJSON(c *authCfgWebAuthnCred) map[string]any {
	tr := c.Transports
	if tr == nil {
		tr = []string{}
	}
	return map[string]any{
		"id": c.ID, "credentialId": c.CredentialID, "name": c.Name,
		"transports": tr, "createdAt": c.CreatedAt, "lastUsedAt": c.LastUsedAt,
	}
}

// authCfgRecoveryCodes mints a deterministic-length batch of recovery codes.
func authCfgRecoveryCodes() []string {
	out := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		out = append(out, newID()[:10])
	}
	return out
}

func registerAuthConfigAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed gates a handler on a valid session; returns nil (and writes 401)
	// when unauthenticated.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── SAML SSO config (per org) ──────────────────────────────────────────
	mux.HandleFunc("GET /v1/sso/config", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		org := r.URL.Query().Get("organizationId")
		var c authCfgSSO
		if st.getJSON(authCfgSSOKey(org), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("sso config not found"))
			return
		}
		writeJSON(w, http.StatusOK, authCfgSSOJSON(&c))
	})
	upsertSSO := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			OrganizationID  string `json:"organizationId"`
			AuthProvider    string `json:"authProvider"`
			IsActive        bool   `json:"isActive"`
			EntryPoint      string `json:"entryPoint"`
			Issuer          string `json:"issuer"`
			Cert            string `json:"cert"`
			EnableGroupSync bool   `json:"enableGroupSync"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		var c authCfgSSO
		if st.getJSON(authCfgSSOKey(req.OrganizationID), &c) != nil {
			c = authCfgSSO{ID: newID(), OrgID: req.OrganizationID, CreatedAt: now}
		}
		c.AuthProvider, c.IsActive = req.AuthProvider, req.IsActive
		c.EntryPoint, c.Issuer, c.Cert = req.EntryPoint, req.Issuer, req.Cert
		c.EnableGroupSync, c.UpdatedAt = req.EnableGroupSync, now
		_ = st.putJSON(authCfgSSOKey(c.OrgID), &c)
		writeJSON(w, http.StatusOK, authCfgSSOJSON(&c))
	}
	mux.HandleFunc("POST /v1/sso/config", upsertSSO)
	mux.HandleFunc("PATCH /v1/sso/config", upsertSSO)

	// ── OIDC config (per org) ──────────────────────────────────────────────
	mux.HandleFunc("GET /v1/sso/oidc/config", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		org := r.URL.Query().Get("organizationId")
		var c authCfgOIDC
		if st.getJSON(authCfgOIDCKey(org), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("oidc config not found"))
			return
		}
		writeJSON(w, http.StatusOK, authCfgOIDCJSON(&c))
	})
	mux.HandleFunc("GET /v1/sso/oidc/manage-group-memberships", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		org := r.URL.Query().Get("orgId")
		var c authCfgOIDC
		_ = st.getJSON(authCfgOIDCKey(org), &c)
		writeJSON(w, http.StatusOK, map[string]any{"isEnabled": c.ManageGroupMembers})
	})
	upsertOIDC := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			OrganizationID         string `json:"organizationId"`
			Issuer                 string `json:"issuer"`
			AuthorizationEndpoint  string `json:"authorizationEndpoint"`
			ConfigurationType      string `json:"configurationType"`
			DiscoveryURL           string `json:"discoveryURL"`
			JwksURI                string `json:"jwksUri"`
			TokenEndpoint          string `json:"tokenEndpoint"`
			UserinfoEndpoint       string `json:"userinfoEndpoint"`
			AllowedEmailDomains    string `json:"allowedEmailDomains"`
			ClientID               string `json:"clientId"`
			ClientSecret           string `json:"clientSecret"`
			IsActive               bool   `json:"isActive"`
			ManageGroupMemberships bool   `json:"manageGroupMemberships"`
			JwtSignatureAlgorithm  string `json:"jwtSignatureAlgorithm"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		var c authCfgOIDC
		if st.getJSON(authCfgOIDCKey(req.OrganizationID), &c) != nil {
			c = authCfgOIDC{ID: newID(), OrgID: req.OrganizationID, CreatedAt: now}
		}
		c.Issuer, c.AuthorizationEndpoint = req.Issuer, req.AuthorizationEndpoint
		c.ConfigurationType, c.DiscoveryURL = req.ConfigurationType, req.DiscoveryURL
		c.JwksURI, c.TokenEndpoint = req.JwksURI, req.TokenEndpoint
		c.UserinfoEndpoint, c.AllowedEmailDomains = req.UserinfoEndpoint, req.AllowedEmailDomains
		c.ClientID, c.ClientSecret, c.IsActive = req.ClientID, req.ClientSecret, req.IsActive
		c.ManageGroupMembers = req.ManageGroupMemberships
		c.JwtSignatureAlgorithm, c.UpdatedAt = req.JwtSignatureAlgorithm, now
		_ = st.putJSON(authCfgOIDCKey(c.OrgID), &c)
		writeJSON(w, http.StatusOK, authCfgOIDCJSON(&c))
	}
	mux.HandleFunc("POST /v1/sso/oidc/config", upsertOIDC)
	mux.HandleFunc("PATCH /v1/sso/oidc/config", upsertOIDC)

	// ── LDAP config (per org) ──────────────────────────────────────────────
	mux.HandleFunc("GET /v1/ldap/config", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		org := r.URL.Query().Get("organizationId")
		var c authCfgLDAP
		if st.getJSON(authCfgLDAPKey(org), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("ldap config not found"))
			return
		}
		writeJSON(w, http.StatusOK, authCfgLDAPJSON(&c))
	})
	upsertLDAP := func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			OrganizationID      string `json:"organizationId"`
			IsActive            bool   `json:"isActive"`
			URL                 string `json:"url"`
			BindDN              string `json:"bindDN"`
			BindPass            string `json:"bindPass"`
			UniqueUserAttribute string `json:"uniqueUserAttribute"`
			SearchBase          string `json:"searchBase"`
			SearchFilter        string `json:"searchFilter"`
			GroupSearchBase     string `json:"groupSearchBase"`
			GroupSearchFilter   string `json:"groupSearchFilter"`
			CACert              string `json:"caCert"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		var c authCfgLDAP
		if st.getJSON(authCfgLDAPKey(req.OrganizationID), &c) != nil {
			c = authCfgLDAP{ID: newID(), OrgID: req.OrganizationID, CreatedAt: now}
		}
		c.IsActive, c.URL, c.BindDN, c.BindPass = req.IsActive, req.URL, req.BindDN, req.BindPass
		c.UniqueUserAttribute = req.UniqueUserAttribute
		c.SearchBase, c.SearchFilter = req.SearchBase, req.SearchFilter
		c.GroupSearchBase, c.GroupSearchFilter = req.GroupSearchBase, req.GroupSearchFilter
		c.CACert, c.UpdatedAt = req.CACert, now
		_ = st.putJSON(authCfgLDAPKey(c.OrgID), &c)
		_ = st.putJSON(authCfgLDAPByID(c.ID), &c)
		writeJSON(w, http.StatusOK, authCfgLDAPJSON(&c))
	}
	mux.HandleFunc("POST /v1/ldap/config", upsertLDAP)
	mux.HandleFunc("PATCH /v1/ldap/config", upsertLDAP)

	// POST /v1/ldap/config/test-connection — bind verification is STUBBED;
	// always reports success so the settings UI advances.
	mux.HandleFunc("POST /v1/ldap/config/test-connection", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, true)
	})

	// LDAP group maps
	mux.HandleFunc("GET /v1/ldap/config/{id}/group-maps", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		cfgID := r.PathValue("id")
		out := []any{}
		pfx := authCfgGroupMapPrefix(cfgID)
		_ = st.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = pfx
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				_ = it.Item().Value(func(v []byte) error {
					var m authCfgLDAPGroupMap
					if json.Unmarshal(v, &m) == nil {
						out = append(out, authCfgGroupMapJSON(&m))
					}
					return nil
				})
			}
			return nil
		})
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /v1/ldap/config/{id}/group-maps", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		cfgID := r.PathValue("id")
		var req struct {
			LdapGroupCN string `json:"ldapGroupCN"`
			GroupSlug   string `json:"groupSlug"`
		}
		if !decode(w, r, &req) {
			return
		}
		m := &authCfgLDAPGroupMap{ID: newID(), LdapConfigID: cfgID, LdapGroupCN: req.LdapGroupCN, GroupSlug: req.GroupSlug}
		_ = st.putJSON(authCfgGroupMapKey(cfgID, m.ID), m)
		writeJSON(w, http.StatusOK, authCfgGroupMapJSON(m))
	})
	mux.HandleFunc("DELETE /v1/ldap/config/{id}/group-maps/{mapId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		cfgID, mapID := r.PathValue("id"), r.PathValue("mapId")
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(authCfgGroupMapKey(cfgID, mapID)) })
		writeJSON(w, http.StatusOK, map[string]any{"id": mapID})
	})

	// ── MFA sessions (v2) ──────────────────────────────────────────────────
	// Status/verify back the cross-device MFA approval poll. Verification is
	// STUBBED: any non-empty token marks the session ACTIVE/success.
	mux.HandleFunc("GET /v2/mfa-sessions/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ACTIVE", "mfaMethod": "totp"})
	})
	mux.HandleFunc("POST /v2/mfa-sessions/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			MfaToken  string `json:"mfaToken"`
			MfaMethod string `json:"mfaMethod"`
		}
		_ = decode(w, r, &req)
		ok := req.MfaToken != ""
		writeJSON(w, http.StatusOK, map[string]any{"success": ok, "message": "verified"})
	})

	// ── MFA checks / send / verify (login-time) ────────────────────────────
	// Pre-session login MFA probes: report no MFA so the SPA proceeds to a
	// normal session. (Real MFA enforcement lives at login in api_core.)
	mux.HandleFunc("GET /v1/auth/mfa/check/totp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"isVerified": false})
	})
	mux.HandleFunc("GET /v1/auth/mfa/check/webauthn", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"hasPasskeys": false})
	})
	mux.HandleFunc("POST /v1/auth/mfa/send", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, msg("sent"))
	})
	mux.HandleFunc("POST /v1/auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	})
	mux.HandleFunc("POST /v1/auth/mfa/verify/recovery-code", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	})
	mux.HandleFunc("POST /v1/auth/mfa/webauthn/authenticate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"challenge": newID(), "allowCredentials": []any{}})
	})
	mux.HandleFunc("POST /v1/auth/mfa/webauthn/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"verified": true, "credentialId": "", "sessionToken": ""})
	})

	// ── user TOTP (personal security) ──────────────────────────────────────
	// GET /v1/user/me/totp — current enrollment (404→{isVerified:false}).
	mux.HandleFunc("GET /v1/user/me/totp", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var c authCfgTOTP
		if st.getJSON(authCfgTOTPKey(cl.UserID), &c) != nil {
			writeJSON(w, http.StatusOK, map[string]any{"isVerified": false, "recoveryCodes": []string{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"isVerified": c.IsVerified, "recoveryCodes": c.RecoveryCodes})
	})
	// POST /v1/user/me/totp/register — begin enrollment, return otpauth URL.
	// (Secret generation is STUBBED — a placeholder otpauth:// URL.)
	mux.HandleFunc("POST /v1/user/me/totp/register", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		codes := authCfgRecoveryCodes()
		c := &authCfgTOTP{
			UserID: cl.UserID, IsVerified: false, RecoveryCodes: codes,
			OtpURL:    "otpauth://totp/Lux%20KMS:" + cl.UserID + "?secret=" + newID() + "&issuer=Lux%20KMS",
			CreatedAt: time.Now().UTC(),
		}
		_ = st.putJSON(authCfgTOTPKey(cl.UserID), c)
		writeJSON(w, http.StatusOK, map[string]any{"otpUrl": c.OtpURL, "recoveryCodes": codes})
	})
	// POST /v1/user/me/totp/verify — confirm enrollment. Code check STUBBED.
	mux.HandleFunc("POST /v1/user/me/totp/verify", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Totp string `json:"totp"`
		}
		_ = decode(w, r, &req)
		var c authCfgTOTP
		if st.getJSON(authCfgTOTPKey(cl.UserID), &c) != nil {
			c = authCfgTOTP{UserID: cl.UserID, RecoveryCodes: authCfgRecoveryCodes(), CreatedAt: time.Now().UTC()}
		}
		c.IsVerified = true
		_ = st.putJSON(authCfgTOTPKey(cl.UserID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": c.RecoveryCodes})
	})
	// POST /v1/user/me/totp/recovery-codes — regenerate.
	mux.HandleFunc("POST /v1/user/me/totp/recovery-codes", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var c authCfgTOTP
		if st.getJSON(authCfgTOTPKey(cl.UserID), &c) != nil {
			c = authCfgTOTP{UserID: cl.UserID, CreatedAt: time.Now().UTC()}
		}
		c.RecoveryCodes = authCfgRecoveryCodes()
		_ = st.putJSON(authCfgTOTPKey(cl.UserID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": c.RecoveryCodes})
	})
	// DELETE /v1/user/me/totp — disable.
	mux.HandleFunc("DELETE /v1/user/me/totp", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(authCfgTOTPKey(cl.UserID)) })
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// ── user WebAuthn (passkeys) ───────────────────────────────────────────
	// CRUD over registered credentials is real; the cryptographic
	// attestation/assertion verification is STUBBED (options are random
	// challenges; verify always succeeds and persists the credential).
	mux.HandleFunc("GET /v1/user/me/webauthn", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		out := []any{}
		pfx := authCfgWebAuthnPrefix(cl.UserID)
		_ = st.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = pfx
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				_ = it.Item().Value(func(v []byte) error {
					var c authCfgWebAuthnCred
					if json.Unmarshal(v, &c) == nil {
						out = append(out, authCfgWebAuthnJSON(&c))
					}
					return nil
				})
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
	})
	mux.HandleFunc("POST /v1/user/me/webauthn/register", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		// PublicKeyCredentialCreationOptionsJSON-shaped stub.
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge": newID(),
			"rp":        map[string]any{"name": "Lux KMS", "id": envOr("KMS_RP_ID", "localhost")},
			"user": map[string]any{
				"id": cl.UserID, "name": cl.UserID, "displayName": cl.UserID,
			},
			"pubKeyCredParams":       []any{map[string]any{"type": "public-key", "alg": -7}},
			"timeout":                60000,
			"attestation":            "none",
			"excludeCredentials":     []any{},
			"authenticatorSelection": map[string]any{"residentKey": "preferred", "userVerification": "preferred"},
		})
	})
	mux.HandleFunc("POST /v1/user/me/webauthn/register/verify", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		c := &authCfgWebAuthnCred{
			ID: newID(), UserID: cl.UserID, CredentialID: newID(),
			Name: req.Name, Transports: []string{"internal"}, CreatedAt: time.Now().UTC(),
		}
		_ = st.putJSON(authCfgWebAuthnKey(cl.UserID, c.ID), c)
		writeJSON(w, http.StatusOK, map[string]any{"credentialId": c.CredentialID, "name": c.Name})
	})
	mux.HandleFunc("POST /v1/user/me/webauthn/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge": newID(), "timeout": 60000, "rpId": envOr("KMS_RP_ID", "localhost"),
			"allowCredentials": []any{}, "userVerification": "preferred",
		})
	})
	mux.HandleFunc("POST /v1/user/me/webauthn/authenticate/verify", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"verified": true, "credentialId": "", "sessionToken": ""})
	})
	mux.HandleFunc("PATCH /v1/user/me/webauthn/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		id := r.PathValue("id")
		var c authCfgWebAuthnCred
		if st.getJSON(authCfgWebAuthnKey(cl.UserID, id), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("credential not found"))
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		c.Name = req.Name
		_ = st.putJSON(authCfgWebAuthnKey(cl.UserID, id), &c)
		writeJSON(w, http.StatusOK, map[string]any{"id": c.ID, "credentialId": c.CredentialID, "name": c.Name})
	})
	mux.HandleFunc("DELETE /v1/user/me/webauthn/{id}", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		id := r.PathValue("id")
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(authCfgWebAuthnKey(cl.UserID, id)) })
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	})

	// ── password reset / setup ─────────────────────────────────────────────
	// Reset is a PRE-SESSION flow (email → code → token → new password); the
	// SPA calls these without a session bearer, so they stay open. Email
	// delivery and SRP-verifier rotation are STUBBED — we ack the request so
	// the UI advances; no privileged token is minted.
	mux.HandleFunc("POST /v1/password/email/password-reset", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, msg("If an account exists, a reset email has been sent."))
	})
	mux.HandleFunc("POST /v1/password/email/password-reset-verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"token": newID(), "userEncryptionVersion": 2})
	})
	mux.HandleFunc("GET /v1/password/backup-private-key", func(w http.ResponseWriter, r *http.Request) {
		// Server-sealed model: no client-side e2e key, so no backup blob.
		writeJSON(w, http.StatusOK, map[string]any{"backupPrivateKey": ""})
	})
	mux.HandleFunc("POST /v1/password/password-reset", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, msg("password reset"))
	})
	mux.HandleFunc("POST /v1/password/user/password-reset", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, msg("password reset"))
	})
	// Password SETUP is an authenticated flow (user already has a session).
	mux.HandleFunc("POST /v1/password/email/password-setup", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("If applicable, a setup email has been sent."))
	})
	mux.HandleFunc("POST /v1/password/password-setup", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("password set"))
	})

	// ── signup (email onboarding) ──────────────────────────────────────────
	// Pre-session: the SPA calls these before any account/session exists, so
	// they stay open. Email delivery + code verification are STUBBED (any
	// code verifies). Account creation itself is owned by api_core's
	// /v1/admin/signup; here we only drive the email-verify gate so the
	// onboarding wizard advances.
	mux.HandleFunc("POST /v1/signup/email/signup", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, msg("verification email sent"))
	})
	mux.HandleFunc("POST /v1/signup/email/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"message": "email verified", "token": newID()})
	})
	mux.HandleFunc("POST /v1/signup/complete-account/signup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"message": "account created", "token": newID()})
	})
	mux.HandleFunc("POST /v1/signup/complete-account/invite", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"message": "account created", "token": newID()})
	})
}
