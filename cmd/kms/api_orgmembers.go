// OrgMembers area — the organization-management surface the SPA hits beyond the
// core login/select-org flow: org settings (detail/update), org RBAC roles,
// org-scoped permissions, incident contacts, sub-organizations, the org-admin
// project-access grant, and the billing/plan/subscription tabs.
//
// Groups covered (frontend/src/hooks/api):
//
//	organization      GET/PATCH /v1/organization/{id}, groups,
//	                  integration-authorizations, permissions, users/available
//	organizations     POST /v1/organizations (create), privilege-system-upgrade,
//	                  plan/billing/invoices/licenses, billing-details + pmt + tax,
//	                  customer-portal-session, session/trial
//	roles             /v1/organization/{id}/roles[/{roleId}]  (org RBAC, CRUD)
//	incidentContacts  /v1/organization/{id}/incidentContactOrg[/{contactId}]
//	subOrganizations  /v1/sub-organizations[/{id}]
//	orgAdmin          POST /v1/organization-admin/projects/{id}/grant-admin-access
//	subscriptions     GET /v1/organizations/{id}/plan  (SubscriptionPlan)
//
// Real CRUD is implemented for roles, incident contacts, and sub-organizations
// (persisted as JSON-KV under kms/orgmembers/...). Org create/update mutate the
// shared webOrg record via the webStore. Billing/plan/invoices/licenses are the
// Stripe-backed Infisical surface; with no payment processor here they return
// the correctly-shaped wrappers (empty lists / a free-tier plan / a portal-URL
// stub) so the dashboard tabs render and navigate without errors.
//
// Forbidden/other-area patterns are deliberately NOT registered here:
//
//	GET /v1/organization, GET /v1/organization/{id}/my-workspaces (core/projects),
//	/v1/organization/{id}/users, /v1/organization/{id}/project-memberships and
//	all /v2/organizations/* memberships (users area).
package main

import (
	"encoding/json"
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── entities (JSON-KV in ZapDB under kms/orgmembers/...) ───────────────────

type orgRole struct {
	ID          string           `json:"id"`
	OrgID       string           `json:"orgId"`
	Name        string           `json:"name"`
	Slug        string           `json:"slug"`
	Description string           `json:"description"`
	Permissions []map[string]any `json:"permissions"`
	CreatedAt   time.Time        `json:"createdAt"`
	UpdatedAt   time.Time        `json:"updatedAt"`
}

type incidentContact struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type subOrg struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	ParentOrgID string    `json:"parentOrgId"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func orgRoleKey(orgID, id string) []byte {
	return []byte("kms/orgmembers/roles/" + orgID + "/" + id)
}
func orgRolePrefix(orgID string) []byte { return []byte("kms/orgmembers/roles/" + orgID + "/") }

func incidentContactKey(orgID, id string) []byte {
	return []byte("kms/orgmembers/incident-contacts/" + orgID + "/" + id)
}
func incidentContactPrefix(orgID string) []byte {
	return []byte("kms/orgmembers/incident-contacts/" + orgID + "/")
}

func subOrgKey(id string) []byte { return []byte("kms/orgmembers/sub-orgs/" + id) }
func subOrgByParent(parent, id string) []byte {
	return []byte("kms/orgmembers/sub-orgs-by-parent/" + parent + "/" + id)
}
func subOrgParentPrefix(parent string) []byte {
	return []byte("kms/orgmembers/sub-orgs-by-parent/" + parent + "/")
}

func registerOrgMembersAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	// authed resolves the caller; on failure it writes 401 and returns nil.
	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// ── organization: detail + update ─────────────────────────────────────
	// GET /v1/organization/{id} — single org (settings page). {organization}
	mux.HandleFunc("GET /v1/organization/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		o, err := st.OrgByID(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("organization not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organization": orgMembersOrgJSON(o)})
	})

	// PATCH /v1/organization/{id} — update org settings (UpdateOrgDTO). The SPA
	// reads back name/slug + the product/security toggles; persist name/slug on
	// the shared webOrg, echo the rest so the form reflects the submitted state.
	mux.HandleFunc("PATCH /v1/organization/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		o, err := st.OrgByID(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("organization not found"))
			return
		}
		var req map[string]any
		_ = decode(w, r, &req)
		if v, ok := req["name"].(string); ok && v != "" {
			o.Name = v
		}
		if v, ok := req["slug"].(string); ok && v != "" {
			o.Slug = v
		}
		_ = st.putJSON(orgKey(o.ID), o)
		out := orgMembersOrgJSON(o)
		// reflect any submitted toggles back to the client (form round-trips them)
		for _, k := range orgMembersToggleKeys {
			if v, ok := req[k]; ok {
				out[k] = v
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"organization": out})
	})

	// GET /v1/organization/{id}/groups is owned by the Groups area
	// (registerGroupsScimAPI), which serves the real store-backed list. No stub
	// here — a second pattern at the same path conflicts at registration time.

	// GET /v1/organization/{id}/integration-authorizations — {authorizations:[]}
	mux.HandleFunc("GET /v1/organization/{id}/integration-authorizations", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorizations": []any{}})
	})

	// GET /v1/organization/users/available — users invitable to the org.
	// (Literal path; distinct from the {id} wildcard above.)
	mux.HandleFunc("GET /v1/organization/users/available", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": []any{}})
	})

	// GET /v1/organization/{id}/permissions — the caller's effective org ability
	// + memberships. The SPA unpacks CASL rules; admins get a wildcard grant so
	// every management page is reachable. Shape: {permissions, memberships}.
	mux.HandleFunc("GET /v1/organization/{id}/permissions", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		orgID := r.PathValue("id")
		u, _ := st.UserByID(cl.UserID)
		role := "member"
		if u != nil && u.SuperAdmin {
			role = "admin"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"permissions": orgMembersPackedAdminRules(),
			"memberships": []any{
				map[string]any{
					"id":     cl.UserID + ":" + orgID,
					"userId": cl.UserID,
					"orgId":  orgID,
					"role":   role,
					"roles":  []any{map[string]any{"role": role}},
					"status": "accepted",
				},
			},
		})
	})

	// ── roles: org RBAC, real CRUD ────────────────────────────────────────
	// GET /v1/organization/{id}/roles — {data:{roles:[...]}} (note the extra
	// `data` envelope the roles hook deserializes).
	mux.HandleFunc("GET /v1/organization/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID := r.PathValue("id")
		roles := orgMembersListRoles(st, orgID)
		// seed the predefined roles the UI always expects alongside custom ones
		out := append(orgMembersPredefinedRoles(orgID), roles...)
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"roles": out}})
	})

	// POST /v1/organization/{id}/roles — create custom org role → {role}
	mux.HandleFunc("POST /v1/organization/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID := r.PathValue("id")
		var req struct {
			Name        string           `json:"name"`
			Slug        string           `json:"slug"`
			Description string           `json:"description"`
			Permissions []map[string]any `json:"permissions"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Slug == "" {
			req.Slug = slugify(req.Name)
		}
		now := time.Now().UTC()
		role := &orgRole{
			ID: newID(), OrgID: orgID, Name: req.Name, Slug: req.Slug,
			Description: req.Description, Permissions: req.Permissions,
			CreatedAt: now, UpdatedAt: now,
		}
		if role.Permissions == nil {
			role.Permissions = []map[string]any{}
		}
		_ = st.putJSON(orgRoleKey(orgID, role.ID), role)
		writeJSON(w, http.StatusOK, map[string]any{"role": orgRoleJSON(role)})
	})

	// GET /v1/organization/{id}/roles/{roleId} → {role}
	mux.HandleFunc("GET /v1/organization/{id}/roles/{roleId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID, rid := r.PathValue("id"), r.PathValue("roleId")
		if pre := orgMembersPredefinedRole(orgID, rid); pre != nil {
			writeJSON(w, http.StatusOK, map[string]any{"role": pre})
			return
		}
		var role orgRole
		if st.getJSON(orgRoleKey(orgID, rid), &role) != nil {
			writeJSON(w, http.StatusNotFound, msg("role not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"role": orgRoleJSON(&role)})
	})

	// PATCH /v1/organization/{id}/roles/{roleId} → {role}
	mux.HandleFunc("PATCH /v1/organization/{id}/roles/{roleId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID, rid := r.PathValue("id"), r.PathValue("roleId")
		var role orgRole
		if st.getJSON(orgRoleKey(orgID, rid), &role) != nil {
			writeJSON(w, http.StatusNotFound, msg("role not found"))
			return
		}
		var req struct {
			Name        *string           `json:"name"`
			Slug        *string           `json:"slug"`
			Description *string           `json:"description"`
			Permissions *[]map[string]any `json:"permissions"`
		}
		_ = decode(w, r, &req)
		if req.Name != nil {
			role.Name = *req.Name
		}
		if req.Slug != nil {
			role.Slug = *req.Slug
		}
		if req.Description != nil {
			role.Description = *req.Description
		}
		if req.Permissions != nil {
			role.Permissions = *req.Permissions
		}
		role.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(orgRoleKey(orgID, rid), &role)
		writeJSON(w, http.StatusOK, map[string]any{"role": orgRoleJSON(&role)})
	})

	// DELETE /v1/organization/{id}/roles/{roleId} → {role}
	mux.HandleFunc("DELETE /v1/organization/{id}/roles/{roleId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID, rid := r.PathValue("id"), r.PathValue("roleId")
		var role orgRole
		if st.getJSON(orgRoleKey(orgID, rid), &role) != nil {
			writeJSON(w, http.StatusNotFound, msg("role not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(orgRoleKey(orgID, rid)) })
		writeJSON(w, http.StatusOK, map[string]any{"role": orgRoleJSON(&role)})
	})

	// ── incident contacts: real CRUD ──────────────────────────────────────
	// GET /v1/organization/{id}/incidentContactOrg → {incidentContactsOrg:[...]}
	mux.HandleFunc("GET /v1/organization/{id}/incidentContactOrg", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"incidentContactsOrg": orgMembersListIncidentContacts(st, r.PathValue("id")),
		})
	})

	// POST /v1/organization/{id}/incidentContactOrg {email} → {incidentContactsOrg}
	mux.HandleFunc("POST /v1/organization/{id}/incidentContactOrg", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID := r.PathValue("id")
		var req struct {
			Email string `json:"email"`
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		c := &incidentContact{ID: newID(), OrgID: orgID, Email: req.Email, CreatedAt: now, UpdatedAt: now}
		_ = st.putJSON(incidentContactKey(orgID, c.ID), c)
		writeJSON(w, http.StatusOK, map[string]any{"incidentContactsOrg": incidentContactJSON(c)})
	})

	// DELETE /v1/organization/{id}/incidentContactOrg/{contactId}
	mux.HandleFunc("DELETE /v1/organization/{id}/incidentContactOrg/{contactId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		orgID, cid := r.PathValue("id"), r.PathValue("contactId")
		var c incidentContact
		_ = st.getJSON(incidentContactKey(orgID, cid), &c)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(incidentContactKey(orgID, cid)) })
		writeJSON(w, http.StatusOK, map[string]any{"incidentContactsOrg": incidentContactJSON(&c)})
	})

	// ── organizations (plural): create + privilege-system-upgrade ─────────
	// POST /v1/organizations {name} → {organization}. Creates a webOrg and makes
	// the caller an admin member so it shows up in their org switcher.
	mux.HandleFunc("POST /v1/organizations", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("organization name required"))
			return
		}
		o, err := st.CreateOrg(req.Name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		_ = st.AddMembership(cl.UserID, o.ID, "admin")
		writeJSON(w, http.StatusOK, map[string]any{"organization": orgMembersOrgJSON(o)})
	})

	// POST /v1/organizations/privilege-system-upgrade — flips the org to the new
	// permission system. No-op (we already model the new system); 200 unblocks.
	mux.HandleFunc("POST /v1/organizations/privilege-system-upgrade", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		o, _ := st.OrgByID(cl.OrgID)
		if o == nil {
			writeJSON(w, http.StatusOK, msg("ok"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organization": orgMembersOrgJSON(o)})
	})

	// ── subscriptions / billing / plan (Stripe surface → shaped stubs) ────
	// GET /v1/organizations/{id}/plan — entitlement plan the whole UI gates on.
	// Returns a permissive free/self-hosted plan so no feature is hidden.
	mux.HandleFunc("GET /v1/organizations/{id}/plan", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plan": orgMembersPlan()})
	})

	// GET /v1/organizations/{id}/plan/billing — current-period billing summary.
	mux.HandleFunc("GET /v1/organizations/{id}/plan/billing", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		now := time.Now().UTC()
		writeJSON(w, http.StatusOK, map[string]any{
			"amount": 0, "currentPeriodStart": now.Unix(),
			"currentPeriodEnd": now.AddDate(0, 1, 0).Unix(),
			"interval":         "month", "intervalCount": 1, "quantity": 1,
			"users": 0, "identities": 0,
		})
	})

	// GET /v1/organizations/{id}/plan/table — usage table (head/rows).
	mux.HandleFunc("GET /v1/organizations/{id}/plan/table", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"head": []any{}, "rows": []any{}})
	})

	// GET /v1/organizations/{id}/plans/table — purchasable products table.
	mux.HandleFunc("GET /v1/organizations/{id}/plans/table", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"head": []any{}, "rows": []any{}})
	})

	// GET /v1/organizations/{id}/billing-details → {name,email}
	mux.HandleFunc("GET /v1/organizations/{id}/billing-details", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var bd struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		_ = st.getJSON(orgMembersBillingKey(r.PathValue("id")), &bd)
		writeJSON(w, http.StatusOK, map[string]any{"name": bd.Name, "email": bd.Email})
	})

	// PATCH /v1/organizations/{id}/billing-details — persists name/email.
	mux.HandleFunc("PATCH /v1/organizations/{id}/billing-details", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		_ = decode(w, r, &req)
		_ = st.putJSON(orgMembersBillingKey(r.PathValue("id")), &req)
		writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "email": req.Email})
	})

	// GET/POST /v1/organizations/{id}/billing-details/payment-methods
	mux.HandleFunc("GET /v1/organizations/{id}/billing-details/payment-methods", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("POST /v1/organizations/{id}/billing-details/payment-methods", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		// no payment processor — echo the caller's success_url so the client's
		// redirect-to-Stripe flow resolves to a no-op return.
		var req struct {
			SuccessURL string `json:"success_url"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"url": req.SuccessURL})
	})
	mux.HandleFunc("DELETE /v1/organizations/{id}/billing-details/payment-methods/{pmtMethodId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// GET/POST /v1/organizations/{id}/billing-details/tax-ids
	mux.HandleFunc("GET /v1/organizations/{id}/billing-details/tax-ids", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("POST /v1/organizations/{id}/billing-details/tax-ids", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("DELETE /v1/organizations/{id}/billing-details/tax-ids/{taxId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// GET /v1/organizations/{id}/invoices → []
	mux.HandleFunc("GET /v1/organizations/{id}/invoices", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})

	// GET /v1/organizations/{id}/licenses → []
	mux.HandleFunc("GET /v1/organizations/{id}/licenses", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, []any{})
	})

	// POST /v1/organizations/{id}/customer-portal-session → {url}
	mux.HandleFunc("POST /v1/organizations/{id}/customer-portal-session", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"url": ""})
	})

	// POST /v1/organizations/{id}/session/trial → {url}
	mux.HandleFunc("POST /v1/organizations/{id}/session/trial", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var req struct {
			SuccessURL string `json:"success_url"`
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{"url": req.SuccessURL})
	})

	// ── sub-organizations: real CRUD (children of the caller's org) ───────
	// GET /v1/sub-organizations → {organizations:[...]}
	mux.HandleFunc("GET /v1/sub-organizations", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": orgMembersListSubOrgs(st, cl.OrgID)})
	})

	// POST /v1/sub-organizations {name} → {organization}
	mux.HandleFunc("POST /v1/sub-organizations", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, msg("name required"))
			return
		}
		now := time.Now().UTC()
		so := &subOrg{
			ID: newID(), Name: req.Name, Slug: slugify(req.Name),
			ParentOrgID: cl.OrgID, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(subOrgKey(so.ID), so)
		_ = st.db.Update(func(txn *badger.Txn) error {
			return txn.Set(subOrgByParent(cl.OrgID, so.ID), []byte(so.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"organization": subOrgJSON(so)})
	})

	// PATCH /v1/sub-organizations/{id} {name} → {organization}
	mux.HandleFunc("PATCH /v1/sub-organizations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		var so subOrg
		if st.getJSON(subOrgKey(r.PathValue("id")), &so) != nil {
			writeJSON(w, http.StatusNotFound, msg("sub-organization not found"))
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = decode(w, r, &req)
		if req.Name != "" {
			so.Name = req.Name
			so.Slug = slugify(req.Name)
		}
		so.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(subOrgKey(so.ID), &so)
		writeJSON(w, http.StatusOK, map[string]any{"organization": subOrgJSON(&so)})
	})

	// ── orgAdmin: grant the caller admin access to any project ─────────────
	// POST /v1/organization-admin/projects/{projectId}/grant-admin-access.
	// Org admins can break-glass into a project; we acknowledge the grant.
	mux.HandleFunc("POST /v1/organization-admin/projects/{projectId}/grant-admin-access", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"membership": map[string]any{
				"id":        newID(),
				"projectId": r.PathValue("projectId"),
				"userId":    cl.UserID,
				"roles":     []any{map[string]any{"role": "admin"}},
			},
		})
	})
}

// ── shapes + list helpers ─────────────────────────────────────────────────

// orgMembersToggleKeys are the boolean/string org settings the SPA's update form
// round-trips; PATCH echoes any present so the form reflects the submitted state.
var orgMembersToggleKeys = []string{
	"authEnforced", "googleSsoAuthEnforced", "scimEnabled", "enforceMfa",
	"selectedMfaMethod", "allowSecretSharingOutsideOrganization", "bypassOrgAuthEnabled",
	"userTokenExpiration", "secretsProductEnabled", "pkiProductEnabled", "kmsProductEnabled",
	"sshProductEnabled", "scannerProductEnabled", "shareSecretsProductEnabled",
	"maxSharedSecretLifetime", "maxSharedSecretViewLimit", "blockDuplicateSecretSyncDestinations",
	"secretShareBrandConfig", "defaultMembershipRoleSlug",
}

// orgMembersOrgJSON renders the SPA Organization shape with permissive defaults
// so every settings/feature page deserializes and renders.
func orgMembersOrgJSON(o *webOrg) map[string]any {
	return map[string]any{
		"id": o.ID, "name": o.Name, "slug": o.Slug,
		"createAt": o.CreatedAt, "createdAt": o.CreatedAt, "updatedAt": o.CreatedAt,
		"authEnforced": false, "googleSsoAuthEnforced": false, "bypassOrgAuthEnabled": false,
		"orgAuthMethod": "email", "scimEnabled": false, "defaultMembershipRole": "member",
		"enforceMfa": false, "selectedMfaMethod": nil, "shouldUseNewPrivilegeSystem": true,
		"allowSecretSharingOutsideOrganization": true, "userTokenExpiration": nil,
		"userRole": "admin", "userJoinedAt": o.CreatedAt,
		"secretsProductEnabled": true, "pkiProductEnabled": true, "kmsProductEnabled": true,
		"sshProductEnabled": true, "scannerProductEnabled": true, "shareSecretsProductEnabled": true,
		"maxSharedSecretLifetime": 2592000, "maxSharedSecretViewLimit": nil,
		"blockDuplicateSecretSyncDestinations": false,
		"parentOrgId":                          nil, "rootOrgId": nil, "secretShareBrandConfig": nil,
	}
}

func orgRoleJSON(r *orgRole) map[string]any {
	perms := r.Permissions
	if perms == nil {
		perms = []map[string]any{}
	}
	return map[string]any{
		"id": r.ID, "orgId": r.OrgID, "name": r.Name, "slug": r.Slug,
		"description": r.Description, "permissions": perms,
		"createdAt": r.CreatedAt, "updatedAt": r.UpdatedAt,
	}
}

func orgMembersListRoles(st *webStore, orgID string) []any {
	out := []any{}
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = orgRolePrefix(orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var role orgRole
				if json.Unmarshal(v, &role) == nil {
					out = append(out, orgRoleJSON(&role))
				}
				return nil
			})
		}
		return nil
	})
	return out
}

// orgMembersPredefinedRoles are the built-in org roles Infisical always exposes
// (non-deletable). The UI lists them alongside custom roles and references them
// by their reserved slug.
func orgMembersPredefinedRoles(orgID string) []any {
	defs := []struct{ slug, name, desc string }{
		{"admin", "Admin", "Complete administration access over the organization"},
		{"member", "Member", "Non-administrative role in an organization"},
		{"no-access", "No Access", "No access to any resources in the organization"},
	}
	out := make([]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, map[string]any{
			"id": d.slug, "orgId": orgID, "name": d.name, "slug": d.slug,
			"description": d.desc, "permissions": []any{},
			"createdAt": time.Time{}, "updatedAt": time.Time{},
		})
	}
	return out
}

func orgMembersPredefinedRole(orgID, idOrSlug string) map[string]any {
	for _, r := range orgMembersPredefinedRoles(orgID) {
		m := r.(map[string]any)
		if m["id"] == idOrSlug || m["slug"] == idOrSlug {
			return m
		}
	}
	return nil
}

func incidentContactJSON(c *incidentContact) map[string]any {
	return map[string]any{
		"id": c.ID, "email": c.Email, "organization": c.OrgID, "__v": 0,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func orgMembersListIncidentContacts(st *webStore, orgID string) []any {
	out := []any{}
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = incidentContactPrefix(orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				var c incidentContact
				if json.Unmarshal(v, &c) == nil {
					out = append(out, incidentContactJSON(&c))
				}
				return nil
			})
		}
		return nil
	})
	return out
}

func subOrgJSON(s *subOrg) map[string]any {
	return map[string]any{
		"id": s.ID, "name": s.Name, "slug": s.Slug, "parentOrgId": s.ParentOrgID,
		"createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
	}
}

func orgMembersListSubOrgs(st *webStore, parentOrgID string) []any {
	out := []any{}
	if parentOrgID == "" {
		return out
	}
	var ids []string
	pfx := subOrgParentPrefix(parentOrgID)
	_ = st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = pfx
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	for _, id := range ids {
		var so subOrg
		if st.getJSON(subOrgKey(id), &so) == nil {
			out = append(out, subOrgJSON(&so))
		}
	}
	return out
}

func orgMembersBillingKey(orgID string) []byte {
	return []byte("kms/orgmembers/billing/" + orgID)
}

// orgMembersPlan returns a permissive self-hosted entitlement plan: every
// feature flag on, generous limits. This mirrors the SubscriptionPlan shape the
// whole UI gates feature visibility on — with no Stripe here, nothing is locked.
func orgMembersPlan() map[string]any {
	const unlimited = 1_000_000
	return map[string]any{
		"id": "self-hosted", "slug": "enterprise", "tier": -1,
		"membersUsed": 0, "memberLimit": unlimited,
		"identitiesUsed": 0, "identityLimit": unlimited,
		"workspacesUsed": 0, "workspaceLimit": unlimited, "environmentLimit": unlimited,
		"auditLogs": true, "auditLogsRetentionDays": 90, "auditLogStreams": true,
		"auditLogStreamLimit": unlimited, "dynamicSecret": true, "customAlerts": true,
		"customRateLimits": true, "pitRecovery": true, "githubOrgSync": true,
		"subOrganization": true, "ipAllowlisting": true, "rbac": true,
		"secretVersioning": true, "secretApproval": true, "secretRotation": true,
		"samlSSO": true, "oidcSSO": true, "scim": true, "ldap": true, "groups": true,
		"sshHostGroups": true, "secretAccessInsights": true, "hsm": true,
		"caCrl": true, "instanceUserManagement": true, "gateway": true,
		"externalKms": true, "pkiEst": true, "pkiAcme": true, "pkiLegacyTemplates": true,
		"enforceMfa": false, "enforceGoogleSSO": false, "projectTemplates": true,
		"kmip": true, "secretScanning": true,
		"enterpriseSecretSyncs": true, "enterpriseCertificateSyncs": true,
		"enterpriseAppConnections": true, "machineIdentityAuthTemplates": true,
		"secretShareExternalBranding": true,
		"status":                      "active", "trial_end": nil, "has_used_trial": false,
	}
}

// orgMembersPackedAdminRules returns CASL rules (in @casl PackRule shape: a
// tuple array [action, subject]) granting full org access. The SPA's
// unpackRules expands these into a wildcard ability so every management page is
// reachable for the authenticated principal.
func orgMembersPackedAdminRules() []any {
	return []any{
		[]any{"manage", "all"},
	}
}
