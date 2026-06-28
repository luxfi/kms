// SSH PKI surface — CAs, certificate templates, hosts, host-groups.
//
//	POST   /v1/ssh/ca/                                  {ca}
//	GET    /v1/ssh/ca/{caId}                            {ca}
//	PATCH  /v1/ssh/ca/{caId}                            {ca}
//	DELETE /v1/ssh/ca/{caId}                            {ca}
//	GET    /v1/ssh/ca/{caId}/certificate-templates      {certificateTemplates}
//	POST   /v1/ssh/certificates/sign                    {serialNumber, signedKey}        (stub)
//	POST   /v1/ssh/certificates/issue                   {serialNumber, signedKey, ...}   (stub)
//	POST   /v1/ssh/certificate-templates               <template>
//	GET    /v1/ssh/certificate-templates/{id}          <template>
//	PATCH  /v1/ssh/certificate-templates/{id}          <template>
//	DELETE /v1/ssh/certificate-templates/{id}          <template>
//	POST   /v1/ssh/hosts                               <host>
//	GET    /v1/ssh/hosts/{sshHostId}                   <host>
//	PATCH  /v1/ssh/hosts/{sshHostId}                   <host>
//	DELETE /v1/ssh/hosts/{sshHostId}                   <host>
//	GET    /v1/ssh/hosts/{sshHostId}/user-ca-public-key  "<openssh-public-key>"          (stub)
//	POST   /v1/ssh/host-groups                         <group>
//	GET    /v1/ssh/host-groups/{sshHostGroupId}        <group>
//	PATCH  /v1/ssh/host-groups/{sshHostGroupId}        <group>
//	DELETE /v1/ssh/host-groups/{sshHostGroupId}        <group>
//	GET    /v1/ssh/host-groups/{sshHostGroupId}/hosts  {hosts, totalCount}
//	POST   /v1/ssh/host-groups/{gid}/hosts/{hid}       (add membership)
//	DELETE /v1/ssh/host-groups/{gid}/hosts/{hid}       (remove membership)
//	GET    /v1/projects/{projectId}/ssh-cas            {cas}
//	GET    /v1/projects/{projectId}/ssh-hosts          {hosts}
//	GET    /v1/projects/{projectId}/ssh-host-groups    {groups}
//	GET    /v1/projects/{projectId}/ssh-certificate-templates {certificateTemplates}
//	GET    /v1/projects/{projectId}/ssh-certificates   {certificates, totalCount}
//
// CAs / templates / hosts / host-groups persist as JSON-KV in ZapDB under
// kms/ssh/<kind>/{id}, with a per-project secondary index (kms/ssh/<kind>/
// by-project/{projectId}/{id}) so the project SSH tabs list real entities.
// Host-group membership is a small JSON-KV edge set. The actual cryptographic
// SSH-CA signing / credential issuance (sign, issue, user-ca-public-key) is
// STUBBED — it persists/echoes plausible-shaped responses without minting real
// OpenSSH certificates (that belongs to the MPC/CA crypto path, not this HTTP
// shell).
package main

import (
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

// ── persisted entities ────────────────────────────────────────────────────

type sshCA struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"projectId"`
	Status       string    `json:"status"`
	FriendlyName string    `json:"friendlyName"`
	KeyAlgorithm string    `json:"keyAlgorithm"`
	KeySource    string    `json:"keySource"`
	PublicKey    string    `json:"publicKey"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type sshCertTemplate struct {
	ID                    string    `json:"id"`
	SshCaID               string    `json:"sshCaId"`
	Status                string    `json:"status"`
	Name                  string    `json:"name"`
	TTL                   string    `json:"ttl"`
	MaxTTL                string    `json:"maxTTL"`
	AllowedUsers          []string  `json:"allowedUsers"`
	AllowedHosts          []string  `json:"allowedHosts"`
	AllowUserCertificates bool      `json:"allowUserCertificates"`
	AllowHostCertificates bool      `json:"allowHostCertificates"`
	AllowCustomKeyIds     bool      `json:"allowCustomKeyIds"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

type sshLoginMapping struct {
	LoginUser         string `json:"loginUser"`
	AllowedPrincipals struct {
		Usernames []string `json:"usernames,omitempty"`
		Groups    []string `json:"groups,omitempty"`
	} `json:"allowedPrincipals"`
}

type sshHost struct {
	ID            string            `json:"id"`
	ProjectID     string            `json:"projectId"`
	Hostname      string            `json:"hostname"`
	Alias         string            `json:"alias"`
	UserCertTtl   string            `json:"userCertTtl"`
	HostCertTtl   string            `json:"hostCertTtl"`
	LoginMappings []sshLoginMapping `json:"loginMappings"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type sshHostGroup struct {
	ID            string            `json:"id"`
	ProjectID     string            `json:"projectId"`
	Name          string            `json:"name"`
	LoginMappings []sshLoginMapping `json:"loginMappings"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

// ── keyspace ──────────────────────────────────────────────────────────────

func sshCAKey(id string) []byte           { return []byte("kms/ssh/ca/" + id) }
func sshCAByProj(pid, id string) []byte   { return []byte("kms/ssh/ca/by-project/" + pid + "/" + id) }
func sshCAProjPfx(pid string) []byte      { return []byte("kms/ssh/ca/by-project/" + pid + "/") }
func sshTmplKey(id string) []byte         { return []byte("kms/ssh/tmpl/" + id) }
func sshTmplByCA(caID, id string) []byte  { return []byte("kms/ssh/tmpl/by-ca/" + caID + "/" + id) }
func sshTmplCAPfx(caID string) []byte     { return []byte("kms/ssh/tmpl/by-ca/" + caID + "/") }
func sshTmplByProj(pid, id string) []byte { return []byte("kms/ssh/tmpl/by-project/" + pid + "/" + id) }
func sshTmplProjPfx(pid string) []byte    { return []byte("kms/ssh/tmpl/by-project/" + pid + "/") }
func sshHostKey(id string) []byte         { return []byte("kms/ssh/host/" + id) }
func sshHostByProj(pid, id string) []byte { return []byte("kms/ssh/host/by-project/" + pid + "/" + id) }
func sshHostProjPfx(pid string) []byte    { return []byte("kms/ssh/host/by-project/" + pid + "/") }
func sshGroupKey(id string) []byte        { return []byte("kms/ssh/group/" + id) }
func sshGroupByProj(pid, id string) []byte {
	return []byte("kms/ssh/group/by-project/" + pid + "/" + id)
}
func sshGroupProjPfx(pid string) []byte   { return []byte("kms/ssh/group/by-project/" + pid + "/") }
func sshMemberKey(gid, hid string) []byte { return []byte("kms/ssh/group-host/" + gid + "/" + hid) }
func sshMemberPfx(gid string) []byte      { return []byte("kms/ssh/group-host/" + gid + "/") }

// sshDefault returns def when s is empty.
func sshDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// sshIDsByPrefix collects the trailing id segment of every key under pfx.
func sshIDsByPrefix(db *badger.DB, pfx []byte) []string {
	var ids []string
	_ = db.View(func(txn *badger.Txn) error {
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
	return ids
}

// ── render helpers (match the SPA TS shapes) ──────────────────────────────

func sshCAJSON(c *sshCA) map[string]any {
	return map[string]any{
		"id": c.ID, "projectId": c.ProjectID, "status": sshDefault(c.Status, "active"),
		"friendlyName": c.FriendlyName, "keyAlgorithm": c.KeyAlgorithm,
		"keySource": c.KeySource, "publicKey": c.PublicKey,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func sshTmplJSON(t *sshCertTemplate) map[string]any {
	return map[string]any{
		"id": t.ID, "sshCaId": t.SshCaID, "status": sshDefault(t.Status, "active"),
		"name": t.Name, "ttl": t.TTL, "maxTTL": t.MaxTTL,
		"allowedUsers": sshStrs(t.AllowedUsers), "allowedHosts": sshStrs(t.AllowedHosts),
		"allowUserCertificates": t.AllowUserCertificates,
		"allowHostCertificates": t.AllowHostCertificates,
		"allowCustomKeyIds":     t.AllowCustomKeyIds,
		"createdAt":             t.CreatedAt, "updatedAt": t.UpdatedAt,
	}
}

func sshHostJSON(h *sshHost) map[string]any {
	var alias any = h.Alias
	if h.Alias == "" {
		alias = nil
	}
	return map[string]any{
		"id": h.ID, "projectId": h.ProjectID, "hostname": h.Hostname, "alias": alias,
		"userCertTtl": sshDefault(h.UserCertTtl, "8h"), "hostCertTtl": sshDefault(h.HostCertTtl, "8h"),
		"loginMappings": sshMappings(h.LoginMappings, "host"),
		"createdAt":     h.CreatedAt, "updatedAt": h.UpdatedAt,
	}
}

func sshGroupJSON(g *sshHostGroup) map[string]any {
	return map[string]any{
		"id": g.ID, "projectId": g.ProjectID, "name": g.Name,
		"loginMappings": sshMappings(g.LoginMappings, "hostGroup"),
		"createdAt":     g.CreatedAt, "updatedAt": g.UpdatedAt,
	}
}

func sshStrs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sshMappings(in []sshLoginMapping, source string) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, m := range in {
		out = append(out, map[string]any{
			"loginUser": m.LoginUser,
			"allowedPrincipals": map[string]any{
				"usernames": sshStrs(m.AllowedPrincipals.Usernames),
				"groups":    sshStrs(m.AllowedPrincipals.Groups),
			},
			"source": source,
		})
	}
	return out
}

// sshCAProjectOf resolves the project a CA belongs to (used to index templates
// by project). Returns "" if the CA is unknown.
func sshCAProjectOf(st *webStore, caID string) string {
	var c sshCA
	if st.getJSON(sshCAKey(caID), &c) != nil {
		return ""
	}
	return c.ProjectID
}

func registerSshAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth.fromRequest(r) == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
			return false
		}
		return true
	}

	// ── SSH CAs ──────────────────────────────────────────────────────────
	mux.HandleFunc("POST /v1/ssh/ca/", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, FriendlyName, KeySource, KeyAlgorithm, PublicKey, PrivateKey string
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		c := &sshCA{
			ID: newID(), ProjectID: req.ProjectID, Status: "active",
			FriendlyName: req.FriendlyName, KeyAlgorithm: req.KeyAlgorithm,
			KeySource: sshDefault(req.KeySource, "internal"),
			// internal key material is generated by the (stubbed) CA crypto path;
			// echo any externally-supplied public key so the UI shows it.
			PublicKey: req.PublicKey, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(sshCAKey(c.ID), c)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshCAByProj(c.ProjectID, c.ID), []byte(c.ID)) })
		writeJSON(w, http.StatusOK, map[string]any{"ca": sshCAJSON(c)})
	})

	mux.HandleFunc("GET /v1/ssh/ca/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var c sshCA
		if st.getJSON(sshCAKey(r.PathValue("caId")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh ca not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ca": sshCAJSON(&c)})
	})

	mux.HandleFunc("PATCH /v1/ssh/ca/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var c sshCA
		if st.getJSON(sshCAKey(r.PathValue("caId")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh ca not found"))
			return
		}
		var req struct{ FriendlyName, Status string }
		_ = decode(w, r, &req)
		if req.FriendlyName != "" {
			c.FriendlyName = req.FriendlyName
		}
		if req.Status != "" {
			c.Status = req.Status
		}
		c.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(sshCAKey(c.ID), &c)
		writeJSON(w, http.StatusOK, map[string]any{"ca": sshCAJSON(&c)})
	})

	mux.HandleFunc("DELETE /v1/ssh/ca/{caId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var c sshCA
		if st.getJSON(sshCAKey(r.PathValue("caId")), &c) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh ca not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(sshCAKey(c.ID))
			return txn.Delete(sshCAByProj(c.ProjectID, c.ID))
		})
		writeJSON(w, http.StatusOK, map[string]any{"ca": sshCAJSON(&c)})
	})

	// certificate templates that belong to a CA
	mux.HandleFunc("GET /v1/ssh/ca/{caId}/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []any{}
		for _, id := range sshIDsByPrefix(st.db, sshTmplCAPfx(r.PathValue("caId"))) {
			var t sshCertTemplate
			if st.getJSON(sshTmplKey(id), &t) == nil {
				out = append(out, sshTmplJSON(&t))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplates": out})
	})

	// ── SSH certificate sign / issue (crypto STUB) ───────────────────────
	mux.HandleFunc("POST /v1/ssh/certificates/sign", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, CertificateTemplateID, PublicKey, CertType, KeyID, TTL string
			Principals                                                        []string
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"serialNumber": newID(),
			"signedKey":    "", // real OpenSSH cert minting is delegated to the CA crypto path
		})
	})

	mux.HandleFunc("POST /v1/ssh/certificates/issue", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, CertificateTemplateID, KeyAlgorithm, CertType, KeyID, TTL string
			Principals                                                           []string
		}
		_ = decode(w, r, &req)
		writeJSON(w, http.StatusOK, map[string]any{
			"serialNumber": newID(),
			"signedKey":    "",
			"privateKey":   "",
			"publicKey":    "",
			"keyAlgorithm": req.KeyAlgorithm,
		})
	})

	// ── SSH certificate templates ────────────────────────────────────────
	mux.HandleFunc("POST /v1/ssh/certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			SshCaID, Name, TTL, MaxTTL                                      string
			AllowedUsers, AllowedHosts                                      []string
			AllowUserCertificates, AllowHostCertificates, AllowCustomKeyIds bool
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		t := &sshCertTemplate{
			ID: newID(), SshCaID: req.SshCaID, Status: "active", Name: req.Name,
			TTL: req.TTL, MaxTTL: req.MaxTTL, AllowedUsers: req.AllowedUsers, AllowedHosts: req.AllowedHosts,
			AllowUserCertificates: req.AllowUserCertificates, AllowHostCertificates: req.AllowHostCertificates,
			AllowCustomKeyIds: req.AllowCustomKeyIds, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(sshTmplKey(t.ID), t)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshTmplByCA(t.SshCaID, t.ID), []byte(t.ID)) })
		// index by the CA's project so the project tab lists it
		if pid := sshCAProjectOf(st, t.SshCaID); pid != "" {
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshTmplByProj(pid, t.ID), []byte(t.ID)) })
		}
		writeJSON(w, http.StatusOK, sshTmplJSON(t))
	})

	mux.HandleFunc("GET /v1/ssh/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var t sshCertTemplate
		if st.getJSON(sshTmplKey(r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh certificate template not found"))
			return
		}
		writeJSON(w, http.StatusOK, sshTmplJSON(&t))
	})

	mux.HandleFunc("PATCH /v1/ssh/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var t sshCertTemplate
		if st.getJSON(sshTmplKey(r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh certificate template not found"))
			return
		}
		var req struct {
			Status, Name, TTL, MaxTTL                                       string
			AllowedUsers, AllowedHosts                                      *[]string
			AllowUserCertificates, AllowHostCertificates, AllowCustomKeyIds *bool
		}
		_ = decode(w, r, &req)
		if req.Status != "" {
			t.Status = req.Status
		}
		if req.Name != "" {
			t.Name = req.Name
		}
		if req.TTL != "" {
			t.TTL = req.TTL
		}
		if req.MaxTTL != "" {
			t.MaxTTL = req.MaxTTL
		}
		if req.AllowedUsers != nil {
			t.AllowedUsers = *req.AllowedUsers
		}
		if req.AllowedHosts != nil {
			t.AllowedHosts = *req.AllowedHosts
		}
		if req.AllowUserCertificates != nil {
			t.AllowUserCertificates = *req.AllowUserCertificates
		}
		if req.AllowHostCertificates != nil {
			t.AllowHostCertificates = *req.AllowHostCertificates
		}
		if req.AllowCustomKeyIds != nil {
			t.AllowCustomKeyIds = *req.AllowCustomKeyIds
		}
		t.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(sshTmplKey(t.ID), &t)
		writeJSON(w, http.StatusOK, sshTmplJSON(&t))
	})

	mux.HandleFunc("DELETE /v1/ssh/certificate-templates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var t sshCertTemplate
		if st.getJSON(sshTmplKey(r.PathValue("id")), &t) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh certificate template not found"))
			return
		}
		pid := sshCAProjectOf(st, t.SshCaID)
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(sshTmplKey(t.ID))
			_ = txn.Delete(sshTmplByCA(t.SshCaID, t.ID))
			if pid != "" {
				_ = txn.Delete(sshTmplByProj(pid, t.ID))
			}
			return nil
		})
		writeJSON(w, http.StatusOK, sshTmplJSON(&t))
	})

	// ── SSH hosts ────────────────────────────────────────────────────────
	mux.HandleFunc("POST /v1/ssh/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, Hostname, Alias, UserCertTtl, HostCertTtl string
			LoginMappings                                        []sshLoginMapping
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		h := &sshHost{
			ID: newID(), ProjectID: req.ProjectID, Hostname: req.Hostname, Alias: req.Alias,
			UserCertTtl: req.UserCertTtl, HostCertTtl: req.HostCertTtl,
			LoginMappings: req.LoginMappings, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(sshHostKey(h.ID), h)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshHostByProj(h.ProjectID, h.ID), []byte(h.ID)) })
		writeJSON(w, http.StatusOK, sshHostJSON(h))
	})

	mux.HandleFunc("GET /v1/ssh/hosts/{sshHostId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h sshHost
		if st.getJSON(sshHostKey(r.PathValue("sshHostId")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host not found"))
			return
		}
		writeJSON(w, http.StatusOK, sshHostJSON(&h))
	})

	mux.HandleFunc("PATCH /v1/ssh/hosts/{sshHostId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h sshHost
		if st.getJSON(sshHostKey(r.PathValue("sshHostId")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host not found"))
			return
		}
		var req struct {
			Hostname, Alias, UserCertTtl, HostCertTtl string
			LoginMappings                             *[]sshLoginMapping
		}
		_ = decode(w, r, &req)
		if req.Hostname != "" {
			h.Hostname = req.Hostname
		}
		if req.Alias != "" {
			h.Alias = req.Alias
		}
		if req.UserCertTtl != "" {
			h.UserCertTtl = req.UserCertTtl
		}
		if req.HostCertTtl != "" {
			h.HostCertTtl = req.HostCertTtl
		}
		if req.LoginMappings != nil {
			h.LoginMappings = *req.LoginMappings
		}
		h.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(sshHostKey(h.ID), &h)
		writeJSON(w, http.StatusOK, sshHostJSON(&h))
	})

	mux.HandleFunc("DELETE /v1/ssh/hosts/{sshHostId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var h sshHost
		if st.getJSON(sshHostKey(r.PathValue("sshHostId")), &h) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(sshHostKey(h.ID))
			return txn.Delete(sshHostByProj(h.ProjectID, h.ID))
		})
		writeJSON(w, http.StatusOK, sshHostJSON(&h))
	})

	// user-ca-public-key — the response is a bare JSON string (crypto STUB).
	mux.HandleFunc("GET /v1/ssh/hosts/{sshHostId}/user-ca-public-key", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, "")
	})

	// ── SSH host groups ──────────────────────────────────────────────────
	mux.HandleFunc("POST /v1/ssh/host-groups", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var req struct {
			ProjectID, Name string
			LoginMappings   []sshLoginMapping
		}
		if !decode(w, r, &req) {
			return
		}
		now := time.Now().UTC()
		g := &sshHostGroup{
			ID: newID(), ProjectID: req.ProjectID, Name: req.Name,
			LoginMappings: req.LoginMappings, CreatedAt: now, UpdatedAt: now,
		}
		_ = st.putJSON(sshGroupKey(g.ID), g)
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshGroupByProj(g.ProjectID, g.ID), []byte(g.ID)) })
		writeJSON(w, http.StatusOK, sshGroupJSON(g))
	})

	mux.HandleFunc("GET /v1/ssh/host-groups/{sshHostGroupId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var g sshHostGroup
		if st.getJSON(sshGroupKey(r.PathValue("sshHostGroupId")), &g) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host group not found"))
			return
		}
		writeJSON(w, http.StatusOK, sshGroupJSON(&g))
	})

	mux.HandleFunc("PATCH /v1/ssh/host-groups/{sshHostGroupId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var g sshHostGroup
		if st.getJSON(sshGroupKey(r.PathValue("sshHostGroupId")), &g) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host group not found"))
			return
		}
		var req struct {
			Name          string
			LoginMappings *[]sshLoginMapping
		}
		_ = decode(w, r, &req)
		if req.Name != "" {
			g.Name = req.Name
		}
		if req.LoginMappings != nil {
			g.LoginMappings = *req.LoginMappings
		}
		g.UpdatedAt = time.Now().UTC()
		_ = st.putJSON(sshGroupKey(g.ID), &g)
		writeJSON(w, http.StatusOK, sshGroupJSON(&g))
	})

	mux.HandleFunc("DELETE /v1/ssh/host-groups/{sshHostGroupId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var g sshHostGroup
		if st.getJSON(sshGroupKey(r.PathValue("sshHostGroupId")), &g) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host group not found"))
			return
		}
		_ = st.db.Update(func(txn *badger.Txn) error {
			_ = txn.Delete(sshGroupKey(g.ID))
			return txn.Delete(sshGroupByProj(g.ProjectID, g.ID))
		})
		// drop membership edges
		for _, hid := range sshIDsByPrefix(st.db, sshMemberPfx(g.ID)) {
			gid := g.ID
			_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(sshMemberKey(gid, hid)) })
		}
		writeJSON(w, http.StatusOK, sshGroupJSON(&g))
	})

	// list hosts in a group (or, with ?filter=non-group-members, the rest of
	// the project's hosts). Returns {hosts, totalCount}.
	mux.HandleFunc("GET /v1/ssh/host-groups/{sshHostGroupId}/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		gid := r.PathValue("sshHostGroupId")
		var g sshHostGroup
		if st.getJSON(sshGroupKey(gid), &g) != nil {
			writeJSON(w, http.StatusNotFound, msg("ssh host group not found"))
			return
		}
		filter := r.URL.Query().Get("filter")
		member := map[string]bool{}
		for _, hid := range sshIDsByPrefix(st.db, sshMemberPfx(gid)) {
			member[hid] = true
		}
		out := []any{}
		for _, hid := range sshIDsByPrefix(st.db, sshHostProjPfx(g.ProjectID)) {
			isMember := member[hid]
			switch filter {
			case "group-members":
				if !isMember {
					continue
				}
			case "non-group-members":
				if isMember {
					continue
				}
			}
			var h sshHost
			if st.getJSON(sshHostKey(hid), &h) != nil {
				continue
			}
			row := sshHostJSON(&h)
			row["isPartOfGroup"] = isMember
			row["joinedGroupAt"] = h.UpdatedAt
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": out, "totalCount": len(out)})
	})

	mux.HandleFunc("POST /v1/ssh/host-groups/{sshHostGroupId}/hosts/{sshHostId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		gid, hid := r.PathValue("sshHostGroupId"), r.PathValue("sshHostId")
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Set(sshMemberKey(gid, hid), []byte(hid)) })
		writeJSON(w, http.StatusOK, msg("added"))
	})

	mux.HandleFunc("DELETE /v1/ssh/host-groups/{sshHostGroupId}/hosts/{sshHostId}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		gid, hid := r.PathValue("sshHostGroupId"), r.PathValue("sshHostId")
		_ = st.db.Update(func(txn *badger.Txn) error { return txn.Delete(sshMemberKey(gid, hid)) })
		writeJSON(w, http.StatusOK, msg("removed"))
	})

	// ── project-scoped SSH lists (back the project SSH tabs) ─────────────
	mux.HandleFunc("GET /v1/projects/{projectId}/ssh-cas", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []any{}
		for _, id := range sshIDsByPrefix(st.db, sshCAProjPfx(r.PathValue("projectId"))) {
			var c sshCA
			if st.getJSON(sshCAKey(id), &c) == nil {
				j := sshCAJSON(&c)
				delete(j, "publicKey") // list shape omits the public key
				out = append(out, j)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"cas": out})
	})

	mux.HandleFunc("GET /v1/projects/{projectId}/ssh-hosts", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []any{}
		for _, id := range sshIDsByPrefix(st.db, sshHostProjPfx(r.PathValue("projectId"))) {
			var h sshHost
			if st.getJSON(sshHostKey(id), &h) == nil {
				out = append(out, sshHostJSON(&h))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
	})

	mux.HandleFunc("GET /v1/projects/{projectId}/ssh-host-groups", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []any{}
		for _, id := range sshIDsByPrefix(st.db, sshGroupProjPfx(r.PathValue("projectId"))) {
			var g sshHostGroup
			if st.getJSON(sshGroupKey(id), &g) == nil {
				j := sshGroupJSON(&g)
				j["hostCount"] = len(sshIDsByPrefix(st.db, sshMemberPfx(g.ID)))
				out = append(out, j)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": out})
	})

	mux.HandleFunc("GET /v1/projects/{projectId}/ssh-certificate-templates", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []any{}
		for _, id := range sshIDsByPrefix(st.db, sshTmplProjPfx(r.PathValue("projectId"))) {
			var t sshCertTemplate
			if st.getJSON(sshTmplKey(id), &t) == nil {
				out = append(out, sshTmplJSON(&t))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificateTemplates": out})
	})

	// issued certificates aren't minted (crypto STUB) — empty, paginated list.
	mux.HandleFunc("GET /v1/projects/{projectId}/ssh-certificates", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"certificates": []any{}, "totalCount": 0})
	})
}
