// Tier 2 — projects + environments (the secrets-manager shell).
//
//	GET  /v1/projects                          {projects: [...]}
//	POST /v1/projects                          {project}            (default envs dev/staging/prod)
//	GET  /v1/projects/{id}                      {project}
//	DELETE /v1/projects/{id}
//	POST /v1/projects/{id}/environments         {environment}
//	PATCH/DELETE /v1/projects/{id}/environments/{envId}
//	GET  /v1/organization/{orgId}/my-workspaces {workspaces: [...]}
//	GET  /v1/projects/{id}/environment-folder-tree  (secrets-nav scaffold)
//
// Projects/envs persist as JSON-KV in ZapDB (kms/projects/{id} +
// kms/projects/by-org/{orgId}/{id}). Environments live inline on the project.
package main

import (
	"net/http"
	"time"

	badger "github.com/luxfi/zapdb"
)

type projectEnv struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type project struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Slug         string       `json:"slug"`
	Description  string       `json:"description"`
	OrgID        string       `json:"orgId"`
	Environments []projectEnv `json:"environments"`
	CreatedAt    time.Time    `json:"createdAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
}

func projectKey(id string) []byte { return []byte("kms/projects/" + id) }
func projectOrgIdx(orgID, id string) []byte {
	return []byte("kms/projects/by-org/" + orgID + "/" + id)
}
func projectOrgPrefix(orgID string) []byte { return []byte("kms/projects/by-org/" + orgID + "/") }

func defaultEnvs() []projectEnv {
	return []projectEnv{
		{ID: newID(), Name: "Development", Slug: "dev"},
		{ID: newID(), Name: "Staging", Slug: "staging"},
		{ID: newID(), Name: "Production", Slug: "prod"},
	}
}

func (s *webStore) CreateProject(orgID, name string) (*project, error) {
	now := time.Now().UTC()
	p := &project{
		ID: newID(), Name: name, Slug: slugify(name), OrgID: orgID,
		Environments: defaultEnvs(), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.putJSON(projectKey(p.ID), p); err != nil {
		return nil, err
	}
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(projectOrgIdx(orgID, p.ID), []byte(p.ID))
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *webStore) GetProject(id string) (*project, error) {
	var p project
	if err := s.getJSON(projectKey(id), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *webStore) SaveProject(p *project) error {
	p.UpdatedAt = time.Now().UTC()
	return s.putJSON(projectKey(p.ID), p)
}

func (s *webStore) ProjectsForOrg(orgID string) ([]*project, error) {
	var ids []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = projectOrgPrefix(orgID)
		it := txn.NewIterator(opts)
		defer it.Close()
		pfx := projectOrgPrefix(orgID)
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			ids = append(ids, string(k[len(pfx):]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]*project, 0, len(ids))
	for _, id := range ids {
		if p, err := s.GetProject(id); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *webStore) DeleteProject(id string) error {
	p, err := s.GetProject(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		_ = txn.Delete(projectKey(id))
		return txn.Delete(projectOrgIdx(p.OrgID, id))
	})
}

// projectJSON renders the SPA Project shape (fields the UI reads; the rest get
// sensible defaults so deserialization never trips).
func projectJSON(p *project) map[string]any {
	envs := make([]map[string]any, 0, len(p.Environments))
	for _, e := range p.Environments {
		envs = append(envs, map[string]any{"id": e.ID, "name": e.Name, "slug": e.Slug})
	}
	return map[string]any{
		"__v": 0, "id": p.ID, "name": p.Name, "slug": p.Slug, "type": "secret-manager",
		"description": p.Description, "orgId": p.OrgID, "version": 3, "upgradeStatus": nil,
		"autoCapitalization": false, "environments": envs, "pitVersionLimit": 10,
		"auditLogsRetentionDays": 0, "hasDeleteProtection": false, "secretSharing": true,
		"showSnapshotsLegacy": false, "secretDetectionIgnoreValues": []string{},
		"createdAt": p.CreatedAt, "updatedAt": p.UpdatedAt,
	}
}

func registerProjectAPI(mux *http.ServeMux, db *badger.DB) {
	st := newWebStore(db)
	auth := newWebAuth(webAuthSecret(db))

	authed := func(w http.ResponseWriter, r *http.Request) *webClaims {
		cl := auth.fromRequest(r)
		if cl == nil {
			writeJSON(w, http.StatusUnauthorized, msg("unauthorized"))
		}
		return cl
	}

	// GET /v1/projects — projects in the caller's selected org.
	mux.HandleFunc("GET /v1/projects", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		ps, _ := st.ProjectsForOrg(cl.OrgID)
		out := make([]any, 0, len(ps))
		for _, p := range ps {
			out = append(out, projectJSON(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"projects": out})
	})

	// POST /v1/projects — create a project (with default environments).
	mux.HandleFunc("POST /v1/projects", func(w http.ResponseWriter, r *http.Request) {
		cl := authed(w, r)
		if cl == nil {
			return
		}
		var req struct {
			ProjectName string `json:"projectName"`
			Name        string `json:"name"`
			Slug        string `json:"slug"`
		}
		_ = decode(w, r, &req)
		name := req.ProjectName
		if name == "" {
			name = req.Name
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, msg("project name required"))
			return
		}
		p, err := st.CreateProject(cl.OrgID, name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, msg(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"project": projectJSON(p)})
	})

	// GET /v1/projects/{id}
	mux.HandleFunc("GET /v1/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		p, err := st.GetProject(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"project": projectJSON(p)})
	})

	// DELETE /v1/projects/{id}
	mux.HandleFunc("DELETE /v1/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		if err := st.DeleteProject(r.PathValue("id")); err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// POST /v1/projects/{id}/environments
	mux.HandleFunc("POST /v1/projects/{id}/environments", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		p, err := st.GetProject(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		var req struct{ Name, Slug string }
		if !decode(w, r, &req) {
			return
		}
		if req.Slug == "" {
			req.Slug = slugify(req.Name)
		}
		env := projectEnv{ID: newID(), Name: req.Name, Slug: req.Slug}
		p.Environments = append(p.Environments, env)
		_ = st.SaveProject(p)
		writeJSON(w, http.StatusOK, map[string]any{"environment": map[string]any{"id": env.ID, "name": env.Name, "slug": env.Slug}})
	})

	// PATCH /v1/projects/{id}/environments/{envId}
	mux.HandleFunc("PATCH /v1/projects/{id}/environments/{envId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		p, err := st.GetProject(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		var req struct{ Name, Slug string }
		_ = decode(w, r, &req)
		eid := r.PathValue("envId")
		for i := range p.Environments {
			if p.Environments[i].ID == eid {
				if req.Name != "" {
					p.Environments[i].Name = req.Name
				}
				if req.Slug != "" {
					p.Environments[i].Slug = req.Slug
				}
				_ = st.SaveProject(p)
				writeJSON(w, http.StatusOK, map[string]any{"environment": map[string]any{"id": p.Environments[i].ID, "name": p.Environments[i].Name, "slug": p.Environments[i].Slug}})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, msg("environment not found"))
	})

	// DELETE /v1/projects/{id}/environments/{envId}
	mux.HandleFunc("DELETE /v1/projects/{id}/environments/{envId}", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		p, err := st.GetProject(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		eid := r.PathValue("envId")
		kept := p.Environments[:0]
		for _, e := range p.Environments {
			if e.ID != eid {
				kept = append(kept, e)
			}
		}
		p.Environments = kept
		_ = st.SaveProject(p)
		writeJSON(w, http.StatusOK, msg("deleted"))
	})

	// GET /v1/organization/{orgId}/my-workspaces
	mux.HandleFunc("GET /v1/organization/{orgId}/my-workspaces", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		ps, _ := st.ProjectsForOrg(r.PathValue("orgId"))
		out := make([]any, 0, len(ps))
		for _, p := range ps {
			out = append(out, projectJSON(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": out})
	})

	// GET /v1/projects/{id}/environment-folder-tree — secrets-nav scaffold:
	// each environment with its (root) folder list. Folders fill in with Tier 3.
	mux.HandleFunc("GET /v1/projects/{id}/environment-folder-tree", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) == nil {
			return
		}
		p, err := st.GetProject(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, msg("project not found"))
			return
		}
		tree := map[string]any{}
		for _, e := range p.Environments {
			tree[e.Slug] = map[string]any{
				"environment": map[string]any{"id": e.ID, "name": e.Name, "slug": e.Slug},
				"folders":     []any{},
			}
		}
		writeJSON(w, http.StatusOK, tree)
	})
}
