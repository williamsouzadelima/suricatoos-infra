package tenants

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// Service exposes the admin-bearer tenant management API.
type Service struct {
	reg         *Registry
	adminSecret string
}

// NewService builds a Service. An empty adminSecret disables the routes (401).
func NewService(reg *Registry, adminSecret string) *Service {
	return &Service{reg: reg, adminSecret: adminSecret}
}

// authed reports whether r carries exactly "Authorization: Bearer <adminSecret>". The
// compare is constant-time (no timing side channel on the secret) and an empty secret
// never matches (fail closed).
func (s *Service) authed(r *http.Request) bool {
	if s.adminSecret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.adminSecret)) == 1
}

// PutHandler serves PUT /api/v1/tenants/{t}: create/update a tenant's scope +
// gvmd user + enabled flag.
func (s *Service) PutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := r.PathValue("t")
		if name == "" {
			http.Error(w, "tenant obrigatório", http.StatusBadRequest)
			return
		}
		var body struct {
			Scope   string `json:"scope"`
			GmpUser string `json:"gmp_user"`
			Enabled *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		rec := Record{Name: name, Scope: body.Scope, GmpUser: body.GmpUser, Enabled: enabled}
		if err := s.reg.Put(rec); err != nil {
			http.Error(w, "erro ao salvar", http.StatusInternalServerError)
			return
		}
		got, _ := s.reg.Get(name)
		writeJSON(w, http.StatusOK, got)
	}
}

// GetHandler serves GET /api/v1/tenants/{t}.
func (s *Service) GetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got, ok := s.reg.Get(r.PathValue("t"))
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, got)
	}
}

// ListHandler serves GET /api/v1/tenants.
func (s *Service) ListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, s.reg.List())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
