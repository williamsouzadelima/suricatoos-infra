package aiproviders

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
)

// Service exposes the admin API for managing AI providers. Every route is gated by
// the shared admin bearer (ADMIN_SECRET); nginx additionally fronts it. The API key
// is WRITE-ONLY: it is accepted on upsert and never returned by any handler.
type Service struct {
	reg   *Registry
	admin string
}

// NewService builds the admin service over reg, gated by adminSecret.
func NewService(reg *Registry, adminSecret string) *Service {
	return &Service{reg: reg, admin: adminSecret}
}

// Register wires the routes onto mux. Intended to be mounted DARK (behind
// AI_CONFIG_ENABLED) by the control-plane main.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/ai/providers", s.upsertHandler())
	mux.HandleFunc("GET /api/v1/ai/providers", s.listHandler())
	mux.HandleFunc("DELETE /api/v1/ai/providers/{id}", s.deleteHandler())
	// Private admin page (inert HTML; the API above is the security boundary).
	mux.HandleFunc("GET /admin/ai-providers", s.AdminPageHandler())
}

func (s *Service) adminOK(w http.ResponseWriter, r *http.Request) bool {
	want := "Bearer " + s.admin
	if s.admin == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// operator returns the approver identity set by nginx (auth_request → gsad), or a
// default. nginx strips any client-supplied X-Operator, so this is trustworthy.
func operator(r *http.Request) string {
	if o := r.Header.Get("X-Operator"); o != "" {
		return o
	}
	return "admin"
}

// upsertRequest is the accepted body. api_key is write-only (never echoed back).
type upsertRequest struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model,omitempty"`
	EURegion bool   `json:"eu_region"`
	ZDR      bool   `json:"zdr"`
	Enabled  bool   `json:"enabled"`
	APIKey   string `json:"api_key,omitempty"`
}

func (s *Service) upsertHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		var body upsertRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
			return
		}
		p, err := s.reg.Upsert(UpsertInput{
			ID: body.ID, Name: body.Name, Kind: body.Kind, BaseURL: body.BaseURL,
			Model: body.Model, EURegion: body.EURegion, ZDR: body.ZDR,
			Enabled: body.Enabled, APIKey: body.APIKey,
		}, operator(r))
		if err != nil {
			switch {
			case errors.Is(err, ErrGovernance):
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			case errors.Is(err, ErrValidation):
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			case errors.Is(err, ErrNotFound):
				http.Error(w, "not found", http.StatusNotFound)
			default:
				http.Error(w, "erro interno", http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"provider": p})
	}
}

func (s *Service) listHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": s.reg.List()})
	}
}

func (s *Service) deleteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		if s.reg.Delete(r.PathValue("id")) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
