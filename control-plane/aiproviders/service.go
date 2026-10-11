package aiproviders

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
)

// Service exposes the admin API for managing AI providers. Two gates reach the
// SAME logic:
//
//   - the /api/v1/ai/providers and /api/v1/ai/policy routes are gated by the shared
//     admin bearer (ADMIN_SECRET) — for direct/machine admin;
//   - the /ai/providers and /ai/policy session routes carry NO bearer and are safe
//     ONLY behind nginx's STRONG gsad-session gate (auth_request → gsad,
//     token-validated, like /feed-sync) — for the logged-in operator in the GSA UI.
//     They must NEVER be exposed through a cookie-only gate (that gate is
//     forgeable). As defense in depth they also refuse (403) any request without
//     the sessiongate marker, which nginx sets only on session-gated locations.
//
// The API key is WRITE-ONLY on every route: accepted on upsert, never returned.
type Service struct {
	reg   *Registry
	admin string

	// Free-models listing (models.go): outbound client, body cap, clock, cache.
	modelsHC  *http.Client
	modelsMax int64
	now       func() time.Time
	cacheMu   sync.Mutex
	cache     map[string]modelsCacheEntry
}

// NewService builds the service over reg; adminSecret gates the bearer routes.
func NewService(reg *Registry, adminSecret string) *Service {
	return &Service{
		reg:       reg,
		admin:     adminSecret,
		modelsHC:  newModelsClient(nil),
		modelsMax: modelsMaxBody,
		now:       time.Now,
		cache:     map[string]modelsCacheEntry{},
	}
}

// Register wires all routes onto mux. Mounted DARK (behind AI_CONFIG_ENABLED) by
// the control-plane main. The session routes additionally REQUIRE the strong nginx
// gsad gate in front of them (see the type comment).
func (s *Service) Register(mux *http.ServeMux) {
	// Bearer-gated (direct/machine admin).
	mux.HandleFunc("POST /api/v1/ai/providers", s.upsertHandler())
	mux.HandleFunc("GET /api/v1/ai/providers", s.listHandler())
	mux.HandleFunc("DELETE /api/v1/ai/providers/{id}", s.deleteHandler())
	mux.HandleFunc("GET /api/v1/ai/providers/{id}/models", s.modelsHandler())
	mux.HandleFunc("GET /api/v1/ai/policy", s.policyHandler())
	// Session-gated by nginx (GSA UI). No bearer here — the nginx auth_request→gsad
	// in front is the security boundary; the control-plane is internal-only. The
	// handlers also require the sessiongate marker nginx sets only on those locations.
	mux.HandleFunc("GET /ai/providers", s.SessionListHandler())
	mux.HandleFunc("POST /ai/providers", s.SessionUpsertHandler())
	mux.HandleFunc("DELETE /ai/providers/{id}", s.SessionDeleteHandler())
	mux.HandleFunc("GET /ai/providers/{id}/models", s.SessionModelsHandler())
	mux.HandleFunc("GET /ai/policy", s.SessionPolicyHandler())
	// Private static admin page (inert HTML; the API is the security boundary).
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

// operator returns the identity set by nginx (auth_request → gsad), or a default.
// nginx strips any client-supplied X-Operator, so this is trustworthy.
func operator(r *http.Request) string {
	if o := r.Header.Get("X-Operator"); o != "" {
		return o
	}
	return "operator"
}

// upsertRequest is the accepted body. api_key is write-only (never echoed back).
// data_policy_ack is the operator's acknowledgment; who/when acknowledged are set
// by the server (any data_policy_ack_by/_at in the body is ignored).
type upsertRequest struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	BaseURL       string `json:"base_url"`
	Model         string `json:"model,omitempty"`
	EURegion      bool   `json:"eu_region"`
	ZDR           bool   `json:"zdr"`
	Enabled       bool   `json:"enabled"`
	DataPolicyAck bool   `json:"data_policy_ack"`
	APIKey        string `json:"api_key,omitempty"`
}

// --- bearer-gated handlers ---

func (s *Service) upsertHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		s.doUpsert(w, r)
	}
}

func (s *Service) listHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		s.doList(w, r)
	}
}

func (s *Service) deleteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		s.doDelete(w, r)
	}
}

func (s *Service) modelsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		s.doModels(w, r)
	}
}

func (s *Service) policyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		s.doPolicy(w, r)
	}
}

// --- session-gated handlers (nginx gsad gate is the boundary; no bearer) ---
//
// Each one is wrapped in sessiongate.Require (defense in depth): a request that does
// not carry the marker nginx sets only on session-gated locations is refused with 403
// before any logic runs, so a location without the gate cannot reach these routes.

// SessionUpsertHandler serves POST /ai/providers for the GSA UI.
func (s *Service) SessionUpsertHandler() http.HandlerFunc {
	return sessiongate.Require(s.doUpsert)
}

// SessionListHandler serves GET /ai/providers for the GSA UI.
func (s *Service) SessionListHandler() http.HandlerFunc {
	return sessiongate.Require(s.doList)
}

// SessionDeleteHandler serves DELETE /ai/providers/{id} for the GSA UI.
func (s *Service) SessionDeleteHandler() http.HandlerFunc {
	return sessiongate.Require(s.doDelete)
}

// SessionModelsHandler serves GET /ai/providers/{id}/models (the provider's live
// FREE models) for the GSA UI.
func (s *Service) SessionModelsHandler() http.HandlerFunc {
	return sessiongate.Require(s.doModels)
}

// SessionPolicyHandler serves GET /ai/policy (the free-models policy) for the GSA UI.
func (s *Service) SessionPolicyHandler() http.HandlerFunc {
	return sessiongate.Require(s.doPolicy)
}

// --- shared logic (auth already enforced by the wrapper or by nginx) ---

func (s *Service) doUpsert(w http.ResponseWriter, r *http.Request) {
	var body upsertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	p, err := s.reg.Upsert(UpsertInput{
		ID: body.ID, Name: body.Name, Kind: body.Kind, BaseURL: body.BaseURL,
		Model: body.Model, EURegion: body.EURegion, ZDR: body.ZDR,
		Enabled: body.Enabled, DataPolicyAck: body.DataPolicyAck, APIKey: body.APIKey,
	}, operator(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrGovernance), errors.Is(err, ErrFreeOnly):
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

func (s *Service) doList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.reg.List()})
}

func (s *Service) doDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.reg.Delete(id) {
		s.dropModels(id)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
