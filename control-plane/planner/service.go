package planner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
)

// Service exposes the operator-triggered draft endpoint. A draft is produced ONLY
// on an explicit, admin-authenticated request — never automatically — which keeps
// the AI inside the approval-per-action model.
type Service struct {
	planner *Planner
	admin   string
}

// NewService builds the admin service over a configured Planner.
func NewService(p *Planner, adminSecret string) *Service {
	return &Service{planner: p, admin: adminSecret}
}

// Register wires the route. Mounted DARK by the control-plane main (behind
// AI_PLANNER_ENABLED).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/remediation/plan", s.planHandler())
}

func (s *Service) adminOK(w http.ResponseWriter, r *http.Request) bool {
	want := "Bearer " + s.admin
	if s.admin == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Service) planHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		var req PlanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
			http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
			return
		}
		plan, err := s.planner.Plan(r.Context(), req)
		if err != nil {
			switch {
			case errors.Is(err, ErrConsentOff):
				writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			case errors.Is(err, ErrBudget):
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
			default:
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plan": plan})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
