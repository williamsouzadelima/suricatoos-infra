package planner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// planWriteMargin is the time left to write the response after the planner's
// overall timeout (the plan route's write deadline is Timeout + this margin).
const planWriteMargin = 30 * time.Second

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
		// A draft can take far longer than the server-wide WriteTimeout (a slow free
		// model, several providers/formats): without this the connection would be
		// torn down before the draft is written. THIS response gets its own write
		// deadline, bounded by the planner's overall timeout (the server-wide one
		// stays as is for every other route). Best effort: a writer without deadline
		// support simply keeps the server's.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.planner.Timeout() + planWriteMargin))
		plan, err := s.planner.Plan(r.Context(), req)
		if err != nil {
			switch {
			case errors.Is(err, ErrConsentOff), errors.Is(err, ErrNonFreeModel), errors.Is(err, ErrUngoverned):
				writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			case errors.Is(err, ErrBudget):
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
			case errors.Is(err, ErrTimeout):
				writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": err.Error()})
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
