package commands

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Service serves the command channel HTTP endpoints.
type Service struct {
	q           *Queue
	allowedType map[string]bool
}

// NewService returns a Service over q.
func NewService(q *Queue) *Service {
	return &Service{q: q, allowedType: map[string]bool{CmdScanNow: true}}
}

// agentCN extracts the agent identity (cert CommonName) from the client cert DN
// that nginx forwards on the mTLS-gated command route (X-Client-Cert-DN). It
// accepts both RFC2253 ("CN=foo,O=bar") and legacy slash ("/O=bar/CN=foo")
// forms. Empty when no verified client cert reached the upstream.
func agentCN(r *http.Request) string {
	dn := r.Header.Get("X-Client-Cert-DN")
	for _, sep := range []string{",", "/"} {
		for _, part := range strings.Split(dn, sep) {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "CN=") {
				return strings.TrimSpace(strings.TrimPrefix(part, "CN="))
			}
		}
	}
	return ""
}

// PollHandler serves GET /commands: returns the pending command for the agent
// identified by its mTLS client cert (204 when none). The route MUST be gated by
// nginx mTLS so X-Client-Cert-DN is trustworthy.
func (s *Service) PollHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := agentCN(r)
		if cn == "" {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		c, ok := s.q.Pending(cn)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	}
}

// AckHandler serves POST /commands/ack {"id": "..."}: removes the agent's pending
// command once it has been processed. Identity comes from the client cert.
func (s *Service) AckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := agentCN(r)
		if cn == "" {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		s.q.Ack(cn, body.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// EnqueueHandler serves POST /api/v1/agents/{id}/commands {"type": "scan_now"}.
// It is admin-authenticated (Bearer adminSecret) — the operator/CLI trigger for
// an on-demand scan; gvmd's play button cannot drive a passive agent.
func (s *Service) EnqueueHandler(adminSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") ||
			strings.TrimPrefix(auth, "Bearer ") != adminSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		agentID := r.PathValue("id")
		if agentID == "" {
			http.Error(w, "agent id required", http.StatusBadRequest)
			return
		}
		var body struct {
			Type string `json:"type"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
		if body.Type == "" {
			body.Type = CmdScanNow
		}
		if !s.allowedType[body.Type] {
			http.Error(w, "unknown command type", http.StatusBadRequest)
			return
		}
		c := s.q.Enqueue(agentID, body.Type)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(c)
	}
}
