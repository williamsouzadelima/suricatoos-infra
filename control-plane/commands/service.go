package commands

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
)

// Service serves the command channel HTTP endpoints.
type Service struct {
	q           *Queue
	allowedType map[string]bool
	known       func(agentID string) bool
	isRevoked   func(serialHex string) bool // nil: revocation not checked
	noSerial    onceSet                     // agents already logged for coming without a serial
	logf        func(format string, args ...any)
}

// onceSet remembers the keys already logged, so a condition that lasts a whole deploy
// transition logs one line per agent instead of one per poll (agents poll every
// minute). Bounded: when full it starts over, and an agent may be logged once more.
type onceSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

const onceSetMax = 10000

// first reports whether key is new, and records it.
func (o *onceSet) first(key string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.seen[key]; ok {
		return false
	}
	if o.seen == nil || len(o.seen) >= onceSetMax {
		o.seen = make(map[string]struct{})
	}
	o.seen[key] = struct{}{}
	return true
}

// NewService returns a Service over q. known, when set, says whether an agent id is
// an enrolled agent; the Agents UI route (SessionEnqueueHandler) refuses ids it does
// not recognize. nil means no check (use it when there is no durable enrollment
// record to ask). The admin-bearer route never consults it.
func NewService(q *Queue, known func(agentID string) bool) *Service {
	return &Service{q: q, allowedType: map[string]bool{CmdScanNow: true}, known: known, logf: log.Printf}
}

// WithRevocationCheck makes Poll and Ack refuse (403) a client certificate whose
// serial — forwarded by nginx as X-Client-Cert-Serial — isRevoked reports revoked:
// a revoked agent neither receives its command nor acks it. Wire the in-process CA's
// IsRevoked.
//
// Unlike the ingest's inventory check there is no log-only mode here, on purpose: the
// CA lives in this process, so its revoked set is authoritative, always loaded and
// deterministic — there is no "CRL unavailable" state to fail open on, and a
// certificate that was not revoked is never affected. The only transition case is an
// nginx that does not forward the serial yet: that request is accepted and logged
// once per agent, so deploying this before the nginx change cannot cut the fleet off.
func (s *Service) WithRevocationCheck(isRevoked func(serialHex string) bool) *Service {
	s.isRevoked = isRevoked
	return s
}

// certAllowed applies the revocation check to the agent identified by cn. It writes
// the 403 and returns false for a revoked certificate.
func (s *Service) certAllowed(w http.ResponseWriter, r *http.Request, cn string) bool {
	if s.isRevoked == nil {
		return true
	}
	serial := strings.TrimSpace(r.Header.Get("X-Client-Cert-Serial"))
	if serial == "" {
		if s.noSerial.first(cn) {
			s.logf("commands: agente %q sem X-Client-Cert-Serial (nginx ainda não encaminha o serial) — revogação não conferida; aceito (logado uma vez por agente)", cn)
		}
		return true
	}
	if s.isRevoked(serial) {
		s.logf("commands: certificado revogado no canal de comandos (cn=%q serial=%s) — 403", cn, serial)
		http.Error(w, "certificate revoked", http.StatusForbidden)
		return false
	}
	return true
}

// adminOK reports whether r carries "Authorization: Bearer <secret>". The compare is
// constant-time and an empty secret never matches (fail closed), as in the other
// admin services.
func adminOK(r *http.Request, secret string) bool {
	want := "Bearer " + secret
	return secret != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) == 1
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
// identified by its mTLS client cert (204 when none) and marks it DELIVERED. The
// body is the bare Command ({id,type,created_at}) — the lifecycle state is for the
// operator's history route, never part of the agent contract. The route MUST be
// gated by nginx mTLS so X-Client-Cert-DN (identity) and X-Client-Cert-Serial
// (revocation, see WithRevocationCheck) are trustworthy.
func (s *Service) PollHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := agentCN(r)
		if cn == "" {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		if !s.certAllowed(w, r, cn) {
			return
		}
		c, ok := s.q.Poll(cn)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	}
}

// AckHandler serves POST /commands/ack {"id": "..."}: marks the agent's command
// ACKED once it has been processed. Identity comes from the client cert, and a
// revoked cert is refused as in PollHandler.
func (s *Service) AckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := agentCN(r)
		if cn == "" {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		if !s.certAllowed(w, r, cn) {
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

// enqueue queues cmdType for agentID and answers 202 with the Command, or: 400 for an
// id that could not be an agent's, 503 when the queue is full, 500 when the command
// could not be persisted. A 202 always means "queued, durably if the queue is".
func (s *Service) enqueue(w http.ResponseWriter, agentID, cmdType string) {
	c, err := s.q.Enqueue(agentID, cmdType)
	switch {
	case errors.Is(err, ErrInvalidAgentID):
		http.Error(w, "invalid agent id", http.StatusBadRequest)
		return
	case errors.Is(err, ErrQueueFull):
		log.Printf("commands: fila cheia — agente %q recusado (limite de agentes distintos)", agentID)
		http.Error(w, "command queue is full", http.StatusServiceUnavailable)
		return
	case err != nil:
		log.Printf("commands: enfileirar %s para o agente %q: %v", cmdType, agentID, err)
		http.Error(w, "could not persist the command", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(c)
}

// SessionEnqueueHandler serves POST /agents/scan?id=<agent> for the Agents UI's
// "Escanear agora" button. It has NO auth of its own and MUST be reached only
// through the session-gated nginx location (GSAD_SID cookie + same-origin) — the
// same trust model as the provision endpoint. It enqueues a scan_now (the only
// UI-triggerable command) on the SAME queue the admin/CLI handler uses. As defense in
// depth it is wrapped in sessiongate.Require: a request without the marker nginx sets
// only on session-gated locations is refused (403) before anything is enqueued.
//
// That gate is weaker than a bearer, so this route is also the one that cannot be
// allowed to create queue entries out of thin air: the id must be well formed (400)
// and, when the service has an enrollment lookup, an enrolled agent (404).
func (s *Service) SessionEnqueueHandler() http.HandlerFunc {
	return sessiongate.Require(func(w http.ResponseWriter, r *http.Request) {
		agentID := strings.TrimSpace(r.URL.Query().Get("id"))
		if agentID == "" {
			http.Error(w, "agent id required", http.StatusBadRequest)
			return
		}
		if !validAgentID(agentID) {
			http.Error(w, "invalid agent id", http.StatusBadRequest)
			return
		}
		if s.known != nil && !s.known(agentID) {
			http.Error(w, "unknown agent", http.StatusNotFound)
			return
		}
		s.enqueue(w, agentID, CmdScanNow)
	})
}

// EnqueueHandler serves POST /api/v1/agents/{id}/commands {"type": "scan_now"}.
// It is admin-authenticated (Bearer adminSecret) — the operator/CLI trigger for
// an on-demand scan; gvmd's play button cannot drive a passive agent.
func (s *Service) EnqueueHandler(adminSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(r, adminSecret) {
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
		s.enqueue(w, agentID, body.Type)
	}
}

// HistoryHandler serves GET /api/v1/agents/{id}/commands: the agent's recent
// commands, newest first, each with its state (PENDING, DELIVERED, ACKED,
// SUPERSEDED, EXPIRED) and timestamps — how an operator learns whether the agent
// picked a request up. Admin-authenticated (Bearer adminSecret). An agent with no
// commands gets an empty list, not a 404: the queue does not know which agents exist.
func (s *Service) HistoryHandler(adminSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(r, adminSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		agentID := r.PathValue("id")
		if agentID == "" {
			http.Error(w, "agent id required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			AgentID  string   `json:"agent_id"`
			Commands []Record `json:"commands"`
		}{AgentID: agentID, Commands: s.q.History(agentID)})
	}
}
