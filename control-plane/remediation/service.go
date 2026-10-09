package remediation

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// RevokedFunc reports whether a client-cert serial (hex) is revoked. The control
// plane IS the CA, so its revoked set is authoritative and in-memory. A nil
// RevokedFunc means CRL is not wired → the service denies every agent route
// (fail-closed), matching sensorjobs.
type RevokedFunc func(serialHex string) bool

// Service serves the remediation routes. Agent routes (poll/ack/report) are mTLS
// + CRL gated and scoped to the agent's own CN+O; the operator routes
// (enqueue/approve/reject) are bearer gated.
type Service struct {
	reg     *Registry
	known   TenantKnown
	revoked RevokedFunc
	admin   string
}

// NewService builds a Service. known may be nil (any non-empty tenant O);
// revoked SHOULD be wired to the CA (nil = fail-closed deny). admin is the
// bearer secret for the operator routes.
func NewService(reg *Registry, known TenantKnown, revoked RevokedFunc, adminSecret string) *Service {
	return &Service{reg: reg, known: known, revoked: revoked, admin: adminSecret}
}

// auth validates the forwarded mTLS identity + CRL (fail-closed). On failure it
// writes 403 and returns ok=false.
//
// WIRING-CRITICAL (F2c): this TRUSTS X-Client-Cert-* (and the operator routes
// trust X-Operator) as set by nginx. It is ONLY safe when (a) a dedicated nginx
// location terminates mTLS and forwards verify/DN/serial for these exact paths
// (the generic /agent/ location CLEARS X-Client-Cert-*, so without it the agent
// routes fail closed), (b) nginx STRIPS any client-supplied X-Operator and sets
// it from the gsad session, and (c) the control-plane's :8080 is reachable only
// from nginx (not other compose neighbors). Mounting this service without those
// lets a direct caller forge identity. Do not enable REMEDIATION before F2c.
func (s *Service) auth(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, err := Authorize(
		r.Header.Get("X-Client-Cert-Verify"),
		r.Header.Get("X-Client-Cert-DN"),
		s.known,
	)
	if err != nil {
		log.Printf("remediation: authz negada: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return Identity{}, false
	}
	serial := normalizeSerial(r.Header.Get("X-Client-Cert-Serial"))
	if s.revoked == nil || s.revoked(serial) {
		log.Printf("remediation: CRL negada (cn=%s serial=%s wired=%v)", id.CN, serial, s.revoked != nil)
		http.Error(w, "forbidden", http.StatusForbidden)
		return Identity{}, false
	}
	return id, true
}

func (s *Service) adminOK(w http.ResponseWriter, r *http.Request) bool {
	want := "Bearer " + s.admin
	if s.admin == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// PollHandler serves GET /v1/remediation-jobs: the next approved job for the
// agent (CN+O), or 204. The returned job carries its signature; the agent MUST
// verify it against the pinned remediation pubkey before acting.
func (s *Service) PollHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.auth(w, r)
		if !ok {
			return
		}
		job, has := s.reg.Poll(id.CN, id.O)
		if !has {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, job)
	}
}

// AckHandler serves POST /v1/remediation-jobs/{id}/ack: the agent accepted the
// job and will apply it. Scoped to the agent's CN+O; foreign/unknown id → 404.
func (s *Service) AckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.auth(w, r)
		if !ok {
			return
		}
		jobID := r.PathValue("id")
		if jobID == "" {
			http.Error(w, "job id obrigatório", http.StatusBadRequest)
			return
		}
		if !s.reg.Ack(jobID, id.CN, id.O) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ReportHandler serves POST /v1/remediation-jobs/{id}/report: the agent reports
// its apply result (applied/failed + before/after/rollback_token). Scoped to
// CN+O; foreign/unknown id → 404. APPLIED is not terminal — the server verifies
// later by re-scan.
func (s *Service) ReportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.auth(w, r)
		if !ok {
			return
		}
		jobID := r.PathValue("id")
		if jobID == "" {
			http.Error(w, "job id obrigatório", http.StatusBadRequest)
			return
		}
		var res Result
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&res); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		if res.Status != "applied" && res.Status != "failed" {
			http.Error(w, "status deve ser applied|failed", http.StatusBadRequest)
			return
		}
		if !s.reg.Report(jobID, id.CN, id.O, &res) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// enqueueBody is the operator enqueue payload.
type enqueueBody struct {
	Tenant    string          `json:"tenant"`
	AgentID   string          `json:"agent_id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	NotBefore string          `json:"not_before,omitempty"` // RFC3339
	NotAfter  string          `json:"not_after,omitempty"`  // RFC3339
	TTL       string          `json:"ttl,omitempty"`        // Go duration
}

// EnqueueHandler serves POST /api/v1/remediation/jobs (admin bearer): create a
// PENDING_APPROVAL job. It is NOT signed and NOT deliverable until Approve.
func (s *Service) EnqueueHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		var body enqueueBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		req := EnqueueRequest{
			Tenant:  body.Tenant,
			AgentID: body.AgentID,
			Type:    Type(body.Type),
			Payload: body.Payload,
		}
		if body.NotBefore != "" {
			if t, err := time.Parse(time.RFC3339, body.NotBefore); err == nil {
				req.NotBefore = t
			}
		}
		if body.NotAfter != "" {
			if t, err := time.Parse(time.RFC3339, body.NotAfter); err == nil {
				req.NotAfter = t
			}
		}
		if body.TTL != "" {
			if d, err := time.ParseDuration(body.TTL); err == nil {
				req.TTL = d
			}
		}
		job, err := s.reg.Enqueue(req)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"job": job})
	}
}

// ApproveHandler serves POST /api/v1/remediation/jobs/{id}/approve (admin bearer):
// the human approval gate — it SIGNS the job and makes it deliverable. The
// approver identity (X-Operator, set by nginx from the gsad session, or a body
// field) is REQUIRED and recorded for audit. Nothing is signed without it.
func (s *Service) ApproveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		jobID := r.PathValue("id")
		if jobID == "" {
			http.Error(w, "job id obrigatório", http.StatusBadRequest)
			return
		}
		approver := r.Header.Get("X-Operator")
		if approver == "" {
			var b struct {
				ApprovedBy string `json:"approved_by"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&b)
			approver = b.ApprovedBy
		}
		if approver == "" {
			http.Error(w, "aprovador obrigatório (X-Operator ou approved_by)", http.StatusBadRequest)
			return
		}
		job, err := s.reg.Approve(jobID, approver)
		if err != nil {
			if err == ErrNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		log.Printf("remediation: job %s aprovado por %q (tenant=%s agent=%s)", job.JobID, approver, job.Tenant, job.AgentID)
		writeJSON(w, http.StatusOK, map[string]any{"job": job})
	}
}

// RejectHandler serves POST /api/v1/remediation/jobs/{id}/reject (admin bearer).
func (s *Service) RejectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(w, r) {
			return
		}
		jobID := r.PathValue("id")
		if jobID == "" {
			http.Error(w, "job id obrigatório", http.StatusBadRequest)
			return
		}
		approver := r.Header.Get("X-Operator")
		if approver == "" {
			http.Error(w, "aprovador obrigatório (X-Operator)", http.StatusBadRequest)
			return
		}
		if err := s.reg.Reject(jobID, approver); err != nil {
			if err == ErrNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "erro interno", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// Register wires all remediation routes onto mux. Intended to be mounted DARK
// (behind REMEDIATION_ENABLED) by the control-plane main in a later slice (F2c);
// the agent routes additionally require nginx mTLS gating + CRL forwarding, and
// the operator routes require the bearer/auth_request gate.
func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("GET /v1/remediation-jobs", s.PollHandler())
	mux.Handle("POST /v1/remediation-jobs/{id}/ack", s.AckHandler())
	mux.Handle("POST /v1/remediation-jobs/{id}/report", s.ReportHandler())
	mux.Handle("POST /api/v1/remediation/jobs", s.EnqueueHandler())
	mux.Handle("POST /api/v1/remediation/jobs/{id}/approve", s.ApproveHandler())
	mux.Handle("POST /api/v1/remediation/jobs/{id}/reject", s.RejectHandler())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
