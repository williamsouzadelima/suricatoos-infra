package sensorjobs

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RevokedFunc reports whether a client-cert serial (hex) is revoked. The control
// plane IS the CA, so its revoked set is authoritative and always in-memory. A nil
// RevokedFunc means CRL is not wired → the service denies everything (fail-closed).
type RevokedFunc func(serialHex string) bool

// Service serves the sensor scan-job routes. All sensor-facing routes are mTLS +
// CRL gated; the admin enqueue and list routes are bearer gated.
type Service struct {
	reg     *Registry
	known   TenantKnown
	revoked RevokedFunc
}

// NewService builds a Service. known may be nil (accept any non-empty tenant O);
// revoked SHOULD be wired to the CA (nil = fail-closed deny).
func NewService(reg *Registry, known TenantKnown, revoked RevokedFunc) *Service {
	return &Service{reg: reg, known: known, revoked: revoked}
}

// AuthorizeRequest validates the forwarded mTLS identity + CRL (fail-closed) and
// writes 403 on failure. Exposed so sibling sensor routes (e.g. the feed service)
// reuse the exact same gate. Returns ok=false when the response was already written.
func (s *Service) AuthorizeRequest(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.auth(w, r)
	return ok
}

// auth validates the forwarded mTLS identity + CRL (fail-closed). On failure it
// writes 403 and returns ok=false.
func (s *Service) auth(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, err := Authorize(
		r.Header.Get("X-Client-Cert-Verify"),
		r.Header.Get("X-Client-Cert-DN"),
		s.known,
	)
	if err != nil {
		log.Printf("sensorjobs: authz negada: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return Identity{}, false
	}
	serial := normalizeSerial(r.Header.Get("X-Client-Cert-Serial"))
	if s.revoked == nil || s.revoked(serial) {
		log.Printf("sensorjobs: CRL negada (cn=%q serial=%q wired=%v)", id.CN, serial, s.revoked != nil)
		http.Error(w, "forbidden", http.StatusForbidden)
		return Identity{}, false
	}
	return id, true
}

// PollHandler serves GET /v1/scan-jobs: the next job for the sensor's tenant, or
// 204. Route MUST be nginx mTLS-gated (verify + DN + serial forwarded).
func (s *Service) PollHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.auth(w, r)
		if !ok {
			return
		}
		job, has := s.reg.Poll(id.O)
		if !has {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, job)
	}
}

// AckHandler serves POST /v1/scan-jobs/{id}/ack: the sensor concludes the job
// (DONE) — it acks only after the scan ran and its report was pushed. Owner-scoped
// by the sensor's tenant O; a foreign/unknown id — or a job the sensor never
// received (still PENDING) — → 404 (no enumeration). A repeated ack is a 204.
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
		if !s.reg.Ack(jobID, id.O) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// HeartbeatHandler serves POST /v1/heartbeat: an authenticated liveness ping from
// a sensor. It validates the mTLS identity + CRL (fail-closed) and returns 204.
// The body (feed_version/gvmd_up/active_jobs) is accepted for logging; richer
// posture surfacing (the Sensors UI) is a later slice.
func (s *Service) HeartbeatHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.auth(w, r)
		if !ok {
			return
		}
		var hb struct {
			SensorID    string `json:"sensor_id"`
			FeedVersion string `json:"feed_version"`
			GvmdUp      bool   `json:"gvmd_up"`
			ActiveJobs  int    `json:"active_jobs"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&hb)
		// Everything but the numbers and the flag comes from outside (the cert and the
		// body), so it is quoted: a hostile feed_version cannot start a log line.
		log.Printf("sensorjobs: heartbeat tenant=%q cn=%q feed=%q gvmd_up=%v jobs=%d",
			id.O, id.CN, hb.FeedVersion, hb.GvmdUp, hb.ActiveJobs)
		w.WriteHeader(http.StatusNoContent)
	}
}

// enqueueBody is the admin enqueue payload (POST /api/v1/tenants/{t}/scan-jobs).
type enqueueBody struct {
	Targets     []string `json:"targets"`
	Ports       string   `json:"ports,omitempty"`
	ScanConfig  string   `json:"scan_config,omitempty"`
	AliveTest   string   `json:"alive_test,omitempty"`
	MaxDuration string   `json:"max_duration,omitempty"`
	Source      string   `json:"source,omitempty"`
	TTL         string   `json:"ttl,omitempty"`
}

// EnqueueHandler serves POST /api/v1/tenants/{t}/scan-jobs (admin bearer): enqueue
// a scan job for tenant {t}. Targets are scope-gated; out-of-scope entries are
// dropped and reported. 422 when nothing is left in scope.
func (s *Service) EnqueueHandler(adminSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminSecret) {
			return
		}
		tenant := r.PathValue("t")
		if tenant == "" {
			http.Error(w, "tenant obrigatório", http.StatusBadRequest)
			return
		}
		var body enqueueBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		src := Source(body.Source)
		if src == "" {
			src = SourceOperator
		}
		var ttl time.Duration
		if body.TTL != "" {
			if d, err := time.ParseDuration(body.TTL); err == nil {
				ttl = d
			}
		}
		job, dropped, err := s.reg.Enqueue(EnqueueRequest{
			Tenant: tenant, Source: src, Targets: body.Targets, Ports: body.Ports,
			ScanConfig: body.ScanConfig, AliveTest: body.AliveTest, MaxDuration: body.MaxDuration, TTL: ttl,
		})
		if len(dropped) > 0 {
			log.Printf("sensorjobs: tenant=%q %d alvo(s) fora de escopo dropados: %q", tenant, len(dropped), dropped)
		}
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "dropped": dropped})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"job": job, "dropped": dropped})
	}
}

// ListHandler serves GET /api/v1/tenants/{t}/scan-jobs (admin bearer): tenant {t}'s
// jobs, newest first (created_at desc), so an operator can follow dispatch → DONE.
// Strictly that tenant's jobs — another tenant's are never returned. Optional
// filters: state (case-insensitive) and limit (default 200, capped at 1000); a bad
// state/limit is a 400, not an empty list, so a typo cannot read as "no jobs". A
// tenant with no jobs (or an unknown one) gets 200 with an empty list.
func (s *Service) ListHandler(adminSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminSecret) {
			return
		}
		tenant := r.PathValue("t")
		if tenant == "" {
			http.Error(w, "tenant obrigatório", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		var f ListFilter
		if v := strings.TrimSpace(q.Get("state")); v != "" {
			f.State = JobState(strings.ToUpper(v))
			if !f.State.valid() {
				http.Error(w, "state inválido (use PENDING|DELIVERED|DONE|EXPIRED; ACKED só em registros antigos)", http.StatusBadRequest)
				return
			}
		}
		if v := strings.TrimSpace(q.Get("limit")); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				http.Error(w, "limit deve ser um inteiro >= 1", http.StatusBadRequest)
				return
			}
			f.Limit = n
		}
		jobs, total := s.reg.List(tenant, f)
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs, "total": total, "limit": clampLimit(f.Limit)})
	}
}

// adminOK gates the operator routes on the admin bearer. The comparison is
// constant-time and an EMPTY secret closes the route (a naive compare would let
// "Authorization: Bearer " through when the secret is unset). On failure it writes
// 401 and returns false.
func adminOK(w http.ResponseWriter, r *http.Request, adminSecret string) bool {
	want := "Bearer " + adminSecret
	if adminSecret == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// normalizeSerial lowercases a hex serial and strips separators/leading zeros so
// nginx's "0A:1B" and the CA's big.Int hex compare equal.
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", " ", "", "0x", "").Replace(s)
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
