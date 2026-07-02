package scanlaunch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
)

// Service exposes the mTLS scan-request routes and owns the reconciler + CRL.
// It is constructed only when SCAN_LAUNCH_ENABLED wiring is present; the routes
// still 503 on POST while cfg.Enabled is false (dark deploy).
type Service struct {
	cfg   Config
	reg   *Registry
	crl   *CRL
	allow *Allowlist
	rc    *reconciler
}

// New builds a Service from cfg. It fails only on unrecoverable config errors
// (bad allowlist CIDR / unreadable registry) so a misconfig is loud, not silent.
func New(cfg Config) (*Service, error) {
	allow, err := NewAllowlist(cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	reg, err := NewRegistry(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	crl := NewCRL(cfg.CRLURL, cfg.RequireCRL)
	rc := newReconciler(reg, cfg, execBridge(cfg))
	return &Service{cfg: cfg, reg: reg, crl: crl, allow: allow, rc: rc}, nil
}

// Start launches the CRL refresher and the single reconciler goroutine.
func (s *Service) Start(ctx context.Context) {
	s.crl.Start(ctx)
	go s.rc.Run(ctx)
	log.Printf("scanlaunch: ativo (enabled=%v, allowlist_vazia=%v, max_concurrent=%d, usuario_gvmd=%s, crl_required=%v)",
		s.cfg.Enabled, s.allow.Empty(), s.cfg.MaxConcurrent, s.cfg.GmpUsername, s.cfg.RequireCRL)
}

// Register mounts the scan-request routes on mux (Go 1.22 pattern routing).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/scan-request", s.handleCreate)
	mux.HandleFunc("GET /v1/scan-request/{id}", s.handleGet)
	mux.HandleFunc("DELETE /v1/scan-request/{id}", s.handleDelete)
}

// auth validates the forwarded mTLS identity and the CRL. Returns the identity
// or writes a 403 and returns ok=false.
func (s *Service) auth(w http.ResponseWriter, r *http.Request) (certIdentity, bool) {
	id, err := authorize(
		r.Header.Get("X-Client-Cert-Verify"),
		r.Header.Get("X-Client-Cert-DN"),
		s.cfg.AllowedO, s.cfg.AllowedOU,
	)
	if err != nil {
		log.Printf("scanlaunch: authz negada: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return certIdentity{}, false
	}
	if err := s.crl.Check(r.Header.Get("X-Client-Cert-Serial")); err != nil {
		log.Printf("scanlaunch: CRL negada (cn=%s): %v", id.CN, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return certIdentity{}, false
	}
	return id, true
}

type createResponse struct {
	RequestID        string `json:"request_id"`
	State            State  `json:"state"`
	Idempotent       bool   `json:"idempotent"`
	PollAfterSeconds int    `json:"poll_after_seconds"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Enabled {
		http.Error(w, "scan launch desabilitado", http.StatusServiceUnavailable)
		return
	}
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		http.Error(w, "json inválido", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != SchemaVersion {
		http.Error(w, "schema_version não suportada", http.StatusBadRequest)
		return
	}
	if req.RengineScanHistoryID <= 0 {
		http.Error(w, "rengine_scan_history_id obrigatório", http.StatusBadRequest)
		return
	}
	hosts, err := s.normalizeHosts(&req)
	if err != nil {
		// 422: the request is well-formed JSON but its targets are not scannable
		// (hostname, denied range, off-allowlist, or over caps).
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	req.Hosts = hosts

	job, created, err := s.reg.FindOrCreate(&req, id, s.cfg.RescanWindow)
	if err != nil {
		log.Printf("scanlaunch: create falhou: %v", err)
		http.Error(w, "erro interno", http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		log.Printf("scanlaunch: job %s criado (scan_history=%d, hosts=%d, tenant=%s)",
			job.RequestID, job.ScanHistoryID, len(job.Hosts), job.Tenant)
	}
	writeJSON(w, status, createResponse{
		RequestID:        job.RequestID,
		State:            job.State,
		Idempotent:       !created,
		PollAfterSeconds: 120,
	})
}

type statusResponse struct {
	RequestID            string    `json:"request_id"`
	RengineScanHistoryID int64     `json:"rengine_scan_history_id"`
	State                State     `json:"state"`
	Progress             int       `json:"progress"`
	GVMTaskID            string    `json:"gvm_task_id,omitempty"`
	GVMReportID          string    `json:"gvm_report_id,omitempty"`
	Error                string    `json:"error,omitempty"`
	Findings             []Finding `json:"findings,omitempty"`
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	job := s.lookupOwned(w, r, id)
	if job == nil {
		return
	}
	resp := statusResponse{
		RequestID:            job.RequestID,
		RengineScanHistoryID: job.ScanHistoryID,
		State:                job.State,
		Progress:             job.Progress,
		GVMTaskID:            job.GVMTaskID,
		GVMReportID:          job.GVMReportID,
		Error:                job.Error,
	}
	if job.State == StateCompleted {
		resp.Findings = readFindings(s.cfg.FindingsDir, job.RequestID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	job := s.lookupOwned(w, r, id)
	if job == nil {
		return
	}
	if job.State.terminal() {
		writeJSON(w, http.StatusOK, map[string]any{"request_id": job.RequestID, "state": job.State})
		return
	}
	updated, _ := s.reg.Update(job.RequestID, func(j *Job) { j.StopRequested = true })
	log.Printf("scanlaunch: stop solicitado para %s (cn=%s)", job.RequestID, id.CN)
	writeJSON(w, http.StatusAccepted, map[string]any{"request_id": updated.RequestID, "state": "STOPPING"})
}

// lookupOwned fetches the job and enforces owner scope: a job owned by a different
// tenant returns 404 (not 403) so a caller can't enumerate others' request_ids.
func (s *Service) lookupOwned(w http.ResponseWriter, r *http.Request, id certIdentity) *Job {
	job, ok := s.reg.Get(r.PathValue("id"))
	if !ok || job.Tenant != id.O {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return job
}

// normalizeHosts validates and canonicalizes the target set: every host must pass
// the default-deny allowlist (IP-literal only), ports must be in range, and the
// per-request host cap and the union-of-ports cap are enforced.
func (s *Service) normalizeHosts(req *ScanRequest) ([]Host, error) {
	if len(req.Hosts) == 0 {
		return nil, fmt.Errorf("hosts vazio")
	}
	if len(req.Hosts) > s.cfg.MaxHosts {
		return nil, fmt.Errorf("hosts (%d) excede SCAN_MAX_HOSTS (%d)", len(req.Hosts), s.cfg.MaxHosts)
	}
	out := make([]Host, 0, len(req.Hosts))
	union := map[int]bool{}
	for _, h := range req.Hosts {
		ip, err := s.allow.CheckHost(h.IP)
		if err != nil {
			return nil, err
		}
		ports, err := sortedUniquePorts(h.Ports)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", ip, err)
		}
		for _, p := range ports {
			union[p] = true
		}
		out = append(out, Host{IP: ip, Ports: ports})
	}
	if len(union) > s.cfg.MaxPorts {
		return nil, fmt.Errorf("portas distintas (%d) excede SCAN_MAX_PORTS (%d)", len(union), s.cfg.MaxPorts)
	}
	return out, nil
}

func sortedUniquePorts(ports []int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("porta fora de faixa: %d", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sem portas")
	}
	sort.Ints(out)
	return out, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
