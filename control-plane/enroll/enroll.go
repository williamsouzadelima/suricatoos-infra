// Package enroll is the control-plane enrollment service: it exchanges a valid
// bootstrap token + CSR for a signed mTLS client certificate, binding the cert
// to the token's tenant/policy scope.
package enroll

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// ErrBadRequest marks a malformed/invalid enrollment request (vs. a token-policy
// rejection, which surfaces the tokens.* sentinel errors).
var ErrBadRequest = errors.New("requisição de enrollment inválida")

// Request is the enrollment payload an agent POSTs.
type Request struct {
	Token   string `json:"token"`
	CSR     string `json:"csr"` // PEM
	AgentID string `json:"agent_id"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Response carries the issued client certificate, the CA to pin, and the ingest
// endpoint the agent should report to (so the operator needn't supply it again).
type Response struct {
	Certificate string `json:"certificate"`          // PEM
	CACert      string `json:"ca_cert"`              // PEM
	IngestURL   string `json:"ingest_url,omitempty"` // where the agent pushes inventory
}

// Signer issues a client certificate from a verified CSR. *ca.CA satisfies it;
// the interface keeps the Service testable (e.g. a failing signer).
type Signer interface {
	SignClientCSR(csr *x509.CertificateRequest, p ca.CertProfile, ttl time.Duration, now time.Time) ([]byte, error)
	SignClientCSRIssued(csr *x509.CertificateRequest, p ca.CertProfile, ttl time.Duration, now time.Time) (ca.IssuedCert, error)
	CertPEM() []byte
}

// Service ties the token manager and the CA into the enrollment flow.
type Service struct {
	tokens    *tokens.Manager
	signer    Signer
	now       func() time.Time
	certTTL   time.Duration
	ingestURL string
}

// Option configures a Service.
type Option func(*Service)

// WithClock injects a clock (tests).
func WithClock(f func() time.Time) Option { return func(s *Service) { s.now = f } }

// WithCertTTL sets the issued client-certificate lifetime.
func WithCertTTL(d time.Duration) Option { return func(s *Service) { s.certTTL = d } }

// WithIngestURL sets the ingest endpoint returned to agents on enrollment, so a
// successfully enrolled agent learns where to push inventory without a separate
// out-of-band flag.
func WithIngestURL(u string) Option { return func(s *Service) { s.ingestURL = u } }

// NewService builds an enrollment Service. Default cert TTL is 90 days.
func NewService(tm *tokens.Manager, s Signer, opts ...Option) *Service {
	svc := &Service{tokens: tm, signer: s, now: func() time.Time { return time.Now().UTC() }, certTTL: 90 * 24 * time.Hour}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

// Enroll validates the token and CSR and issues a scoped client certificate.
//
// Order (hardened after the security review):
//  1. cheap, read-only token Validate FIRST — rejects unknown/expired/revoked/
//     exhausted/out-of-scope before any expensive CSR work (anti-DoS on this
//     unauthenticated endpoint);
//  2. parse + verify the CSR (proof-of-possession) and check CN == agent_id;
//  3. sign the certificate;
//  4. Consume the token LAST (atomic commit). A signing failure therefore never
//     burns a single-use token, and a malformed request never consumes one.
//
// Under a race two callers may both sign; only one Consume succeeds, the loser
// gets ErrExhausted and its certificate is discarded (never returned).
func (s *Service) Enroll(req Request) (Response, error) {
	if req.AgentID == "" || req.CSR == "" || req.Token == "" {
		return Response{}, fmt.Errorf("%w: campos obrigatórios ausentes", ErrBadRequest)
	}
	if err := validateAgentID(req.AgentID); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}

	// (1) Gate barato primeiro.
	rec, err := s.tokens.Validate(req.Token, tokens.Scope{OS: req.OS, Arch: req.Arch})
	if err != nil {
		return Response{}, err
	}
	if rec.Scope.Tenant == "" { // defesa-em-profundidade: Mint exige Tenant
		return Response{}, fmt.Errorf("%w: token sem tenant", ErrBadRequest)
	}

	// (2) CSR: proof-of-possession + consistência de identidade.
	csr, err := parseCSR(req.CSR)
	if err != nil {
		return Response{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return Response{}, fmt.Errorf("%w: proof-of-possession falhou", ErrBadRequest)
	}
	if csr.Subject.CommonName != req.AgentID {
		return Response{}, fmt.Errorf("%w: CN do CSR difere de agent_id", ErrBadRequest)
	}

	// (3) Assina ANTES de consumir. Tenant/policy do token são ATRIBUÍDOS (o
	// enrollee não os escolhe). O serial é gravado na trilha de auditoria para
	// permitir revogação do certificado quando o token for revogado.
	issued, err := s.signer.SignClientCSRIssued(csr, ca.CertProfile{
		CommonName: req.AgentID,
		Org:        rec.Scope.Tenant,
		OrgUnit:    rec.Scope.Policy,
	}, s.certTTL, s.now())
	if err != nil {
		return Response{}, err
	}

	// (4) Commit: consome o token (re-checa cap/exp/revogação/escopo sob lock).
	if _, err := s.tokens.Consume(req.Token, tokens.Enrollment{
		AgentID:    req.AgentID,
		OS:         req.OS,
		Arch:       req.Arch,
		Subject:    req.AgentID,
		CertSerial: issued.SerialHex,
	}); err != nil {
		return Response{}, err
	}
	return Response{
		Certificate: string(issued.PEM),
		CACert:      string(s.signer.CertPEM()),
		IngestURL:   s.ingestURL,
	}, nil
}

// Handler returns an http.Handler serving POST /enroll. Client-facing errors are
// generic (the detailed reason is not echoed, to avoid leaking the token's
// expected scope or x509 internals).
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "requisição inválida", http.StatusBadRequest)
			return
		}
		resp, err := s.Enroll(req)
		if err != nil {
			http.Error(w, clientMessage(err), statusFor(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

// statusFor maps enrollment errors to HTTP status codes.
func statusFor(err error) int {
	switch {
	case errors.Is(err, tokens.ErrAgentAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, tokens.ErrExpired),
		errors.Is(err, tokens.ErrRevoked),
		errors.Is(err, tokens.ErrExhausted),
		errors.Is(err, tokens.ErrScopeMismatch),
		errors.Is(err, tokens.ErrNotFound):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

// clientMessage returns a generic, non-leaking message for the client; the
// detailed err stays server-side (for logs/metrics, wired in Fase 2).
func clientMessage(err error) string {
	switch {
	case errors.Is(err, tokens.ErrAgentAlreadyExists):
		return "agent_id já registrado"
	case errors.Is(err, tokens.ErrScopeMismatch):
		return "escopo não permitido para este token"
	case errors.Is(err, tokens.ErrExpired),
		errors.Is(err, tokens.ErrRevoked),
		errors.Is(err, tokens.ErrExhausted),
		errors.Is(err, tokens.ErrNotFound):
		return "token inválido ou não autorizado"
	case errors.Is(err, ErrBadRequest):
		return "requisição de enrollment inválida"
	default:
		return "falha no enrollment"
	}
}

// validateAgentID rejects empty/oversized ids and any control or DN-special
// character, preventing ambiguous Distinguished-Name rendering downstream.
func validateAgentID(id string) error {
	if len(id) == 0 || len(id) > 128 {
		return errors.New("agent_id deve ter 1..128 caracteres")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(",=+\"\\;<>", r) {
			return errors.New("agent_id contém caractere inválido")
		}
	}
	return nil
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: PEM de CSR inválido", ErrBadRequest)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: CSR ilegível", ErrBadRequest)
	}
	return csr, nil
}
