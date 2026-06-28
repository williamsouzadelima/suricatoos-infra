// Package tokens implements the control-plane bootstrap-token lifecycle: minting,
// validation, single-use / deployment-cap consumption, scoping, TTL, revocation
// and an audit trail.
//
// Design (docs/adr/0004-bootstrap-token.md): the wire token is an opaque,
// high-entropy secret "st_<id>.<secret>". The server stores ONLY sha256(secret)
// plus metadata — the secret is shown to the operator once and never persisted.
// Single-use, deployment caps and revocation REQUIRE server-side state, so the
// token carries no claims; the Record is the source of truth.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Sentinel errors. Test with errors.Is.
var (
	ErrMalformed     = errors.New("token malformado")
	ErrNotFound      = errors.New("token inválido ou inexistente")
	ErrExpired       = errors.New("token expirado")
	ErrRevoked       = errors.New("token revogado")
	ErrExhausted     = errors.New("token esgotado (limite de enrollments atingido)")
	ErrScopeMismatch = errors.New("escopo não autorizado para este token")
)

// Type is the consumption model of a bootstrap token.
type Type string

const (
	// SingleHost permits exactly one enrollment (install pontual).
	SingleHost Type = "single_host"
	// Deployment permits up to MaxUses enrollments within the TTL window
	// (deploy em massa via GPO/MDM/Ansible).
	Deployment Type = "deployment"
)

// MaxDeploymentUses caps a deployment token's enrollment count, bounding both
// blast radius and the per-token audit/clone cost.
const MaxDeploymentUses = 100_000

// Scope binds a token (and the enrolled agent) to a tenant/policy and, optionally,
// to expected host attributes — the anti-confused-deputy / multi-tenant control.
type Scope struct {
	Tenant string `json:"tenant"`
	Policy string `json:"policy,omitempty"`
	OS     string `json:"os,omitempty"`   // GOOS esperado; vazio = qualquer
	Arch   string `json:"arch,omitempty"` // GOARCH esperado; vazio = qualquer
	Group  string `json:"group,omitempty"`
}

// permits reports whether the host attributes p are allowed by this token scope.
// Tenant/policy são atribuídos pelo token (não validados aqui). OS/arch são
// verificados ESTRITAMENTE: quando o token fixa um valor, o apresentado precisa
// ser não-vazio E igual (apresentar vazio NÃO satisfaz a restrição).
//
// AVISO: OS/arch são auto-declarados pelo enrollee (não atestados) — isto barra
// erro honesto de configuração, não um adversário determinado. É defesa em
// profundidade, não fronteira de segurança. A mensagem não revela o valor
// esperado (anti-leak). Ver ADR-0004.
func (s Scope) permits(p Scope) error {
	if s.OS != "" && p.OS != s.OS {
		return fmt.Errorf("%w (os)", ErrScopeMismatch)
	}
	if s.Arch != "" && p.Arch != s.Arch {
		return fmt.Errorf("%w (arch)", ErrScopeMismatch)
	}
	return nil
}

// Enrollment is one audited consumption of a token.
type Enrollment struct {
	At      time.Time `json:"at"`
	AgentID string    `json:"agent_id"`
	OS      string    `json:"os,omitempty"`
	Arch    string    `json:"arch,omitempty"`
	Subject string    `json:"subject,omitempty"`
}

// Record is the server-side source of truth for a minted token. The secret is
// never stored — only its SHA-256.
type Record struct {
	ID          string
	SecretHash  [32]byte
	Type        Type
	Scope       Scope
	MaxUses     int
	UsedCount   int
	ExpiresAt   time.Time
	Revoked     bool
	RevokedBy   string
	RevokedAt   time.Time
	CreatedBy   string
	CreatedAt   time.Time
	Enrollments []Enrollment
}

// Remaining reports how many enrollments the token still permits.
func (r Record) Remaining() int {
	if n := r.MaxUses - r.UsedCount; n > 0 {
		return n
	}
	return 0
}

// Minted is returned once by Mint. Token is the wire secret shown to the
// operator and never persisted.
type Minted struct {
	ID     string
	Token  string // "st_<id>.<secret>"
	Record Record
}

// Manager implements the token lifecycle over a Store.
type Manager struct {
	store Store
	now   func() time.Time
	rand  io.Reader
	mu    sync.Mutex // serializa Consume/Revoke (read-modify-write atômico)
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock injects a clock (tests).
func WithClock(f func() time.Time) Option { return func(m *Manager) { m.now = f } }

// WithRand injects an entropy source (tests).
func WithRand(r io.Reader) Option { return func(m *Manager) { m.rand = r } }

// NewManager builds a Manager. Defaults: real UTC clock and crypto/rand.
func NewManager(store Store, opts ...Option) *Manager {
	m := &Manager{store: store, now: func() time.Time { return time.Now().UTC() }, rand: rand.Reader}
	for _, o := range opts {
		o(m)
	}
	return m
}

// MintRequest describes a token to create.
type MintRequest struct {
	Type      Type
	Scope     Scope
	TTL       time.Duration
	MaxUses   int // usado só para Deployment
	CreatedBy string
}

// Mint creates a token and returns its one-time wire secret.
func (m *Manager) Mint(req MintRequest) (Minted, error) {
	switch req.Type {
	case SingleHost, Deployment:
	default:
		return Minted{}, fmt.Errorf("%w: tipo %q", ErrMalformed, req.Type)
	}
	if req.Scope.Tenant == "" {
		return Minted{}, errors.New("Scope.Tenant é obrigatório (binding multi-tenant; sem ele o cert sai sem Organization)")
	}
	if req.TTL <= 0 {
		return Minted{}, errors.New("TTL deve ser positivo")
	}
	maxUses := 1
	if req.Type == Deployment {
		if req.MaxUses < 1 || req.MaxUses > MaxDeploymentUses {
			return Minted{}, fmt.Errorf("MaxUses deve estar entre 1 e %d", MaxDeploymentUses)
		}
		maxUses = req.MaxUses
	}
	id, err := randToken(m.rand, 9)
	if err != nil {
		return Minted{}, err
	}
	secret, err := randToken(m.rand, 32)
	if err != nil {
		return Minted{}, err
	}
	now := m.now()
	rec := Record{
		ID:         id,
		SecretHash: sha256.Sum256([]byte(secret)),
		Type:       req.Type,
		Scope:      req.Scope,
		MaxUses:    maxUses,
		ExpiresAt:  now.Add(req.TTL),
		CreatedBy:  req.CreatedBy,
		CreatedAt:  now,
	}
	if err := m.store.Put(rec); err != nil {
		return Minted{}, err
	}
	return Minted{ID: id, Token: "st_" + id + "." + secret, Record: rec}, nil
}

// Validate checks a token WITHOUT consuming it (read-only pre-check).
func (m *Manager) Validate(token string, presented Scope) (Record, error) {
	return m.check(token, presented)
}

// Consume validates a token and atomically records an enrollment, enforcing the
// single-use / deployment cap. The presented host attributes come from enr.
func (m *Manager) Consume(token string, enr Enrollment) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.check(token, Scope{OS: enr.OS, Arch: enr.Arch})
	if err != nil {
		return Record{}, err
	}
	if enr.At.IsZero() {
		enr.At = m.now()
	}
	rec.UsedCount++
	rec.Enrollments = append(rec.Enrollments, enr)
	if err := m.store.Update(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Revoke marks a token revoked; no further enrollments are allowed.
func (m *Manager) Revoke(id, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.store.Get(id)
	if !ok {
		return ErrNotFound
	}
	rec.Revoked = true
	rec.RevokedBy = by
	rec.RevokedAt = m.now()
	return m.store.Update(rec)
}

func (m *Manager) check(token string, presented Scope) (Record, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return Record{}, err
	}
	rec, ok := m.store.Get(id)
	if !ok {
		return Record{}, ErrNotFound
	}
	want := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(rec.SecretHash[:], want[:]) != 1 {
		return Record{}, ErrNotFound // não distingue secret errado de id inexistente
	}
	if rec.Revoked {
		return Record{}, ErrRevoked
	}
	if m.now().After(rec.ExpiresAt) {
		return Record{}, ErrExpired
	}
	if rec.UsedCount >= rec.MaxUses {
		return Record{}, ErrExhausted
	}
	if err := rec.Scope.permits(presented); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func parseToken(tok string) (id, secret string, err error) {
	tok = strings.TrimPrefix(tok, "st_")
	id, secret, ok := strings.Cut(tok, ".")
	if !ok || id == "" || secret == "" {
		return "", "", ErrMalformed
	}
	return id, secret, nil
}

func randToken(r io.Reader, nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
