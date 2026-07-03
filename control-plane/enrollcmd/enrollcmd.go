// Package enrollcmd generates a ready-to-paste enrollment command for a specific
// tenant, with a freshly-minted token already embedded — the "dynamic per-tenant
// token" that activates an agent/container without anyone copying tokens by hand.
//
// SECURITY (ADR-0007 risk #4 — cross-tenant minting): unlike the session-gated
// provision endpoint (which hardcodes Tenant:"default"), this endpoint is
// admin-bearer gated AND the tenant is taken from the URL path and VALIDATED against
// the authoritative tenant registry (unknown/disabled tenant → 404). It never mints
// for a tenant the caller merely names without the registry knowing it. A UI or CLI
// layer sits on top; the tenant is chosen server-side by an authenticated admin,
// never smuggled in as a free-form request field the control-plane trusts blindly.
package enrollcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// TenantKnown reports whether name is a known+enabled tenant (registry.Known).
type TenantKnown func(name string) bool

// Config wires the command renderer.
type Config struct {
	TM          *tokens.Manager
	Known       TenantKnown     // nil → any non-empty tenant is accepted (dev only)
	Tenants     func() []string // enabled tenant names, for the UI selector (session handler)
	CAPin       string          // authority.Fingerprint() → --ca-pin / CA_PIN
	ServerURL   string          // CONTROL_PLANE_URL (e.g. https://scanner.suricatoos.com/agent/v1)
	Image       string          // container image ref (docker target); empty → a sane default
	AdminSecret string          // Bearer gate
}

// Service renders per-tenant enrollment commands backed by fresh tokens.
type Service struct{ cfg Config }

// New builds a Service.
func New(cfg Config) *Service {
	if cfg.Image == "" {
		cfg.Image = "ghcr.io/williamsouzadelima/suricatoos-agent:stable"
	}
	return &Service{cfg: cfg}
}

// defaults for a deployment token: one command activates a fleet within a window.
const (
	defaultMaxUses  = 100
	defaultTTLHours = 72
	maxTTLHours     = 24 * 30 // 30d ceiling
)

type response struct {
	Tenant    string    `json:"tenant"`
	Target    string    `json:"target"` // docker | linux | windows
	Command   string    `json:"command"`
	Server    string    `json:"server"`
	CAPin     string    `json:"ca_pin"`
	Image     string    `json:"image,omitempty"`
	TokenID   string    `json:"token_id"`
	MaxUses   int       `json:"max_uses"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Handler serves GET /api/v1/tenants/{t}/enroll-command (ADMIN-BEARER). The tenant
// comes from the {t} path. Query params: target (docker|linux|windows), max_uses,
// ttl_hours. For automation/CLI.
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminSecret == "" || r.Header.Get("Authorization") != "Bearer "+s.cfg.AdminSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.serve(w, r, r.PathValue("t"))
	}
}

// SessionHandler serves GET /provision/enroll-command?tenant=<t> for the GSA UI.
// It is NOT bearer-gated: it MUST be mounted behind the nginx session gate (cookie
// GSAD_SID + same-origin), exactly like /provision/install. The tenant comes from
// the ?tenant= query. The GSA is single-admin (only the admin logs into the web),
// so the session gate is an admin gate in practice; the {t} is still validated
// against the registry, so an unknown tenant is refused regardless.
func (s *Service) SessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.serve(w, r, r.URL.Query().Get("tenant"))
	}
}

// SessionTenantsHandler serves GET /provision/tenants (session-gated by nginx) —
// the enabled tenant names for the UI selector. No token minted, no secrets.
func (s *Service) SessionTenantsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var names []string
		if s.cfg.Tenants != nil {
			names = s.cfg.Tenants()
		}
		if names == nil {
			names = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenants": names})
	}
}

// serve is the shared core: validate tenant, mint a scoped token, render the command.
// Query params (both handlers): target=docker|linux|windows, max_uses, ttl_hours.
func (s *Service) serve(w http.ResponseWriter, r *http.Request, tenant string) {
	if tenant == "" {
		http.Error(w, "tenant obrigatório", http.StatusBadRequest)
		return
	}
	// Cross-tenant guard: only mint for a tenant the registry actually knows.
	if s.cfg.Known != nil && !s.cfg.Known(tenant) {
		http.Error(w, "tenant desconhecido ou desabilitado", http.StatusNotFound)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		target = "docker"
	}
	switch target {
	case "docker", "linux", "windows":
	default:
		http.Error(w, "target deve ser docker, linux ou windows", http.StatusBadRequest)
		return
	}

	maxUses := clampInt(r.URL.Query().Get("max_uses"), defaultMaxUses, 1, tokens.MaxDeploymentUses)
	ttlHours := clampInt(r.URL.Query().Get("ttl_hours"), defaultTTLHours, 1, maxTTLHours)

	typ := tokens.Deployment
	if maxUses == 1 {
		typ = tokens.SingleHost
	}
	minted, err := s.cfg.TM.Mint(tokens.MintRequest{
		Type:      typ,
		Scope:     tokens.Scope{Tenant: tenant, Policy: "agent-endpoint"},
		TTL:       time.Duration(ttlHours) * time.Hour,
		MaxUses:   maxUses,
		CreatedBy: "enroll-command (" + tenant + ")",
	})
	if err != nil {
		http.Error(w, "falha ao gerar token", http.StatusInternalServerError)
		return
	}

	resp := response{
		Tenant:    tenant,
		Target:    target,
		Command:   s.command(target, minted.Token),
		Server:    s.cfg.ServerURL,
		CAPin:     s.cfg.CAPin,
		TokenID:   minted.ID,
		MaxUses:   maxUses,
		ExpiresAt: minted.Record.ExpiresAt,
	}
	if target == "docker" {
		resp.Image = s.cfg.Image
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// command renders the paste-ready command with the token embedded.
func (s *Service) command(target, token string) string {
	switch target {
	case "docker":
		// One container that auto-enrolls into the tenant and inventories the HOST.
		return fmt.Sprintf(
			`docker run -d --name suricatoos-agent --restart unless-stopped `+
				`--hostname "$(hostname)" `+
				`-e ENROLL_TOKEN=%s -e CLOUD_BASE_URL=%s -e CA_PIN=%s -e AGENT_ID="$(hostname)" `+
				`-v /:/host:ro -v suricatoos-agent:/var/lib/suricatoos-agent %s`,
			shq(token), shq(s.cfg.ServerURL), shq(s.cfg.CAPin), s.cfg.Image)
	case "windows":
		base := publicBase(s.cfg.ServerURL)
		return fmt.Sprintf(
			`powershell -ExecutionPolicy Bypass -Command "$f=Join-Path $env:TEMP 'suricatoos-install.ps1'; iwr -useb %s/install.ps1 -OutFile $f; & $f -Server '%s' -Token '%s' -CaPin '%s'"`,
			base, s.cfg.ServerURL, token, s.cfg.CAPin)
	default: // linux (binary installer)
		base := publicBase(s.cfg.ServerURL)
		return fmt.Sprintf(
			`curl -fsSL %s/install.sh | sudo sh -s -- --server %s --token %s --ca-pin %s`,
			base, s.cfg.ServerURL, shq(token), shq(s.cfg.CAPin))
	}
}

// publicBase strips the path from serverURL → scheme://host (for install scripts).
func publicBase(serverURL string) string {
	if i := strings.Index(serverURL, "://"); i >= 0 {
		rest := serverURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return serverURL[:i+3] + rest[:j]
		}
		return serverURL
	}
	return serverURL
}

// shq single-quotes a value for POSIX sh only when it contains anything outside the
// safe set (tokens are base64url + "st_." — safe; be defensive anyway).
func shq(v string) string {
	safe := true
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == ':' || c == '.' || c == '_' || c == '-' || c == '/') {
			safe = false
			break
		}
	}
	if safe && v != "" {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

func clampInt(s string, def, lo, hi int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < lo {
		return def
	}
	if n > hi {
		return hi
	}
	return n
}
