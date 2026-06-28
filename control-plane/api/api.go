// Package api exposes the control-plane admin HTTP API.
//
// Endpoints (all require Authorization: Bearer <ADMIN_SECRET>):
//
//	POST   /api/v1/tokens              — mint a bootstrap token; response is a YAML enrollment bundle
//	GET    /api/v1/tokens              — list tokens (JSON, no secrets)
//	DELETE /api/v1/tokens/{id}         — revoke a token
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// Handler is the admin HTTP handler. Use New to create.
type Handler struct {
	tm          *tokens.Manager
	authority   *ca.CA
	serverURL   string
	adminSecret string
}

// New returns an admin Handler. serverURL is the public URL of the control-plane
// enrollment endpoint (e.g. "https://control.suricatoos.example.com"); it is
// embedded in every bundle so agents know where to enroll. adminSecret is the
// shared secret expected in "Authorization: Bearer <secret>" admin requests.
func New(tm *tokens.Manager, authority *ca.CA, serverURL, adminSecret string) *Handler {
	return &Handler{tm: tm, authority: authority, serverURL: serverURL, adminSecret: adminSecret}
}

// Handler returns an http.Handler serving all /api/v1/ routes.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/tokens", h.withAuth(h.createToken))
	mux.HandleFunc("GET /api/v1/tokens", h.withAuth(h.listTokens))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", h.withAuth(h.revokeToken))
	return mux
}

// withAuth wraps a handler with admin secret authentication.
func (h *Handler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != h.adminSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// mintRequest is the JSON body for POST /api/v1/tokens.
type mintRequest struct {
	Type      string `json:"type"` // "single_host" or "deployment"
	Tenant    string `json:"tenant"`
	Policy    string `json:"policy"`
	TTLHours  int    `json:"ttl_hours"`  // defaults to 24
	MaxUses   int    `json:"max_uses"`   // deployment only; defaults to tokens.MaxDeploymentUses
	CreatedBy string `json:"created_by"` // optional label
}

// createToken mints a bootstrap token and returns a YAML enrollment bundle
// as a downloadable attachment. The token secret is embedded in the bundle and
// is shown only once.
func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req mintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	tokType := tokens.SingleHost
	if req.Type == "deployment" {
		tokType = tokens.Deployment
	}

	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	maxUses := req.MaxUses
	if maxUses <= 0 {
		if tokType == tokens.Deployment {
			maxUses = tokens.MaxDeploymentUses
		} else {
			maxUses = 1
		}
	}

	minted, err := h.tm.Mint(tokens.MintRequest{
		Type:      tokType,
		Scope:     tokens.Scope{Tenant: req.Tenant, Policy: req.Policy},
		TTL:       ttl,
		MaxUses:   maxUses,
		CreatedBy: req.CreatedBy,
	})
	if err != nil {
		http.Error(w, "mint failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	bundle := buildBundle(minted, h.authority.Fingerprint(), h.serverURL)
	fname := fmt.Sprintf("enroll-%s.yaml", minted.ID)
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(bundle))
}

// tokenRecord is the JSON representation of a token for list responses.
type tokenRecord struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Tenant    string    `json:"tenant"`
	Policy    string    `json:"policy,omitempty"`
	MaxUses   int       `json:"max_uses"`
	Remaining int       `json:"remaining"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	RevokedBy string    `json:"revoked_by,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// listTokens returns all tokens as JSON (no secrets).
func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	recs, err := h.tm.List()
	if err != nil {
		http.Error(w, "list failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]tokenRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, tokenRecord{
			ID:        rec.ID,
			Type:      string(rec.Type),
			Tenant:    rec.Scope.Tenant,
			Policy:    rec.Scope.Policy,
			MaxUses:   rec.MaxUses,
			Remaining: rec.Remaining(),
			ExpiresAt: rec.ExpiresAt,
			Revoked:   rec.Revoked,
			RevokedBy: rec.RevokedBy,
			CreatedBy: rec.CreatedBy,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// revokeToken revokes a token by ID.
func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing token id", http.StatusBadRequest)
		return
	}
	if err := h.tm.Revoke(id, "admin-api"); err != nil {
		switch err {
		case tokens.ErrNotFound:
			http.Error(w, "token not found", http.StatusNotFound)
		case tokens.ErrRevoked:
			http.Error(w, "already revoked", http.StatusConflict)
		default:
			http.Error(w, "revoke failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "id": id})
}

// buildBundle returns the YAML content for an enrollment bundle.
// The token secret is included once and never stored again after this point.
func buildBundle(m tokens.Minted, caPin, serverURL string) string {
	return fmt.Sprintf(`# Suricatoos Agent — enrollment bundle
# token_id:  %s
# type:      %s
# tenant:    %s
# expires:   %s
# max_uses:  %d
#
# Usage:
#   suricatoos-agent enroll \
#     --server "%s" \
#     --token "%s" \
#     --ca-pin "%s"
#
# The token secret above is shown ONCE. Store this file securely.
# Delete it after the agent enrolls (or after expiry).
server: "%s"
token: "%s"
ca_pin: "%s"
`,
		m.ID,
		string(m.Record.Type),
		m.Record.Scope.Tenant,
		m.Record.ExpiresAt.UTC().Format(time.RFC3339),
		m.Record.MaxUses,
		serverURL,
		m.Token,
		caPin,
		serverURL,
		m.Token,
		caPin,
	)
}
