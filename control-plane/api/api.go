// Package api exposes the control-plane admin HTTP API.
//
// Endpoints (all require Authorization: Bearer <ADMIN_SECRET>):
//
//	POST   /api/v1/tokens              — mint a bootstrap token; response is a YAML enrollment bundle
//	GET    /api/v1/tokens              — list tokens (JSON, no secrets)
//	DELETE /api/v1/tokens/{id}         — revoke a token
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	ingestURL   string
	adminSecret string
	logf        func(format string, args ...any) // log.Printf; tests capture it
}

// New returns an admin Handler. serverURL is the public URL of the control-plane
// enrollment endpoint (e.g. "https://control.suricatoos.example.com"); it is
// embedded in every bundle so agents know where to enroll. ingestURL is the
// public inventory endpoint, embedded in the bundle for operator visibility (the
// agent also learns it from the enrollment response). adminSecret is the shared
// secret expected in "Authorization: Bearer <secret>" admin requests.
func New(tm *tokens.Manager, authority *ca.CA, serverURL, ingestURL, adminSecret string) *Handler {
	return &Handler{tm: tm, authority: authority, serverURL: serverURL, ingestURL: ingestURL, adminSecret: adminSecret, logf: log.Printf}
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
		if !bearerOK(r, h.adminSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// bearerOK reports whether r carries exactly "Authorization: Bearer <secret>". The
// compare is constant-time (no timing side channel on the secret) and an empty
// secret never matches: "Bearer " with an empty token would otherwise open the API.
func bearerOK(r *http.Request, secret string) bool {
	if secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+secret)) == 1
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

	bundle := buildBundle(minted, h.authority.Fingerprint(), h.serverURL, h.ingestURL)
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

// revokeResult is the body of a revocation that fully happened (200 "revoked"), or of
// a repeated one that found everything revoked already (409 "already revoked").
// Persisted says whether the revocation list is on disk: always false without
// CRL_FILE, where it lives in memory only (the control-plane warns about it at boot).
type revokeResult struct {
	Status    string `json:"status"`
	ID        string `json:"id"` // the token
	Persisted bool   `json:"persisted"`
}

// revokeFailure is the 500 body of a revocation that did not fully happen: the token
// store could not record it (status "failed", token_revoked false), or the token was
// revoked but revoking — or saving the revocation of — some of its certificates
// failed (status "partial").
type revokeFailure struct {
	Status        string   `json:"status"`         // "failed" or "partial"
	ID            string   `json:"id"`             // the token
	TokenRevoked  bool     `json:"token_revoked"`  // the token store recorded the revocation
	CertsRevoked  int      `json:"certs_revoked"`  // certificates revoked AND persisted
	FailedSerials []string `json:"failed_serials"` // the first maxFailedInBody that failed
	FailedCount   int      `json:"failed_count"`   // all that failed or were not persisted
	Persisted     bool     `json:"persisted"`      // the revocation list was saved to disk
	Error         string   `json:"error"`
}

const (
	maxFailedInBody = 100 // failed_serials lists these many; failed_count counts them all
	maxFailedInLog  = 20  // serials named in the one summary log line
)

// revokeToken revokes a token by ID and invalidates all mTLS certificates that
// were issued under it by adding their serials to the CA's revocation list.
//
// The token is revoked first. A certificate whose revocation fails, or is kept only in
// memory because CRL_FILE could not be written, turns the answer into a 500 that says
// exactly that: the token IS revoked, which serials failed (the first maxFailedInBody,
// and how many), and to repeat the DELETE; one summary line goes to the log. Until the
// list is saved such a certificate is blocked in memory, and after a restart the boot
// reconciliation (ReconcileRevocations) blocks it again from the token store — with
// TOKEN_DB_PATH set; with neither that nor CRL_FILE, a restart loses it. It used to be
// a 200 that silently lost the revocation.
//
// Repeating the DELETE of a token that is already revoked redoes the certificate
// revocation (RevokeCertSerials is idempotent and saves the list again): the same 500
// while something still fails, and 409 "already revoked" only when every serial is
// revoked AND, with CRL_FILE set, on disk. That also covers a request that crashed
// between the token store and the CRL.
//
// Every answer but the 404/400 is JSON and says "persisted": whether the revocation
// list is on disk — always false without CRL_FILE.
func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing token id", http.StatusBadRequest)
		return
	}
	rec, err := h.tm.RevokeRecord(id, "admin-api")
	already := errors.Is(err, tokens.ErrRevoked)
	switch {
	case already:
		// Fall through to (re)do the certificates; rec carries the enrollments.
	case errors.Is(err, tokens.ErrNotFound):
		http.Error(w, "token not found", http.StatusNotFound)
		return
	case err != nil:
		h.logf("api: revogar o token %s: o token store não gravou a revogação: %v", id, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(revokeFailure{
			Status:        "failed",
			ID:            id,
			FailedSerials: []string{},
			Error: "o token NÃO foi revogado: o token store não gravou a revogação — detalhes no log do " +
				"control-plane; corrija a causa e repita o DELETE.",
		})
		return
	}
	revoked, failed, persisted := h.revokeCerts(id, rec.Enrollments)
	w.Header().Set("Content-Type", "application/json")
	if len(failed) > 0 {
		shown := failed
		if len(shown) > maxFailedInBody {
			shown = shown[:maxFailedInBody]
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(revokeFailure{
			Status:        "partial",
			ID:            id,
			TokenRevoked:  true,
			CertsRevoked:  revoked,
			FailedSerials: shown,
			FailedCount:   len(failed),
			Persisted:     persisted,
			Error: fmt.Sprintf("o token foi revogado, mas a revogação de %d de %d certificado(s) falhou ou não foi gravada "+
				"em disco — detalhes no log do control-plane; repita o DELETE: ele refaz e grava a revogação (responde 409 "+
				"quando todos estiverem revogados e gravados). Até lá eles seguem bloqueados em memória, e num restart a "+
				"reconciliação de boot os bloqueia de novo a partir do token store (com TOKEN_DB_PATH).",
				len(failed), len(failed)+revoked),
		})
		return
	}
	if already {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(revokeResult{Status: "already revoked", ID: id, Persisted: persisted})
		return
	}
	json.NewEncoder(w).Encode(revokeResult{Status: "revoked", ID: id, Persisted: persisted})
}

// revokeCerts revokes every certificate serial recorded in enrollments in ONE batch
// (one save of the list — not one per certificate) and returns how many are revoked
// and saved, which failed, and whether the list is on disk. Each kind of failure is
// ONE summary log line (count and the first maxFailedInLog serials), also when the
// token has no certificates and only the save of the list failed. A serial the save
// could not persist counts as failed although the CA blocks it in memory (and, after a
// restart, the boot reconciliation blocks it again from the token store).
func (h *Handler) revokeCerts(tokenID string, enrollments []tokens.Enrollment) (revoked int, failed []string, persisted bool) {
	var serials []string
	for _, enr := range enrollments {
		if enr.CertSerial != "" {
			serials = append(serials, enr.CertSerial)
		}
	}
	_, invalid, err := h.authority.RevokeCertSerials(serials, time.Now().UTC())
	notHex := make(map[string]bool, len(invalid))
	for _, s := range invalid {
		notHex[s] = true
	}
	failed = []string{}
	var unsaved []string
	for _, s := range serials {
		switch {
		case notHex[s]:
			failed = append(failed, s)
		case err != nil:
			failed = append(failed, s)
			unsaved = append(unsaved, s)
		default:
			revoked++
		}
	}
	if len(invalid) > 0 {
		h.logf("api: token %s revogado, mas %d certificado(s) não foram revogados — serial inválido: %s",
			tokenID, len(invalid), firstSerials(invalid))
	}
	switch {
	case err != nil && len(unsaved) > 0:
		h.logf("api: token %s revogado, mas a lista de revogação não foi gravada: %v — %d certificado(s) bloqueado(s) só em memória: %s; "+
			"repita o DELETE para gravar (num restart a reconciliação de boot os bloqueia de novo a partir do token store, com TOKEN_DB_PATH)",
			tokenID, err, len(unsaved), firstSerials(unsaved))
	case err != nil:
		h.logf("api: token %s revogado (sem certificados), mas a lista de revogação não foi gravada: %v — ela pode guardar revogações "+
			"anteriores ainda não gravadas; repita o DELETE para gravá-la", tokenID, err)
	}
	return revoked, failed, err == nil && h.authority.PersistsRevocations()
}

// firstSerials lists the first maxFailedInLog serials, and how many more there are.
func firstSerials(serials []string) string {
	if len(serials) <= maxFailedInLog {
		return strings.Join(serials, ", ")
	}
	return fmt.Sprintf("%s e mais %d", strings.Join(serials[:maxFailedInLog], ", "), len(serials)-maxFailedInLog)
}

// ReconcileRevocations puts the certificate serials of every revoked token back on
// the CA's revocation list, in one batch (one save). Run it at boot, after the CA has
// loaded its CRL file and with the token store open: it closes, with nobody acting,
// the window in which a token is revoked but its certificates are not — a crash
// between the two writes, or a restart before the operator repeated a DELETE whose
// save failed. Without CRL_FILE it rebuilds the in-memory list from the token store.
//
// It is idempotent: a serial already listed is left as is; one that was missing gets
// now as its revocation time (the original instant was lost with it; what blocks the
// certificate is being listed). It returns how many serials were added, the ones that
// are not valid hex, and the error of listing the tokens or of saving the list — after
// which the serials are still revoked in memory, so the caller logs it and goes on.
func ReconcileRevocations(tm *tokens.Manager, authority *ca.CA, now time.Time) (added int, invalid []string, err error) {
	recs, err := tm.List()
	if err != nil {
		return 0, nil, fmt.Errorf("listar os tokens: %w", err)
	}
	var serials []string
	for _, rec := range recs {
		if !rec.Revoked {
			continue
		}
		for _, enr := range rec.Enrollments {
			if enr.CertSerial != "" {
				serials = append(serials, enr.CertSerial)
			}
		}
	}
	return authority.RevokeCertSerials(serials, now)
}

// buildBundle returns the YAML content for an enrollment bundle.
// The token secret is included once and never stored again after this point.
func buildBundle(m tokens.Minted, caPin, serverURL, ingestURL string) string {
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
#   # then: suricatoos-agent run   (the ingest URL is learned from enrollment;
#   #                                pass --ingest only to override)
#
# The token secret above is shown ONCE. Store this file securely.
# Delete it after the agent enrolls (or after expiry).
server: "%s"
token: "%s"
ca_pin: "%s"
ingest_url: "%s"
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
		ingestURL,
	)
}
