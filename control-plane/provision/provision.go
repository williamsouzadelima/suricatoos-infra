// Package provision powers frictionless agent install: given a logged-in GSA
// session (gated by nginx), it mints a short-lived single-use enrollment token
// and returns a ready-to-paste, OS-specific install command with the token,
// server and CA-pin already embedded — no copying tokens by hand.
//
// SECURITY: this endpoint mints enrollment tokens WITHOUT the admin bearer, so it
// MUST be reachable only behind nginx session validation (auth_request to gsad).
// It is mounted on a path nginx guards; never expose it unguarded.
package provision

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// tokenTTL bounds how long a provisioned token is valid — long enough to run the
// installer, short enough that a leaked command is useless later.
const tokenTTL = 1 * time.Hour

// Service builds install commands backed by freshly-minted tokens.
type Service struct {
	tm         *tokens.Manager
	caPin      string // CA fingerprint (--ca-pin), from authority.Fingerprint()
	serverURL  string // CONTROL_PLANE_URL handed to the agent (ends in /v1)
	publicBase string // scheme+host for the install scripts (derived from serverURL)
}

// New returns a provision Service. serverURL is CONTROL_PLANE_URL (e.g.
// https://scanner.suricatoos.com/agent/v1); the install-script base is derived
// from its scheme+host.
func New(tm *tokens.Manager, caPin, serverURL string) *Service {
	return &Service{tm: tm, caPin: caPin, serverURL: serverURL, publicBase: publicBase(serverURL)}
}

func publicBase(serverURL string) string {
	if u, err := url.Parse(serverURL); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return ""
}

type response struct {
	OS        string    `json:"os"`
	Command   string    `json:"command"`
	Server    string    `json:"server"`
	CAPin     string    `json:"ca_pin"`
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Handler serves GET /provision/install?os=<linux|darwin|windows>.
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		goos := r.URL.Query().Get("os")
		switch goos {
		case "linux", "darwin", "windows":
		default:
			http.Error(w, "os deve ser linux, darwin ou windows", http.StatusBadRequest)
			return
		}

		minted, err := s.tm.Mint(tokens.MintRequest{
			Type:      tokens.SingleHost,
			Scope:     tokens.Scope{Tenant: "default"},
			TTL:       tokenTTL,
			MaxUses:   1,
			CreatedBy: "provision (GSA)",
		})
		if err != nil {
			http.Error(w, "falha ao gerar token", http.StatusInternalServerError)
			return
		}

		resp := response{
			OS:        goos,
			Command:   s.command(goos, minted.Token),
			Server:    s.serverURL,
			CAPin:     s.caPin,
			TokenID:   minted.ID,
			ExpiresAt: minted.Record.ExpiresAt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// command renders the one-liner the operator pastes. Linux/macOS pipe install.sh
// into sh; Windows downloads install.ps1 to a temp file and runs it with params.
func (s *Service) command(goos, token string) string {
	switch goos {
	case "windows":
		return fmt.Sprintf(
			`powershell -ExecutionPolicy Bypass -Command "$f=Join-Path $env:TEMP 'suricatoos-install.ps1'; iwr -useb %s/install.ps1 -OutFile $f; & $f -Server '%s' -Token '%s' -CaPin '%s'"`,
			s.publicBase, s.serverURL, token, s.caPin)
	default: // linux, darwin
		return fmt.Sprintf(
			`curl -fsSL %s/install.sh | sudo sh -s -- --server %s --token %s --ca-pin %s`,
			s.publicBase, s.serverURL, token, escapeShell(s.caPin))
	}
}

// escapeShell guards against odd characters in the pin (it is hex+colons, but be
// safe): wrap in single quotes if it contains anything outside the safe set.
func escapeShell(v string) string {
	if v == "" {
		return "''"
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '.' || c == '_' || c == '-') {
			return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
		}
	}
	return v
}
