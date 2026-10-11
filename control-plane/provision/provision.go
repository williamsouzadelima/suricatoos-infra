// Package provision powers frictionless agent install: given a logged-in GSA
// session (gated by nginx), it mints a short-lived single-use enrollment token
// and returns a ready-to-paste, OS-specific install command with the token,
// server and CA-pin already embedded — no copying tokens by hand.
//
// SECURITY: this endpoint mints enrollment tokens WITHOUT the admin bearer, so it
// MUST be reachable only behind nginx session validation (auth_request to gsad).
// It is mounted on a path nginx guards; never expose it unguarded. As defense in
// depth the handler also requires the sessiongate marker, which nginx sets only on
// session-gated locations (see Handler).
package provision

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/installcmd"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// tokenTTL bounds how long a provisioned token is valid — long enough to run the
// installer, short enough that a leaked command is useless later.
const tokenTTL = 1 * time.Hour

// Service builds install commands backed by freshly-minted tokens.
type Service struct {
	tm        *tokens.Manager
	caPin     string // CA fingerprint (--ca-pin), from authority.Fingerprint()
	serverURL string // CONTROL_PLANE_URL handed to the agent (ends in /v1)
}

// New returns a provision Service. serverURL is CONTROL_PLANE_URL (e.g.
// https://scanner.suricatoos.com/agent/v1); the install scripts are fetched from its
// scheme+host (see installcmd.PublicBase).
func New(tm *tokens.Manager, caPin, serverURL string) *Service {
	return &Service{tm: tm, caPin: caPin, serverURL: serverURL}
}

type response struct {
	OS        string    `json:"os"`
	Command   string    `json:"command"`
	Server    string    `json:"server"`
	CAPin     string    `json:"ca_pin"`
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Handler serves GET /provision/install?os=<linux|darwin|windows>. It is wrapped in
// sessiongate.Require: a request without the marker nginx sets only on session-gated
// locations is refused (403) before any token is minted. When the command cannot be
// rendered safely (see installcmd) the minted token is revoked and the answer is 500.
func (s *Service) Handler() http.HandlerFunc {
	return sessiongate.Require(func(w http.ResponseWriter, r *http.Request) {
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

		cmd, err := s.command(goos, minted.Token)
		if err != nil {
			// Nothing was handed out, so do not leave a live token behind.
			_ = s.tm.Revoke(minted.ID, "provision (comando recusado)")
			log.Printf("provision: comando %s recusado: %v", goos, err)
			http.Error(w, "falha ao montar o comando de instalação", http.StatusInternalServerError)
			return
		}

		resp := response{
			OS:        goos,
			Command:   cmd,
			Server:    s.serverURL,
			CAPin:     s.caPin,
			TokenID:   minted.ID,
			ExpiresAt: minted.Record.ExpiresAt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// command renders the one-liner the operator pastes. The builders live in installcmd,
// shared with enrollcmd, so both endpoints hand out the same command: Linux/macOS pipe
// install.sh into sh (it picks the binary by `uname -s`); Windows downloads install.ps1
// to the invoking user's own temp directory and runs it with params. See the
// installcmd package comment for why the Windows command looks the way it does.
func (s *Service) command(goos, token string) (string, error) {
	switch goos {
	case "windows":
		return installcmd.Windows(s.serverURL, token, s.caPin)
	default: // linux, darwin
		return installcmd.Unix(s.serverURL, token, s.caPin)
	}
}
