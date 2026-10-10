package aiproviders

import (
	_ "embed"
	"net/http"
)

//go:embed admin.html
var adminHTML []byte

// AdminPageHandler serves the static admin page for managing providers. The page
// is inert HTML/JS carrying NO secret: it calls the admin API with a bearer the
// operator enters at runtime (kept only in the tab's sessionStorage, never
// persisted). It is meant for a PRIVATE admin surface — reach the control-plane
// directly (localhost/tunnel), not the public nginx. A strict CSP blocks every
// external resource; connect-src 'self' permits only the same-origin API, so a
// stored key can never be exfiltrated to another origin.
func (s *Service) AdminPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(adminHTML)
	}
}
