package ingest

// Agent identity on POST /v1/inventory.
//
// The inventory names its agent in the body (agent.agent_id), and the gvmd report,
// the lastSeen status and the Agents UI all key on it. Before this check, any
// enrolled agent — of any tenant — could therefore post an inventory as any other
// host, and a revoked certificate kept reporting until it expired. nginx verifies
// the client certificate on /ingest/ and forwards what it verified:
// X-Client-Cert-DN (whose CN is the enrolled agent id) and X-Client-Cert-Serial.
//
// INGEST_AGENT_IDENTITY picks what happens when they disagree with the body:
//
//	off      nothing is checked (the behavior before this check existed)
//	log      (default) agent_id ≠ CN and a revoked certificate are logged, and the
//	         inventory is accepted — the rule is observed before it is enforced
//	enforce  both answer 403
//
// Agents since 0.1.4 report agent_id = the CN of their certificate, so the rule
// matches the current fleet; an older agent reports its OS hostname, which differs
// from the CN when it enrolled with --agent-id or was renamed. Run in log mode until
// no "agent_id≠CN" line shows up, then switch to enforce.
//
// Revocation fails OPEN here, unlike scan-request and sensor-report (fail-closed):
// when no CRL has loaded yet, the inventory is logged and accepted. nginx has already
// authenticated the certificate (mTLS against the enrollment CA), a revoked one still
// expires on its own, and refusing every inventory of the whole fleet because the
// control-plane's CRL endpoint is down would be worse than the window it closes.
// A launch path (scan-request) or a tenant-partitioned import (sensor-report) has a
// different balance, so they keep failing closed.
//
// What nginx does not forward cannot be checked: an nginx without the DN/serial lines
// (deploy transition) is logged once per agent and accepted, in every mode.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IdentityMode is what POST /v1/inventory does about the agent's client certificate
// (INGEST_AGENT_IDENTITY).
type IdentityMode string

const (
	// IdentityOff checks nothing.
	IdentityOff IdentityMode = "off"
	// IdentityLog logs an agent_id that is not the certificate's CN and a revoked
	// certificate, and accepts the inventory. The default.
	IdentityLog IdentityMode = "log"
	// IdentityEnforce answers 403 to both.
	IdentityEnforce IdentityMode = "enforce"
)

// crlWarnEvery spaces the "CRL unavailable" lines: one per report of every agent
// would bury everything else while the control-plane is down.
const crlWarnEvery = 10 * time.Minute

// ParseIdentityMode parses an INGEST_AGENT_IDENTITY value (case and surrounding
// spaces ignored). "" is the default, log. Anything else is an error, returned with
// the default so a typo degrades to the observing mode, never to off or enforce.
func ParseIdentityMode(v string) (IdentityMode, error) {
	switch m := IdentityMode(strings.ToLower(strings.TrimSpace(v))); m {
	case "":
		return IdentityLog, nil
	case IdentityOff, IdentityLog, IdentityEnforce:
		return m, nil
	}
	return IdentityLog, fmt.Errorf("INGEST_AGENT_IDENTITY=%q inválido (use off, log ou enforce)", v)
}

// IdentityModeFromEnv reads INGEST_AGENT_IDENTITY; an invalid value is logged and the
// default (log) is used.
func IdentityModeFromEnv() IdentityMode {
	m, err := ParseIdentityMode(os.Getenv("INGEST_AGENT_IDENTITY"))
	if err != nil {
		log.Printf("ingest: %v — usando %q", err, m)
	}
	return m
}

// RevocationList answers whether a client-certificate serial is revoked. known is
// false when it cannot say (no CRL loaded yet). scanlaunch.CRL implements it.
type RevocationList interface {
	Revoked(serialHex string) (revoked, known bool)
}

// SetAgentIdentity sets the identity mode of POST /v1/inventory and the CRL it checks
// serials against (nil: revocation is not checked), and logs the configuration in
// effect. Call it once, before serving.
func (s *Server) SetAgentIdentity(mode IdentityMode, crl RevocationList) {
	s.identity, s.crl = mode, crl
	const head = "ingest: identidade do agente no inventário (INGEST_AGENT_IDENTITY): "
	var what string
	switch mode {
	case IdentityOff:
		s.logf("%smodo=off — o agent_id do corpo não é comparado ao CN do certificado e a revogação não é conferida", head)
		return
	case IdentityEnforce:
		what = "modo=enforce — agent_id≠CN do certificado ou certificado revogado → 403"
	default:
		what = "modo=log (padrão) — agent_id≠CN do certificado e certificado revogado só geram log, o inventário é aceito; INGEST_AGENT_IDENTITY=enforce passa a responder 403"
	}
	revocation := "revogação não conferida (sem CRL)"
	if crl != nil {
		revocation = "revogação pela CRL do control-plane (CRL indisponível ⇒ loga e aceita)"
	}
	s.logf("%s%s; %s", head, what, revocation)
}

// agentIdentityOK applies the identity mode to an inventory whose body claims
// agentID, against the certificate nginx verified. It writes a 403 and returns false
// only in enforce mode.
func (s *Server) agentIdentityOK(w http.ResponseWriter, r *http.Request, agentID string) bool {
	if s.identity == IdentityOff {
		return true
	}
	enforce := s.identity == IdentityEnforce
	verdict := " — modo log: aceito"
	if enforce {
		verdict = " — 403"
	}
	dn := strings.TrimSpace(r.Header.Get("X-Client-Cert-DN"))
	serial := strings.TrimSpace(r.Header.Get("X-Client-Cert-Serial"))
	cn := certCN(dn)

	// Revocation first: what a revoked certificate claims does not matter.
	if serial != "" && s.crl != nil {
		switch revoked, known := s.crl.Revoked(serial); {
		case !known:
			s.warnCRLUnavailable()
		case revoked:
			s.logf("ingest: certificado revogado no inventário (agent_id=%q cn=%q serial=%s)%s", agentID, cn, serial, verdict)
			if enforce {
				http.Error(w, "certificado revogado", http.StatusForbidden)
				return false
			}
		}
	}

	var missing []string
	if dn == "" {
		missing = append(missing, "X-Client-Cert-DN")
	}
	if serial == "" && s.crl != nil {
		missing = append(missing, "X-Client-Cert-Serial")
	}
	if len(missing) > 0 && s.noted.first(strings.Join(missing, "+")+"|"+agentID) {
		s.logf("ingest: inventário sem %s do nginx (agent_id=%q) — não conferido; aceito (transição de deploy: atualize a location /ingest/ do nginx; logado uma vez por agente)",
			strings.Join(missing, " e "), agentID)
	}

	if dn != "" && cn != agentID {
		s.logf("ingest: agent_id≠CN (agent_id=%q cn=%q)%s", agentID, cn, verdict)
		if enforce {
			http.Error(w, "agent_id difere do CN do certificado", http.StatusForbidden)
			return false
		}
	}
	return true
}

// warnCRLUnavailable logs, at most once per crlWarnEvery, that a serial could not be
// checked because no CRL has loaded.
func (s *Server) warnCRLUnavailable() {
	now := s.now()
	s.crlWarnMu.Lock()
	due := s.crlWarnAt.IsZero() || now.Sub(s.crlWarnAt) >= crlWarnEvery
	if due {
		s.crlWarnAt = now
	}
	s.crlWarnMu.Unlock()
	if due {
		s.logf("ingest: CRL indisponível — revogação do inventário não conferida; aceito (fail-open de propósito: o mTLS do nginx já autenticou o agente; scan-request e sensor-report seguem fail-closed)")
	}
}

// onceSet remembers the keys already logged, so a condition that lasts a whole deploy
// transition logs one line per agent instead of one per report. Bounded: when full
// it starts over (an agent may then be logged once more), since the keys carry the
// agent_id of the body, which any enrolled agent chooses.
type onceSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

const onceSetMax = 10000

// first reports whether key is new, and records it.
func (o *onceSet) first(key string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.seen[key]; ok {
		return false
	}
	if o.seen == nil || len(o.seen) >= onceSetMax {
		o.seen = make(map[string]struct{})
	}
	o.seen[key] = struct{}{}
	return true
}

// certCN returns the CommonName of the subject DN nginx forwards as X-Client-Cert-DN,
// or "". It accepts the same two forms as the control-plane's commands.agentCN (the
// Go modules are independent, so the logic is repeated here): RFC 2253
// ("CN=a,OU=p,O=t" — $ssl_client_s_dn since nginx 1.11.6) and the legacy OpenSSL
// one-line form ("/O=t/OU=p/CN=a"). On top of that it honors RFC 2253 escaping: a
// separator escaped inside another attribute cannot smuggle in a CN, and the escapes
// nginx writes are undone — every non-ASCII byte as \XX, a leading '#' or a trailing
// space as \c — so an agent_id like "estação-01" still equals its own certificate's CN.
func certCN(dn string) string {
	dn = strings.TrimSpace(dn)
	if strings.HasPrefix(dn, "/") {
		// Legacy one-line form: '/' cannot be escaped there; take the first CN.
		for _, part := range strings.Split(dn[1:], "/") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	for _, rdn := range splitRDNs(dn) {
		typ, val, ok := strings.Cut(rdn, "=")
		if ok && strings.EqualFold(strings.TrimSpace(typ), "CN") {
			return unescapeRFC2253(val)
		}
	}
	return ""
}

// splitRDNs splits an RFC 2253 DN on its unescaped separators — ',' between RDNs and
// '+' inside a multi-valued one — leaving the escapes for unescapeRFC2253.
func splitRDNs(dn string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++ // the escaped character (or the first digit of \XX) belongs to the value
		case ',', '+':
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	return append(parts, dn[start:])
}

// unescapeRFC2253 undoes the escapes of an RFC 2253 attribute value: "\XX" (two hex
// digits: one byte — OpenSSL writes each byte of a non-ASCII UTF-8 character so) and
// "\c" (the character c, taken literally).
func unescapeRFC2253(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		if i+2 < len(v) {
			if n, err := strconv.ParseUint(v[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(v[i+1])
		i++
	}
	return b.String()
}
