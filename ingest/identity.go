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
//	enforce  both answer 403, and so does an identity nginx did not establish
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
// An identity nginx did not establish — no DN, no serial while a CRL is wired, an
// X-Client-Cert-Verify other than SUCCESS — is logged once per agent: log accepts it
// (an nginx that predates the forwarding: deploy transition), enforce refuses it. So
// enforce requires the nginx profile with mTLS (default.conf). Never the standalone
// profile until the mTLS parity slice: without mTLS, whatever X-Client-Cert-* the
// client sends reaches the ingest.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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
		what = "modo=enforce — agent_id≠CN do certificado, certificado revogado ou identidade não estabelecida pelo nginx " +
			"(sem DN, sem serial, verify≠SUCCESS) → 403; exige o nginx com mTLS (default.conf), nunca o perfil standalone"
	default:
		what = "modo=log (padrão) — agent_id≠CN do certificado, certificado revogado e identidade não estabelecida pelo nginx " +
			"só geram log, o inventário é aceito; INGEST_AGENT_IDENTITY=enforce passa a responder 403"
	}
	revocation := "revogação não conferida (sem CRL)"
	if crl != nil {
		revocation = "revogação pela CRL do control-plane (CRL indisponível ⇒ loga e aceita)"
	}
	s.logf("%s%s; %s", head, what, revocation)
}

// agentIdentityOK applies the identity mode to an inventory whose body claims
// agentID, against the certificate nginx verified. It writes a 403 and returns false
// only in enforce mode, which refuses, in this order:
//   - an identity nginx did not establish: X-Client-Cert-Verify sent and not SUCCESS,
//     no X-Client-Cert-DN, or no X-Client-Cert-Serial while a CRL is wired (log mode
//     accepts it — an nginx without the forwarding, deploy transition);
//   - a revoked certificate;
//   - an agent_id that is not the certificate's CN.
func (s *Server) agentIdentityOK(w http.ResponseWriter, r *http.Request, agentID string) bool {
	if s.identity == IdentityOff {
		return true
	}
	enforce := s.identity == IdentityEnforce
	verdict := " — modo log: aceito"
	if enforce {
		verdict = " — 403"
	}
	id := clipLogValue(agentID) // the body's agent_id, bounded for log lines and log-once keys
	dn := strings.TrimSpace(r.Header.Get("X-Client-Cert-DN"))
	serial := strings.TrimSpace(r.Header.Get("X-Client-Cert-Serial"))
	verify, verifySent := r.Header.Get("X-Client-Cert-Verify"), len(r.Header.Values("X-Client-Cert-Verify")) > 0
	cn := certCN(dn)

	// An identity nginx did not establish: nothing trustworthy to compare or look up.
	var gaps []string
	if verifySent && verify != "SUCCESS" {
		gaps = append(gaps, fmt.Sprintf("X-Client-Cert-Verify=%q", clipLogValue(verify)))
	}
	if dn == "" {
		gaps = append(gaps, "sem X-Client-Cert-DN")
	}
	if serial == "" && s.crl != nil {
		gaps = append(gaps, "sem X-Client-Cert-Serial")
	}
	if len(gaps) > 0 {
		what := strings.Join(gaps, ", ")
		if s.noted.first(what + "|" + id) {
			hint := "transição de deploy: atualize a location /ingest/ do nginx"
			if enforce {
				hint = "enforce exige o nginx com mTLS repassando DN, verify e serial do cert"
			}
			s.logf("ingest: identidade do agente não estabelecida pelo nginx (agent_id=%q: %s)%s (%s; logado uma vez por agente)", id, what, verdict, hint)
		}
		if enforce {
			http.Error(w, "identidade do certificado não estabelecida", http.StatusForbidden)
			return false
		}
	}

	// Revocation before the CN: what a revoked certificate claims does not matter.
	if serial != "" && s.crl != nil {
		switch revoked, known := s.crl.Revoked(serial); {
		case !known:
			s.warnCRLUnavailable()
		case revoked:
			s.logf("ingest: certificado revogado no inventário (agent_id=%q cn=%q serial=%s)%s", id, clipLogValue(cn), clipLogValue(serial), verdict)
			if enforce {
				http.Error(w, "certificado revogado", http.StatusForbidden)
				return false
			}
		}
	}

	if dn != "" && cn != agentID {
		s.logf("ingest: agent_id≠CN (agent_id=%q cn=%q)%s", id, clipLogValue(cn), verdict)
		if enforce {
			http.Error(w, "agent_id difere do CN do certificado", http.StatusForbidden)
			return false
		}
	}
	return true
}

// maxLogValue bounds what a log line (or a log-once key) carries of a value that came
// with the request: the X-Client-Cert-* headers (an nginx forwards the certificate's,
// a standalone deploy whatever the client sent) and, as a second line of defense, the
// agent_id (already refused above maxAgentIDBytes). The same 128 bytes as an agent
// id, so a real one is never cut.
const maxLogValue = maxAgentIDBytes

// clipLogValue returns v cut to at most maxLogValue bytes on a character boundary,
// marked with "…" when cut.
func clipLogValue(v string) string {
	if len(v) <= maxLogValue {
		return v
	}
	cut := maxLogValue
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
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
