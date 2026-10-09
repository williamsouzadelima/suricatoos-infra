package remediation

import (
	"fmt"
	"strings"
)

// Identity is the agent identity from the verified mTLS cert (forwarded by nginx
// as X-Client-Cert-DN). CN is the agent_id, O the tenant, OU the policy. A
// remediation job is scoped to BOTH CN and O, so a cert binds to exactly one host.
type Identity struct {
	CN string
	O  string
	OU string
}

// TenantKnown reports whether o is a registered, remediation-enabled tenant.
// Injected so the queue never hardcodes a tenant. A nil checker accepts any
// non-empty O (the per-tenant enable gate lives in the wiring layer).
type TenantKnown func(o string) bool

// Authorize validates the forwarded mTLS headers for an agent remediation route
// and returns the identity. Requires verify==SUCCESS, OU==agent-endpoint (exact),
// and a non-empty O that TenantKnown accepts. The serial → CRL check is done
// separately (fail-closed) by the caller.
//
// NOTE: the DN parser below mirrors sensorjobs.parseDN (same escaping defense);
// kept local to avoid coupling the packages. If one changes, change both (or
// extract a shared cert-identity package).
func Authorize(verify, dn string, known TenantKnown) (Identity, error) {
	if verify != "SUCCESS" {
		return Identity{}, fmt.Errorf("cert não verificado (verify=%q)", verify)
	}
	f := parseDN(dn)
	id := Identity{CN: firstOf(f, "CN"), O: firstOf(f, "O"), OU: firstOf(f, "OU")}
	if !hasValue(f, "OU", PolicyAgentEndpoint) {
		return Identity{}, fmt.Errorf("OU=%q não autorizado (requer OU=%q)", id.OU, PolicyAgentEndpoint)
	}
	if id.O == "" {
		return Identity{}, fmt.Errorf("cert sem Organization (tenant)")
	}
	if id.CN == "" {
		return Identity{}, fmt.Errorf("cert sem CN (agent_id)")
	}
	if known != nil && !known(id.O) {
		return Identity{}, fmt.Errorf("tenant %q desconhecido", id.O)
	}
	return id, nil
}

// parseDN parses a subject DN into attribute-type (upper) → values, accepting
// both nginx forms: RFC2253 ("CN=x,OU=y,O=z") and legacy OpenSSL oneline
// ("/O=z/OU=y/CN=x"). Backslash escapes are honored so a crafted value can't
// smuggle an extra attribute.
func parseDN(dn string) map[string][]string {
	dn = strings.TrimSpace(dn)
	out := map[string][]string{}
	if dn == "" {
		return out
	}
	var pairs []string
	if strings.HasPrefix(dn, "/") && !strings.Contains(dn, ",") {
		pairs = splitUnescaped(dn[1:], '/')
	} else {
		pairs = splitUnescaped(dn, ',')
	}
	for _, p := range pairs {
		p = strings.TrimSpace(p)
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(p[:eq]))
		out[key] = append(out[key], unescapeDN(strings.TrimSpace(p[eq+1:])))
	}
	return out
}

func splitUnescaped(s string, sep byte) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == sep {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	return append(parts, cur.String())
}

func unescapeDN(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func firstOf(f map[string][]string, k string) string {
	if v := f[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func hasValue(f map[string][]string, k, want string) bool {
	for _, v := range f[k] {
		if v == want {
			return true
		}
	}
	return false
}

// normalizeSerial lowercases a hex serial and strips separators/leading zeros so
// nginx's "0A:1B" and the CA's big.Int hex compare equal.
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", " ", "", "0x", "").Replace(s)
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
