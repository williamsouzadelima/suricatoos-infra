package sensorjobs

import (
	"fmt"
	"strings"
)

// Identity is the sensor identity from the verified mTLS cert (forwarded by nginx
// as X-Client-Cert-DN). O is the tenant AND the partition key; OU is the policy.
type Identity struct {
	CN string
	O  string
	OU string
}

// TenantKnown reports whether o is a registered tenant. Injected so the queue
// doesn't hardcode a single tenant (multi-tenant: O is the partition key, not a
// fixed AllowedO). A nil checker accepts any non-empty O.
type TenantKnown func(o string) bool

// Authorize validates the forwarded mTLS headers for a sensor route and returns
// the identity. Requires verify==SUCCESS, OU==scanner-sensor (exact), and a
// non-empty O that TenantKnown accepts. The serial → CRL check is done separately
// (fail-closed) by the caller.
func Authorize(verify, dn string, known TenantKnown) (Identity, error) {
	if verify != "SUCCESS" {
		return Identity{}, fmt.Errorf("cert não verificado (verify=%q)", verify)
	}
	f := parseDN(dn)
	id := Identity{CN: firstOf(f, "CN"), O: firstOf(f, "O"), OU: firstOf(f, "OU")}
	if !hasValue(f, "OU", PolicyScannerSensor) {
		return Identity{}, fmt.Errorf("OU=%q não autorizado (requer OU=%q)", id.OU, PolicyScannerSensor)
	}
	if id.O == "" {
		return Identity{}, fmt.Errorf("cert sem Organization (tenant)")
	}
	if known != nil && !known(id.O) {
		return Identity{}, fmt.Errorf("tenant %q desconhecido", id.O)
	}
	return id, nil
}

// parseDN parses a subject DN into attribute-type (upper) → values, accepting both
// nginx forms: RFC2253 ("CN=x,OU=y,O=z") and legacy OpenSSL oneline
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
