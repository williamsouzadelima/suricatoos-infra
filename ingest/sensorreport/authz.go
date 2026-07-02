package sensorreport

import (
	"fmt"
	"strings"
)

// Identity is the sensor identity from the verified mTLS cert. O is the tenant
// (partition key); OU is the policy.
type Identity struct {
	CN string
	O  string
	OU string
}

// authorize validates the forwarded mTLS headers for the sensor-report route:
// verify==SUCCESS, OU==scanner-sensor (exact), non-empty O. The tenant (O) is the
// authority for partitioning; a body "tenant" field is only cross-checked.
func authorize(verify, dn string) (Identity, error) {
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
	return id, nil
}

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
		out[strings.ToUpper(strings.TrimSpace(p[:eq]))] = append(
			out[strings.ToUpper(strings.TrimSpace(p[:eq]))], unescapeDN(strings.TrimSpace(p[eq+1:])))
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

// normalizeSerial lowercases a hex serial and strips separators/leading zeros.
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", " ", "", "0x", "").Replace(s)
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
