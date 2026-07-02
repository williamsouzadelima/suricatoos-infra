package scanlaunch

import (
	"fmt"
	"strings"
)

// certIdentity is the launcher identity extracted from the verified client cert
// (forwarded by nginx). CN is used for ownership/audit; O/OU gate the capability.
type certIdentity struct {
	CN string
	O  string
	OU string
}

// authorize verifies the forwarded mTLS headers and returns the caller identity.
//   - X-Client-Cert-Verify MUST be exactly "SUCCESS" (defense in depth; nginx
//     already 403s a non-verified cert at the location).
//   - The DN MUST carry O == cfg.AllowedO AND OU == cfg.AllowedOU as full-value
//     matches, so an ordinary endpoint-agent cert (same enroll CA) is rejected.
func authorize(verify, dn, allowedO, allowedOU string) (certIdentity, error) {
	if verify != "SUCCESS" {
		return certIdentity{}, fmt.Errorf("cert cliente não verificado (verify=%q)", verify)
	}
	fields := parseDN(dn)
	id := certIdentity{
		CN: firstOf(fields, "CN"),
		O:  firstOf(fields, "O"),
		OU: firstOf(fields, "OU"),
	}
	if !hasValue(fields, "O", allowedO) {
		return certIdentity{}, fmt.Errorf("cert O=%q não autorizado (requer O=%q)", id.O, allowedO)
	}
	if !hasValue(fields, "OU", allowedOU) {
		return certIdentity{}, fmt.Errorf("cert OU=%q não autorizado (requer OU=%q)", id.OU, allowedOU)
	}
	return id, nil
}

// parseDN parses a subject DN into a map of attribute type (upper-case) → values.
// It accepts both nginx forms: RFC2253 ("CN=x,OU=y,O=z", nginx ≥1.11.6, default)
// and the legacy OpenSSL oneline ("/O=z/OU=y/CN=x"). Backslash escapes (e.g. an
// O containing a literal comma "\,") are honored so a crafted value can't smuggle
// an extra attribute.
func parseDN(dn string) map[string][]string {
	dn = strings.TrimSpace(dn)
	out := map[string][]string{}
	if dn == "" {
		return out
	}
	var pairs []string
	if strings.HasPrefix(dn, "/") && !strings.Contains(dn, ",") {
		// OpenSSL oneline: /O=.../OU=.../CN=...  (slashes are not escapable here)
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
		val := unescapeDN(strings.TrimSpace(p[eq+1:]))
		out[key] = append(out[key], val)
	}
	return out
}

// splitUnescaped splits s on sep, treating a backslash as escaping the next rune
// (so "a\,b" is one field). The escape char itself is retained for unescapeDN.
func splitUnescaped(s string, sep byte) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == sep {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}

// unescapeDN removes RFC2253 backslash escapes from a value.
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

func firstOf(fields map[string][]string, key string) string {
	if v := fields[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// hasValue reports whether key has want as an exact full value (not a substring).
func hasValue(fields map[string][]string, key, want string) bool {
	for _, v := range fields[key] {
		if v == want {
			return true
		}
	}
	return false
}
