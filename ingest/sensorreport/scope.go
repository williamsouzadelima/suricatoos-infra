package sensorreport

import (
	"fmt"
	"net"
	"strings"
)

// Scope is a tenant's authorized address space. On the report path it re-validates
// that a returned finding's host IP is one the tenant is allowed to scan — a
// compromised sensor reporting an out-of-scope (e.g. co-tenant) host is dropped,
// never imported (defense in depth: the dispatch already scope-gated the job).
type Scope struct {
	nets []*net.IPNet
}

// NewScope parses a tenant's authorized CIDRs (comma/space/newline separated,
// bare IPs → /32 or /128). Empty = deny-all.
func NewScope(spec string) (*Scope, error) {
	s := &Scope{}
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			if ip := net.ParseIP(tok); ip != nil {
				if ip.To4() != nil {
					tok += "/32"
				} else {
					tok += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("scope: CIDR inválido %q: %w", tok, err)
		}
		s.nets = append(s.nets, n)
	}
	return s, nil
}

// ContainsIP reports whether host (an IP literal) is within the scope. A non-IP
// host is never in scope (the cloud never re-resolves a name).
func (s *Scope) ContainsIP(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
