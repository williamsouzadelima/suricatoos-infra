package sensorjobs

import (
	"fmt"
	"net"
	"strings"
)

// Scope is a tenant's authorized internal address space (a set of CIDRs). The
// cloud is authoritative: a job may only carry targets that fall entirely within
// the tenant's scope. A discovered asset outside the declared scope is DROPPED
// (never scanned) — so a compromised Score or a confused discovery can't smuggle
// arbitrary targets to a sensor (mirrors "scanner authoritative, reNgine never
// trusted on targets" from ADR-0006).
type Scope struct {
	nets []*net.IPNet
}

// NewScope parses a tenant's authorized CIDRs (comma/space/newline separated,
// bare IPs treated as /32 or /128). An empty scope contains nothing (deny-all).
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

// Empty reports whether the scope is deny-all (no CIDRs).
func (s *Scope) Empty() bool { return len(s.nets) == 0 }

// Contains reports whether target (an IP or CIDR literal) lies entirely within
// the scope. For a CIDR target, the whole block must be within one scope CIDR.
func (s *Scope) Contains(target string) bool {
	t := strings.TrimSpace(target)
	if ip := net.ParseIP(t); ip != nil {
		for _, n := range s.nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	_, tnet, err := net.ParseCIDR(t)
	if err != nil {
		return false
	}
	tOnes, tBits := tnet.Mask.Size()
	for _, n := range s.nets {
		nOnes, nBits := n.Mask.Size()
		if nBits == tBits && nOnes <= tOnes && n.Contains(tnet.IP) {
			return true
		}
	}
	return false
}

// Gate splits targets into those within scope (kept) and those outside (dropped).
// Malformed literals are dropped. The cloud enqueues only the kept set.
func (s *Scope) Gate(targets []string) (kept, dropped []string) {
	for _, t := range targets {
		if s.Contains(t) {
			kept = append(kept, strings.TrimSpace(t))
		} else {
			dropped = append(dropped, t)
		}
	}
	return kept, dropped
}
