// Package scopegate is the LOCAL, baked authorization gate on scan targets, shared
// by the sensor (ADR-0007) and the fleet connector (ADR-0011) so neither keeps a
// diverging copy. It is the sensor-side twin of the cloud dispatch scope-gate: even
// though the cloud only dispatches in-scope jobs, the sensor independently
// re-validates every target so a compromised/misbehaving cloud channel can't make
// it scan outside its authorized ranges or its own/cloud infrastructure.
//
// Two invariants (same spirit as ingest/scanlaunch's allowlist):
//  1. IP-LITERAL ONLY — a non-IP target is refused (no scan-time DNS re-resolution).
//  2. ALLOWLIST (the tenant's authorized ranges — RFC1918 IS legitimate here) minus
//     an ABSOLUTE self-protection deny-list (the degenerate space of degenerate.go +
//     the sensor's own interfaces and the cloud endpoints, via SCAN_SELF_DENY_IPS).
//     The self-deny is env-driven because a sensor's "self" is its client, not the
//     Suricatoos prod boxes.
//
// A bare IPv4-mapped address (::ffff:a.b.c.d) is its IPv4 address everywhere.
package scopegate

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Scope authorizes scan targets against a baked allow-set minus self-protection.
// It is never modified after construction: one *Scope is safe for concurrent use.
type Scope struct {
	allow []netip.Prefix // masked
	deny  []netip.Addr   // self-deny; IPv4-mapped forms kept as IPv4
	// warnSelfDenyCIDR, when set, puts the rule "a CIDR that contains a
	// self-deny IP" in log mode for CheckHost/Filter; nil enforces it.
	warnSelfDenyCIDR func(cidr, reason string)
}

// reasonSelfDenyCIDR names the rule without the self-deny IP itself.
const reasonSelfDenyCIDR = "contém IP do self-deny"

// Option configures a Scope built by New.
type Option func(*Scope)

// LogSelfDenyCIDR puts the rule "a CIDR that CONTAINS a self-deny IP" (e.g. the
// /24 of the LAN where the node lives) in LOG mode for CheckHost and Filter: the
// CIDR passes and warn is called once per check with the canonical CIDR and the
// reason — never the self-deny IP — so the caller logs one line. It is how the
// sensor rolls the rule out (ADR-0011 D7); without it, or with a nil warn, the
// rule is enforced. A self-deny IP on its own — bare, /32 or /128 — is always
// denied.
func LogSelfDenyCIDR(warn func(cidr, reason string)) Option {
	return func(s *Scope) { s.warnSelfDenyCIDR = warn }
}

// New builds a Scope from an allow spec (comma/space CIDRs or bare IPs; the
// tenant's authorized internal ranges) and a self-deny spec (the sensor's own
// addresses + the cloud endpoints — never scan targets). Both may be empty; an
// empty allow spec denies everything (deny-all). A self-deny token that is not a
// bare IP is ignored.
func New(allowSpec, selfDenySpec string, opts ...Option) (*Scope, error) {
	s := &Scope{}
	for _, tok := range fields(allowSpec) {
		p, _, ok := literal(tok)
		if !ok {
			return nil, fmt.Errorf("allow: CIDR inválido %q", tok)
		}
		s.allow = append(s.allow, p)
	}
	for _, tok := range fields(selfDenySpec) {
		if p, bare, ok := literal(tok); ok && bare {
			s.deny = append(s.deny, p.Addr())
		}
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Empty reports whether the allow-set is empty (deny-all).
func (s *Scope) Empty() bool { return len(s.allow) == 0 }

// CheckHost validates one target (an IP or CIDR literal) and returns its canonical
// form, or an error. A hostname, a self/cloud address, a degenerate address, an
// off-scope IP, or a CIDR not fully within the allow-set all fail, and so does a
// CIDR that contains a self/cloud address unless LogSelfDenyCIDR is set.
func (s *Scope) CheckHost(host string) (string, error) {
	p, bare, ok := literal(strings.TrimSpace(host))
	if !ok {
		return "", fmt.Errorf("%q não é IP/CIDR literal", host)
	}
	// Individual IP: full degenerate + self-deny + allow-membership checks.
	if bare {
		ip := p.Addr()
		if reason := degenerate(p); reason != "" {
			return "", fmt.Errorf("host %s negado: %s", ip, reason)
		}
		if s.denied(ip) {
			return "", fmt.Errorf("host %s negado: self-deny (IP próprio/nuvem)", ip)
		}
		if !s.allowed(p) {
			return "", fmt.Errorf("host %s fora do escopo autorizado", ip)
		}
		return ip.String(), nil
	}
	// CIDR subnet: must not overlap degenerate space, must be FULLY within one
	// allow CIDR and must not contain a self-deny IP.
	if reason := degenerate(p); reason != "" {
		return "", fmt.Errorf("CIDR %s negado: sobrepõe %s", p, reason)
	}
	if !s.allowed(p) {
		return "", fmt.Errorf("CIDR %s fora do escopo autorizado", p)
	}
	if s.containsDenied(p) {
		// A /32 or /128 IS the self-deny address: denied in any mode.
		if p.IsSingleIP() || s.warnSelfDenyCIDR == nil {
			return "", fmt.Errorf("CIDR %s negado: %s", p, reasonSelfDenyCIDR)
		}
		s.warnSelfDenyCIDR(p.String(), reasonSelfDenyCIDR)
	}
	return p.String(), nil
}

// Filter splits targets into canonical in-scope IPs (kept) and rejected (dropped).
func (s *Scope) Filter(targets []string) (kept, dropped []string) {
	for _, t := range targets {
		if ip, err := s.CheckHost(t); err == nil {
			kept = append(kept, ip)
		} else {
			dropped = append(dropped, t)
		}
	}
	return kept, dropped
}

// allowed reports whether p lies fully within one allow CIDR.
func (s *Scope) allowed(p netip.Prefix) bool {
	for _, a := range s.allow {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// containsDenied reports whether the CIDR p contains a self-deny address.
func (s *Scope) containsDenied(p netip.Prefix) bool {
	for _, d := range s.deny {
		if p.Contains(d) {
			return true
		}
	}
	return false
}

// denied reports whether ip is a self-deny address.
func (s *Scope) denied(ip netip.Addr) bool {
	for _, d := range s.deny {
		if d == ip {
			return true
		}
	}
	return false
}

// literal parses an IP or CIDR literal with the same grammar the sensor always
// accepted (net.ParseIP / net.ParseCIDR: no hostname, range, port or zone) into a
// masked prefix. A bare IP becomes a single-address prefix, with an IPv4-mapped
// address turned into its IPv4; a CIDR keeps the family it was written in.
func literal(s string) (p netip.Prefix, bare, ok bool) {
	if ip := net.ParseIP(s); ip != nil {
		a, _ := netip.AddrFromSlice(ip)
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true, true
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return netip.Prefix{}, false, false
	}
	a, _ := netip.AddrFromSlice(n.IP)
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a, bits), false, true
}

func fields(spec string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}
