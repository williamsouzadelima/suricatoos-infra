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
//     the node's own interfaces and the cloud/hub endpoints: SCAN_SELF_DENY_IPS on
//     the sensor; FLEET_SELF_DENY_IPS plus the hub's IPs, via WithSelfDeny, on the
//     fleet). The self-deny is env-driven because a node's "self" is its client, not
//     the Suricatoos prod boxes. A CIDR that CONTAINS a self-deny IP is denied too.
//
// The sensor filters job targets with CheckHost/Filter, where LogSelfDenyCIDR can
// let a CIDR containing a self-deny IP pass with a warning (its rollout mode); the
// fleet checks a whole gvmd target with CheckTarget, which always denies it.
//
// A bare IPv4-mapped address (::ffff:a.b.c.d) is its IPv4 address everywhere.
package scopegate

import (
	"errors"
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
// tenant's authorized internal ranges) and a self-deny spec (the node's own
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

// WithSelfDeny returns a NEW Scope whose self-deny also holds ips: the fleet
// connector adds the hub's addresses (resolved from FLEET_HUB_URL at start-up and
// on every connection, plus each connection's remote IP) and swaps its pointer
// atomically. s itself is never modified. An IPv4-mapped address counts as its
// IPv4 and a zone is dropped, as targets are compared without them; an invalid
// (zero) address is an error, since a deny that silently didn't happen would fail
// open.
func (s *Scope) WithSelfDeny(ips ...netip.Addr) (*Scope, error) {
	deny := make([]netip.Addr, len(s.deny), len(s.deny)+len(ips))
	copy(deny, s.deny)
	for _, ip := range ips {
		if !ip.IsValid() {
			return nil, errors.New("self-deny: endereço inválido")
		}
		deny = append(deny, ip.Unmap().WithZone(""))
	}
	n := *s
	n.deny = deny
	return &n, nil
}

// Empty reports whether the allow-set is empty (deny-all).
func (s *Scope) Empty() bool { return len(s.allow) == 0 }

// CheckHost validates one target (an IP or CIDR literal) and returns its canonical
// form, or an error. A hostname, a self-deny address, a degenerate address, an
// off-scope IP, or a CIDR not fully within the allow-set all fail, and so does a
// CIDR that contains a self-deny address unless LogSelfDenyCIDR is set.
func (s *Scope) CheckHost(host string) (string, error) {
	canonical, containsSelf, err := s.gate(host)
	if err != nil {
		return "", err
	}
	if containsSelf {
		if s.warnSelfDenyCIDR == nil {
			return "", fmt.Errorf("CIDR %s negado: %s", canonical, reasonSelfDenyCIDR)
		}
		s.warnSelfDenyCIDR(canonical, reasonSelfDenyCIDR)
	}
	return canonical, nil
}

// gate runs every check on one host and returns its canonical form, except the
// decision on a CIDR that CONTAINS a self-deny IP: that one is reported in
// containsSelf for the caller (CheckHost per mode, CheckTarget always denies). A
// single address equal to a self-deny IP — bare, /32 or /128 — is an error here.
func (s *Scope) gate(host string) (canonical string, containsSelf bool, err error) {
	p, bare, ok := literal(strings.TrimSpace(host))
	if !ok {
		return "", false, fmt.Errorf("%s não é IP/CIDR literal", echo(host))
	}
	// Individual IP: full degenerate + self-deny + allow-membership checks.
	if bare {
		ip := p.Addr()
		if reason := degenerate(p); reason != "" {
			return "", false, fmt.Errorf("host %s negado: %s", ip, reason)
		}
		if s.denied(ip) {
			return "", false, fmt.Errorf("host %s negado: IP do self-deny", ip)
		}
		if !s.allowed(p) {
			return "", false, fmt.Errorf("host %s fora do escopo autorizado", ip)
		}
		return ip.String(), false, nil
	}
	// CIDR subnet: must not overlap degenerate space and must be FULLY within one
	// allow CIDR.
	if reason := degenerate(p); reason != "" {
		return "", false, fmt.Errorf("CIDR %s negado: sobrepõe %s", p, reason)
	}
	if !s.allowed(p) {
		return "", false, fmt.Errorf("CIDR %s fora do escopo autorizado", p)
	}
	if !s.containsDenied(p) {
		return p.String(), false, nil
	}
	if p.IsSingleIP() { // a /32 or /128 IS the self-deny address
		return "", false, fmt.Errorf("CIDR %s negado: é IP do self-deny", p)
	}
	return p.String(), true, nil
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
