// Package scope is the sensor's LOCAL, baked authorization gate on scan targets
// (ADR-0007). It is the sensor-side twin of the cloud dispatch scope-gate: even
// though the cloud only dispatches in-scope jobs, the sensor independently
// re-validates every target so a compromised/misbehaving cloud channel can't make
// it scan outside its authorized ranges or its own/cloud infrastructure.
//
// Two invariants (same spirit as ingest/scanlaunch's allowlist):
//  1. IP-LITERAL ONLY — a non-IP target is refused (no scan-time DNS re-resolution).
//  2. ALLOWLIST (the tenant's authorized ranges — RFC1918 IS legitimate here) minus
//     an ABSOLUTE self-protection deny-list (loopback/link-local/metadata/multicast/
//     unspecified + the sensor's own interfaces and the cloud endpoints, via
//     SCAN_SELF_DENY_IPS). The self-deny is env-driven because a sensor's "self"
//     is its client, not the Suricatoos prod boxes.
package scope

import (
	"fmt"
	"net"
	"strings"
)

// Scope authorizes scan targets against a baked allow-set minus self-protection.
type Scope struct {
	allow   []*net.IPNet
	denyIPs []net.IP
}

// New builds a Scope from an allow spec (comma/space CIDRs or bare IPs; the
// tenant's authorized internal ranges) and a self-deny spec (the sensor's own
// addresses + the cloud endpoints — never scan targets). Both may be empty; an
// empty allow spec denies everything (deny-all).
func New(allowSpec, selfDenySpec string) (*Scope, error) {
	s := &Scope{}
	nets, err := parseCIDRs(allowSpec)
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	s.allow = nets
	for _, tok := range fields(selfDenySpec) {
		if ip := net.ParseIP(tok); ip != nil {
			s.denyIPs = append(s.denyIPs, ip)
		}
	}
	return s, nil
}

// Empty reports whether the allow-set is empty (deny-all).
func (s *Scope) Empty() bool { return len(s.allow) == 0 }

// CheckHost validates one target (an IP or CIDR literal) and returns its canonical
// form, or an error. A hostname, a self/cloud address, a degenerate address, an
// off-scope IP, or a CIDR not fully within the allow-set all fail.
func (s *Scope) CheckHost(host string) (string, error) {
	t := strings.TrimSpace(host)
	// Individual IP: full degenerate + self-deny + allow-membership checks.
	if ip := net.ParseIP(t); ip != nil {
		if reason := degenerate(ip); reason != "" {
			return "", fmt.Errorf("host %s negado: %s", ip, reason)
		}
		for _, d := range s.denyIPs {
			if d.Equal(ip) {
				return "", fmt.Errorf("host %s negado: self/nuvem (SCAN_SELF_DENY_IPS)", ip)
			}
		}
		for _, n := range s.allow {
			if n.Contains(ip) {
				return ip.String(), nil
			}
		}
		return "", fmt.Errorf("host %s fora do escopo autorizado", ip)
	}
	// CIDR subnet: must be FULLY within one allow CIDR (the tenant's authorized
	// internal ranges — which never include loopback/metadata, so ⊆ allow already
	// excludes degenerate space).
	_, tnet, err := net.ParseCIDR(t)
	if err != nil {
		return "", fmt.Errorf("%q não é IP/CIDR literal", host)
	}
	tOnes, tBits := tnet.Mask.Size()
	for _, n := range s.allow {
		nOnes, nBits := n.Mask.Size()
		if nBits == tBits && nOnes <= tOnes && n.Contains(tnet.IP) {
			return tnet.String(), nil
		}
	}
	return "", fmt.Errorf("CIDR %s fora do escopo autorizado", tnet)
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

// degenerate returns a reason if ip is an address that must never be a target,
// regardless of the allow-set: loopback, link-local (incl. cloud metadata),
// multicast, unspecified. RFC1918/ULA are NOT here — they're legitimate internal
// targets, gated only by the allow-set.
func degenerate(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "não especificado"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local (inclui metadata da cloud)"
	case ip.IsMulticast():
		return "multicast"
	}
	return ""
}

func parseCIDRs(spec string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, tok := range fields(spec) {
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
			return nil, fmt.Errorf("CIDR inválido %q: %w", tok, err)
		}
		out = append(out, n)
	}
	return out, nil
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
