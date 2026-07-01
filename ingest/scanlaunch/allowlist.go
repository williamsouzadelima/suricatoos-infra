package scanlaunch

import (
	"fmt"
	"net"
	"strings"
)

// Allowlist is the scanner-authoritative, default-deny gate on scan targets.
//
// The premise is adversarial: reNgine's "live hosts" derive from resolving a
// target's DNS, which the target owns — so a host value is attacker-influenced.
// Two invariants defeat that:
//
//  1. IP-LITERAL ONLY. A host that net.ParseIP cannot parse is rejected before
//     it ever reaches gvmd, so gvmd never re-resolves a name at scan time (no
//     scan-time DNS rebinding).
//  2. DEFAULT-DENY. A parsed IP must be a public unicast address that is NOT on
//     the built-in deny-list (loopback/link-local/metadata/private/multicast/
//     self+sibling prod) AND is a member of an explicit operator allowlist. The
//     allowlist ships empty, so nothing scans until CIDRs are added.
type Allowlist struct {
	cidrs   []*net.IPNet // operator-provided allow CIDRs (empty = deny-all)
	denyIPs []net.IP     // explicit host denies (self + sibling prod boxes)
}

// selfAndSiblingIPs are reachable from the scanner's vantage but MUST never be
// targets: the prod boxes themselves and their internal addresses.
var selfAndSiblingIPs = []string{
	"172.233.11.97",  // scanner (self)
	"172.233.13.124", // score (reNgine)
	"172.233.13.89",  // kali3 (CISO fork)
}

// NewAllowlist parses a comma/space-separated list of allow CIDRs (or bare IPs,
// treated as /32 or /128). An empty spec yields a deny-all allowlist.
func NewAllowlist(spec string) (*Allowlist, error) {
	al := &Allowlist{}
	for _, ip := range selfAndSiblingIPs {
		al.denyIPs = append(al.denyIPs, net.ParseIP(ip))
	}
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
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
		_, ipnet, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("allowlist: CIDR inválido %q: %w", tok, err)
		}
		al.cidrs = append(al.cidrs, ipnet)
	}
	return al, nil
}

// Empty reports whether the allowlist has no allow CIDRs (deny-all).
func (a *Allowlist) Empty() bool { return len(a.cidrs) == 0 }

// CheckHost validates a single host string. It returns the canonical IP string
// (as gvmd should receive it) or an error explaining the rejection. A hostname,
// a denied range, or an off-allowlist address all fail.
func (a *Allowlist) CheckHost(host string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return "", fmt.Errorf("host %q não é um IP literal (hostnames são rejeitados)", host)
	}
	if reason := denyReason(ip); reason != "" {
		return "", fmt.Errorf("host %s negado: %s", ip, reason)
	}
	for _, d := range a.denyIPs {
		if d != nil && d.Equal(ip) {
			return "", fmt.Errorf("host %s negado: caixa de prod (self/irmã)", ip)
		}
	}
	for _, n := range a.cidrs {
		if n.Contains(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("host %s fora da allowlist (default-deny)", ip)
}

// denyReason returns a non-empty reason if ip is in a category that must never
// be an active-scan target, or "" if it passes the built-in deny checks.
func denyReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "endereço não especificado"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	case ip.IsPrivate():
		return "RFC1918/ULA privado"
	case isMetadata(ip):
		return "endpoint de metadata da cloud"
	case ip.To4() == nil && isIPv6ULA(ip):
		return "ULA IPv6"
	}
	return ""
}

// isMetadata blocks the well-known cloud link-local metadata address (Linode/AWS/GCP).
func isMetadata(ip net.IP) bool {
	return ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}

// isIPv6ULA reports whether ip is in fc00::/7 (unique local). net.IP.IsPrivate
// already covers this, but kept explicit as defense in depth for clarity.
func isIPv6ULA(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return false
	}
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}
