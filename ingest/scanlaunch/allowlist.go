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
//  2. DEFAULT-DENY. A parsed IP must be a member of an explicit operator allowlist
//     (which ships empty, so nothing scans until CIDRs are added) AND must not be
//     on the ABSOLUTE deny-list.
//
// The absolute deny-list is SELF-PROTECTION only: the scanner's own attack surface
// and degenerate addresses that can never be a legitimate target — loopback,
// link-local incl. cloud metadata (169.254.169.254), multicast, unspecified,
// ::a.b.c.d, 0.0.0.0/8, 240.0.0.0/4, and the prod boxes themselves. It does NOT
// block RFC1918/ULA/CGNAT: Suricatoos is an authorized scanner and internal
// networks are legitimate targets, so they are ALLOWLIST-GATED — an operator
// authorizes a specific internal range by adding its (tight, per-engagement) CIDR
// to SCAN_HOST_ALLOWLIST. Even then the absolute deny-list still protects the
// scanner's own infra, so an allowlisted 169.254.0.0/16 can't reach metadata.
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

// denyReason returns a non-empty reason if ip is on the ABSOLUTE deny-list — the
// scanner's own attack surface or a degenerate address that can never be a
// legitimate target — or "" if it is allowlist-gated. RFC1918/ULA/CGNAT are
// deliberately NOT denied here (internal networks are legitimate authorized
// targets); the allowlist gates them.
func denyReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "endereço não especificado"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local (inclui metadata da cloud)"
	case ip.IsMulticast():
		return "multicast"
	case isMetadata(ip):
		return "endpoint de metadata da cloud"
	case isIPv4CompatibleV6(ip):
		// ::a.b.c.d (deprecated) — To4() does NOT unwrap it, so e.g. ::127.0.0.1
		// would otherwise slip past the v4 loopback check above.
		return "IPv6 compatível-IPv4 (::a.b.c.d) depreciado"
	}
	if ip4 := ip.To4(); ip4 != nil {
		for _, n := range reservedV4Nets {
			if n.Contains(ip4) {
				return "faixa IPv4 reservada/especial"
			}
		}
	}
	return ""
}

// reservedV4Nets are degenerate IPv4 ranges that are never a valid unicast
// target: 0.0.0.0/8 (this-network) and 240.0.0.0/4 (reserved + the
// 255.255.255.255 broadcast). CGNAT 100.64.0.0/10 is intentionally NOT here —
// it's a real (internal) address space and is allowlist-gated like RFC1918.
var reservedV4Nets = mustCIDRs("0.0.0.0/8", "240.0.0.0/4")

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// isIPv4CompatibleV6 reports whether ip is an ::a.b.c.d IPv4-compatible address
// (first 12 bytes zero, IPv6 form). :: and ::1 are already handled by the
// unspecified/loopback checks, so reaching here means a non-trivial embedded v4.
func isIPv4CompatibleV6(ip net.IP) bool {
	v16 := ip.To16()
	if v16 == nil || ip.To4() != nil {
		return false
	}
	for _, b := range v16[:12] {
		if b != 0 {
			return false
		}
	}
	return true
}

// isMetadata blocks the well-known cloud link-local metadata address (Linode/AWS/GCP).
// The IPv6 form fd00:ec2::254 is ULA (which is otherwise allowlist-gated), so it
// must be denied explicitly here.
func isMetadata(ip net.IP) bool {
	return ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}
