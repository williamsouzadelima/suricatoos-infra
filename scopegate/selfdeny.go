package scopegate

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseSelfDeny parses a self-deny spec STRICTLY — the fleet's
// FLEET_SELF_DENY_IPS: every comma/space-separated token must be a single IP, or
// a /32 or /128 (the address itself), or the whole spec is an error naming each
// bad token, since a deny that silently didn't happen would fail open.
// IPv4-mapped addresses come back as IPv4. Add the result with WithSelfDeny.
func ParseSelfDeny(spec string) ([]netip.Addr, error) {
	var ips []netip.Addr
	var bad []string
	for _, tok := range fields(spec) {
		if ip, ok := selfDenyAddr(tok); ok {
			ips = append(ips, ip)
		} else {
			bad = append(bad, echo(tok))
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("self-deny: %s não é IP isolado nem /32 ou /128", strings.Join(bad, ", "))
	}
	return ips, nil
}

// selfDenyAddr reads one self-deny token: a single IP, or a /32 or /128 (the
// address itself), with an IPv4-mapped form turned into IPv4.
func selfDenyAddr(tok string) (netip.Addr, bool) {
	p, _, ok := literal(tok)
	if !ok || !p.IsSingleIP() {
		return netip.Addr{}, false
	}
	return p.Addr().Unmap(), true
}
