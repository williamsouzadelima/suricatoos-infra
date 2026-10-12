package scopegate

import "net/netip"

// degenerateNets are ranges a scan target must never reach, whatever the
// allow-set says: the stricter union of the old sensor set and
// ingest/scanlaunch's denyReason, plus the IPv6 forms that carry an IPv4 through
// a translator (NAT64, 6to4, SIIT) — the embedded IPv4 could be one the deny-list
// refuses. RFC1918/ULA/CGNAT are NOT here — they are legitimate internal targets,
// gated only by the allow-set. The first match gives the reason.
var degenerateNets = []struct {
	net    netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "não especificado (0.0.0.0/8)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local (inclui metadata da cloud)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reservado/broadcast (240.0.0.0/4)"},
	{netip.MustParsePrefix("::/128"), "não especificado"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("::/96"), "IPv6 compatível-IPv4 (::a.b.c.d, depreciado)"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "forma IPv4-mapeada (::ffff:0:0/96; use o IPv4)"},
	{netip.MustParsePrefix("::ffff:0:0:0/96"), "IPv4-traduzido SIIT (::ffff:0:0:0/96)"},
	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64 (64:ff9b::/96, carrega IPv4)"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "NAT64 de uso local (64:ff9b:1::/48, carrega IPv4)"},
	{netip.MustParsePrefix("2002::/16"), "6to4 (2002::/16, carrega IPv4)"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
	{netip.MustParsePrefix("fd00:ec2::254/128"), "metadata da cloud (IPv6)"},
}

// degenerate returns why p — a single address or a CIDR — reaches degenerate
// space, or "" if it doesn't. A CIDR that merely OVERLAPS a degenerate range is
// degenerate: a swept range must never reach 169.254.169.254 & co., even if an
// allow range is ever mis-set too broadly. A bare IPv4-mapped address arrives here
// already as IPv4, so the ::ffff:0:0/96 entry only catches a CIDR written in, or
// covering, the mapped form.
func degenerate(p netip.Prefix) string {
	for _, d := range degenerateNets {
		if d.net.Overlaps(p) {
			return d.reason
		}
	}
	return ""
}
