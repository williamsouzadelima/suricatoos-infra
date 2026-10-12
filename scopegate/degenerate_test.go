package scopegate

import "testing"

// TestCIDROverlappingDegenerateRejected guards the low-severity hardening: a swept
// CIDR must never reach cloud metadata / link-local / loopback even if an allow
// range is mis-set too broadly (ADR-0007 self-protection invariant).
func TestCIDROverlappingDegenerateRejected(t *testing.T) {
	s, err := New("10.0.0.0/8, 169.254.0.0/16", "") // deliberately over-broad allow
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"169.254.169.0/24", "169.254.0.0/16", "127.0.0.0/24"} {
		if _, err := s.CheckHost(bad); err == nil {
			t.Errorf("CIDR %s (metadata/link-local/loopback) deveria ser rejeitado mesmo ⊆ allow", bad)
		}
	}
	// A legitimate internal sweep still passes.
	if _, err := s.CheckHost("10.20.5.0/24"); err != nil {
		t.Fatalf("CIDR interno legítimo deveria passar: %v", err)
	}
}

// broadAllow authorizes ALL of IPv4 and IPv6 on purpose: under it, only the
// degenerate rule can deny a host.
const broadAllow = "0.0.0.0/0, ::/0"

// degenerateHosts are never a legitimate target, whatever the allow-set says: the
// union of the old sensor set and ingest/scanlaunch's denyReason (the stricter of
// the two), as single addresses and as CIDRs that merely OVERLAP the range.
var degenerateHosts = []string{
	// IPv4.
	"0.0.0.0", "0.1.2.3", "0.0.0.0/8", "0.0.0.0/0", // não especificado / 0.0.0.0/8
	"127.0.0.1", "127.0.0.0/24", // loopback
	"169.254.169.254", "169.254.1.1", "169.254.169.0/24", // link-local + metadata
	"224.0.0.1", "224.0.0.0/24", // multicast
	"240.0.0.1", "255.255.255.255", "240.0.0.0/24", "255.255.255.0/24", // 240.0.0.0/4
	// IPv6.
	"::", "::/127", // não especificado
	"::1",                                                    // loopback
	"::127.0.0.1", "::7f00:0/104", "::c000:200/120", "::/96", // IPv4-compatível (::/96)
	"fe80::1", "fe80::/64", // link-local
	"ff02::1", "ff00::/8", // multicast
	"fd00:ec2::254", "fd00:ec2::/64", // metadata da cloud em IPv6 (ULA)
	// IPv4-mapeado: o endereço conta como o próprio IPv4; um CIDR na forma
	// mapeada, ou que cobre o bloco ::ffff:0:0/96, nunca é alvo legítimo.
	"::ffff:127.0.0.1", "::ffff:169.254.169.254",
	"::ffff:127.0.0.0/104", "::ffff:192.0.2.0/120", "::fffe:0:0/95",
	// IPv6 que carrega um IPv4 por tradução: um tradutor entregaria o pacote ao
	// IPv4 embutido, que o deny-list recusaria (ex.: 127.0.0.1, o IP do nó).
	"64:ff9b::7f00:1", "64:ff9b::c000:20a", "64:ff9b::/96", "64:ff9b::/32", // NAT64
	"64:ff9b:1::1", "64:ff9b:1:2::/64", // NAT64 de uso local
	"2002:7f00:1::1", "2002:c000:200::/40", "2002::/16", // 6to4
	"::ffff:0:7f00:1", "::ffff:0:0:0/96", // IPv4-traduzido (SIIT)
}

func TestDegenerateSpaceDeniedEvenWithBroadAllow(t *testing.T) {
	s, err := New(broadAllow, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range degenerateHosts {
		if got, err := s.CheckHost(h); err == nil {
			t.Errorf("%s deveria ser negado (espaço degenerado), passou como %q", h, got)
		}
	}
}

// TestLegitimateTargetsPassBroadAllow keeps the degenerate set from over-blocking and
// pins the canonical form handed to gvmd.
func TestLegitimateTargetsPassBroadAllow(t *testing.T) {
	s, err := New(broadAllow, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want string }{
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.77/24", "192.0.2.0/24"}, // bits de host zerados
		{"198.51.100.7", "198.51.100.7"},
		{"100.64.0.0/10", "100.64.0.0/10"},             // CGNAT: interno legítimo
		{"::ffff:203.0.113.9", "203.0.113.9"},          // endereço IPv4-mapeado = o IPv4
		{"2001:db8::5", "2001:db8::5"},                 // RFC 3849
		{"2001:DB8:0:0::/64", "2001:db8::/64"},         // forma canônica
		{"fd12:3456:789a::/48", "fd12:3456:789a::/48"}, // ULA interna legítima
		{"fd00:ec2::253", "fd00:ec2::253"},             // vizinho da metadata: só o /128 é negado
	} {
		got, err := s.CheckHost(c.in)
		if err != nil || got != c.want {
			t.Errorf("CheckHost(%q) = %q, %v; quer %q", c.in, got, err, c.want)
		}
	}
}
