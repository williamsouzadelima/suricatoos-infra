package scopegate

import (
	"net/netip"
	"strings"
	"testing"
)

// fleetScope: o nó mora em 192.0.2.10 / 2001:db8:1::10 (RFC 5737 / RFC 3849) e o
// escopo do tenant cobre a LAN dele, a faixa do hub e um /32 IPv6.
func fleetScope(t *testing.T, opts ...Option) *Scope {
	t.Helper()
	s, err := New(hubAllow+", 2001:db8::/32", nodeIPs, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckTargetAcceptsInScopeLiterals(t *testing.T) {
	s := fleetScope(t)
	hosts := []string{"192.0.2.128/25", "198.51.100.7", "2001:db8:2::/48", " 192.0.2.64/27 "}
	for _, excl := range [][]string{nil, {"192.0.2.200", "198.51.100.0/30"}} {
		if err := s.CheckTarget(hosts, excl); err != nil {
			t.Errorf("exclude_hosts=%q: alvo dentro do escopo deveria passar: %v", excl, err)
		}
	}
}

func TestCheckTargetDeniesCIDRContainingNode(t *testing.T) {
	var w warnings
	// A frota sempre nega, mesmo num Scope em modo log (o do sensor), e sem aviso.
	for name, s := range map[string]*Scope{"enforce": fleetScope(t), "log": fleetScope(t, LogSelfDenyCIDR(w.record))} {
		for _, h := range []string{"192.0.2.0/24", "192.0.2.8/29", "2001:db8:1::/64", "192.0.2.10", "::ffff:192.0.2.10"} {
			if err := s.CheckTarget([]string{"192.0.2.128/25", h}, nil); err == nil {
				t.Errorf("%s: %s é ou contém o IP do nó e deveria ser negado", name, h)
			}
		}
	}
	if len(w) != 0 {
		t.Errorf("CheckTarget não usa o modo log: %q", w)
	}
}

func TestCheckTargetDeniesCIDRContainingHubAddedLater(t *testing.T) {
	s := fleetScope(t)
	withHub, err := s.WithSelfDeny(netip.MustParseAddr(hubIP))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{hubLAN, hubIP} {
		if err := withHub.CheckTarget([]string{h}, nil); err == nil {
			t.Errorf("%s é ou contém o IP do hub e deveria ser negado", h)
		}
		if err := s.CheckTarget([]string{h}, nil); err != nil {
			t.Errorf("o Scope original não conhece o hub, %s deveria passar: %v", h, err)
		}
	}
}

func TestCheckTargetExcludeHostsNeverSavesNodeOrHub(t *testing.T) {
	withHub, _ := fleetScope(t).WithSelfDeny(netip.MustParseAddr(hubIP))
	for _, c := range []struct{ hosts, excl []string }{
		{[]string{"192.0.2.0/24"}, []string{"192.0.2.10"}},
		{[]string{"192.0.2.0/24"}, []string{"192.0.2.0/28"}},
		{[]string{hubLAN}, []string{hubIP + "/32"}},
		{[]string{"2001:db8:1::/64"}, []string{"2001:db8:1::10"}},
	} {
		if err := withHub.CheckTarget(c.hosts, c.excl); err == nil {
			t.Errorf("hosts=%q: exclude_hosts=%q não salva CIDR com IP do nó/hub", c.hosts, c.excl)
		}
	}
}

func TestCheckTargetExcludeHostsMustBeLiteral(t *testing.T) {
	s := fleetScope(t)
	for _, bad := range []string{"host.example.com", "192.0.2.1-192.0.2.5", "192.0.2.1-5", ""} {
		if err := s.CheckTarget([]string{"192.0.2.128/25"}, []string{bad}); err == nil {
			t.Errorf("exclude_hosts %q não é IP/CIDR literal e deveria ser recusado", bad)
		}
	}
	// Excluir nunca amplia: uma exclusão literal fora do escopo ou degenerada é aceita.
	if err := s.CheckTarget([]string{"192.0.2.128/25"}, []string{"203.0.113.0/24", "127.0.0.1"}); err != nil {
		t.Errorf("exclusão literal qualquer deveria ser aceita: %v", err)
	}
}

func TestCheckTargetRejectsNonLiteralHosts(t *testing.T) {
	s := fleetScope(t)
	for _, bad := range []string{"host.example.com", "192.0.2.1-192.0.2.5", "192.0.2.1-5",
		"192.0.2.5:80", "", "fe80::1%eth0", "192.0.2.5,192.0.2.6"} {
		if err := s.CheckTarget([]string{bad}, nil); err == nil {
			t.Errorf("host %q não é IP/CIDR literal e deveria ser recusado", bad)
		}
	}
}

func TestCheckTargetDeniesDegenerateSpace(t *testing.T) {
	s, err := New(broadAllow, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range degenerateHosts {
		if err := s.CheckTarget([]string{h}, nil); err == nil {
			t.Errorf("%s deveria ser negado (espaço degenerado)", h)
		}
	}
}

func TestCheckTargetIPv6(t *testing.T) {
	s, err := New("2001:db8::/32, fd00::/8", "2001:db8:1::10, fd12:3456:789a::10")
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"2001:db8:2::/48", "2001:db8::5", "fd12:3456:789b::/48"} {
		if err := s.CheckTarget([]string{ok}, nil); err != nil {
			t.Errorf("%s deveria passar: %v", ok, err)
		}
	}
	for _, bad := range []string{"2001:db8:1::/64", "fd12:3456:789a::/64", "2001:db8::/16", "fd00:ec2::/64"} {
		if err := s.CheckTarget([]string{bad}, nil); err == nil {
			t.Errorf("%s deveria ser negado (contém o nó, fora do escopo ou sobrepõe metadata)", bad)
		}
	}
}

func TestCheckTargetEmptyAllowDeniesAll(t *testing.T) {
	s, err := New("", nodeIPs)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"192.0.2.128/25", "198.51.100.7", "2001:db8:2::/48"} {
		if err := s.CheckTarget([]string{h}, nil); err == nil {
			t.Errorf("allow vazio nega tudo, mas %s passou", h)
		}
	}
}

func TestCheckTargetEmptyHostsDenied(t *testing.T) {
	if err := fleetScope(t).CheckTarget(nil, []string{"192.0.2.200"}); err == nil {
		t.Fatal("alvo sem hosts deveria ser recusado")
	}
}

// TestCheckTargetErrorEchoIsBoundedAndQuoted: o motivo do erro cita a entrada
// recusada cortada e entre aspas, sem quebra de linha crua nem eco ilimitado.
func TestCheckTargetErrorEchoIsBoundedAndQuoted(t *testing.T) {
	s := fleetScope(t)
	long := strings.Repeat("x", 10000)
	for _, c := range []struct{ hosts, excl []string }{
		{[]string{long}, nil},
		{[]string{"192.0.2.128/25"}, []string{long}},
		{[]string{"evil.example\r\nfake: line"}, nil},
	} {
		err := s.CheckTarget(c.hosts, c.excl)
		if err == nil {
			t.Fatalf("hosts=%.20q excl=%.20q deveria ser recusado", c.hosts, c.excl)
		}
		if msg := err.Error(); len(msg) > 200 || strings.ContainsAny(msg, "\r\n") {
			t.Errorf("motivo sem limite ou com quebra de linha crua (%d bytes): %.120q", len(msg), msg)
		}
	}
}
