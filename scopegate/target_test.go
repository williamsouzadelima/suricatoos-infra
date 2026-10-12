package scopegate

import (
	"net/netip"
	"reflect"
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
		if _, _, err := s.CheckTarget(hosts, excl); err != nil {
			t.Errorf("exclude_hosts=%q: alvo dentro do escopo deveria passar: %v", excl, err)
		}
	}
}

func TestCheckTargetDeniesCIDRContainingNode(t *testing.T) {
	var w warnings
	// A frota sempre nega, mesmo num Scope em modo log (o do sensor), e sem aviso.
	for name, s := range map[string]*Scope{"enforce": fleetScope(t), "log": fleetScope(t, LogSelfDenyCIDR(w.record))} {
		for _, h := range []string{"192.0.2.0/24", "192.0.2.8/29", "2001:db8:1::/64", "192.0.2.10", "::ffff:192.0.2.10"} {
			if _, _, err := s.CheckTarget([]string{"192.0.2.128/25", h}, nil); err == nil {
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
		if _, _, err := withHub.CheckTarget([]string{h}, nil); err == nil {
			t.Errorf("%s é ou contém o IP do hub e deveria ser negado", h)
		}
		if _, _, err := s.CheckTarget([]string{h}, nil); err != nil {
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
		if _, _, err := withHub.CheckTarget(c.hosts, c.excl); err == nil {
			t.Errorf("hosts=%q: exclude_hosts=%q não salva CIDR com IP do nó/hub", c.hosts, c.excl)
		}
	}
}

func TestCheckTargetExcludeHostsMustBeLiteral(t *testing.T) {
	s := fleetScope(t)
	for _, bad := range []string{"host.example.com", "192.0.2.1-192.0.2.5", "192.0.2.1-5", ""} {
		if _, _, err := s.CheckTarget([]string{"192.0.2.128/25"}, []string{bad}); err == nil {
			t.Errorf("exclude_hosts %q não é IP/CIDR literal e deveria ser recusado", bad)
		}
	}
	// Excluir nunca amplia: uma exclusão literal fora do escopo ou degenerada é aceita.
	if _, _, err := s.CheckTarget([]string{"192.0.2.128/25"}, []string{"203.0.113.0/24", "127.0.0.1"}); err != nil {
		t.Errorf("exclusão literal qualquer deveria ser aceita: %v", err)
	}
}

func TestCheckTargetRejectsNonLiteralHosts(t *testing.T) {
	s := fleetScope(t)
	for _, bad := range []string{"host.example.com", "192.0.2.1-192.0.2.5", "192.0.2.1-5",
		"192.0.2.5:80", "", "fe80::1%eth0", "192.0.2.5,192.0.2.6"} {
		if _, _, err := s.CheckTarget([]string{bad}, nil); err == nil {
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
		if _, _, err := s.CheckTarget([]string{h}, nil); err == nil {
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
		if _, _, err := s.CheckTarget([]string{ok}, nil); err != nil {
			t.Errorf("%s deveria passar: %v", ok, err)
		}
	}
	for _, bad := range []string{"2001:db8:1::/64", "fd12:3456:789a::/64", "2001:db8::/16", "fd00:ec2::/64"} {
		if _, _, err := s.CheckTarget([]string{bad}, nil); err == nil {
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
		if _, _, err := s.CheckTarget([]string{h}, nil); err == nil {
			t.Errorf("allow vazio nega tudo, mas %s passou", h)
		}
	}
}

func TestCheckTargetEmptyHostsDenied(t *testing.T) {
	if _, _, err := fleetScope(t).CheckTarget(nil, []string{"192.0.2.200"}); err == nil {
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
		_, _, err := s.CheckTarget(c.hosts, c.excl)
		if err == nil {
			t.Fatalf("hosts=%.20q excl=%.20q deveria ser recusado", c.hosts, c.excl)
		}
		if msg := err.Error(); len(msg) > 200 || strings.ContainsAny(msg, "\r\n") {
			t.Errorf("motivo sem limite ou com quebra de linha crua (%d bytes): %.120q", len(msg), msg)
		}
	}
}

// TestCheckTargetRefusesNonCanonicalPrefix: o gvm-libs lê o bloco com sscanf
// "%2u"/"%3u", então "/025" vira /2 e "/0120" vira /12 — o que o portão checou não
// seria o que o gvmd varre. A frota só aceita o prefixo escrito como strconv.Itoa.
func TestCheckTargetRefusesNonCanonicalPrefix(t *testing.T) {
	s := fleetScope(t)
	for _, c := range []struct{ hosts, excl []string }{
		{[]string{"192.0.2.128/025"}, nil},
		{[]string{"198.51.100.0/024"}, nil},
		{[]string{"2001:db8:2::/0048"}, nil},
		{[]string{"2001:db8:2::/0120"}, nil},
		{[]string{"192.0.2.128/25"}, []string{"192.0.2.200/032"}},
	} {
		if got, _, err := s.CheckTarget(c.hosts, c.excl); err == nil {
			t.Errorf("hosts=%q exclude_hosts=%q: prefixo com zero à esquerda deveria ser recusado, passou como %q", c.hosts, c.excl, got)
		}
	}
}

// TestCheckTargetRefusesNonASCII: o Go apara espaço Unicode (U+00A0) e o
// g_strstrip do gvm-libs só apara ASCII; a frota recusa qualquer byte não-ASCII.
func TestCheckTargetRefusesNonASCII(t *testing.T) {
	s := fleetScope(t)
	for _, c := range []struct{ hosts, excl []string }{
		{[]string{"192.0.2.5\u00a0"}, nil},
		{[]string{"\u00a0192.0.2.5"}, nil},
		{[]string{"192.0.2.128/25"}, []string{"192.0.2.200\u00a0"}},
	} {
		if got, _, err := s.CheckTarget(c.hosts, c.excl); err == nil {
			t.Errorf("hosts=%+q exclude_hosts=%+q: byte não-ASCII deveria ser recusado, passou como %q", c.hosts, c.excl, got)
		}
	}
}

// TestCheckTargetReturnsCanonicalForms: devolve, na ordem, a forma canônica de
// cada entrada checada — é o que o conector encaminha ao gvmd (checado == usado) —
// e nada quando recusa.
func TestCheckTargetReturnsCanonicalForms(t *testing.T) {
	s := fleetScope(t)
	hosts, excl, err := s.CheckTarget(
		[]string{" 192.0.2.128/25", "198.51.100.7", "2001:DB8:2:0::/48", "192.0.2.77/27", "::ffff:198.51.100.9", "2001:0db8:0002::5"},
		[]string{"192.0.2.200 ", "198.51.100.1/30", "::ffff:192.0.2.201"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantHosts := []string{"192.0.2.128/25", "198.51.100.7", "2001:db8:2::/48", "192.0.2.64/27", "198.51.100.9", "2001:db8:2::5"}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Errorf("hosts canônicos = %q, quer %q", hosts, wantHosts)
	}
	if wantExcl := []string{"192.0.2.200", "198.51.100.0/30", "192.0.2.201"}; !reflect.DeepEqual(excl, wantExcl) {
		t.Errorf("exclude_hosts canônicos = %q, quer %q", excl, wantExcl)
	}
	if hosts, excl, err := s.CheckTarget([]string{"192.0.2.128/25", "192.0.2.0/24"}, []string{"192.0.2.200"}); err == nil || hosts != nil || excl != nil {
		t.Errorf("alvo recusado não devolve hosts: %q %q %v", hosts, excl, err)
	}
}
