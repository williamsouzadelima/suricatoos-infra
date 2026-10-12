package scopegate

import (
	"reflect"
	"strings"
	"testing"
)

// Nó de documentação (RFC 5737 / RFC 3849): mora em 192.0.2.10, no /24 da LAN.
const (
	lanAllow = "192.0.2.0/24, 2001:db8::/32"
	nodeIPs  = "192.0.2.10, 2001:db8:1::10"
)

// warnings records what a log-mode Scope reports, one entry per call.
type warnings []string

func (w *warnings) record(cidr, reason string) { *w = append(*w, cidr+" | "+reason) }

func TestCIDRContainingSelfIPDeniedByDefault(t *testing.T) {
	for _, c := range []struct{ deny, host string }{
		{nodeIPs, "192.0.2.0/24"}, // o /24 inteiro da LAN do nó
		{nodeIPs, "192.0.2.0/25"},
		{nodeIPs, "192.0.2.8/29"},
		{nodeIPs, "2001:db8:1::/64"},
		{"::ffff:192.0.2.10", "192.0.2.0/24"}, // self-deny escrito na forma IPv4-mapeada
	} {
		s, err := New(lanAllow, c.deny)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.CheckHost(c.host); err == nil {
			t.Errorf("deny=%q: CIDR %s contém IP do self-deny e deveria ser negado, passou como %q", c.deny, c.host, got)
		}
	}
	// Uma faixa da LAN que não contém o nó continua passando.
	s, _ := New(lanAllow, nodeIPs)
	for _, ok := range []string{"192.0.2.128/25", "192.0.2.0/29", "2001:db8:2::/48"} {
		if _, err := s.CheckHost(ok); err != nil {
			t.Errorf("CIDR %s não contém o nó e deveria passar: %v", ok, err)
		}
	}
}

func TestCIDRContainingSelfIPPassesAndWarnsInLogMode(t *testing.T) {
	var w warnings
	s, err := New(lanAllow, nodeIPs, LogSelfDenyCIDR(w.record))
	if err != nil {
		t.Fatal(err)
	}
	// 192.0.0.0/16 também contém o nó, mas sai por estar fora do escopo: sem aviso.
	kept, dropped := s.Filter([]string{"192.0.2.0/24", "192.0.2.128/25", "192.0.2.10", "192.0.0.0/16"})
	if !reflect.DeepEqual(kept, []string{"192.0.2.0/24", "192.0.2.128/25"}) {
		t.Fatalf("kept errado: %v", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"192.0.2.10", "192.0.0.0/16"}) {
		t.Fatalf("dropped errado: %v (o IP do nó isolado é sempre negado)", dropped)
	}
	if len(w) != 1 || !strings.HasPrefix(w[0], "192.0.2.0/24 | ") {
		t.Fatalf("esperado UM aviso para 192.0.2.0/24, veio %q", w)
	}
	if strings.Contains(w[0], "192.0.2.10") {
		t.Fatalf("o aviso não pode expor o IP do self-deny: %q", w[0])
	}
}

// TestSelfIPAsSingleAddressCIDRAlwaysDenied: um /32 ou /128 É o próprio IP do
// self-deny, que é negado isolado em qualquer modo (antes passava como CIDR).
func TestSelfIPAsSingleAddressCIDRAlwaysDenied(t *testing.T) {
	var w warnings
	enforce, _ := New(lanAllow, nodeIPs)
	logMode, _ := New(lanAllow, nodeIPs, LogSelfDenyCIDR(w.record))
	for _, h := range []string{"192.0.2.10/32", "2001:db8:1::10/128"} {
		for name, s := range map[string]*Scope{"enforce": enforce, "log": logMode} {
			if got, err := s.CheckHost(h); err == nil {
				t.Errorf("%s (%s) é o IP do nó e deveria ser negado, passou como %q", h, name, got)
			}
		}
	}
	if len(w) != 0 {
		t.Fatalf("IP do self-deny negado não gera aviso de modo log: %q", w)
	}
}
