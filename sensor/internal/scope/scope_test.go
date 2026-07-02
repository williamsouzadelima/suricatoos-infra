package scope

import (
	"reflect"
	"testing"
)

func TestScopeAllowsInternalRanges(t *testing.T) {
	s, err := New("10.20.0.0/16, 192.168.50.0/24", "")
	if err != nil {
		t.Fatal(err)
	}
	// Redes internas SÃO alvos legítimos (o ponto do sensor).
	for _, ip := range []string{"10.20.5.5", "192.168.50.13"} {
		if got, err := s.CheckHost(ip); err != nil || got != ip {
			t.Errorf("%s deveria passar, got %q err=%v", ip, got, err)
		}
	}
	// Fora do escopo.
	if _, err := s.CheckHost("10.99.0.1"); err == nil {
		t.Error("IP fora do escopo deveria falhar")
	}
}

func TestScopeAbsoluteDeny(t *testing.T) {
	// Mesmo com escopo amplo, self-protection sempre nega.
	s, _ := New("0.0.0.0/0,::/0", "")
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1"} {
		if _, err := s.CheckHost(ip); err == nil {
			t.Errorf("%s deveria ser negado (self-protection)", ip)
		}
	}
}

func TestScopeSelfDeny(t *testing.T) {
	// A allowlist inclui a faixa, mas SCAN_SELF_DENY_IPS nega o próprio IP do sensor + a nuvem.
	s, _ := New("10.20.0.0/16", "10.20.0.9, 172.233.11.97")
	if _, err := s.CheckHost("10.20.0.9"); err == nil {
		t.Error("IP do próprio sensor deveria ser negado")
	}
	if _, err := s.CheckHost("172.233.11.97"); err == nil {
		t.Error("endpoint da nuvem deveria ser negado")
	}
	if _, err := s.CheckHost("10.20.0.10"); err != nil {
		t.Errorf("outro host da faixa deveria passar: %v", err)
	}
}

func TestScopeCIDRTargets(t *testing.T) {
	s, _ := New("10.20.0.0/16", "")
	// CIDR ⊆ allow → aceito (canônico).
	if got, err := s.CheckHost("10.20.5.0/24"); err != nil || got != "10.20.5.0/24" {
		t.Errorf("/24 dentro do /16 deveria passar, got %q err=%v", got, err)
	}
	// CIDR mais amplo que o allow → rejeitado.
	if _, err := s.CheckHost("10.20.0.0/8"); err == nil {
		t.Error("/8 (mais amplo) não deveria passar")
	}
	// CIDR fora do escopo → rejeitado.
	if _, err := s.CheckHost("192.168.0.0/24"); err == nil {
		t.Error("CIDR fora do escopo não deveria passar")
	}
}

func TestScopeRejectsHostname(t *testing.T) {
	s, _ := New("10.20.0.0/16", "")
	for _, h := range []string{"evil.com", "notanip", "", "10.20.0.1:80"} {
		if _, err := s.CheckHost(h); err == nil {
			t.Errorf("hostname/malformado %q deveria ser rejeitado", h)
		}
	}
}

func TestScopeEmptyDenyAll(t *testing.T) {
	s, _ := New("", "")
	if !s.Empty() {
		t.Fatal("escopo vazio deveria reportar Empty")
	}
	if _, err := s.CheckHost("10.0.0.1"); err == nil {
		t.Error("escopo vazio deveria negar tudo")
	}
}

func TestScopeFilter(t *testing.T) {
	s, _ := New("10.20.0.0/16", "10.20.0.9")
	kept, dropped := s.Filter([]string{"10.20.1.1", "8.8.8.8", "10.20.0.9", "evil.com"})
	if !reflect.DeepEqual(kept, []string{"10.20.1.1"}) {
		t.Fatalf("kept errado: %v", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"8.8.8.8", "10.20.0.9", "evil.com"}) {
		t.Fatalf("dropped errado: %v", dropped)
	}
}
