package planner

import (
	"strings"
	"testing"
)

func TestPseudonymizer_TokenStableAndRoundTrip(t *testing.T) {
	p := newPseudonymizer()
	a := p.token("blackburn", "host")
	b := p.token("blackburn", "host")
	if a != b || a != "host-1" {
		t.Fatalf("token instável: %q %q", a, b)
	}
	if p.token("", "host") != "" {
		t.Fatal("vazio deve mapear p/ vazio")
	}
	s := "corrigir blackburn já"
	scr := p.scrub(s)
	if strings.Contains(scr, "blackburn") {
		t.Fatalf("scrub não removeu: %q", scr)
	}
	if p.restore(scr) != s {
		t.Fatalf("restore não reverteu: %q", p.restore(scr))
	}
}

func TestPseudonymizer_ApplyHidesIdentifiers(t *testing.T) {
	p := newPseudonymizer()
	req := PlanRequest{
		Title:    "Patch ausente em blackburn",
		Evidence: "host blackburn (10.0.0.5) agente win-agent-7 tenant acme",
		Host:     "blackburn", AgentID: "win-agent-7", Tenant: "acme", IP: "10.0.0.5",
	}
	out := p.apply(req)
	blob := out.Title + " " + out.Evidence + " " + out.Host + " " + out.AgentID + " " + out.Tenant + " " + out.IP
	for _, raw := range []string{"blackburn", "10.0.0.5", "win-agent-7", "acme"} {
		if strings.Contains(blob, raw) {
			t.Fatalf("apply deixou identificador cru %q em %q", raw, blob)
		}
	}
	if out.Host != "host-1" || out.IP != "ip-1" {
		t.Fatalf("campos não tokenizados: host=%q ip=%q", out.Host, out.IP)
	}
}
