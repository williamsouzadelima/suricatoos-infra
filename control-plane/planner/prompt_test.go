package planner

import (
	"strings"
	"testing"
)

func TestBuildMessages_AllowlistExcludesNonTechnicalIDs(t *testing.T) {
	// Even with RAW identifying fields set, buildMessages emits only the allowlisted
	// fields — Tenant/IP/FindingID are never serialized into the prompt.
	preq := PlanRequest{
		FindingID: "f1", Type: "config_hardening", Title: "SMBv1 habilitado",
		Severity: "8.1 High", CVEs: []string{"CVE-2017-0144"}, RuleRef: "2.3.x",
		Evidence: "current=1 expected=0", OS: "Windows Server 2019",
		Tenant: "acme", IP: "10.0.0.5", Host: "host-1",
	}
	msgs := buildMessages(preq)
	if len(msgs) != 2 || msgs[0].Role != "system" || msgs[1].Role != "user" {
		t.Fatalf("esperava system+user, veio %+v", msgs)
	}
	user := msgs[1].Content
	for _, must := range []string{"8.1 High", "CVE-2017-0144", "2.3.x", "SMBv1", "current=1 expected=0"} {
		if !strings.Contains(user, must) {
			t.Fatalf("prompt deveria conter fato atestado %q", must)
		}
	}
	for _, forbidden := range []string{"acme", "10.0.0.5", "f1"} {
		if strings.Contains(user, forbidden) {
			t.Fatalf("prompt NÃO deveria conter %q (fora do allowlist)", forbidden)
		}
	}
	if !strings.Contains(msgs[0].Content, "NÃO invente") {
		t.Fatal("system prompt deveria fixar a regra de não-fabricação")
	}
}
