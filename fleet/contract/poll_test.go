package contract

import (
	"strings"
	"testing"
)

// TestDecodePollResponse: only the outer object is judged (1–10 commands, exact member, strict JSON, 1 MiB);
// each envelope comes back raw and byte-exact, and a bad one does not sink the others — it fails alone, at
// its own verification.
func TestDecodePollResponse(t *testing.T) {
	list := func(n int, item string) string {
		return `{"commands":[` + strings.TrimSuffix(strings.Repeat(item+",", n), ",") + `]}`
	}
	dupInside := strings.Replace(adrEnvelope, `"tenant":"acme",`, `"tenant":"acme","tenant":"acme",`, 1)
	cases := []struct {
		name    string
		in      string
		keyword string
		path    string
		n       int
	}{
		{"um comando", list(1, adrEnvelope), "", "", 1},
		{"dez comandos", list(10, adrEnvelope), "", "", 10},
		{"onze comandos", list(11, adrEnvelope), "maxItems", "/commands", 0},
		{"lista vazia", `{"commands":[]}`, "minItems", "/commands", 0},
		{"sem commands", `{}`, "required", "", 0},
		{"membro desconhecido", `{"commands":[` + adrEnvelope + `],"next":"x"}`, "additionalProperties", "", 0},
		{"commands repetido", `{"commands":[` + adrEnvelope + `],"commands":[` + adrEnvelope + `]}`, "duplicate_key", "/commands", 0},
		{"commands não é array", `{"commands":{}}`, "type", "/commands", 0},
		{"não é objeto", `[]`, "type", "", 0},
		{"dado depois", list(1, adrEnvelope) + `x`, "json_syntax", "", 0},
		{"envelope com chave duplicada ainda separa", `{"commands":[` + dupInside + `,` + adrEnvelope + `]}`, "", "", 2},
		{"acima de 1 MiB", `{"commands":[` + adrEnvelope + strings.Repeat(" ", MaxPollResponseBytes) + `]}`, "size", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds, err := DecodePollResponse([]byte(c.in))
			kw, path := violationOf(t, err)
			if kw != c.keyword || path != c.path || len(cmds) != c.n {
				t.Fatalf("got (%q, %q, %d comandos), want (%q, %q, %d)", kw, path, len(cmds), c.keyword, c.path, c.n)
			}
			for i, raw := range cmds {
				_, verr := Verify(goldenPub, raw)
				if c.name == "envelope com chave duplicada ainda separa" && i == 0 {
					if r, _ := ReasonOf(verr); r != ReasonBadEnvelope || string(raw) != dupInside {
						t.Fatalf("o envelope ruim falha sozinho, com os bytes exatos: %v", verr)
					}
					continue
				}
				if verr != nil || string(raw) != adrEnvelope {
					t.Fatalf("comando %d: %v %q", i, verr, raw)
				}
			}
		})
	}
}
