package verifier

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// scenario is one envelope with the local state it meets.
type scenario struct {
	name    string
	cmd     contract.Command
	payload string
	at      time.Time
	allow   []contract.CommandType
	total   int
	pre     []func(n *node) // before anything else breaks the node (a recorded entry, the floor)
	setup   []func(n *node)
}

// breaker introduces ONE defect into a scenario; alone, it yields want.
type breaker struct {
	name  string
	want  contract.RejectReason
	apply func(s *scenario)
}

// breakers are the defects in the ADR's order of verification: when two coexist, the earlier one decides. A read
// failure (unavailable) sits where its read is: the registry before line 6's verdict, the gvmd read before the gate.
var breakers = []breaker{
	{"bad_window", contract.ReasonBadWindow, func(s *scenario) { s.cmd.NotAfter = contract.FormatUTCTime(t0.Add(24*time.Hour + time.Second)) }},
	{"not_yet_valid", contract.ReasonNotYetValid, func(s *scenario) { s.at = t0.Add(-skew - time.Second) }},
	{"expired", contract.ReasonExpired, func(s *scenario) { s.at = t0.Add(time.Hour + skew + time.Second) }},
	{"wrong_node", contract.ReasonWrongNode, func(s *scenario) { s.cmd.NodeID = "node-lab-0002" }},
	{"replay", contract.ReasonReplay, func(s *scenario) {
		s.pre = append(s.pre, func(n *node) { // the same command_id, recorded earlier with another canonical form
			c := command(s.name, contract.TypeTaskStart)
			c.Nonce = nonceOf("anterior/" + s.name)
			c.IssuedAt, c.NotAfter = contract.FormatUTCTime(boot.Add(-30*time.Minute)), contract.FormatUTCTime(boot.Add(30*time.Minute))
			if o := n.process(signed(c, payloads[contract.TypeTaskStart]), boot); o.Kind != Ack || o.Ack.Decision == contract.DecisionDeferred {
				n.t.Fatalf("a entrada anterior não foi gravada: %+v", o)
			}
		})
	}},
	{"replay_floor", contract.ReasonReplay, func(s *scenario) {
		s.pre = append(s.pre, func(n *node) {
			if err := n.st.Store.SetFloor(t0); err != nil {
				n.t.Fatal(err)
			}
		})
	}},
	{"tenants_unreadable", contract.ReasonUnavailable, func(s *scenario) {
		s.setup = append(s.setup, func(n *node) {
			p := filepath.Join(n.dir, "tenants.json")
			os.Remove(p)
			os.Mkdir(p, 0o700)
		})
	}},
	{"tenant_unknown", contract.ReasonTenantUnknown, func(s *scenario) { s.cmd.Tenant = "desconhecido" }},
	{"unsupported", contract.ReasonUnsupported, func(s *scenario) { s.cmd.Type = "foo.bar" }},
	// the policy is read only for what needs it (allow, budgets): after the tenant and the catalog
	{"policy_unreadable", contract.ReasonUnavailable, func(s *scenario) {
		s.setup = append(s.setup, func(n *node) {
			if err := os.WriteFile(filepath.Join(n.dir, "policy.json"), []byte("{"), 0o600); err != nil {
				n.t.Fatal(err)
			}
		})
	}},
	{"type_not_allowed", contract.ReasonTypeNotAllowed, func(s *scenario) { s.allow = []contract.CommandType{contract.TypeTaskStop} }},
	{"rate_limited", contract.ReasonRateLimited, func(s *scenario) { s.total = 0 }},
	{"bad_payload", contract.ReasonBadPayload, func(s *scenario) { s.payload = `{"task_id":"não é uuid"}` }},
	{"gvm_read", contract.ReasonUnavailable, func(s *scenario) {
		s.setup = append(s.setup, func(n *node) { n.scope.readErr = errors.New("gvmd fora do ar (simulado)") })
	}},
	{"scope_denied", contract.ReasonScopeDenied, func(s *scenario) {
		s.setup = append(s.setup, func(n *node) { n.scope.targets[tgtID] = TargetHosts{Hosts: []string{"203.0.113.0/24"}} })
	}},
}

// exclusive are pairs that cannot coexist (both set the instant of the verification).
var exclusive = map[[2]string]bool{{"not_yet_valid", "expired"}: true}

func (s *scenario) run(t *testing.T) Outcome {
	t.Helper()
	n := newNode(t)
	writePolicy(t, n.dir, s.allow, 1000, s.total)
	for _, f := range s.pre {
		f(n)
	}
	for _, f := range s.setup {
		f(n)
	}
	n.build()
	return n.process(signed(s.cmd, s.payload), s.at)
}

func newScenario(name string) *scenario {
	return &scenario{name: name, cmd: command(name, contract.TypeTaskStart), payload: payloads[contract.TypeTaskStart],
		at: tv, allow: allTypes(), total: 3600}
}

// Cada defeito sozinho dá o seu motivo; dois defeitos juntos dão o motivo do que vem primeiro na tabela do ADR.
func TestOrdemQuandoDoisDefeitosCoexistem(t *testing.T) {
	for _, b := range breakers {
		s := newScenario("só " + b.name)
		b.apply(s)
		if got := reasonOf(s.run(t)); got != b.want {
			t.Errorf("%s sozinho: %q, esperava %q", b.name, got, b.want)
		}
	}
	for i, first := range breakers {
		for _, second := range breakers[i+1:] {
			if exclusive[[2]string{first.name, second.name}] {
				continue
			}
			s := newScenario(first.name + " + " + second.name)
			first.apply(s)
			second.apply(s)
			if got := reasonOf(s.run(t)); got != first.want {
				t.Errorf("%s + %s: %q, esperava %q (o primeiro)", first.name, second.name, got, first.want)
			}
		}
	}
}

// Na linha 8, payload inválido vem antes da variante não anunciada; e a política (linha 7) antes das duas.
func TestOrdemDentroDaLinha8(t *testing.T) {
	n := newNode(t)
	n.formats = nil // nada anunciado
	exp := command("export ruim", contract.TypeReportExport)
	o := n.process(signed(exp, `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","format":"suricatoos-pdf","lang":"pt_BR","variant":"client","filter":"sem os tokens"}`), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonBadPayload)
	writePolicy(t, n.dir, []contract.CommandType{contract.TypeTaskStart}, 1000, 3600)
	expectAck(t, n.process(env("export fora de allow", contract.TypeReportExport), tv), Ack, contract.DecisionRejected, contract.ReasonTypeNotAllowed)
}
