package verifier

import (
	"crypto/ed25519"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// goldenPath is the file the hub (commandcenter) runs too, pinned by sha256: never edited here.
var goldenPath = filepath.Join("..", "..", "contract", "testdata", "golden-v1.json")

// outcomeName maps an outcome to the expect of a golden vector.
func outcomeName(o Outcome) string {
	switch {
	case o.Kind == NoAck && o.Reason != "":
		return string(o.Reason)
	case o.Kind == Redelivery:
		return contract.OutcomeRedelivery
	case o.Kind == Ack && o.Ack.Decision == contract.DecisionAccepted:
		return contract.OutcomeAccept
	case o.Kind == Ack:
		return string(reasonOf(o))
	}
	return "sem desfecho: " + errText(o.Err)
}

// goldenNode is a node configured with the golden public key — ONLY here, through newVerifier(..., true): New refuses
// it — the vector's own node_id and the file's skew, and every check of local state passing (ADR "Golden vectors",
// item 5): the tenant acme known with a gvmd user and a password, every type allowed in a central node, wide budgets,
// every report format advertised, and the vectors' hosts inside the scope.
func goldenNode(t *testing.T, pub ed25519.PublicKey, ownNodeID string, skew time.Duration) *node {
	t.Helper()
	n := newNode(t)
	n.cfg.CommandKey, n.cfg.NodeID, n.cfg.Skew = pub, ownNodeID, skew
	v, err := newVerifier(n.cfg, n.d, true)
	if err != nil {
		t.Fatal(err)
	}
	n.v = v
	return n
}

// O pipeline, alimentado com o estado local de cada vetor de golden-v1.json — as formas canônicas de seen gravadas
// no store, o relógio em verify_at, o node_id do vetor e o resto do estado local passando —, reproduz TODOS os
// desfechos do arquivo que o hub também roda.
func TestGoldenVectorsNoPipeline(t *testing.T) {
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := contract.ParseGoldenFile(b)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := contract.ParsePublicKeyPEM([]byte(f.TestKey.PublicKeyPEM))
	if err != nil || !contract.IsGoldenTestKey(pub) {
		t.Fatalf("chave de teste do arquivo: %v", err)
	}
	skew := time.Duration(f.SkewSeconds) * time.Second
	byCanon := map[string]string{} // canonical sha256 → the envelope that carries it
	for _, v := range f.Vectors {
		if _, ok := byCanon[v.CanonicalSHA256]; !ok {
			byCanon[v.CanonicalSHA256] = v.CommandJSON
		}
	}
	seen := map[string]int{}
	for _, gv := range f.Vectors {
		t.Run(gv.Name, func(t *testing.T) {
			at, err := contract.ParseUTCTime(gv.VerifyAt)
			if err != nil {
				t.Fatal(err)
			}
			n := goldenNode(t, pub, gv.OwnNodeID, skew)
			for i, s := range gv.Seen { // what the store already recorded under the vector's nonce or command_id
				raw, ok := byCanon[s]
				if !ok {
					t.Fatalf("seen %s sem envelope no arquivo", s)
				}
				ver, err := contract.Verify(pub, []byte(raw))
				if err != nil {
					t.Fatalf("envelope de seen não autentica: %v", err)
				}
				d := replay.Decision{Decision: contract.DecisionAccepted} // the original...
				if i > 0 {
					d = replay.Decision{Decision: contract.DecisionRejected, Reason: contract.ReasonReplay} // ...then the recorded replay
				}
				if _, err := n.st.Store.Record(ver, d, ver.IssuedAt()); err != nil {
					t.Fatalf("gravar seen: %v", err)
				}
			}
			o := n.process([]byte(gv.CommandJSON), at)
			if got := outcomeName(o); got != gv.Expect {
				t.Fatalf("desfecho %s, esperava %s", got, gv.Expect)
			}
			seen[gv.Expect]++
		})
	}
	if len(seen) < 12 || seen[contract.OutcomeAccept] < 20 || seen[contract.OutcomeRedelivery] != 2 {
		t.Fatalf("cobertura dos desfechos: %v", seen)
	}
}

// New recusa a chave de teste pública dos golden vectors; o pipeline só a aceita pelo caminho interno do teste.
func TestNewRecusaAChaveGolden(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 30, 120)
	st, err := OpenState(dir, boot, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := newNodeOver(t, dir, st)
	cfg := n.cfg
	cfg.CommandKey = contract.GoldenTestPublicKey()
	if _, err := New(cfg, st); err == nil {
		t.Fatal("New aceitou a chave golden")
	}
	if _, err := newVerifier(cfg, n.d, false); err == nil {
		t.Fatal("newVerifier sem a permissão de teste aceitou a chave golden")
	}
	cfg.CommandKey = testPub()
	v, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New com uma chave de teste comum: %v", err)
	}
	if o := v.Process(env("a", contract.TypeTaskStart), tv); o.Kind != Ack || o.Ack.Decision != contract.DecisionAccepted {
		t.Fatalf("o pipeline do New: %+v", o)
	}
}

// O resto da configuração também é conferido no New.
func TestNewConfereAConfiguracao(t *testing.T) {
	n := newNode(t)
	for name, mod := range map[string]func(c *Config){
		"chave curta":   func(c *Config) { c.CommandKey = c.CommandKey[:31] },
		"node_id":       func(c *Config) { c.NodeID = "Nó Inválido" },
		"node_kind":     func(c *Config) { c.NodeKind = "hub" },
		"skew negativo": func(c *Config) { c.Skew = -time.Second },
		"skew > 10 min": func(c *Config) { c.Skew = contract.MaxClockSkew + time.Second },
		"sem state dir": func(c *Config) { c.StateDir = "" },
		"sem tenants":   func(c *Config) { c.Tenants = nil },
		"sem formatos":  func(c *Config) { c.ReportFormats = nil },
		"sem escopo":    func(c *Config) { c.Scope = nil },
	} {
		cfg := n.cfg
		mod(&cfg)
		if _, err := New(cfg, n.st); err == nil {
			t.Errorf("%s: New aceitou", name)
		}
	}
	if _, err := New(n.cfg, nil); err == nil {
		t.Error("New sem estado local aceitou")
	}
	if _, err := New(n.cfg, n.st); err != nil {
		t.Fatalf("configuração válida: %v", err)
	}
	if !errors.Is(func() error { c := n.cfg; c.Skew = 11 * time.Minute; _, err := New(c, n.st); return err }(), contract.ErrInvalidSkew) {
		t.Error("skew acima do teto é ErrInvalidSkew")
	}
}

// Um único ponto de chamada do Verify no código do pacote, com a chave PINADA (o campo key, que só o newVerifier
// preenche, a partir da Config), e nenhum VerifyAt: o selo do Verified amarra o conteúdo, não a chave. E a permissão
// de usar a chave golden (newVerifier(..., true)) só aparece em teste.
func TestUmUnicoPontoDeChamadaDoVerifyComAChavePinada(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var verifyCalls, verifyAtCalls, goldenAllowed, keyWrites int
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "contract" {
						switch sel.Sel.Name {
						case "Verify":
							verifyCalls++
							if arg, ok := x.Args[0].(*ast.SelectorExpr); !ok || arg.Sel.Name != "key" {
								t.Errorf("%s: contract.Verify sem a chave pinada (v.key)", fset.Position(x.Pos()))
							}
						case "VerifyAt":
							verifyAtCalls++
						}
					}
				}
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "newVerifier" && len(x.Args) == 3 {
					if lit, ok := x.Args[2].(*ast.Ident); !ok || lit.Name != "false" {
						goldenAllowed++
					}
				}
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "key" {
					keyWrites++
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "key" {
						keyWrites += 100 // nunca: a chave não muda depois do newVerifier
					}
				}
			}
			return true
		})
	}
	if verifyCalls != 1 || verifyAtCalls != 0 || goldenAllowed != 0 || keyWrites != 1 {
		t.Fatalf("Verify %d (esperava 1), VerifyAt %d, newVerifier com a chave golden permitida %d, escritas da chave %d",
			verifyCalls, verifyAtCalls, goldenAllowed, keyWrites)
	}
}
