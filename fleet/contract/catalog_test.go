package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// typeMapping reads an allOf of if/then entries that select a member's $defs by "type" (const or enum).
func typeMapping(t *testing.T, allOf []any, member string) map[CommandType]string {
	t.Helper()
	out := map[CommandType]string{}
	for _, c := range allOf {
		o := c.(*ordObj)
		typ := o.obj("if").obj("properties").obj("type")
		then := o.obj("then").obj("properties").obj(member)
		if typ == nil || then == nil {
			continue
		}
		def := strings.TrimPrefix(then.str("$ref"), "#/$defs/")
		types := strList(typ.arr("enum"))
		if typ.has("const") {
			types = []string{typ.str("const")}
		}
		for _, ty := range types {
			if _, dup := out[CommandType(ty)]; dup {
				t.Errorf("%s mapeado duas vezes", ty)
			}
			out[CommandType(ty)] = def
		}
	}
	return out
}

// TestCatalogSchema: the catalog is the command_type enum, in order, and each type's payload and output are the
// $defs the schemas select for it (fleet-command allOf, fleet-result allOf).
func TestCatalogSchema(t *testing.T) {
	docs := loadSchemas(t)
	cmdDefs := docs["fleet-command.schema.json"].obj("$defs")
	var types []string
	for _, e := range Catalog() {
		types = append(types, string(e.Type))
	}
	if want := strList(cmdDefs.obj("command_type").arr("enum")); !slices.Equal(types, want) {
		t.Fatalf("catálogo %v != command_type %v", types, want)
	}
	payloads := typeMapping(t, cmdDefs.obj("command").arr("allOf"), "payload")
	outputs := typeMapping(t, docs["fleet-result.schema.json"].obj("$defs").obj("result").arr("allOf"), "output")
	for _, e := range Catalog() {
		if payloads[e.Type] != e.Payload {
			t.Errorf("%s: payload %q, schema %q", e.Type, e.Payload, payloads[e.Type])
		}
		if outputs[e.Type] != e.Output {
			t.Errorf("%s: saída %q, schema %q", e.Type, e.Output, outputs[e.Type])
		}
		if payloadSpecs[e.Payload] == nil {
			t.Errorf("%s: payload %s sem espelho", e.Type, e.Payload)
		}
	}
	if len(payloads) != len(Catalog()) || len(outputs) != len(Catalog()) {
		t.Errorf("mapeamentos do schema: %d payloads, %d saídas, catálogo %d", len(payloads), len(outputs), len(Catalog()))
	}
}

// TestCatalogADRTable: payload, default policy (permitido / opt-in), budget and node kinds of every type are
// those of the ADR table "Catálogo de comandos v1"; sensitive = opt-in + report.export + report.summary.
func TestCatalogADRTable(t *testing.T) {
	rows := adrTable(t, adrSection(t, "## Catálogo de comandos v1"), 7)
	if len(rows) != len(Catalog()) {
		t.Fatalf("ADR tem %d tipos, Go %d", len(rows), len(Catalog()))
	}
	for i, r := range rows {
		typ := CommandType(backticked.FindStringSubmatch(r[0])[1])
		e, ok := LookupType(typ)
		if !ok {
			t.Errorf("%s do ADR fora do catálogo Go", typ)
			continue
		}
		if Catalog()[i].Type != typ {
			t.Errorf("ordem: ADR %s, Go %s", typ, Catalog()[i].Type)
		}
		if p := backticked.FindStringSubmatch(r[1])[1]; p != e.Payload {
			t.Errorf("%s: payload ADR %s, Go %s", typ, p, e.Payload)
		}
		optIn := strings.HasPrefix(r[2], "opt-in")
		if !optIn && !strings.HasPrefix(r[2], "permitido") {
			t.Fatalf("%s: política %q", typ, r[2])
		}
		if optIn != e.OptIn {
			t.Errorf("%s: opt-in ADR %v, Go %v", typ, optIn, e.OptIn)
		}
		if budget := strings.Contains(r[2], "conta no orçamento"); e.Sensitive != (optIn || budget) {
			t.Errorf("%s: sensível Go %v, ADR opt-in=%v orçamento=%v", typ, e.Sensitive, optIn, budget)
		}
		var kinds []NodeKind
		switch r[3] {
		case "todos":
			kinds = []NodeKind{NodeCentral, NodeStandalone, NodeSensor}
		default:
			for _, k := range strings.Split(r[3], ",") {
				kinds = append(kinds, NodeKind(strings.TrimSpace(k)))
			}
		}
		if !slices.Equal(kinds, e.NodeKinds) {
			t.Errorf("%s: nós ADR %v, Go %v", typ, kinds, e.NodeKinds)
		}
		if o := backticked.FindStringSubmatch(r[6])[1]; o != e.Output {
			t.Errorf("%s: saída ADR %s, Go %s", typ, o, e.Output)
		}
	}
}

// TestCatalogNodeKinds: the valid central-node state example announces every type and the default policy
// (no policy.json), whose policy_sha256 PolicySHA256 recomputes.
func TestCatalogNodeKinds(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(examplesDir, "valid", "state", "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap StateSnapshot
	if err := DecodeStrict(b, &snap); err != nil {
		t.Fatal(err)
	}
	var node DataNode
	if err := DecodeStrict(snap.Data, &node); err != nil {
		t.Fatal(err)
	}
	if node.NodeKind != NodeCentral {
		t.Fatalf("exemplo de nó central: %s", node.NodeKind)
	}
	if got := SupportedTypes(NodeCentral); !slices.Equal(got, node.Capabilities.SupportedTypes) {
		t.Errorf("tipos do central %v != exemplo %v", got, node.Capabilities.SupportedTypes)
	}
	def := DefaultPolicy(NodeCentral)
	if !slices.Equal(sortedTypes(def.Allow), node.Policy.Allow) || def.SensitivePerHour != node.Policy.SensitivePerHour || def.TotalPerHour != node.Policy.TotalPerHour {
		t.Errorf("política padrão do central %+v != exemplo %+v", def, node.Policy)
	}
	if got := PolicySHA256(node.Policy); got != node.PolicySHA256 {
		t.Errorf("PolicySHA256 %s != exemplo %s", got, node.PolicySHA256)
	}
	if PolicySHA256(def) != node.PolicySHA256 {
		t.Error("policy_sha256 independe da ordem de allow")
	}
	for _, k := range []NodeKind{NodeStandalone, NodeSensor} {
		allow := DefaultAllow(k)
		if slices.Contains(allow, TypeAgentScanNow) || !slices.Contains(allow, TypeTaskStart) {
			t.Errorf("%s: padrão %v", k, allow)
		}
		if slices.Contains(SupportedTypes(k), TypeEnrollTokenCreate) {
			t.Errorf("%s não suporta enroll_token.create", k)
		}
	}
	if !slices.Contains(SupportedTypes(NodeStandalone), TypeFeedSyncNow) || slices.Contains(SupportedTypes(NodeSensor), TypeFeedSyncNow) {
		t.Error("feed.sync_now: central e standalone")
	}
	if _, ok := LookupType("tenant.scope_set"); ok {
		t.Error("tipo fora do catálogo")
	}
	if e, _ := LookupType(TypeReportExport); !e.Sensitive || e.OptIn || !e.Supports(NodeSensor) {
		t.Errorf("report.export: %+v", e)
	}
	// policy_sha256 = compact JSON with sorted keys: the struct's members must stay in alphabetical order
	var names []string
	for _, f := range fieldsOf(reflect.TypeOf(Policy{})).list {
		names = append(names, f.name)
	}
	if !slices.IsSorted(names) {
		t.Errorf("membros de Policy fora de ordem alfabética: %v", names)
	}
	c := Catalog()
	c[0].NodeKinds[0] = "x"
	if Catalog()[0].NodeKinds[0] == "x" {
		t.Error("Catalog deve devolver cópia")
	}
	var p Policy
	if err := json.Unmarshal([]byte(`{"allow":null,"sensitive_per_hour":1,"total_per_hour":2}`), &p); err != nil || PolicySHA256(p) != PolicySHA256(Policy{Allow: []CommandType{}, SensitivePerHour: 1, TotalPerHour: 2}) {
		t.Error("allow nil conta como lista vazia")
	}
}

func sortedTypes(ts []CommandType) []CommandType {
	c := slices.Clone(ts)
	slices.Sort(c)
	return c
}
