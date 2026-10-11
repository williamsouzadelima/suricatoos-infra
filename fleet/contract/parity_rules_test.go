package contract

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// toNode rebuilds a schema node as the Go mirror; a keyword the mirror does not model fails the test, so a
// constraint added to the schema can never be silently ignored by the Go validators.
func toNode(t *testing.T, loc string, o *ordObj) *node {
	t.Helper()
	n := &node{}
	intOf := func(k string) *int {
		v, ok := o.num(k)
		if !ok {
			t.Fatalf("%s: %s não é inteiro", loc, k)
		}
		i := int(v)
		return &i
	}
	for _, k := range o.keys {
		switch k {
		case "$ref":
			n.Ref = o.str(k)
		case "type":
			n.Type = o.str(k)
		case "format":
			n.Format = o.str(k)
		case "minLength":
			n.MinLength = intOf(k)
		case "maxLength":
			n.MaxLength = intOf(k)
		case "minItems":
			n.MinItems = intOf(k)
		case "maxItems":
			n.MaxItems = intOf(k)
		case "minimum", "maximum":
			v, ok := o.num(k)
			if !ok {
				t.Fatalf("%s: %s não é inteiro", loc, k)
			}
			if k == "minimum" {
				n.Minimum = &v
			} else {
				n.Maximum = &v
			}
		case "pattern":
			n.Pattern = o.str(k)
		case "not":
			n.Not = toNode(t, loc+"/not", o.obj(k))
		case "allOf", "anyOf":
			var list []*node
			for i, a := range o.arr(k) {
				list = append(list, toNode(t, loc+"/"+k+"/"+string(rune('0'+i)), a.(*ordObj)))
			}
			if k == "allOf" {
				n.AllOf = list
			} else {
				n.AnyOf = list
			}
		case "enum":
			n.Enum = strList(o.arr(k))
		case "const":
			s, ok := o.get(k).(string)
			if !ok {
				t.Fatalf("%s: const não-string sem espelho", loc)
			}
			n.Const = &s
		case "uniqueItems":
			n.UniqueItems, _ = o.get(k).(bool)
		case "items":
			n.Items = toNode(t, loc+"/items", o.obj(k))
		case "description":
		default:
			t.Errorf("%s: palavra-chave %q sem espelho no Go", loc, k)
		}
	}
	return n
}

// canonicalJSON renders an ordered schema value (or a Go JSON string) with sorted keys, for comparison.
func canonicalJSON(t *testing.T, v any) string {
	t.Helper()
	var plain func(any) any
	plain = func(x any) any {
		switch x := x.(type) {
		case *ordObj:
			m := map[string]any{}
			for _, k := range x.keys {
				m[k] = plain(x.m[k])
			}
			return m
		case []any:
			out := make([]any, len(x))
			for i := range x {
				out[i] = plain(x[i])
			}
			return out
		}
		return x
	}
	if s, ok := v.(string); ok {
		var x any
		if err := json.Unmarshal([]byte(s), &x); err != nil {
			t.Fatalf("JSON do combinador no Go: %v", err)
		}
		v = x
	} else {
		v = plain(v)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type specView struct {
	props       []string
	nodes       map[string]*node
	required    []string
	closed      bool
	minProps    *int
	maxProps    *int
	combinators map[string]string
}

func toSpec(t *testing.T, loc string, o *ordObj) specView {
	t.Helper()
	s := specView{nodes: map[string]*node{}, combinators: map[string]string{}}
	for _, k := range o.keys {
		switch k {
		case "type":
			if o.str(k) != "object" {
				t.Errorf("%s: type %q", loc, o.str(k))
			}
		case "required":
			s.required = strList(o.arr(k))
		case "additionalProperties":
			if b, ok := o.get(k).(bool); !ok || b {
				t.Errorf("%s: additionalProperties diferente de false", loc)
			}
			s.closed = true
		case "properties":
			props := o.obj(k)
			for _, p := range props.keys {
				s.props = append(s.props, p)
				s.nodes[p] = toNode(t, loc+"/"+p, props.obj(p))
			}
		case "minProperties", "maxProperties":
			v, _ := o.num(k)
			i := int(v)
			if k == "minProperties" {
				s.minProps = &i
			} else {
				s.maxProps = &i
			}
		case "allOf", "oneOf", "not":
			s.combinators[k] = canonicalJSON(t, o.get(k))
		case "description":
		default:
			t.Errorf("%s: palavra-chave de objeto %q sem espelho no Go", loc, k)
		}
	}
	return s
}

func (s *objectSpec) view(t *testing.T) specView {
	v := specView{nodes: map[string]*node{}, combinators: map[string]string{}, required: s.Required,
		closed: s.Closed, minProps: s.MinProps, maxProps: s.MaxProps}
	for _, p := range s.Props {
		v.props = append(v.props, p.Name)
		v.nodes[p.Name] = p.Node
	}
	for k, js := range s.Combinators {
		v.combinators[k] = canonicalJSON(t, js)
	}
	return v
}

func compareSpecs(t *testing.T, loc string, schema, goSide specView) {
	t.Helper()
	if !slices.Equal(schema.props, goSide.props) {
		t.Errorf("%s: propriedades %v != Go %v", loc, schema.props, goSide.props)
	}
	for _, p := range schema.props {
		if !reflect.DeepEqual(schema.nodes[p], goSide.nodes[p]) {
			sj, _ := json.Marshal(schema.nodes[p])
			gj, _ := json.Marshal(goSide.nodes[p])
			t.Errorf("%s/%s:\n schema %s\n     Go %s", loc, p, sj, gj)
		}
	}
	if !slices.Equal(sortedCopy(schema.required), sortedCopy(goSide.required)) {
		t.Errorf("%s: required %v != Go %v", loc, schema.required, goSide.required)
	}
	if schema.closed != goSide.closed || !reflect.DeepEqual(schema.minProps, goSide.minProps) || !reflect.DeepEqual(schema.maxProps, goSide.maxProps) {
		t.Errorf("%s: additionalProperties/minProperties/maxProperties divergem", loc)
	}
	if !reflect.DeepEqual(schema.combinators, goSide.combinators) {
		t.Errorf("%s: combinadores\n schema %v\n     Go %v", loc, schema.combinators, goSide.combinators)
	}
}

// TestParityRules: every primitive of fleet-command.schema.json#/$defs (and the state_kind the payloads
// reference) is mirrored in Go with IDENTICAL keywords — the patterns as identical strings — and the envelope
// that line 0 checks plus every v1 payload of line 8 carry exactly the schema's constraints.
func TestParityRules(t *testing.T) {
	docs := loadSchemas(t)
	cmdDefs := docs["fleet-command.schema.json"].obj("$defs")
	want := map[string]*node{}
	for _, name := range cmdDefs.keys {
		d := cmdDefs.obj(name)
		if d.has("properties") || d.str("type") == "object" {
			continue
		}
		want["#/$defs/"+name] = toNode(t, "fleet-command.schema.json#/$defs/"+name, d)
	}
	stateKind := "fleet-state.schema.json#/$defs/state_kind"
	want[stateKind] = toNode(t, stateKind, docs["fleet-state.schema.json"].obj("$defs").obj("state_kind"))
	for ref, n := range want {
		g, ok := defs[ref]
		if !ok {
			t.Errorf("primitivo %s sem espelho no Go", ref)
			continue
		}
		if !reflect.DeepEqual(n, g) {
			sj, _ := json.Marshal(n)
			gj, _ := json.Marshal(g)
			t.Errorf("%s:\n schema %s\n     Go %s", ref, sj, gj)
		}
	}
	for ref := range defs {
		if want[ref] == nil {
			t.Errorf("espelho Go %s não existe no schema", ref)
		}
	}

	// the envelope (line 0) and the root command (same members; type from the closed catalog)
	compareSpecs(t, "envelope", toSpec(t, "envelope", cmdDefs.obj("envelope")), envelopeSpec.view(t))
	cmd := toSpec(t, "command", cmdDefs.obj("command"))
	env := envelopeSpec.view(t)
	if !reflect.DeepEqual(cmd.nodes["type"], &node{Ref: "#/$defs/command_type"}) {
		t.Errorf("command.type deveria ser #/$defs/command_type")
	}
	cmd.nodes["type"] = env.nodes["type"]
	delete(cmd.combinators, "allOf") // type -> payload: TestCatalogSchema
	compareSpecs(t, "command (membros)", cmd, env)

	// the payloads (line 8)
	var schemaPayloads []string
	for _, name := range cmdDefs.keys {
		if strings.HasPrefix(name, "payload_") {
			schemaPayloads = append(schemaPayloads, name)
			spec, ok := payloadSpecs[name]
			if !ok {
				t.Errorf("%s sem espelho no Go", name)
				continue
			}
			if spec.Name != name {
				t.Errorf("%s: nome %q", name, spec.Name)
			}
			compareSpecs(t, name, toSpec(t, name, cmdDefs.obj(name)), spec.view(t))
		}
	}
	if len(schemaPayloads) != len(payloadSpecs) {
		t.Errorf("schema tem %d payloads, Go %d", len(schemaPayloads), len(payloadSpecs))
	}
}

// TestNoNumberInEnvelope locks the premise of the line-0 integer rule: no member of the envelope or of a v1
// payload is a JSON Schema "number", so every number in an envelope must be an integer literal.
func TestNoNumberInEnvelope(t *testing.T) {
	b := loadSchemas(t)["fleet-command.schema.json"]
	var walk func(any, string)
	walk = func(v any, loc string) {
		switch x := v.(type) {
		case *ordObj:
			if x.str("type") == "number" {
				t.Errorf("%s: type number no fleet-command (a regra de inteiros da linha 0 precisa ser revista)", loc)
			}
			for _, k := range x.keys {
				walk(x.m[k], loc+"/"+k)
			}
		case []any:
			for _, e := range x {
				walk(e, loc)
			}
		}
	}
	walk(b, "fleet-command.schema.json")
}
