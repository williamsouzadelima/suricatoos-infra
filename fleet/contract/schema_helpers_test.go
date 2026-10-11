package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The fleet schemas and examples live outside the module, in the repository root.
var (
	schemaDir   = filepath.Join("..", "..", "schema")
	examplesDir = filepath.Join(schemaDir, "examples", "fleet")
	adrPath     = filepath.Join("..", "..", "docs", "adr", "0011-gestao-remota-da-frota.md")
)

var schemaFiles = []string{
	"fleet-command.schema.json", "fleet-enroll.schema.json", "fleet-heartbeat.schema.json",
	"fleet-state.schema.json", "fleet-event.schema.json", "fleet-result.schema.json",
}

// ordObj is a JSON object that keeps its member order (the schemas' property order is part of the parity).
type ordObj struct {
	keys []string
	m    map[string]any
}

func (o *ordObj) has(k string) bool { _, ok := o.m[k]; return ok }
func (o *ordObj) get(k string) any  { return o.m[k] }

func (o *ordObj) obj(k string) *ordObj {
	v, _ := o.m[k].(*ordObj)
	return v
}

func (o *ordObj) str(k string) string {
	v, _ := o.m[k].(string)
	return v
}

func (o *ordObj) arr(k string) []any {
	v, _ := o.m[k].([]any)
	return v
}

func (o *ordObj) num(k string) (int64, bool) {
	n, ok := o.m[k].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// decodeOrdered decodes one JSON value: objects as *ordObj, arrays as []any, numbers as json.Number.
func decodeOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		o := &ordObj{m: map[string]any{}}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k := kt.(string)
			if _, dup := o.m[k]; dup {
				return nil, fmt.Errorf("chave duplicada %q", k)
			}
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			o.keys = append(o.keys, k)
			o.m[k] = v
		}
		_, err = dec.Token()
		return o, err
	case '[':
		a := []any{}
		for dec.More() {
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err = dec.Token()
		return a, err
	}
	return nil, fmt.Errorf("delimitador inesperado %v", d)
}

func parseOrdered(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return decodeOrdered(dec)
}

var (
	schemasOnce sync.Once
	schemasErr  error
	schemaDocs  map[string]*ordObj
)

// loadSchemas reads the six fleet schemas once, keeping member order.
func loadSchemas(t testing.TB) map[string]*ordObj {
	t.Helper()
	schemasOnce.Do(func() {
		schemaDocs = map[string]*ordObj{}
		for _, f := range schemaFiles {
			b, err := os.ReadFile(filepath.Join(schemaDir, f))
			if err != nil {
				schemasErr = err
				return
			}
			v, err := parseOrdered(b)
			if err != nil {
				schemasErr = fmt.Errorf("%s: %w", f, err)
				return
			}
			schemaDocs[f] = v.(*ordObj)
		}
	})
	if schemasErr != nil {
		t.Fatalf("schemas: %v", schemasErr)
	}
	return schemaDocs
}

// resolveRef follows one "$ref" ("#/$defs/x" or "fleet-y.schema.json#/$defs/x") from file; it returns the file of
// the target and the target node.
func resolveRef(t testing.TB, docs map[string]*ordObj, file, ref string) (string, *ordObj) {
	t.Helper()
	target, ptr, ok := strings.Cut(ref, "#")
	if !ok {
		t.Fatalf("$ref sem fragmento: %q", ref)
	}
	if target == "" {
		target = file
	}
	doc := docs[target]
	if doc == nil {
		t.Fatalf("$ref para arquivo desconhecido: %q", ref)
	}
	name, ok := strings.CutPrefix(ptr, "/$defs/")
	if !ok || strings.Contains(name, "/") {
		t.Fatalf("$ref fora da forma #/$defs/<nome>: %q", ref)
	}
	n := doc.obj("$defs").obj(name)
	if n == nil {
		t.Fatalf("$ref sem alvo: %q (em %s)", ref, file)
	}
	return target, n
}

// defNode returns "file#/$defs/name" or the root of "file".
func defNode(t testing.TB, docs map[string]*ordObj, ptr string) (string, *ordObj) {
	t.Helper()
	file, frag, _ := strings.Cut(ptr, "#")
	if frag == "" {
		return file, docs[file]
	}
	return resolveRef(t, docs, file, "#"+frag)
}

func strList(a []any) []string {
	out := make([]string, 0, len(a))
	for _, v := range a {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

// goStringConstants collects, from the package's non-test sources, every constant declared with a named type
// and a string literal: type name -> values in declaration order.
func goStringConstants(t testing.TB) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name == "string" || len(vs.Values) != len(vs.Names) {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out[id.Name] = append(out[id.Name], s)
				}
			}
		}
	}
	return out
}

// goStringTypes lists the named types of the package whose underlying type is string.
func goStringTypes(t testing.TB) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				if id, ok := ts.Type.(*ast.Ident); ok && id.Name == "string" && ts.Assign == 0 {
					out = append(out, ts.Name.Name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
