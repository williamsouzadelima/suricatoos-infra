package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Violation is one contract violation found while decoding or validating a body: a JSON Schema keyword
// ("required", "additionalProperties", "type", "pattern", "enum", "const", "minimum", …) or one of the lexical
// checks of schema/examples/fleet/index.json ("json_syntax", "duplicate_key", "integer_lexical"), at a JSON
// pointer (RFC 6901; "" = the value itself). Two keywords exist only on the Go side: "size" (the byte caps of
// "Limites") and "base64" (a fail-safe behind the schema's canonical-base64 pattern of the signature: a
// signature that does not decode to exactly 64 bytes).
type Violation struct {
	Keyword string
	Path    string
	Detail  string // short text; member names from the input are quoted and truncated
}

// Error is bounded: the JSON pointer (which carries member names taken from the input) is quoted and cut to a
// short prefix, and Detail only holds fixed text and quoted, truncated names.
func (v *Violation) Error() string {
	if v.Path == "" {
		return fmt.Sprintf("%s: %s", v.Keyword, v.Detail)
	}
	return fmt.Sprintf("%s em %s: %s", v.Keyword, quoteBounded(v.Path, 96), v.Detail)
}

// maxDepth is ADR-0011's nesting limit for every body: at most 32 levels of objects and arrays, the top-level
// value at level 1 (no fleet body nests deeper than 6). Deeper input is json_syntax, refused before any
// recursion can grow with it.
const maxDepth = 32

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

type scanOptions struct {
	// integersOnly refuses ANY number written with a fraction or an exponent. The command envelope uses it: no
	// v1 envelope or payload member is a JSON Schema "number", so every number in it must be an integer, and
	// the ADR refuses 70.0 / 7e1 lexically at line 0 even inside a payload whose type is not known yet.
	integersOnly bool
}

func syntaxViolation(detail string) *Violation {
	return &Violation{Keyword: "json_syntax", Detail: detail}
}

// escapePointer escapes one JSON pointer segment (RFC 6901).
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// quoteName renders a member name taken from the input for an error detail: quoted (no control characters
// survive) and truncated.
func quoteName(s string) string { return quoteBounded(s, 64) }

// quoteBounded quotes s, cut to its first max runes.
func quoteBounded(s string, max int) string {
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return strconv.Quote(s)
}

// scanJSON is the type-agnostic pass of ADR-0011 "Codificação JSON": valid UTF-8 without BOM, no unpaired
// surrogate escape in any string, exactly one JSON value followed only by whitespace, no duplicate member name at
// any level (compared after unescaping, so
// "a" and "\u0061" collide while "a" and "A" do not), nesting bounded by maxDepth and, with integersOnly, no
// number written with a fraction or an exponent.
func scanJSON(data []byte, opts scanOptions) *Violation {
	if !utf8.Valid(data) {
		return syntaxViolation("UTF-8 inválido")
	}
	if bytes.HasPrefix(data, utf8BOM) {
		return syntaxViolation("BOM UTF-8 não é permitido")
	}
	if v := checkSurrogates(data); v != nil {
		return v
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	s := scanner{dec: dec, opts: opts}
	if v := s.value("", 0); v != nil {
		return v
	}
	if _, err := dec.Token(); err != io.EOF {
		return syntaxViolation("dado depois do valor JSON")
	}
	return nil
}

// checkSurrogates refuses, in any string (member names included), an escaped UTF-16 surrogate without its pair:
// a high one (D800–DBFF) not immediately followed by an escaped low one (DC00–DFFF), or a low one on its own
// (ADR-0011 "Codificação JSON"). It reads the raw bytes because encoding/json silently turns such an escape into
// U+FFFD — so two different lone-surrogate keys would even collide — while other parsers keep it. A raw surrogate
// cannot appear at all: it is invalid UTF-8, refused before.
func checkSurrogates(data []byte) *Violation {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' || i+1 >= len(data) {
			continue
		}
		u, ok := hexEscape(data, i)
		if !ok {
			i++ // any other escape: skip the escaped character (a malformed one is the decoder's to report)
			continue
		}
		switch {
		case u >= 0xd800 && u <= 0xdbff:
			if low, ok := hexEscape(data, i+6); ok && low >= 0xdc00 && low <= 0xdfff {
				i += 11 // the pair
				continue
			}
			return syntaxViolation("surrogate UTF-16 desemparelhado num escape de string")
		case u >= 0xdc00 && u <= 0xdfff:
			return syntaxViolation("surrogate UTF-16 desemparelhado num escape de string")
		}
		i += 5
	}
	return nil
}

// hexEscape reads the escape \uXXXX starting at data[i] (the backslash).
func hexEscape(data []byte, i int) (rune, bool) {
	if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, false
	}
	var r rune
	for _, h := range data[i+2 : i+6] {
		switch {
		case h >= '0' && h <= '9':
			r = r<<4 | rune(h-'0')
		case h >= 'a' && h <= 'f':
			r = r<<4 | rune(h-'a'+10)
		case h >= 'A' && h <= 'F':
			r = r<<4 | rune(h-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

type scanner struct {
	dec  *json.Decoder
	opts scanOptions
}

func (s *scanner) value(path string, depth int) *Violation {
	tok, err := s.dec.Token()
	if err != nil {
		return syntaxViolation("JSON malformado")
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth+1 > maxDepth {
			return syntaxViolation(fmt.Sprintf("aninhamento além de %d níveis", maxDepth))
		}
		switch t {
		case '{':
			seen := map[string]bool{}
			for s.dec.More() {
				kt, err := s.dec.Token()
				if err != nil {
					return syntaxViolation("JSON malformado")
				}
				k, _ := kt.(string)
				p := path + "/" + escapePointer(k)
				if seen[k] {
					return &Violation{Keyword: "duplicate_key", Path: p, Detail: "membro " + quoteName(k) + " repetido"}
				}
				seen[k] = true
				if v := s.value(p, depth+1); v != nil {
					return v
				}
			}
		case '[':
			for i := 0; s.dec.More(); i++ {
				if v := s.value(path+"/"+strconv.Itoa(i), depth+1); v != nil {
					return v
				}
			}
		default:
			return syntaxViolation("JSON malformado")
		}
		if _, err := s.dec.Token(); err != nil { // the closing delimiter
			return syntaxViolation("JSON malformado")
		}
	case json.Number:
		if s.opts.integersOnly && strings.ContainsAny(string(t), ".eE") {
			return &Violation{Keyword: "integer_lexical", Path: path, Detail: "inteiro com fração ou expoente"}
		}
	}
	return nil
}

var rawMessageGoType = reflect.TypeOf(json.RawMessage(nil))

type fieldInfo struct {
	name     string
	index    int
	typ      reflect.Type
	required bool
}

type structInfo struct {
	list   []fieldInfo
	byName map[string]int
}

var structCache sync.Map // reflect.Type -> *structInfo

// fieldsOf lists the json members of a struct: a member is required unless its tag has an option
// (",omitzero" in this package).
func fieldsOf(t reflect.Type) *structInfo {
	if v, ok := structCache.Load(t); ok {
		return v.(*structInfo)
	}
	si := &structInfo{byName: map[string]int{}}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !ok || !f.IsExported() || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		si.byName[name] = len(si.list)
		si.list = append(si.list, fieldInfo{name: name, index: i, typ: f.Type, required: opts == ""})
	}
	v, _ := structCache.LoadOrStore(t, si)
	return v.(*structInfo)
}

// walkTyped is the typed pass, run after scanJSON: every member name exists, case-exact, in the Go struct,
// every required member is present, no value is null, every JSON type matches the Go type, integer members
// are integer literals that fit, and a json.RawMessage member (a free object of the schema) is an object.
func walkTyped(data []byte, t reflect.Type) *Violation {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	w := walker{dec: dec}
	return w.value(t, "")
}

type walker struct{ dec *json.Decoder }

func typeViolation(path, want string) *Violation {
	return &Violation{Keyword: "type", Path: path, Detail: "esperado " + want}
}

func (w *walker) skipRest(depth int) {
	for depth > 0 {
		tok, err := w.dec.Token()
		if err != nil {
			return
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
}

func (w *walker) value(t reflect.Type, path string) *Violation {
	tok, err := w.dec.Token()
	if err != nil {
		return syntaxViolation("JSON malformado")
	}
	if t == rawMessageGoType {
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return typeViolation(path, "objeto")
		}
		w.skipRest(1)
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if tok == nil {
		return &Violation{Keyword: "type", Path: path, Detail: "null não é permitido"}
	}
	switch t.Kind() {
	case reflect.String:
		if _, ok := tok.(string); !ok {
			return typeViolation(path, "string")
		}
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return typeViolation(path, "booleano")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := tok.(json.Number)
		if !ok {
			return typeViolation(path, "inteiro")
		}
		if strings.ContainsAny(string(n), ".eE") {
			return &Violation{Keyword: "integer_lexical", Path: path, Detail: "inteiro com fração ou expoente"}
		}
		if _, err := strconv.ParseInt(string(n), 10, t.Bits()); err != nil {
			return rangeViolation(path, string(n))
		}
	case reflect.Float32, reflect.Float64:
		n, ok := tok.(json.Number)
		if !ok {
			return typeViolation(path, "número")
		}
		if _, err := strconv.ParseFloat(string(n), t.Bits()); err != nil {
			return rangeViolation(path, string(n))
		}
	case reflect.Struct:
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return typeViolation(path, "objeto")
		}
		return w.object(t, path)
	case reflect.Map:
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return typeViolation(path, "objeto")
		}
		for w.dec.More() {
			kt, err := w.dec.Token()
			if err != nil {
				return syntaxViolation("JSON malformado")
			}
			k, _ := kt.(string)
			if v := w.value(t.Elem(), path+"/"+escapePointer(k)); v != nil {
				return v
			}
		}
		w.dec.Token() // '}'
	case reflect.Slice:
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return typeViolation(path, "array")
		}
		for i := 0; w.dec.More(); i++ {
			if v := w.value(t.Elem(), path+"/"+strconv.Itoa(i)); v != nil {
				return v
			}
		}
		w.dec.Token() // ']'
	case reflect.Interface:
		if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
			w.skipRest(1)
		}
	default:
		return &Violation{Keyword: "type", Path: path, Detail: "tipo Go sem suporte: " + t.String()}
	}
	return nil
}

func rangeViolation(path, literal string) *Violation {
	if strings.HasPrefix(literal, "-") {
		return &Violation{Keyword: "minimum", Path: path, Detail: "número fora do intervalo representável"}
	}
	return &Violation{Keyword: "maximum", Path: path, Detail: "número fora do intervalo representável"}
}

func (w *walker) object(t reflect.Type, path string) *Violation {
	si := fieldsOf(t)
	seen := make([]bool, len(si.list))
	for w.dec.More() {
		kt, err := w.dec.Token()
		if err != nil {
			return syntaxViolation("JSON malformado")
		}
		k, _ := kt.(string)
		i, ok := si.byName[k]
		if !ok {
			return &Violation{Keyword: "additionalProperties", Path: path, Detail: "membro desconhecido " + quoteName(k)}
		}
		seen[i] = true
		if v := w.value(si.list[i].typ, path+"/"+escapePointer(k)); v != nil {
			return v
		}
	}
	w.dec.Token() // '}'
	for i, f := range si.list {
		if f.required && !seen[i] {
			return &Violation{Keyword: "required", Path: path, Detail: "falta o membro " + strconv.Quote(f.name)}
		}
	}
	return nil
}

// errNotPointer is returned when the destination of a decode is not a non-nil pointer.
var errNotPointer = errors.New("contract: o destino do decode precisa ser um ponteiro não-nil")

// DecodeStrict decodes one contract body into v, a pointer to one of this package's types, under the rules
// of ADR-0011 "Codificação JSON": UTF-8 without BOM, exactly one value, no duplicate member at any level,
// case-exact member names (a name that differs only in case is an unknown member), no unknown member, every
// required member present, no null, integers without fraction or exponent, and json.RawMessage members kept
// byte for byte. Any violation is a *Violation. It checks STRUCTURE only: patterns, enums, ranges and the
// other value constraints are the job of the validators (line 0 in Verify, line 8 in ValidatePayload).
func DecodeStrict(data []byte, v any) error {
	if rv := reflect.ValueOf(v); rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errNotPointer
	}
	if viol := decodeStrict(data, v, scanOptions{}); viol != nil {
		return viol
	}
	return nil
}

func decodeStrict(data []byte, v any, opts scanOptions) *Violation {
	if viol := scanJSON(data, opts); viol != nil {
		return viol
	}
	if viol := walkTyped(data, reflect.TypeOf(v).Elem()); viol != nil {
		return viol
	}
	if err := json.Unmarshal(data, v); err != nil {
		// unreachable after the two passes; kept fail-closed
		return syntaxViolation("decode: " + err.Error())
	}
	return nil
}

// MarshalCompact serializes v the way ADR-0011 "Codificação JSON" requires an emitter to: compact, with no
// trailing newline, WITHOUT HTML escaping and with U+2028/U+2029 literal ('<', '>', '&' and the two JS line
// terminators travel as they are). encoding/json alone does not guarantee the last part: it always escapes
// U+2028/U+2029 inside Go strings and, on the json/v2 core (GOEXPERIMENT=jsonv2 — in the baseline of go1.27,
// not of go1.25), also inside json.RawMessage members; those escapes are rewritten here to the literal
// characters, so the output is the same on every Go toolchain.
// json.RawMessage members must already be in this form (e.g. produced by MarshalCompact): they come out with
// the same bytes. Hash exactly the bytes it returns — for a command payload, pass them to Sign.
func MarshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return literalLineTerminators(bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})), nil
}

// literalLineTerminators rewrites, inside the strings of valid JSON, the escapes of U+2028 and U+2029 to the
// literal characters (any other escape, including an escaped backslash followed by "u2028", is kept).
func literalLineTerminators(b []byte) []byte {
	needle := []byte{'\\', 'u', '2', '0', '2'}
	if !bytes.Contains(b, needle) {
		return b
	}
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case !inString:
			inString = c == '"'
			out = append(out, c)
		case c == '"':
			inString = false
			out = append(out, c)
		case c == '\\' && i+1 < len(b):
			if i+5 < len(b) && bytes.HasPrefix(b[i+1:], needle[1:]) && (b[i+5] == '8' || b[i+5] == '9') {
				out = append(out, 0xe2, 0x80, 0xa8+(b[i+5]-'8'))
				i += 5
				continue
			}
			out = append(out, c, b[i+1]) // the escape and the character it escapes
			i++
		default:
			out = append(out, c)
		}
	}
	return out
}

// appendJSONString appends s as a JSON string: '"', '\' and the C0 control characters escaped, everything
// else literal (no HTML escaping). escapeInvisible also escapes U+2028, U+2029 and U+FEFF (only for the golden
// file, where an invisible character would hide in review); the wire form keeps them literal.
func appendJSONString(dst []byte, s string, escapeInvisible bool) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		case escapeInvisible && c == 0xe2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xa8 || s[i+2] == 0xa9):
			dst = append(dst, '\\', 'u', '2', '0', '2', '8'+(s[i+2]-0xa8))
			i += 3
			continue
		case escapeInvisible && c == 0xef && i+2 < len(s) && s[i+1] == 0xbb && s[i+2] == 0xbf:
			dst = append(dst, '\\', 'u', 'f', 'e', 'f', 'f')
			i += 3
			continue
		default:
			dst = append(dst, c)
		}
		i++
	}
	return append(dst, '"')
}

// isCompactJSON reports whether valid JSON has no insignificant whitespace (outside strings).
func isCompactJSON(b []byte) bool {
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inString && c == '\\':
			i++
		case c == '"':
			inString = !inString
		case !inString && (c == ' ' || c == '\t' || c == '\n' || c == '\r'):
			return false
		}
	}
	return true
}
