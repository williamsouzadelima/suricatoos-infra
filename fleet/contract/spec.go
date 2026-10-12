package contract

import (
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// The patterns of fleet-command.schema.json, as IDENTICAL strings (TestParityRules compares them with the
// schema byte for byte). They are written in the subset where ECMA-262 (JSON Schema) and RE2 (Go) agree, with
// one documented difference: RE2's '$' never matches before a trailing newline, Python's does — Go is stricter,
// and the schema guards most free strings with no_control anyway.
const (
	PatternUUID               = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	PatternNodeID             = `^[a-z0-9][a-z0-9-]{2,63}$`
	PatternTenant             = `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
	PatternIssuedBy           = `^[A-Za-z0-9._+-]+$`
	PatternUTCTime            = `^(000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$`
	PatternSHA256Hex          = `^[0-9a-f]{64}$`
	PatternPin                = `^sha256:[0-9a-f]{64}$`
	PatternVersionString      = `^[0-9A-Za-z][0-9A-Za-z.+_-]*$`
	PatternIPLiteral          = `^[0-9A-Fa-f:.]+$`
	PatternIPOrCIDR           = `^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$`
	PatternPortRange          = `^[TU]:[0-9,-]+$`
	PatternAgentID            = `^[^,=+"\\;<>]+$`
	PatternTokenID            = `^[A-Za-z0-9_-]+$`
	PatternSchemaVersionWire  = `^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.0$`
	PatternSchemaVersionsItem = `^[0-9]{1,3}\.[0-9]{1,3}$`
	PatternCommandTypeAny     = `^[a-z][a-z_]*\.[a-z][a-z_]*$`
	PatternIANATimezone       = `^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$`
	PatternICalendar          = `^BEGIN:VCALENDAR`
	PatternNonce              = `^[0-9a-f]{64}$`
	PatternSignature          = `^[A-Za-z0-9+/]{85}[AQgw]==$` // canonical base64: zero padding bits before "=="
	PatternLevels             = `^c?h?m?l?g?$`

	// no_control: C0 controls, DEL and the noncharacters U+FFFE/U+FFFF that XML 1.0 forbids (the two runes are
	// written as their UTF-8 bytes; the schema's JSON escapes decode to exactly these characters)
	patternControl = `[\x00-\x1f\x7f` + "\xef\xbf\xbe\xef\xbf\xbf" + `]`
	// icalendar: the same set, except that CR, LF and TAB are allowed
	patternICalendarControl = `[\x00-\x08\x0b\x0c\x0e-\x1f\x7f` + "\xef\xbf\xbe\xef\xbf\xbf" + `]`
)

var regexCache sync.Map // pattern -> *regexp.Regexp

// compiled returns the compiled form of one of the patterns above (all are compiled at init).
func compiled(p string) *regexp.Regexp {
	if re, ok := regexCache.Load(p); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(p)
	regexCache.Store(p, re)
	return re
}

// node mirrors one JSON Schema node of the fleet schemas, with only the keywords the line-0 envelope and the v1
// payloads use. TestParityRules rebuilds every node from the schema files and requires equality, and fails on
// any keyword this struct does not model — so the Go validators can never silently ignore a constraint.
type node struct {
	Ref         string   `json:"$ref,omitempty"`
	Type        string   `json:"type,omitempty"`
	Format      string   `json:"format,omitempty"`
	MinLength   *int     `json:"minLength,omitempty"`
	MaxLength   *int     `json:"maxLength,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Not         *node    `json:"not,omitempty"`
	AllOf       []*node  `json:"allOf,omitempty"`
	AnyOf       []*node  `json:"anyOf,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Const       *string  `json:"const,omitempty"`
	Minimum     *int64   `json:"minimum,omitempty"`
	Maximum     *int64   `json:"maximum,omitempty"`
	MinItems    *int     `json:"minItems,omitempty"`
	MaxItems    *int     `json:"maxItems,omitempty"`
	UniqueItems bool     `json:"uniqueItems,omitempty"`
	Items       *node    `json:"items,omitempty"`
}

// prop is one property of an object spec, in schema order.
type prop struct {
	Name string
	Node *node
}

// objectSpec mirrors one object definition (the envelope, a payload). Combinators holds its object-level
// allOf/oneOf/not exactly as the schema's JSON (TestParityRules compares them); cross implements them.
type objectSpec struct {
	Name        string
	Props       []prop
	Required    []string
	Closed      bool // additionalProperties: false
	MinProps    *int
	MaxProps    *int
	Combinators map[string]string
	cross       func(v reflect.Value, path string) *Violation
}

func intp(i int) *int       { return &i }
func int64p(i int64) *int64 { return &i }
func strp(s string) *string { return &s }
func ref(r string) *node    { return &node{Ref: r} }

func enumOf[T ~string](vs ...T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

var noControl = []*node{{Ref: "#/$defs/no_control"}}

// defs mirrors the primitive $defs of fleet-command.schema.json (keyed by the "$ref" that names them) and the
// state_kind of fleet-state.schema.json that payload_state_resync references.
var defs = map[string]*node{
	"#/$defs/no_control":          {Not: &node{Pattern: patternControl}},
	"#/$defs/uuid":                {Type: "string", Format: "uuid", MinLength: intp(36), MaxLength: intp(36), Pattern: PatternUUID},
	"#/$defs/node_id":             {Type: "string", MinLength: intp(3), MaxLength: intp(64), Pattern: PatternNodeID, AllOf: noControl},
	"#/$defs/tenant":              {Type: "string", MinLength: intp(1), MaxLength: intp(64), Pattern: PatternTenant, AllOf: noControl},
	"#/$defs/issued_by":           {Type: "string", MinLength: intp(1), MaxLength: intp(128), Pattern: PatternIssuedBy, AllOf: noControl},
	"#/$defs/utc_time":            {Type: "string", Format: "date-time", MinLength: intp(20), MaxLength: intp(20), Pattern: PatternUTCTime},
	"#/$defs/sha256_hex":          {Type: "string", MinLength: intp(64), MaxLength: intp(64), Pattern: PatternSHA256Hex},
	"#/$defs/pin":                 {Type: "string", MinLength: intp(71), MaxLength: intp(71), Pattern: PatternPin},
	"#/$defs/version_string":      {Type: "string", MinLength: intp(1), MaxLength: intp(64), Pattern: PatternVersionString, AllOf: noControl},
	"#/$defs/gvm_name":            {Type: "string", MinLength: intp(1), MaxLength: intp(128), AllOf: noControl},
	"#/$defs/gvm_comment":         {Type: "string", MaxLength: intp(400), AllOf: noControl},
	"#/$defs/gmp_filter":          {Type: "string", MinLength: intp(1), MaxLength: intp(1024), AllOf: noControl},
	"#/$defs/ip_literal":          {Type: "string", MinLength: intp(2), MaxLength: intp(39), Pattern: PatternIPLiteral, AllOf: noControl},
	"#/$defs/ip_or_cidr":          {Type: "string", MinLength: intp(2), MaxLength: intp(43), Pattern: PatternIPOrCIDR, AllOf: noControl},
	"#/$defs/port_range":          {Type: "string", MinLength: intp(3), MaxLength: intp(1024), Pattern: PatternPortRange, AllOf: noControl},
	"#/$defs/alive_test":          {Enum: enumOf(AliveICMPTCPSYNARP, AliveICMPTCPACKARP, AliveICMPTCPACK, AliveICMPARP, AliveTCPACKARP, AliveICMP, AliveTCPACK, AliveTCPSYN, AliveARP, AliveConsiderAlive, AliveScanConfigDefault)},
	"#/$defs/agent_id":            {Type: "string", MinLength: intp(1), MaxLength: intp(128), Pattern: PatternAgentID, AllOf: noControl},
	"#/$defs/token_id":            {Type: "string", MinLength: intp(8), MaxLength: intp(64), Pattern: PatternTokenID, AllOf: noControl},
	"#/$defs/command_type":        {Enum: enumOf(commandTypes()...)},
	"#/$defs/schema_version_wire": {Type: "string", MinLength: intp(5), MaxLength: intp(9), Pattern: PatternSchemaVersionWire},
	"#/$defs/schema_versions": {Type: "array", MinItems: intp(1), MaxItems: intp(8), UniqueItems: true,
		Items: &node{Type: "string", MinLength: intp(3), MaxLength: intp(7), Pattern: PatternSchemaVersionsItem, AllOf: noControl}},
	"#/$defs/command_type_any": {Type: "string", MinLength: intp(3), MaxLength: intp(64), Pattern: PatternCommandTypeAny, AllOf: noControl},
	"#/$defs/report_format":    {Enum: enumOf(FormatSuricatoosPDF, FormatGVMXML, FormatGVMCSVResults, FormatGVMPDF)},
	"#/$defs/report_lang":      {Enum: enumOf(LangEN, LangPTBR, LangES)},
	"#/$defs/report_variant":   {Enum: enumOf(VariantTechnical, VariantClient, VariantExecutive)},
	"#/$defs/iana_timezone":    {Type: "string", MinLength: intp(1), MaxLength: intp(64), Pattern: PatternIANATimezone, AllOf: noControl},
	"#/$defs/icalendar":        {Type: "string", MinLength: intp(15), MaxLength: intp(8192), Pattern: PatternICalendar, Not: &node{Pattern: patternICalendarControl}},

	"fleet-state.schema.json#/$defs/state_kind": {Enum: enumOf(KindNode, KindTasks, KindTargets, KindSchedules, KindReports, KindAgents, KindTokens, KindSensors, KindScanRequests, KindRemediation, KindScope, KindAuditTail)},
}

// envelopeSpec mirrors fleet-command.schema.json#/$defs/envelope: the shape verification line 0 checks, with
// type = command_type_any and payload = any object.
var envelopeSpec = &objectSpec{
	Name: "envelope",
	Props: []prop{
		{"schema_version", &node{Ref: "#/$defs/schema_version_wire", Const: strp(SchemaVersion)}},
		{"command_id", ref("#/$defs/uuid")},
		{"node_id", ref("#/$defs/node_id")},
		{"tenant", ref("#/$defs/tenant")},
		{"type", ref("#/$defs/command_type_any")},
		{"issued_by", ref("#/$defs/issued_by")},
		{"issued_at", ref("#/$defs/utc_time")},
		{"not_after", ref("#/$defs/utc_time")},
		{"nonce", &node{Type: "string", MinLength: intp(64), MaxLength: intp(64), Pattern: PatternNonce}},
		{"payload_sha256", ref("#/$defs/sha256_hex")},
		{"payload", &node{Type: "object"}},
		{"signature", &node{Type: "string", MinLength: intp(88), MaxLength: intp(88), Pattern: PatternSignature}},
	},
	Required: []string{"schema_version", "command_id", "node_id", "tenant", "type", "issued_by", "issued_at", "not_after", "nonce", "payload_sha256", "payload", "signature"},
	Closed:   true,
}

func init() {
	// compile every pattern once; a bad one panics at init (and fails every test)
	var walk func(*node)
	walk = func(n *node) {
		if n == nil {
			return
		}
		if n.Pattern != "" {
			compiled(n.Pattern)
		}
		walk(n.Not)
		walk(n.Items)
		for _, a := range append(append([]*node{}, n.AllOf...), n.AnyOf...) {
			walk(a)
		}
	}
	for _, n := range defs {
		walk(n)
	}
	for _, s := range append([]*objectSpec{envelopeSpec}, payloadSpecList...) {
		for _, p := range s.Props {
			walk(p.Node)
		}
	}
}

// check validates one decoded Go value against the node (and the $defs it references). The order inside one
// node follows the schema validator's most specific report for single defects: the referenced definition,
// then allOf / not (control characters), anyOf, and the value's own pattern, length, format, enum and const.
func (n *node) check(path string, v reflect.Value) *Violation {
	if n.Ref != "" {
		d, ok := defs[n.Ref]
		if !ok { // unreachable: TestParityRules covers every $ref
			return &Violation{Keyword: "$ref", Path: path, Detail: "referência sem espelho " + n.Ref}
		}
		if viol := d.check(path, v); viol != nil {
			return viol
		}
	}
	for _, a := range n.AllOf {
		if viol := a.check(path, v); viol != nil {
			return viol
		}
	}
	if n.Not != nil && n.Not.check(path, v) == nil {
		return &Violation{Keyword: "not", Path: path, Detail: "valor contém caractere proibido"}
	}
	if len(n.AnyOf) > 0 {
		ok := false
		for _, a := range n.AnyOf {
			if a.check(path, v) == nil {
				ok = true
				break
			}
		}
		if !ok {
			return &Violation{Keyword: "anyOf", Path: path, Detail: "nenhuma alternativa casa"}
		}
	}
	switch v.Kind() {
	case reflect.String:
		return n.checkString(path, v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x := v.Int()
		if n.Minimum != nil && x < *n.Minimum {
			return &Violation{Keyword: "minimum", Path: path, Detail: "abaixo do mínimo"}
		}
		if n.Maximum != nil && x > *n.Maximum {
			return &Violation{Keyword: "maximum", Path: path, Detail: "acima do máximo"}
		}
	case reflect.Slice:
		if v.Type() == rawMessageGoType {
			return nil // a free object: its shape is the type's (line 8)
		}
		return n.checkArray(path, v)
	}
	return nil
}

func (n *node) checkString(path, s string) *Violation {
	if n.Pattern != "" && !compiled(n.Pattern).MatchString(s) {
		return &Violation{Keyword: "pattern", Path: path, Detail: "fora do padrão"}
	}
	if n.MinLength != nil && utf8.RuneCountInString(s) < *n.MinLength {
		return &Violation{Keyword: "minLength", Path: path, Detail: "curto demais"}
	}
	if n.MaxLength != nil && utf8.RuneCountInString(s) > *n.MaxLength {
		return &Violation{Keyword: "maxLength", Path: path, Detail: "longo demais"}
	}
	if n.Format == "date-time" {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return &Violation{Keyword: "format", Path: path, Detail: "instante inexistente"}
		}
	}
	if n.Enum != nil && !slices.Contains(n.Enum, s) {
		return &Violation{Keyword: "enum", Path: path, Detail: "valor fora do enum"}
	}
	if n.Const != nil && s != *n.Const {
		return &Violation{Keyword: "const", Path: path, Detail: "valor diferente do fixo " + *n.Const}
	}
	return nil
}

func (n *node) checkArray(path string, v reflect.Value) *Violation {
	l := v.Len()
	if n.MinItems != nil && l < *n.MinItems {
		return &Violation{Keyword: "minItems", Path: path, Detail: "itens de menos"}
	}
	if n.MaxItems != nil && l > *n.MaxItems {
		return &Violation{Keyword: "maxItems", Path: path, Detail: "itens demais"}
	}
	if n.UniqueItems {
		seen := map[string]bool{}
		for i := 0; i < l; i++ {
			k := v.Index(i).String()
			if seen[k] {
				return &Violation{Keyword: "uniqueItems", Path: path, Detail: "item repetido"}
			}
			seen[k] = true
		}
	}
	if n.Items != nil {
		for i := 0; i < l; i++ {
			if viol := n.Items.check(path+"/"+strconv.Itoa(i), v.Index(i)); viol != nil {
				return viol
			}
		}
	}
	return nil
}

func (s *objectSpec) node(name string) *node {
	for _, p := range s.Props {
		if p.Name == name {
			return p.Node
		}
	}
	return nil
}

func absent(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		return v.IsNil()
	}
	return false
}

// validate checks a decoded struct (after DecodeStrict) against the spec: every present member against its
// node, then minProperties/maxProperties, then the object-level combinators.
func (s *objectSpec) validate(v reflect.Value, path string) *Violation {
	si := fieldsOf(v.Type())
	present := 0
	for _, f := range si.list {
		fv := v.Field(f.index)
		if absent(fv) {
			continue
		}
		present++
		n := s.node(f.name)
		if n == nil { // unreachable: the parity tests tie struct fields to schema properties
			return &Violation{Keyword: "additionalProperties", Path: path, Detail: "membro sem regra " + f.name}
		}
		for fv.Kind() == reflect.Pointer {
			fv = fv.Elem()
		}
		if viol := n.check(path+"/"+escapePointer(f.name), fv); viol != nil {
			return viol
		}
	}
	if s.MinProps != nil && present < *s.MinProps {
		return &Violation{Keyword: "minProperties", Path: path, Detail: "membros de menos"}
	}
	if s.MaxProps != nil && present > *s.MaxProps {
		return &Violation{Keyword: "maxProperties", Path: path, Detail: "membros demais"}
	}
	if s.cross != nil {
		return s.cross(v, path)
	}
	return nil
}
