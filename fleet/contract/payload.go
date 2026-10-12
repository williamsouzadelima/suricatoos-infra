package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// ErrUnknownType is returned by DecodePayload for a type outside the v1 catalog (line 7: unsupported, which the
// connector checks before line 8).
var ErrUnknownType = errors.New("contract: tipo fora do catálogo v1")

// DecodePayload is verification line 8's "schema estrito" (ADR-0011): it decodes the payload of a command of
// type t strictly — the same token pass as line 0: exact member names, no duplicate, no unknown member, no
// null, integers only as integer literals — into the type's Go struct, then applies EVERY constraint of the
// type's fleet-command.schema.json#/$defs/payload_* (patterns, enums, lengths, ranges, item counts and
// uniqueness, minProperties/maxProperties, and the oneOf / not / if-then-else rules such as gvm-* formats only
// in en + technical) and the semantic rules of line 8 (report.export's explicit filter, "export_filter"). It returns a pointer to the payload struct (e.g. *PayloadTaskRef): the connector passes
// exactly these values on, never the raw JSON. Any error is a *Violation (keyword + JSON pointer inside the
// payload), and means bad_payload; ErrUnknownType means the type is not in the catalog.
//
// It does not check what needs local state: the scope gate (line 9), the report formats the node advertises
// (unsupported_report_variant) and the existence or ownership of the gvmd objects.
func DecodePayload(t CommandType, raw []byte) (any, error) {
	e, ok := LookupType(t)
	if !ok {
		return nil, ErrUnknownType
	}
	spec, typ := payloadSpecs[e.Payload], payloadTypes[e.Payload]
	if len(raw) > MaxPayloadBytes {
		return nil, &Violation{Keyword: "size", Detail: fmt.Sprintf("payload com mais de %d bytes", MaxPayloadBytes)}
	}
	if viol := scanJSON(raw, scanOptions{}); viol != nil {
		return nil, viol
	}
	if !spec.Closed && spec.MaxProps != nil {
		// payload_empty is {"type":"object","maxProperties":0}: an extra member breaks maxProperties (there is
		// no additionalProperties keyword to break)
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) == nil && len(members) > *spec.MaxProps {
			return nil, &Violation{Keyword: "maxProperties", Detail: "membros demais"}
		}
	}
	p := reflect.New(typ)
	if viol := walkTyped(raw, typ); viol != nil {
		return nil, viol
	}
	if err := json.Unmarshal(raw, p.Interface()); err != nil {
		return nil, syntaxViolation("decode: " + err.Error()) // unreachable after the two passes
	}
	if viol := spec.validate(p.Elem(), ""); viol != nil {
		return nil, viol
	}
	if e, ok := p.Interface().(*PayloadReportExport); ok {
		if problem := exportFilterProblem(e.Filter); problem != "" {
			return nil, &Violation{Keyword: "export_filter", Path: "/filter", Detail: problem}
		}
	}
	return p.Interface(), nil
}

// exportFilterRules are the three tokens report.export's filter must carry explicitly (ADR-0011 "Filtro
// explícito", normative): never gvmd's hidden defaults (min_qod=70, apply_overrides=0).
var exportFilterRules = map[string]*regexp.Regexp{
	"apply_overrides": regexp.MustCompile(`^[01]$`),
	"min_qod":         regexp.MustCompile(`^(0|[1-9][0-9]?|100)$`),
	"levels":          regexp.MustCompile(`^[chmlgf]{1,6}$`),
}

// exportFilterProblem is the semantic rule of line 8 for report.export (a rule, not a schema pattern: RE2 has no
// lookahead), as the ADR pins it so that Go and Python agree. No double quote at all: gvmd's split_filter reads a
// part that starts with one (also after = or ~) as ONE term up to the next, which would hide the keywords. Without
// quotes, the tokens are the filter split on single spaces; a token belongs to a key when it is the key alone (a
// bare word would be a gvmd search term narrowing the export in silence) or starts with the key followed by a
// relation (= < > ~ or :); each of apply_overrides, min_qod and levels exactly once, with '=' and a valid value
// (levels: a subset of chmlgf without a repeated letter). It returns why the filter is refused, or "".
func exportFilterProblem(filter string) string {
	if strings.ContainsRune(filter, '"') {
		return "o filtro tem aspas (o gvmd leria a parte entre aspas como um termo só)"
	}
	seen := map[string]bool{}
	for _, tok := range strings.Split(filter, " ") {
		key, value, rel := tok, "", byte(0)
		if i := strings.IndexAny(tok, "=<>~:"); i >= 0 {
			key, value, rel = tok[:i], tok[i+1:], tok[i]
		}
		re, ok := exportFilterRules[key]
		if !ok {
			continue
		}
		if seen[key] {
			return key + " aparece mais de uma vez"
		}
		if rel != '=' || !re.MatchString(value) || (key == "levels" && repeatsALetter(value)) {
			return "token " + quoteName(tok) + " não é " + key + "=<valor válido>"
		}
		seen[key] = true
	}
	for _, key := range []string{"apply_overrides", "min_qod", "levels"} {
		if !seen[key] {
			return "falta " + key + "= explícito"
		}
	}
	return ""
}

func repeatsALetter(s string) bool {
	for i := range s {
		if strings.IndexByte(s[i+1:], s[i]) >= 0 {
			return true
		}
	}
	return false
}

// ValidatePayload reports whether raw is a valid payload for type t (verification line 8): nil, ErrUnknownType
// or a *Violation (bad_payload). See DecodePayload.
func ValidatePayload(t CommandType, raw []byte) error {
	_, err := DecodePayload(t, raw)
	return err
}
