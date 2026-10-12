package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SchemaVersion is the wire schema_version of every v1 body and envelope: MAJOR.MINOR.0 (the PATCH is editorial
// and never travels) — the value that enters the signed canonical form.
const SchemaVersion = "1.0.0"

// Version is a contract version MAJOR.MINOR (ADR-0011 "Versões e evolução": MINOR adds a member, an enum value
// or a type; MAJOR breaks).
type Version struct{ Major, Minor int }

// String renders the announced form, MAJOR.MINOR (an item of schema_versions).
func (v Version) String() string { return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) }

// Wire renders the schema_version form, MAJOR.MINOR.0.
func (v Version) Wire() string { return v.String() + ".0" }

func (v Version) less(o Version) bool {
	return v.Major < o.Major || (v.Major == o.Major && v.Minor < o.Minor)
}

// SupportedVersions lists the contract versions this package implements: v1 speaks only 1.0.
func SupportedVersions() []Version { return []Version{{1, 0}} }

var (
	// ErrVersionMalformed: schema_version missing, duplicated or outside the wire form
	// (fleet-command.schema.json#/$defs/schema_version_wire) — the hub answers 400.
	ErrVersionMalformed = errors.New("contract: schema_version ausente ou fora da forma MAJOR.MINOR.0")
	// ErrVersionUnsupported: in the wire form but not a supported version — the hub answers 426 with its
	// announcement (fleet-heartbeat.schema.json#/$defs/version_unsupported), without consuming an enroll token.
	ErrVersionUnsupported = errors.New("contract: schema_version sem suporte")
)

// ParseWireVersion parses a schema_version: exactly the schema_version_wire form
// ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.0$ (decimal without leading zeros; no PATCH). Else
// ErrVersionMalformed.
func ParseWireVersion(s string) (Version, error) {
	if viol := defs["#/$defs/schema_version_wire"].check("", reflect.ValueOf(s)); viol != nil {
		return Version{}, fmt.Errorf("%w (%s)", ErrVersionMalformed, viol.Keyword)
	}
	parts := strings.Split(s, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return Version{major, minor}, nil
}

// ParseAnnouncement parses a schema_versions announcement (enroll, renew, heartbeat and their responses, the
// 426 body) under the schema's constraints: 1–8 unique items MAJOR.MINOR. Any error is a *Violation.
func ParseAnnouncement(items []string) ([]Version, error) {
	if items == nil {
		return nil, &Violation{Keyword: "required", Detail: "anúncio schema_versions ausente"}
	}
	if viol := defs["#/$defs/schema_versions"].check("", reflect.ValueOf(items)); viol != nil {
		return nil, viol
	}
	out := make([]Version, 0, len(items))
	for _, s := range items {
		major, minor, _ := strings.Cut(s, ".")
		m, _ := strconv.Atoi(major)
		n, _ := strconv.Atoi(minor)
		out = append(out, Version{m, n})
	}
	return out, nil
}

// Announcement renders versions as a schema_versions announcement.
func Announcement(vs []Version) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}

// HighestCommon is the version rule of ADR-0011: each side speaks the HIGHEST version common to its own and
// the other side's latest announcement. ok is false when there is none (the node enters blocked_version).
func HighestCommon(ours, theirs []Version) (best Version, ok bool) {
	for _, a := range ours {
		if slices.Contains(theirs, a) && (!ok || best.less(a)) {
			best, ok = a, true
		}
	}
	return best, ok
}

// PeekSchemaVersion reads the schema_version at the TOP of a body before any strict validation — the
// version-invariant member (name, position at the top level and form never change, not even in a new MAJOR) —
// and classifies it against supported: missing, duplicated, not a string or outside the wire form (or a body
// that is not one JSON object) => ErrVersionMalformed (400); in the form but not supported =>
// ErrVersionUnsupported (426, returned with the version read). Nothing else of the body is judged here: the
// strict validation of its version comes next.
func PeekSchemaVersion(body []byte, supported []Version) (Version, error) {
	malformed := func(why string) (Version, error) {
		return Version{}, fmt.Errorf("%w (%s)", ErrVersionMalformed, why)
	}
	if !utf8.Valid(body) || bytes.HasPrefix(body, utf8BOM) {
		return malformed("UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return malformed("o corpo não é um objeto JSON")
	}
	var wire string
	found := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return malformed("JSON malformado")
		}
		if kt != "schema_version" {
			if err := skipValue(dec); err != nil {
				return malformed("JSON malformado")
			}
			continue
		}
		if found {
			return malformed("schema_version repetido")
		}
		tok, err := dec.Token()
		s, isString := tok.(string)
		if err != nil || !isString {
			return malformed("schema_version não é string")
		}
		wire, found = s, true
	}
	if _, err := dec.Token(); err != nil {
		return malformed("JSON malformado")
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed("dado depois do valor JSON")
	}
	if !found {
		return malformed("schema_version ausente")
	}
	v, err := ParseWireVersion(wire)
	if err != nil {
		return Version{}, err
	}
	if !slices.Contains(supported, v) {
		return v, fmt.Errorf("%w: %s", ErrVersionUnsupported, v.Wire())
	}
	return v, nil
}
