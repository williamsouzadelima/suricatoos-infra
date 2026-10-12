package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodePollResponse splits the 200 body of GET /fleet/v1/commands (fleet-command.schema.json#/$defs/poll_response)
// into the raw bytes of each envelope, exactly as received. Only the outer object is judged here — at most
// 1 MiB, strict JSON, exactly the member "commands" holding 1 to 10 values; a malformed body is a contract error
// of the hub. The envelopes are NOT: each one goes through the verification lines on its own (VerifyAt), so one
// bad envelope never discards the others.
func DecodePollResponse(raw []byte) ([]json.RawMessage, error) {
	if len(raw) > MaxPollResponseBytes {
		return nil, &Violation{Keyword: "size", Detail: fmt.Sprintf("resposta do long-poll com mais de %d bytes", MaxPollResponseBytes)}
	}
	if !utf8.Valid(raw) {
		return nil, syntaxViolation("UTF-8 inválido")
	}
	if bytes.HasPrefix(raw, utf8BOM) {
		return nil, syntaxViolation("BOM UTF-8 não é permitido")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, syntaxViolation("JSON malformado")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, typeViolation("", "objeto")
	}
	seen, count := false, 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, syntaxViolation("JSON malformado")
		}
		k, _ := kt.(string)
		if k != "commands" {
			return nil, &Violation{Keyword: "additionalProperties", Detail: "membro desconhecido " + quoteName(k)}
		}
		if seen {
			return nil, &Violation{Keyword: "duplicate_key", Path: "/commands", Detail: "membro repetido"}
		}
		seen = true
		tok, err := dec.Token()
		if err != nil {
			return nil, syntaxViolation("JSON malformado")
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return nil, typeViolation("/commands", "array")
		}
		for dec.More() {
			if err := skipValue(dec); err != nil {
				return nil, syntaxViolation("JSON malformado")
			}
			count++
		}
		if _, err := dec.Token(); err != nil { // ']'
			return nil, syntaxViolation("JSON malformado")
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, syntaxViolation("JSON malformado")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, syntaxViolation("dado depois do valor JSON")
	}
	switch {
	case !seen:
		return nil, &Violation{Keyword: "required", Detail: "falta o membro \"commands\""}
	case count < 1:
		return nil, &Violation{Keyword: "minItems", Path: "/commands", Detail: "nada pendente é 204, não lista vazia"}
	case count > MaxPollCommands:
		return nil, &Violation{Keyword: "maxItems", Path: "/commands", Detail: fmt.Sprintf("mais de %d comandos", MaxPollCommands)}
	}
	var pr PollResponse
	if err := json.Unmarshal(raw, &pr); err != nil { // the outer object is exact: no duplicate, no other member
		return nil, syntaxViolation("decode: " + err.Error())
	}
	return pr.Commands, nil
}

// skipValue consumes one JSON value of any shape (validating its syntax) without recursion.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
