package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenera testdata/golden-v1.json (go test ./contract -run TestGolden -update)")

const goldenPath = "testdata/golden-v1.json"

// Values shared by the vectors. Command ids and nonces are derived from the vector name; the ADR example keeps
// its own.
const (
	gOwn              = "node-lab-0001"
	gAt               = "2026-10-11T12:30:00Z"
	gIssuedAt         = "2026-10-11T12:00:00Z"
	gNotAfter         = "2026-10-11T13:00:00Z"
	remediationDomain = "suricatoos-remediation-v1"
	lineSeparator     = "\xe2\x80\xa8"
	goldenSeedText    = "Ed25519 seed = SHA-256 of the ASCII text suricatoos-fleet-command-v1/golden-test-key"
)

func goldenUUID(name string) string {
	s := sha256.Sum256([]byte("suricatoos-fleet-golden/command_id/" + name))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func goldenNonce(name string) string {
	return sha256hex([]byte("suricatoos-fleet-golden/nonce/" + name))
}

func gCommand(name string, typ CommandType) Command {
	return Command{SchemaVersion: SchemaVersion, CommandID: goldenUUID(name), NodeID: gOwn, Tenant: "acme", Type: typ,
		IssuedBy: "op-7f3a", IssuedAt: gIssuedAt, NotAfter: gNotAfter, Nonce: goldenNonce(name)}
}

// one compact payload per payload format of the catalog (task.start's is the ADR example's)
var gPayloads = map[CommandType]string{
	TypeStateResync:       `{"kinds":["tasks","targets"]}`,
	TypeTaskCreate:        `{"name":"Varredura semanal LAB","target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35","scan_config_id":"daba56c8-73ec-11df-a475-002264764cea","schedule_id":"5c3e9a71-2b8d-4f06-9e1a-7d4c2b8f6a03"}`,
	TypeTaskModify:        `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","schedule_id":""}`,
	TypeTaskClone:         `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","name":"Varredura semanal LAB (cópia) — ação"}`,
	TypeTargetCreate:      `{"name":"LAB DMZ","hosts":["192.0.2.0/24","198.51.100.10"],"exclude_hosts":["192.0.2.1"],"port_range":"T:1-1024","alive_test":"ICMP, TCP-SYN Service & ARP Ping"}`,
	TypeTargetModify:      `{"target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35","hosts":["192.0.2.0/25"],"alive_test":"ICMP, TCP-ACK Service & ARP Ping"}`,
	TypeTargetDelete:      `{"target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35"}`,
	TypeScheduleCreate:    `{"name":"Semanal LAB","icalendar":"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20261012T020000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=MO\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n","timezone":"America/Sao_Paulo","task_ids":["2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"]}`,
	TypeScheduleModify:    `{"schedule_id":"5c3e9a71-2b8d-4f06-9e1a-7d4c2b8f6a03","timezone":"UTC"}`,
	TypeScheduleDelete:    `{"schedule_id":"5c3e9a71-2b8d-4f06-9e1a-7d4c2b8f6a03"}`,
	TypeReportExport:      `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","format":"suricatoos-pdf","lang":"pt_BR","variant":"technical","filter":"apply_overrides=1 min_qod=70 levels=chmlg rows=-1"}`,
	TypeReportSummary:     `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":70,"apply_overrides":true,"levels":"chml"}`,
	TypeAgentScanNow:      `{"agent_id":"win-lab-0001"}`,
	TypeAgentRevoke:       `{"agent_id":"win-lab-0001","reason":"máquina descomissionada"}`,
	TypeEnrollTokenCreate: `{"token_type":"deployment","policy":"agent-endpoint","ttl_hours":72,"max_uses":50}`,
	TypeEnrollTokenRevoke: `{"token_id":"Ab3dEf6hIj9k"}`,
	TypeSensorJobEnqueue:  `{"targets":["192.0.2.0/28"],"ports":"T:22,80,443"}`,
	TypeFeedSyncNow:       `{}`,
}

// htmlPayload carries '<', '>', '&' and U+2028 LITERALLY (task.create).
var htmlPayload = `{"name":"Rede <LAB> & DMZ","comment":"linha 1` + lineSeparator + `linha 2","target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35","scan_config_id":"daba56c8-73ec-11df-a475-002264764cea"}`

// htmlReescaped is htmlPayload after an HTML-escaping re-encoder (e.g. Go's json.Marshal): same JSON value,
// other bytes.
func htmlReescaped() string {
	esc := func(hex string) string { return `\` + "u" + hex }
	return strings.NewReplacer("<", esc("003c"), ">", esc("003e"), "&", esc("0026"), lineSeparator, esc("2028")).Replace(htmlPayload)
}

// vectorSpec builds one golden vector. cmd holds the SIGNED fields; payload is the payload whose sha256 is
// signed (and sent, unless sent is set); alter makes the transmitted fields differ from the signed ones;
// mutate edits the envelope JSON after assembly. One defect per vector.
type vectorSpec struct {
	name    string
	cmd     Command
	payload string
	sent    *string
	alter   func(*Command)
	key     ed25519.PrivateKey
	domain  string
	mutate  func(string) string
	own, at string
	seen    []string
	expect  string
}

func (s vectorSpec) build() GoldenVector {
	signed := s.cmd
	signed.PayloadSHA256 = sha256hex([]byte(s.payload))
	canonical := Canonical(&signed)
	if s.domain != "" {
		canonical = append([]byte(s.domain), canonical[len(Domain):]...)
	}
	key := s.key
	if key == nil {
		key = goldenPriv
	}
	sent := signed
	if s.alter != nil {
		s.alter(&sent)
	}
	sentPayload := s.payload
	if s.sent != nil {
		sentPayload = *s.sent
	}
	sent.Payload = []byte(sentPayload)
	sent.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical))
	raw := string(appendEnvelope(nil, &sent))
	if s.mutate != nil {
		raw = s.mutate(raw)
	}
	own, at := s.own, s.at
	if own == "" {
		own = gOwn
	}
	if at == "" {
		at = gAt
	}
	return GoldenVector{Name: s.name, OwnNodeID: own, VerifyAt: at, CommandJSON: raw, Canonical: string(canonical),
		CanonicalSHA256: sha256hex(canonical), PayloadSHA256: sha256hex([]byte(sentPayload)), Seen: s.seen, Expect: s.expect}
}

func strPtr(s string) *string { return &s }

func replaceIn(old, new string) func(string) string {
	return func(s string) string {
		if strings.Count(s, old) != 1 {
			panic("mutação ambígua: " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

// padEnvelope inserts insignificant whitespace after the opening brace up to total bytes.
func padEnvelope(total int) func(string) string {
	return func(s string) string { return "{" + strings.Repeat(" ", total-len(s)) + s[1:] }
}

// padPayload is the ADR payload with insignificant whitespace before its closing brace, total bytes long.
func padPayload(total int) string {
	return adrPayload[:len(adrPayload)-1] + strings.Repeat(" ", total-len(adrPayload)) + "}"
}

func goldenSpecs() []vectorSpec {
	var specs []vectorSpec
	add := func(s vectorSpec) { specs = append(specs, s) }
	adr := adrCommand()
	named := func(name string, typ CommandType, edit func(*Command)) Command {
		c := gCommand(name, typ)
		if edit != nil {
			edit(&c)
		}
		return c
	}

	// accept: the ADR worked example, then one vector per payload format (task.start is payload_task_ref)
	add(vectorSpec{name: "accept/task.start", cmd: adr, payload: adrPayload, expect: "accept"})
	for _, e := range Catalog() {
		if p, ok := gPayloads[e.Type]; ok {
			name := "accept/" + string(e.Type)
			add(vectorSpec{name: name, cmd: gCommand(name, e.Type), payload: p, expect: "accept"})
		}
	}
	add(vectorSpec{name: "accept/html-and-line-separator-literal", cmd: gCommand("accept/html-and-line-separator-literal", TypeTaskCreate), payload: htmlPayload, expect: "accept"})
	// a well-formed type outside the closed catalog authenticates (never bad_envelope) and is unsupported at line 7
	add(vectorSpec{name: "unsupported/type-outside-catalog", cmd: gCommand("unsupported/type-outside-catalog", "tenant.scope_set"), payload: `{"scope":["192.0.2.0/24"]}`, expect: "unsupported"})

	// line 3 at its exact edges (skew 120 s), on the ADR envelope
	add(vectorSpec{name: "accept/window-lower-edge", cmd: adr, payload: adrPayload, at: "2026-10-11T11:58:00Z", expect: "accept"})
	add(vectorSpec{name: "not_yet_valid/lower-edge-minus-1s", cmd: adr, payload: adrPayload, at: "2026-10-11T11:57:59Z", expect: "not_yet_valid"})
	add(vectorSpec{name: "accept/window-upper-edge", cmd: adr, payload: adrPayload, at: "2026-10-11T13:02:00Z", expect: "accept"})
	add(vectorSpec{name: "expired/upper-edge-plus-1s", cmd: adr, payload: adrPayload, at: "2026-10-11T13:02:01Z", expect: "expired"})
	add(vectorSpec{name: "accept/window-exactly-24h", payload: adrPayload, expect: "accept",
		cmd: named("accept/window-exactly-24h", TypeTaskStart, func(c *Command) { c.NotAfter = "2026-10-12T12:00:00Z" })})
	add(vectorSpec{name: "bad_window/not-after-equals-issued-at", payload: adrPayload, at: gIssuedAt, expect: "bad_window",
		cmd: named("bad_window/not-after-equals-issued-at", TypeTaskStart, func(c *Command) { c.NotAfter = gIssuedAt })})
	add(vectorSpec{name: "bad_window/not-after-before-issued-at", payload: adrPayload, at: gIssuedAt, expect: "bad_window",
		cmd: named("bad_window/not-after-before-issued-at", TypeTaskStart, func(c *Command) { c.NotAfter = "2026-10-11T11:00:00Z" })})
	add(vectorSpec{name: "bad_window/longer-than-24h", payload: adrPayload, expect: "bad_window",
		cmd: named("bad_window/longer-than-24h", TypeTaskStart, func(c *Command) { c.NotAfter = "2026-10-12T12:00:01Z" })})

	// line 4
	add(vectorSpec{name: "wrong_node/other-node", cmd: adr, payload: adrPayload, own: "node-lab-0002", expect: "wrong_node"})

	// lines 2a and 5: the hub re-signed (same command_id, new nonce and window) / reused a nonce
	resigned := adr
	resigned.Nonce = goldenNonce("replay/same-command-id")
	resigned.IssuedAt, resigned.NotAfter = "2026-10-11T12:20:00Z", "2026-10-11T13:20:00Z"
	replayCmdID := vectorSpec{name: "replay/same-command-id", cmd: resigned, payload: adrPayload, seen: []string{adrCanonicalSHA256}, expect: "replay"}
	add(replayCmdID)
	reusedNonce := adr
	reusedNonce.CommandID = goldenUUID("replay/same-nonce")
	add(vectorSpec{name: "replay/same-nonce", cmd: reusedNonce, payload: adrPayload, seen: []string{adrCanonicalSHA256}, expect: "replay"})
	add(vectorSpec{name: "redelivery/after-not-after", cmd: adr, payload: adrPayload, at: "2026-10-12T13:00:00Z", seen: []string{adrCanonicalSHA256}, expect: "redelivery"})
	add(vectorSpec{name: "redelivery/recorded-replay", cmd: resigned, payload: adrPayload,
		seen: []string{adrCanonicalSHA256, replayCmdID.build().CanonicalSHA256}, expect: "redelivery"})

	// line 1
	add(vectorSpec{name: "payload_mismatch/payload-swapped", cmd: gCommand("payload_mismatch/payload-swapped", TypeTaskStart), payload: adrPayload,
		sent: strPtr(`{"task_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35"}`), expect: "payload_mismatch"})
	add(vectorSpec{name: "payload_mismatch/html-escaped-after-hash", cmd: gCommand("payload_mismatch/html-escaped-after-hash", TypeTaskCreate), payload: htmlPayload,
		sent: strPtr(htmlReescaped()), expect: "payload_mismatch"})
	add(vectorSpec{name: "payload_mismatch/reserialized-with-whitespace", cmd: gCommand("payload_mismatch/reserialized-with-whitespace", TypeTaskStart), payload: adrPayload,
		sent: strPtr(`{"task_id": "2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`), expect: "payload_mismatch"})

	// line 2: each signed field altered after signing (the transmitted value is valid), another key, the
	// remediation's domain
	altered := []struct {
		field        string
		signed, sent func(*Command)
	}{
		{"schema_version", func(c *Command) { c.SchemaVersion = "1.1.0" }, func(c *Command) { c.SchemaVersion = SchemaVersion }},
		{"command_id", nil, func(c *Command) { c.CommandID = goldenUUID("bad_signature/command_id/enviado") }},
		{"node_id", func(c *Command) { c.NodeID = "node-lab-0002" }, func(c *Command) { c.NodeID = gOwn }},
		{"tenant", nil, func(c *Command) { c.Tenant = "globex" }},
		{"type", func(c *Command) { c.Type = TypeTaskStop }, func(c *Command) { c.Type = TypeTaskDelete }},
		{"issued_by", nil, func(c *Command) { c.IssuedBy = "op-0000" }},
		{"issued_at", nil, func(c *Command) { c.IssuedAt = "2026-10-11T11:00:00Z" }},
		{"not_after", nil, func(c *Command) { c.NotAfter = "2026-10-11T14:00:00Z" }},
		{"nonce", nil, func(c *Command) { c.Nonce = goldenNonce("bad_signature/nonce/enviado") }},
	}
	for _, a := range altered {
		name := "bad_signature/" + a.field
		add(vectorSpec{name: name, cmd: named(name, TypeTaskStart, a.signed), payload: adrPayload, alter: a.sent, expect: "bad_signature"})
	}
	add(vectorSpec{name: "bad_signature/payload_sha256", cmd: gCommand("bad_signature/payload_sha256", TypeTaskStart),
		payload: `{"task_id":"5c3e9a71-2b8d-4f06-9e1a-7d4c2b8f6a03"}`, sent: strPtr(adrPayload),
		alter: func(c *Command) { c.PayloadSHA256 = sha256hex([]byte(adrPayload)) }, expect: "bad_signature"})
	add(vectorSpec{name: "bad_signature/other-key", cmd: gCommand("bad_signature/other-key", TypeTaskStart), payload: adrPayload, key: otherPriv, expect: "bad_signature"})
	add(vectorSpec{name: "bad_signature/remediation-domain", cmd: gCommand("bad_signature/remediation-domain", TypeTaskStart), payload: adrPayload, domain: remediationDomain, expect: "bad_signature"})

	// line 0
	bad := func(name string, edit func(*Command), payload string, mutate func(string) string) {
		typ := CommandType(TypeTaskStart)
		if payload == "" {
			payload = adrPayload
		} else if strings.Contains(payload, "min_qod") {
			typ = TypeReportSummary
		}
		add(vectorSpec{name: "bad_envelope/" + name, cmd: named("bad_envelope/"+name, typ, edit), payload: payload, mutate: mutate, expect: "bad_envelope"})
	}
	bad("issued-at-fraction", func(c *Command) { c.IssuedAt = "2026-10-11T12:00:00.000Z" }, "", nil)
	bad("issued-at-offset", func(c *Command) { c.IssuedAt = "2026-10-11T09:00:00-03:00" }, "", nil)
	bad("nonce-uppercase", func(c *Command) { c.Nonce = strings.ToUpper(c.Nonce) }, "", nil)
	bad("missing-field", nil, "", replaceIn(`"issued_by":"op-7f3a",`, ""))
	bad("unknown-field", nil, "", replaceIn(`{"schema_version"`, `{"debug":true,"schema_version"`))
	bad("null-value", nil, "", replaceIn(`"issued_by":"op-7f3a"`, `"issued_by":null`))
	bad("schema-version-1.1.0", func(c *Command) { c.SchemaVersion = "1.1.0" }, "", nil)
	bad("schema-version-1.0.1", func(c *Command) { c.SchemaVersion = "1.0.1" }, "", nil)
	bad("type-malformed", func(c *Command) { c.Type = "TASK.START" }, "", nil)
	bad("duplicate-key-envelope", nil, "", replaceIn(`"tenant":"acme",`, `"tenant":"acme","tenant":"globex",`))
	bad("duplicate-key-payload", nil, `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","task_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35"}`, nil)
	bad("key-case-node-id", nil, "", replaceIn(`"node_id":`, `"Node_ID":`))
	bad("data-after-value", nil, "", func(s string) string { return s + " {}" })
	bad("integer-fraction", nil, `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":70.0,"apply_overrides":true,"levels":"chml"}`, nil)
	bad("integer-exponent", nil, `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":7e1,"apply_overrides":true,"levels":"chml"}`, nil)
	bad("payload-not-object", nil, `["2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"]`, nil)
	bad("utf8-bom", nil, "", func(s string) string { return "\xef\xbb\xbf" + s })
	bad("signature-base64-noncanonical", nil, "", func(s string) string {
		i := strings.Index(s, `"signature":"`) + len(`"signature":"`)
		b := []byte(s)
		b[i+85] = base64Std[strings.IndexByte(base64Std, b[i+85])|1] // a padding bit: same 64 bytes, other text
		return string(b)
	})
	add(vectorSpec{name: "accept/envelope-65536-bytes", cmd: gCommand("accept/envelope-65536-bytes", TypeTaskStart), payload: adrPayload, mutate: padEnvelope(MaxEnvelopeBytes), expect: "accept"})
	bad("envelope-65537-bytes", nil, "", padEnvelope(MaxEnvelopeBytes+1))
	add(vectorSpec{name: "accept/payload-49152-bytes", cmd: gCommand("accept/payload-49152-bytes", TypeTaskStart), payload: padPayload(MaxPayloadBytes), expect: "accept"})
	bad("payload-49153-bytes", nil, padPayload(MaxPayloadBytes+1), nil)
	// the strict rules of "Codificação JSON" (amendment 2)
	bad("issued-at-february-30", func(c *Command) { c.IssuedAt = "2026-02-30T12:00:00Z" }, "", nil)
	bad("issued-at-hour-24", func(c *Command) { c.IssuedAt = "2026-10-11T24:00:00Z" }, "", nil)
	bad("not-after-second-60", func(c *Command) { c.NotAfter = "2026-10-11T13:00:60Z" }, "", nil)
	bad("type-trailing-newline", func(c *Command) { c.Type = "task.start\n" }, "", nil)
	bad("nesting-depth-33", nil, `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","x":`+strings.Repeat("[", 31)+strings.Repeat("]", 31)+`}`, nil)
	bad("lone-surrogate", nil, `{"name":"Rede `+esc("d800")+` LAB","target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35","scan_config_id":"daba56c8-73ec-11df-a475-002264764cea"}`, nil)
	// two DIFFERENT lone-surrogate keys: encoding/json would turn both into U+FFFD and see one key twice
	bad("lone-surrogate-key", nil, `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","`+esc("d800")+`":1,"`+esc("d801")+`":2}`, nil)

	// line 8 (the contract part: the payload against its type), after lines 0-5 pass
	add(vectorSpec{name: "bad_payload/name-noncharacter", cmd: gCommand("bad_payload/name-noncharacter", TypeTaskCreate), expect: "bad_payload",
		payload: `{"name":"Rede` + esc("fffe") + `LAB","target_id":"9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35","scan_config_id":"daba56c8-73ec-11df-a475-002264764cea"}`})
	add(vectorSpec{name: "bad_payload/token-id-trailing-newline", cmd: gCommand("bad_payload/token-id-trailing-newline", TypeEnrollTokenRevoke), expect: "bad_payload",
		payload: `{"token_id":"AbCdEfGhIjKl\n"}`})
	add(vectorSpec{name: "bad_payload/export-filter-without-levels", cmd: gCommand("bad_payload/export-filter-without-levels", TypeReportExport), expect: "bad_payload",
		payload: `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","format":"suricatoos-pdf","lang":"pt_BR","variant":"technical","filter":"apply_overrides=1 min_qod=70 rows=-1"}`})

	// canonical framing: values holding '\n', '=' and ':' (refused by the v1 envelope, bad_envelope) still
	// cannot move a field boundary; the a/b pair collides in a naive "key=value\n" join
	shift := gCommand("canonical/newline-shift", TypeTaskStop)
	a, b := shift, shift
	a.Tenant = "acme\ntype=task.start"
	b.Type = "task.start\ntype=task.stop"
	add(vectorSpec{name: "canonical/newline-shift-a", cmd: a, payload: adrPayload, expect: "bad_envelope"})
	add(vectorSpec{name: "canonical/newline-shift-b", cmd: b, payload: adrPayload, expect: "bad_envelope"})
	add(vectorSpec{name: "canonical/equals-and-colon", payload: adrPayload, expect: "bad_envelope",
		cmd: named("canonical/equals-and-colon", TypeTaskStart, func(c *Command) { c.Tenant, c.IssuedBy = "acme=1:x", "op:7f3a=9:" })})
	return specs
}

func buildGoldenFile(t *testing.T) *GoldenFile {
	t.Helper()
	pub := GoldenTestPublicKey()
	pemBytes, err := MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := KeyPin(pub)
	if err != nil {
		t.Fatal(err)
	}
	f := &GoldenFile{Format: GoldenFormat, Domain: Domain, SkewSeconds: int(DefaultClockSkew / time.Second),
		TestKey: GoldenKey{SeedDerivation: goldenSeedText, PublicKeyPEM: string(pemBytes), Pin: pin}}
	for _, s := range goldenSpecs() {
		f.Vectors = append(f.Vectors, s.build())
	}
	return f
}

// encodeGolden writes the file deterministically, by hand (no dependence on encoding/json's formatting, which
// changes between Go versions): two-space indentation, members in the ADR's order, invisible characters
// (U+2028, U+2029, BOM) escaped so that review sees them.
func encodeGolden(f *GoldenFile) []byte {
	var b []byte
	str := func(s string) { b = appendJSONString(b, s, true) }
	member := func(indent, name string, last bool, value func()) {
		b = append(b, indent...)
		str(name)
		b = append(b, ": "...)
		value()
		if !last {
			b = append(b, ',')
		}
		b = append(b, '\n')
	}
	b = append(b, "{\n"...)
	member("  ", "format", false, func() { str(f.Format) })
	member("  ", "domain", false, func() { str(f.Domain) })
	member("  ", "skew_seconds", false, func() { b = strconv.AppendInt(b, int64(f.SkewSeconds), 10) })
	member("  ", "test_key", false, func() {
		b = append(b, "{\n"...)
		member("    ", "seed_derivation", false, func() { str(f.TestKey.SeedDerivation) })
		member("    ", "public_key_pem", false, func() { str(f.TestKey.PublicKeyPEM) })
		member("    ", "pin", true, func() { str(f.TestKey.Pin) })
		b = append(b, "  }"...)
	})
	member("  ", "vectors", true, func() {
		b = append(b, "[\n"...)
		for i, v := range f.Vectors {
			b = append(b, "    {\n"...)
			const in = "      "
			member(in, "name", false, func() { str(v.Name) })
			member(in, "own_node_id", false, func() { str(v.OwnNodeID) })
			member(in, "verify_at", false, func() { str(v.VerifyAt) })
			member(in, "command_json", false, func() { str(v.CommandJSON) })
			member(in, "canonical", false, func() { str(v.Canonical) })
			member(in, "canonical_sha256", false, func() { str(v.CanonicalSHA256) })
			member(in, "payload_sha256", false, func() { str(v.PayloadSHA256) })
			if len(v.Seen) > 0 {
				member(in, "seen", false, func() {
					b = append(b, '[')
					for j, s := range v.Seen {
						if j > 0 {
							b = append(b, ", "...)
						}
						str(s)
					}
					b = append(b, ']')
				})
			}
			member(in, "expect", true, func() { str(v.Expect) })
			b = append(b, "    }"...)
			if i < len(f.Vectors)-1 {
				b = append(b, ',')
			}
			b = append(b, '\n')
		}
		b = append(b, "  ]"...)
	})
	return append(b, "}\n"...)
}

// TestGolden regenerates testdata/golden-v1.json in memory and FAILS on any byte of difference (the drift lock
// of TestCanonicalGolden in control-plane/remediation). With -update it rewrites the file instead.
func TestGolden(t *testing.T) {
	got := encodeGolden(buildGoldenFile(t))
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s regenerado (%d bytes, sha256 %s)", goldenPath, len(got), sha256hex(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (gere com: go test ./contract -run TestGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		i := 0
		for i < len(got) && i < len(want) && got[i] == want[i] {
			i++
		}
		lo := max(0, i-80)
		t.Fatalf("%s divergiu no byte %d (regenerado %d bytes, arquivo %d):\n regenerado: %q\n    arquivo: %q",
			goldenPath, i, len(got), len(want), got[lo:min(len(got), i+80)], want[lo:min(len(want), i+80)])
	}
}

func loadGolden(t testing.TB) *GoldenFile {
	t.Helper()
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseGoldenFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestGoldenVectors is the test the commandcenter runs too: every vector of the file, through VerifyAt and the
// replay classification, gives exactly its expect; the test key is the documented one.
func TestGoldenVectors(t *testing.T) {
	f := loadGolden(t)
	for _, err := range f.Check() {
		t.Error(err)
	}
	if len(f.Vectors) < 70 {
		t.Fatalf("só %d vetores", len(f.Vectors))
	}
}

// TestGoldenAnchors: the test key and its pin are EXACTLY the ADR's, and the vector accept/task.start is the
// ADR worked example byte for byte (envelope, canonical form, canonical_sha256 a9a4d175…, signature).
func TestGoldenAnchors(t *testing.T) {
	f := loadGolden(t)
	pub, err := ParsePublicKeyPEM([]byte(f.TestKey.PublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := MarshalPublicKeyPEM(pub)
	if !strings.Contains(string(der), adrPublicKeySPKI) || f.TestKey.Pin != adrPin || !IsGoldenTestKey(pub) {
		t.Fatalf("chave de teste do arquivo != ADR: %s %s", f.TestKey.PublicKeyPEM, f.TestKey.Pin)
	}
	if !strings.Contains(f.TestKey.SeedDerivation, GoldenTestKeySeedText) || keyFromSeedText(GoldenTestKeySeedText).Public().(ed25519.PublicKey).Equal(pub) == false {
		t.Fatal("derivação da semente")
	}
	if f.Format != GoldenFormat || f.Domain != Domain || f.SkewSeconds != 120 {
		t.Fatalf("cabeçalho: %s %s %d", f.Format, f.Domain, f.SkewSeconds)
	}
	v := f.Vectors[0]
	want := GoldenVector{Name: "accept/task.start", OwnNodeID: "node-lab-0001", VerifyAt: "2026-10-11T12:30:00Z",
		CommandJSON: adrEnvelope, Canonical: adrCanonical, CanonicalSHA256: adrCanonicalSHA256,
		PayloadSHA256: sha256hex([]byte(adrPayload)), Expect: "accept"}
	if !slices.Equal(v.Seen, nil) || v.Name != want.Name || v.OwnNodeID != want.OwnNodeID || v.VerifyAt != want.VerifyAt ||
		v.CommandJSON != want.CommandJSON || v.Canonical != want.Canonical || v.CanonicalSHA256 != want.CanonicalSHA256 ||
		v.PayloadSHA256 != want.PayloadSHA256 || v.Expect != want.Expect {
		t.Fatalf("o 1º vetor não é o exemplo do ADR:\n%+v", v)
	}
	if !strings.Contains(v.CommandJSON, `"signature":"`+adrSignature+`"`) {
		t.Fatal("assinatura do exemplo")
	}
}

var signatureMember = regexp.MustCompile(`"signature":"([^"]*)"`)

// lenientFields reads the transmitted values of an envelope however malformed (first value, last duplicate
// wins, case-insensitive): enough to inspect a vector's single defect.
func lenientFields(raw string) (Command, bool) {
	var c Command
	err := json.NewDecoder(strings.NewReader(strings.TrimPrefix(raw, "\xef\xbb\xbf"))).Decode(&c)
	return c, err == nil
}

// TestGoldenOneDefect: every vector has exactly the defect its expect names — the signature in command_json
// verifies over "canonical" (the bytes the generator signed) with the golden test key, except the
// other-key vector; a field-altered vector differs from the signed canonical form in that field only;
// payload_sha256 is the sha256 of the raw payload bytes inside command_json; and the name's prefix is its
// expect. So an implementation that checks in another order still lands on the same reason.
func TestGoldenOneDefect(t *testing.T) {
	f := loadGolden(t)
	names := map[string]bool{}
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	for _, v := range f.Vectors {
		if names[v.Name] {
			t.Errorf("nome repetido %s", v.Name)
		}
		names[v.Name] = true
		prefix, rest, _ := strings.Cut(v.Name, "/")
		if prefix != v.Expect && !(prefix == "canonical" && v.Expect == "bad_envelope") {
			t.Errorf("%s: nome não começa pelo expect %s", v.Name, v.Expect)
		}
		m := signatureMember.FindStringSubmatch(v.CommandJSON)
		if m == nil {
			t.Errorf("%s: sem assinatura", v.Name)
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(m[1]) // lenient on purpose (the non-canonical vector)
		key := goldenPub
		if v.Name == "bad_signature/other-key" {
			key = otherPub
		}
		if err != nil || !ed25519.Verify(key, []byte(v.Canonical), sig) {
			t.Errorf("%s: a assinatura não confere com canonical", v.Name)
		}
		if sha256hex([]byte(v.Canonical)) != v.CanonicalSHA256 {
			t.Errorf("%s: canonical_sha256", v.Name)
		}
		var outer struct {
			Payload json.RawMessage `json:"payload"`
		}
		if json.NewDecoder(strings.NewReader(strings.TrimPrefix(v.CommandJSON, "\xef\xbb\xbf"))).Decode(&outer) != nil || sha256hex(outer.Payload) != v.PayloadSHA256 {
			t.Errorf("%s: payload_sha256 não é o dos bytes crus do payload em command_json", v.Name)
		}
		sent, ok := lenientFields(v.CommandJSON)
		switch {
		case v.Name == "bad_signature/remediation-domain":
			if !strings.HasPrefix(v.Canonical, remediationDomain+"\n") || v.Canonical[len(remediationDomain):] != string(Canonical(&sent))[len(Domain):] {
				t.Errorf("%s: só o domínio difere", v.Name)
			}
		case prefix == "bad_signature" && rest != "other-key":
			derived := strings.Split(string(Canonical(&sent)), "\n")
			signed := strings.Split(v.Canonical, "\n")
			var diff []string
			for i := range signed {
				if derived[i] != signed[i] {
					diff = append(diff, strings.SplitN(signed[i], "=", 2)[0])
				}
			}
			if !slices.Equal(diff, []string{rest}) {
				t.Errorf("%s: campos alterados %v", v.Name, diff)
			}
		case ok && prefix != "bad_signature" && !strings.Contains(v.Name, "key-case") && !strings.Contains(v.Name, "missing-field") && !strings.Contains(v.Name, "null-value") && !strings.Contains(v.Name, "duplicate-key-envelope"):
			sent.Payload = nil
			if string(Canonical(&sent)) != v.Canonical {
				t.Errorf("%s: o envelope transmitido não é o assinado", v.Name)
			}
		}
	}
}

// TestGoldenCoverage: the mandatory vectors of ADR-0011 "Golden vectors" are all there, with the properties
// that make them what they claim to be.
func TestGoldenCoverage(t *testing.T) {
	f := loadGolden(t)
	byName := map[string]GoldenVector{}
	for _, v := range f.Vectors {
		byName[v.Name] = v
	}
	mandatory := []string{
		"accept/task.start", "accept/html-and-line-separator-literal", "unsupported/type-outside-catalog",
		"payload_mismatch/payload-swapped", "payload_mismatch/html-escaped-after-hash",
		"bad_signature/schema_version", "bad_signature/command_id", "bad_signature/node_id", "bad_signature/tenant",
		"bad_signature/type", "bad_signature/issued_by", "bad_signature/issued_at", "bad_signature/not_after",
		"bad_signature/nonce", "bad_signature/payload_sha256", "bad_signature/other-key", "bad_signature/remediation-domain",
		"accept/window-lower-edge", "not_yet_valid/lower-edge-minus-1s", "accept/window-upper-edge", "expired/upper-edge-plus-1s",
		"bad_window/not-after-equals-issued-at", "bad_window/longer-than-24h", "wrong_node/other-node",
		"replay/same-command-id", "replay/same-nonce", "redelivery/after-not-after",
		"bad_envelope/issued-at-fraction", "bad_envelope/issued-at-offset", "bad_envelope/nonce-uppercase",
		"bad_envelope/missing-field", "bad_envelope/unknown-field", "bad_envelope/schema-version-1.1.0",
		"bad_envelope/schema-version-1.0.1", "bad_envelope/duplicate-key-envelope", "bad_envelope/duplicate-key-payload",
		"bad_envelope/key-case-node-id", "bad_envelope/data-after-value", "bad_envelope/integer-fraction",
		"bad_envelope/integer-exponent", "bad_envelope/envelope-65537-bytes", "bad_envelope/payload-49153-bytes",
		"canonical/newline-shift-a", "canonical/newline-shift-b", "canonical/equals-and-colon",
		"bad_envelope/signature-base64-noncanonical", "bad_envelope/issued-at-february-30", "bad_envelope/issued-at-hour-24",
		"bad_envelope/not-after-second-60", "bad_envelope/nesting-depth-33", "bad_envelope/lone-surrogate",
		"bad_envelope/lone-surrogate-key", "bad_envelope/type-trailing-newline",
		"bad_payload/name-noncharacter", "bad_payload/token-id-trailing-newline",
	}
	for _, n := range mandatory {
		if _, ok := byName[n]; !ok {
			t.Errorf("falta o vetor obrigatório %s", n)
		}
	}
	// one accept per payload format, and a payload with multi-byte UTF-8 hashed over its raw bytes
	formats := map[string]bool{}
	utf8Seen := false
	for _, v := range f.Vectors {
		if v.Expect != "accept" {
			continue
		}
		c, _ := lenientFields(v.CommandJSON)
		if e, ok := LookupType(c.Type); ok {
			formats[e.Payload] = true
			if err := ValidatePayload(c.Type, c.Payload); err != nil {
				t.Errorf("%s: o payload de um accept precisa ser válido para o tipo (linha 8): %v", v.Name, err)
			}
		}
		utf8Seen = utf8Seen || strings.ContainsFunc(string(c.Payload), func(r rune) bool { return r > 0x7f })
	}
	if len(formats) != len(payloadSpecs) || !utf8Seen {
		t.Errorf("accept cobre %d de %d formatos de payload; UTF-8: %v", len(formats), len(payloadSpecs), utf8Seen)
	}
	html := byName["accept/html-and-line-separator-literal"].CommandJSON
	if !strings.Contains(html, "<LAB> & DMZ") || !strings.Contains(html, lineSeparator) {
		t.Error("vetor de caracteres literais")
	}
	if esc := byName["payload_mismatch/html-escaped-after-hash"].CommandJSON; !strings.Contains(esc, `\`+"u003cLAB") || strings.Contains(esc, lineSeparator) {
		t.Error("vetor re-escapado")
	}
	// edges relative to the window and the skew of the file
	skew := time.Duration(f.SkewSeconds) * time.Second
	at := func(n string) time.Time { tm, _ := ParseUTCTime(byName[n].VerifyAt); return tm }
	adrIssued, adrNotAfter := utc(gIssuedAt), utc(gNotAfter)
	if !at("accept/window-lower-edge").Equal(adrIssued.Add(-skew)) || !at("not_yet_valid/lower-edge-minus-1s").Equal(adrIssued.Add(-skew-time.Second)) ||
		!at("accept/window-upper-edge").Equal(adrNotAfter.Add(skew)) || !at("expired/upper-edge-plus-1s").Equal(adrNotAfter.Add(skew+time.Second)) {
		t.Error("bordas da janela")
	}
	if r := at("redelivery/after-not-after"); !r.After(adrNotAfter.Add(skew)) || !r.Before(adrNotAfter.Add(7*24*time.Hour)) {
		t.Error("reentrega entre not_after+skew e not_after+7d")
	}
	// the replays really share the command_id / the nonce with the recorded form, under another canonical form
	adr, _ := lenientFields(adrEnvelope)
	sameID, _ := lenientFields(byName["replay/same-command-id"].CommandJSON)
	sameNonce, _ := lenientFields(byName["replay/same-nonce"].CommandJSON)
	if sameID.CommandID != adr.CommandID || sameID.Nonce == adr.Nonce || sameNonce.Nonce != adr.Nonce || sameNonce.CommandID == adr.CommandID {
		t.Error("vetores de replay")
	}
	// injectivity: the a/b pair collides in the naive join, never in the canonical form
	a, _ := lenientFields(byName["canonical/newline-shift-a"].CommandJSON)
	b, _ := lenientFields(byName["canonical/newline-shift-b"].CommandJSON)
	if naiveJoin(&a) != naiveJoin(&b) || byName["canonical/newline-shift-a"].Canonical == byName["canonical/newline-shift-b"].Canonical {
		t.Error("par de injetividade")
	}
	for _, v := range f.Vectors {
		if !strings.HasPrefix(v.Canonical, Domain+"\n") {
			continue
		}
		if _, ok := parseCanonical(v.Canonical); !ok {
			t.Errorf("%s: forma canônica não decodifica", v.Name)
		}
	}
}
