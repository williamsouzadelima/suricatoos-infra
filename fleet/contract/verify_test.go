package contract

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const skew2m = 2 * time.Minute

// TestVerifyADRExample: the ADR envelope authenticates with the public golden test key, exposing what the
// anti-replay store needs (canonical form and its sha256) and the exact payload bytes.
func TestVerifyADRExample(t *testing.T) {
	v, err := Verify(goldenPub, []byte(adrEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Canonical) != adrCanonical || v.CanonicalSHA256 != adrCanonicalSHA256 {
		t.Fatalf("forma canônica/sha: %q %s", v.Canonical, v.CanonicalSHA256)
	}
	if string(v.Command.Payload) != adrPayload || v.Command.Type != TypeTaskStart || v.Command.Signature != adrSignature {
		t.Fatalf("envelope decodificado: %+v", v.Command)
	}
	if !v.IssuedAt.Equal(utc("2026-10-11T12:00:00Z")) || !v.NotAfter.Equal(utc("2026-10-11T13:00:00Z")) {
		t.Fatalf("tempos: %v %v", v.IssuedAt, v.NotAfter)
	}
	if v2, err := VerifyAt(goldenPub, []byte(adrEnvelope), utc("2026-10-11T12:30:00Z"), "node-lab-0001", skew2m); err != nil || v2 == nil {
		t.Fatalf("VerifyAt do exemplo do ADR: %v", err)
	}
}

// TestVerifyLines0to2 covers every line of the unauthenticated part, in order, with the typed reason and the
// line-0 violation (keyword + path). A refusal at lines 0–2 never returns a *Verified (no ack possible).
func TestVerifyLines0to2(t *testing.T) {
	good := string(envelopeFor(goldenPriv, adrCommand(), adrPayload))
	if good != adrEnvelope {
		t.Fatalf("envelopeFor não reproduz o exemplo do ADR:\n%s", good)
	}
	summary := adrCommand()
	summary.Type = TypeReportSummary
	withPayload := func(p string) string { return string(envelopeFor(goldenPriv, summary, p)) }
	field := func(mut func(*Command)) string {
		c := adrCommand()
		mut(&c)
		return string(envelopeFor(goldenPriv, c, adrPayload))
	}
	sig := func(s string) string {
		c := adrCommand()
		c.Payload = []byte(adrPayload)
		c.Signature = s
		return string(appendEnvelope(nil, &c))
	}
	// a signature whose base64 is not canonical: same 64 bytes, a non-zero padding bit in the last character
	nonCanonical := []byte(adrSignature)
	nonCanonical[85] = base64Std[strings.IndexByte(base64Std, nonCanonical[85])|1]

	cases := []struct {
		name    string
		raw     string
		reason  RejectReason
		keyword string
		path    string
	}{
		{"campo faltando", replaceOnce(t, good, `"issued_by":"op-7f3a",`, ""), ReasonBadEnvelope, "required", ""},
		{"campo desconhecido", replaceOnce(t, good, `{"schema_version"`, `{"debug":true,"schema_version"`), ReasonBadEnvelope, "additionalProperties", ""},
		{"chave com caixa diferente", replaceOnce(t, good, `"node_id"`, `"Node_ID"`), ReasonBadEnvelope, "additionalProperties", ""},
		{"chave duplicada no envelope", replaceOnce(t, good, `"tenant":"acme",`, `"tenant":"acme","tenant":"globex",`), ReasonBadEnvelope, "duplicate_key", "/tenant"},
		{"chave duplicada no payload", withPayload(`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`), ReasonBadEnvelope, "duplicate_key", "/payload/task_id"},
		{"dado depois do valor", good + " {}", ReasonBadEnvelope, "json_syntax", ""},
		{"inteiro com fração", withPayload(`{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":70.0,"apply_overrides":true,"levels":"chml"}`), ReasonBadEnvelope, "integer_lexical", "/payload/min_qod"},
		{"inteiro com expoente", withPayload(`{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":7e1,"apply_overrides":true,"levels":"chml"}`), ReasonBadEnvelope, "integer_lexical", "/payload/min_qod"},
		{"payload não é objeto", withPayload(`[]`), ReasonBadEnvelope, "type", "/payload"},
		{"null", replaceOnce(t, good, `"issued_by":"op-7f3a"`, `"issued_by":null`), ReasonBadEnvelope, "type", "/issued_by"},
		{"BOM", "\xef\xbb\xbf" + good, ReasonBadEnvelope, "json_syntax", ""},
		{"UTF-8 inválido", replaceOnce(t, good, `"op-7f3a"`, "\"op-7f3a\xff\""), ReasonBadEnvelope, "json_syntax", ""},
		{"fração de segundo", field(func(c *Command) { c.IssuedAt = "2026-10-11T12:00:00.000Z" }), ReasonBadEnvelope, "pattern", "/issued_at"},
		{"offset", field(func(c *Command) { c.IssuedAt = "2026-10-11T09:00:00-03:00" }), ReasonBadEnvelope, "pattern", "/issued_at"},
		{"data inexistente", field(func(c *Command) { c.NotAfter = "2026-02-30T13:00:00Z" }), ReasonBadEnvelope, "format", "/not_after"},
		{"hora 24", field(func(c *Command) { c.IssuedAt = "2026-10-11T24:00:00Z" }), ReasonBadEnvelope, "pattern", "/issued_at"},
		{"ano 0000", field(func(c *Command) { c.IssuedAt = "0000-10-11T12:00:00Z" }), ReasonBadEnvelope, "pattern", "/issued_at"},
		{"segundo 60", field(func(c *Command) { c.NotAfter = "2026-10-11T13:00:60Z" }), ReasonBadEnvelope, "pattern", "/not_after"},
		{"nonce maiúsculo", field(func(c *Command) { c.Nonce = strings.ToUpper(c.Nonce) }), ReasonBadEnvelope, "pattern", "/nonce"},
		{"schema_version sem suporte", field(func(c *Command) { c.SchemaVersion = "1.1.0" }), ReasonBadEnvelope, "const", "/schema_version"},
		{"schema_version com PATCH", field(func(c *Command) { c.SchemaVersion = "1.0.1" }), ReasonBadEnvelope, "pattern", "/schema_version"},
		{"command_id maiúsculo", field(func(c *Command) { c.CommandID = strings.ToUpper(c.CommandID) }), ReasonBadEnvelope, "pattern", "/command_id"},
		{"node_id com newline", field(func(c *Command) { c.NodeID += "\n" }), ReasonBadEnvelope, "not", "/node_id"},
		{"tenant inválido", field(func(c *Command) { c.Tenant = "-acme" }), ReasonBadEnvelope, "pattern", "/tenant"},
		{"issued_by com e-mail", field(func(c *Command) { c.IssuedBy = "op@example.com" }), ReasonBadEnvelope, "pattern", "/issued_by"},
		{"type malformado", field(func(c *Command) { c.Type = "TASK.START" }), ReasonBadEnvelope, "pattern", "/type"},
		{"type com newline final", field(func(c *Command) { c.Type = "task.start\n" }), ReasonBadEnvelope, "not", "/type"},
		{"assinatura curta", sig(adrSignature[:84] + "=="), ReasonBadEnvelope, "pattern", "/signature"},
		{"assinatura base64 não canônica", sig(string(nonCanonical)), ReasonBadEnvelope, "pattern", "/signature"},
		{"payload trocado", replaceOnce(t, good, `"payload":{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`, `"payload":{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a50"}`), ReasonPayloadMismatch, "", ""},
		{"payload re-serializado com espaço", replaceOnce(t, good, `{"task_id":"2d5b8f0e`, `{"task_id": "2d5b8f0e`), ReasonPayloadMismatch, "", ""},
		{"campo alterado depois de assinar", replaceOnce(t, good, `"tenant":"acme"`, `"tenant":"globex"`), ReasonBadSignature, "", ""},
		{"outra chave", string(envelopeFor(otherPriv, adrCommand(), adrPayload)), ReasonBadSignature, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := Verify(goldenPub, []byte(c.raw))
			reason, viol := rejectOf(t, err)
			if reason != c.reason {
				t.Fatalf("motivo %q, esperado %q (err=%v)", reason, c.reason, err)
			}
			if v != nil || envelopeOf(err) != nil {
				t.Fatal("recusa nas linhas 0–2 não traz envelope autenticado (sem ack)")
			}
			if c.keyword == "" {
				if viol != nil {
					t.Fatalf("violação inesperada: %v", viol)
				}
				return
			}
			if viol == nil || viol.Keyword != c.keyword || (c.keyword != "json_syntax" && viol.Path != c.path) {
				t.Fatalf("violação %+v, esperado (%q, %q)", viol, c.keyword, c.path)
			}
		})
	}
}

const base64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// TestVerifySizeCaps: envelope <= 64 KiB and payload <= 48 KiB, measured on the raw bytes, both edges.
func TestVerifySizeCaps(t *testing.T) {
	good := envelopeFor(goldenPriv, adrCommand(), adrPayload)
	padEnvelope := func(total int) []byte {
		pad := total - len(good)
		return append([]byte("{"+strings.Repeat(" ", pad)), good[1:]...)
	}
	padPayload := func(total int) []byte {
		p := `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"` + strings.Repeat(" ", total-len(adrPayload)) + `}`
		return envelopeFor(goldenPriv, adrCommand(), p)
	}
	cases := []struct {
		name string
		raw  []byte
		path string // "" = accepted
		ok   bool
	}{
		{"envelope de 65536 bytes", padEnvelope(MaxEnvelopeBytes), "", true},
		{"envelope de 65537 bytes", padEnvelope(MaxEnvelopeBytes + 1), "", false},
		{"payload de 49152 bytes", padPayload(MaxPayloadBytes), "", true},
		{"payload de 49153 bytes", padPayload(MaxPayloadBytes + 1), "/payload", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(goldenPub, c.raw)
			if c.ok {
				if err != nil {
					t.Fatalf("deveria passar: %v", err)
				}
				return
			}
			reason, viol := rejectOf(t, err)
			if reason != ReasonBadEnvelope || viol == nil || viol.Keyword != "size" || viol.Path != c.path {
				t.Fatalf("got %q %+v", reason, viol)
			}
		})
	}
}

// TestVerifyAtWindow covers line 3 at its exact edges (skew 2 min) and line 4. VerifyAt never returns a
// *Verified together with an error; an authenticated refusal carries the envelope inside the RejectError,
// because it gets an ack.
func TestVerifyAtWindow(t *testing.T) {
	withTimes := func(issued, notAfter string) []byte {
		c := adrCommand()
		c.IssuedAt, c.NotAfter = issued, notAfter
		return envelopeFor(goldenPriv, c, adrPayload)
	}
	adr := []byte(adrEnvelope)
	cases := []struct {
		name   string
		raw    []byte
		at     string
		own    string
		reason RejectReason
	}{
		{"dentro da janela", adr, "2026-10-11T12:30:00Z", "node-lab-0001", ""},
		{"borda inferior issued_at-skew aceita", adr, "2026-10-11T11:58:00Z", "node-lab-0001", ""},
		{"1 s antes da borda inferior", adr, "2026-10-11T11:57:59Z", "node-lab-0001", ReasonNotYetValid},
		{"borda superior not_after+skew aceita", adr, "2026-10-11T13:02:00Z", "node-lab-0001", ""},
		{"1 s depois da borda superior", adr, "2026-10-11T13:02:01Z", "node-lab-0001", ReasonExpired},
		{"not_after igual a issued_at", withTimes("2026-10-11T12:00:00Z", "2026-10-11T12:00:00Z"), "2026-10-11T12:00:00Z", "node-lab-0001", ReasonBadWindow},
		{"not_after antes de issued_at", withTimes("2026-10-11T12:00:00Z", "2026-10-11T11:00:00Z"), "2026-10-11T12:00:00Z", "node-lab-0001", ReasonBadWindow},
		{"janela de 24 h exatas", withTimes("2026-10-11T12:00:00Z", "2026-10-12T12:00:00Z"), "2026-10-11T12:30:00Z", "node-lab-0001", ""},
		{"janela de 24 h + 1 s", withTimes("2026-10-11T12:00:00Z", "2026-10-12T12:00:01Z"), "2026-10-11T12:30:00Z", "node-lab-0001", ReasonBadWindow},
		{"bad_window antes de not_yet_valid", withTimes("2026-10-11T12:00:00Z", "2026-10-11T12:00:00Z"), "2026-10-11T10:00:00Z", "node-lab-0001", ReasonBadWindow},
		{"bad_window antes de expired", withTimes("2026-10-11T12:00:00Z", "2026-10-13T12:00:00Z"), "2026-10-20T12:00:00Z", "node-lab-0001", ReasonBadWindow},
		{"outro nó", adr, "2026-10-11T12:30:00Z", "node-lab-0002", ReasonWrongNode},
		{"janela antes do nó", adr, "2026-10-11T14:00:00Z", "node-lab-0002", ReasonExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := VerifyAt(goldenPub, c.raw, utc(c.at), c.own, skew2m)
			reason, _ := rejectOf(t, err)
			if reason != c.reason {
				t.Fatalf("motivo %q, esperado %q", reason, c.reason)
			}
			if err == nil {
				if v == nil {
					t.Fatal("aceito sem *Verified")
				}
				return
			}
			if v != nil {
				t.Fatal("VerifyAt nunca devolve *Verified junto com um erro")
			}
			env := envelopeOf(err)
			if env == nil || env.Command.CommandID == "" || !env.sealed {
				t.Fatal("recusa autenticada (linhas 3–4) traz o envelope verificado no RejectError, para o ack")
			}
		})
	}
}

// envelopeOf returns the authenticated envelope a RejectError carries (nil for lines 0–2 or no RejectError).
func envelopeOf(err error) *Verified {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Envelope
	}
	return nil
}

// TestVerifiedSealed: only Verify builds a *Verified that CheckAt accepts — a hand-made one (or nil) is a
// programming error, never a way around the signature.
func TestVerifiedSealed(t *testing.T) {
	forged := &Verified{Command: adrCommand(), IssuedAt: utc("2026-10-11T12:00:00Z"), NotAfter: utc("2026-10-11T13:00:00Z")}
	if err := forged.CheckAt(utc("2026-10-11T12:30:00Z"), "node-lab-0001", skew2m); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("Verified fabricado: %v", err)
	}
	var none *Verified
	if err := none.CheckAt(utc("2026-10-11T12:30:00Z"), "node-lab-0001", skew2m); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("Verified nil: %v", err)
	}
	v, err := Verify(goldenPub, []byte(adrEnvelope))
	if err != nil || v.CheckAt(utc("2026-10-11T12:30:00Z"), "node-lab-0001", skew2m) != nil {
		t.Fatalf("Verified de verdade: %v", err)
	}
}

// TestRejectErrorBounded: an error message never carries more than a short quoted prefix of input-controlled
// text (member names, JSON pointers), however long the input is.
func TestRejectErrorBounded(t *testing.T) {
	long := strings.Repeat("k", 40000) + `\n` // a JSON-escaped newline inside the name
	cases := map[string]string{
		"chave longa duplicada":    `{"` + long + `":1,"` + long + `":2}`,
		"chave longa desconhecida": strings.Replace(adrEnvelope, `"tenant":"acme",`, `"tenant":"acme","`+long+`":1,`, 1),
		"payload com chave longa":  strings.Replace(adrEnvelope, `{"task_id"`, `{"`+long+`":{"x":1.5},"task_id"`, 1),
	}
	for name, raw := range cases {
		_, err := Verify(goldenPub, []byte(raw))
		if err == nil {
			t.Fatalf("%s: deveria falhar", name)
		}
		if msg := err.Error(); len(msg) > 400 || strings.Contains(msg, "\n") {
			t.Errorf("%s: mensagem de %d bytes (ou com quebra de linha): %.120q", name, len(msg), msg)
		}
	}
}

// TestVerifyAtSubSecond: the verification clock may have sub-second precision; the edges are exact.
func TestVerifyAtSubSecond(t *testing.T) {
	edge := utc("2026-10-11T13:02:00Z")
	if _, err := VerifyAt(goldenPub, []byte(adrEnvelope), edge, "node-lab-0001", skew2m); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyAt(goldenPub, []byte(adrEnvelope), edge.Add(time.Nanosecond), "node-lab-0001", skew2m)
	if r, _ := rejectOf(t, err); r != ReasonExpired {
		t.Fatalf("1 ns depois de not_after+skew: %q", r)
	}
}

// TestVerifyUnknownType: a well-formed type outside the catalog passes lines 0–4 (it is unsupported, line 7).
func TestVerifyUnknownType(t *testing.T) {
	c := adrCommand()
	c.Type = "tenant.scope_set"
	raw := envelopeFor(goldenPriv, c, `{"scope":["192.0.2.0/24"]}`)
	if _, err := VerifyAt(goldenPub, raw, utc("2026-10-11T12:30:00Z"), "node-lab-0001", skew2m); err != nil {
		t.Fatalf("tipo fora do catálogo não é bad_envelope: %v", err)
	}
}

// TestVerifyConfigErrors: a pinned key of the wrong size and a skew outside [0, 10 min] are local configuration
// errors, not reject reasons — and never a panic.
func TestVerifyConfigErrors(t *testing.T) {
	if _, err := Verify(goldenPub[:31], []byte(adrEnvelope)); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("chave curta: %v", err)
	}
	for _, s := range []time.Duration{-time.Second, MaxClockSkew + time.Second} {
		if _, err := VerifyAt(goldenPub, []byte(adrEnvelope), utc("2026-10-11T12:30:00Z"), "node-lab-0001", s); !errors.Is(err, ErrInvalidSkew) {
			t.Fatalf("skew %v: %v", s, err)
		}
	}
	if _, err := VerifyAt(goldenPub, []byte(adrEnvelope), utc("2026-10-11T12:30:00Z"), "node-lab-0001", MaxClockSkew); err != nil {
		t.Fatalf("skew de 10 min é o teto permitido: %v", err)
	}
	var re *RejectError
	if _, err := Verify(goldenPub[:31], []byte(adrEnvelope)); errors.As(err, &re) {
		t.Fatal("erro de configuração não é RejectError")
	}
}

// TestRejectErrorHelpers: ReasonOf and the message never echo raw input.
func TestRejectErrorHelpers(t *testing.T) {
	_, err := Verify(goldenPub, []byte(`{"x":"`+strings.Repeat("A", 10)+`"`))
	r, ok := ReasonOf(err)
	if !ok || r != ReasonBadEnvelope {
		t.Fatalf("ReasonOf: %q %v", r, ok)
	}
	if _, ok := ReasonOf(errors.New("x")); ok {
		t.Fatal("ReasonOf de erro qualquer")
	}
	if !strings.Contains(err.Error(), "bad_envelope") {
		t.Fatalf("mensagem: %q", err.Error())
	}
}

// TestVerifiedIsACopy: the *Verified does not alias the caller's buffer.
func TestVerifiedIsACopy(t *testing.T) {
	raw := []byte(adrEnvelope)
	v, err := Verify(goldenPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if string(v.Command.Payload) != adrPayload || !bytes.Equal(v.Canonical, []byte(adrCanonical)) {
		t.Fatal("Verified depende do buffer de entrada")
	}
	if base64.StdEncoding.EncodeToString(v.Signature) != adrSignature {
		t.Fatal("assinatura decodificada")
	}
}
