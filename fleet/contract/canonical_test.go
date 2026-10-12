package contract

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestCanonicalADRExample pins the exact signed bytes of the ADR-0011 worked example: domain on the first line,
// the ten fields in order, "key=<len in bytes>:<value>\n" on every line including the last.
func TestCanonicalADRExample(t *testing.T) {
	c := adrCommand()
	got := Canonical(&c)
	if string(got) != adrCanonical {
		t.Fatalf("forma canônica divergiu:\n got=%q\nwant=%q", got, adrCanonical)
	}
	if sha256hex(got) != adrCanonicalSHA256 {
		t.Fatalf("sha256 da forma canônica = %s, ADR diz %s", sha256hex(got), adrCanonicalSHA256)
	}
	if len(adrPayload) != adrPayloadBytes || sha256hex([]byte(adrPayload)) != c.PayloadSHA256 {
		t.Fatal("payload do exemplo do ADR: 50 bytes cujo sha256 é o payload_sha256")
	}
}

// TestCanonicalIgnoresPayloadAndSignature: the payload enters only through payload_sha256 and the signature is
// not part of the signed bytes.
func TestCanonicalIgnoresPayloadAndSignature(t *testing.T) {
	a, b := adrCommand(), adrCommand()
	b.Payload = []byte(`{"task_id":"x"}`)
	b.Signature = "y"
	if string(Canonical(&a)) != string(Canonical(&b)) {
		t.Fatal("payload e assinatura não entram na forma canônica")
	}
}

// TestCanonicalBindsEveryField: changing any of the ten fields changes the signed bytes.
func TestCanonicalBindsEveryField(t *testing.T) {
	base := adrCommand()
	want := string(Canonical(&base))
	mut := map[string]func(*Command){
		"schema_version": func(c *Command) { c.SchemaVersion = "1.1.0" },
		"command_id":     func(c *Command) { c.CommandID = "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c19" },
		"node_id":        func(c *Command) { c.NodeID = "node-lab-0002" },
		"tenant":         func(c *Command) { c.Tenant = "globex" },
		"type":           func(c *Command) { c.Type = TypeTaskDelete },
		"issued_by":      func(c *Command) { c.IssuedBy = "op-0000" },
		"issued_at":      func(c *Command) { c.IssuedAt = "2026-10-11T12:00:01Z" },
		"not_after":      func(c *Command) { c.NotAfter = "2026-10-11T14:00:00Z" },
		"nonce":          func(c *Command) { c.Nonce = strings.Repeat("0", 64) },
		"payload_sha256": func(c *Command) { c.PayloadSHA256 = strings.Repeat("f", 64) },
	}
	if len(mut) != len(signedFields) {
		t.Fatalf("o teste cobre %d campos, a forma canônica tem %d", len(mut), len(signedFields))
	}
	for name, f := range mut {
		c := adrCommand()
		f(&c)
		if string(Canonical(&c)) == want {
			t.Errorf("mudar %s precisa mudar a forma canônica", name)
		}
	}
}

// TestCanonicalLengthIsBytes: <len> is the UTF-8 byte length, in decimal, without leading zeros.
func TestCanonicalLengthIsBytes(t *testing.T) {
	c := adrCommand()
	c.Tenant = "açaí"
	if got := string(Canonical(&c)); !strings.Contains(got, "\ntenant=6:açaí\n") {
		t.Fatalf("comprimento deve ser em bytes UTF-8: %q", got)
	}
	c.Tenant = ""
	if got := string(Canonical(&c)); !strings.Contains(got, "\ntenant=0:\n") {
		t.Fatalf("valor vazio: %q", got)
	}
}

// naiveJoin is the framing the length prefix exists to avoid: "key=value\n" without the length.
func naiveJoin(c *Command) string {
	var b strings.Builder
	b.WriteString(Domain + "\n")
	for _, f := range signedFields {
		b.WriteString(f.name + "=" + f.value(c) + "\n")
	}
	return b.String()
}

// parseCanonical decodes a canonical form back into its ten values: if it always succeeds and round-trips,
// the framing is injective (two different commands can never share signed bytes).
func parseCanonical(s string) ([]string, bool) {
	rest, ok := strings.CutPrefix(s, Domain+"\n")
	if !ok {
		return nil, false
	}
	var vals []string
	for _, f := range signedFields {
		rest, ok = strings.CutPrefix(rest, f.name+"=")
		if !ok {
			return nil, false
		}
		lenText, after, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, false
		}
		n, err := strconv.Atoi(lenText)
		if err != nil || n < 0 || n > len(after) || strconv.Itoa(n) != lenText || !strings.HasPrefix(after[n:], "\n") {
			return nil, false
		}
		vals = append(vals, after[:n])
		rest = after[n+1:]
	}
	return vals, rest == ""
}

// TestCanonicalInjective: values holding "\n", "=" and ":" (which the v1 envelope refuses by format) still
// cannot move a field boundary, while the naive join collides.
func TestCanonicalInjective(t *testing.T) {
	a, b := adrCommand(), adrCommand()
	a.Tenant, a.Type = "acme\ntype=task.start", "task.stop"
	b.Tenant, b.Type = "acme", "task.start\ntype=task.stop"
	if naiveJoin(&a) != naiveJoin(&b) {
		t.Fatal("o par de teste deveria colidir no join ingênuo")
	}
	if string(Canonical(&a)) == string(Canonical(&b)) {
		t.Fatal("a forma canônica com prefixo de comprimento não pode colidir")
	}
	c := adrCommand()
	c.Tenant, c.IssuedBy = "acme=1:x", "op:7f3a=9:"
	for _, cmd := range []Command{a, b, c, adrCommand()} {
		vals, ok := parseCanonical(string(Canonical(&cmd)))
		if !ok {
			t.Fatalf("forma canônica não decodifica: %q", Canonical(&cmd))
		}
		for i, f := range signedFields {
			if vals[i] != f.value(&cmd) {
				t.Errorf("%s: %q != %q", f.name, vals[i], f.value(&cmd))
			}
		}
	}
}

// TestADRWorkedExampleText re-reads the worked example from the ADR itself (as the Python contract test
// does): the Go constants of this package's tests are exactly the document's.
func TestADRWorkedExampleText(t *testing.T) {
	b, err := os.ReadFile(adrPath)
	if err != nil {
		t.Fatalf("ADR-0011 ilegível: %v", err)
	}
	adr := strings.ReplaceAll(string(b), "\r\n", "\n")
	find := func(name, re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(adr)
		if m == nil {
			t.Fatalf("ADR-0011: não achei %s", name)
		}
		return m[1]
	}
	checks := []struct{ name, got, want string }{
		{"envelope", find("envelope", `(?m)^(\{"schema_version":"1\.0\.0","command_id":[^\n]*\})$`), adrEnvelope},
		{"forma canônica", find("forma canônica", "(?m)^```\n("+regexp.QuoteMeta(Domain)+`\n(?:[a-z_0-9]+=[0-9]+:[^\n]*\n)+)`+"```"), adrCanonical},
		{"sha256", find("sha256", "Bytes assinados \\(`sha256` = `([0-9a-f]{64})`\\)"), adrCanonicalSHA256},
		{"bytes do payload", find("bytes", `sha256 dos ([0-9]+) bytes`), strconv.Itoa(adrPayloadBytes)},
		{"pubkey", find("pubkey", "pubkey `([A-Za-z0-9+/=]+)`"), adrPublicKeySPKI},
		{"pin", find("pin", "pin `(sha256:[0-9a-f]{64})`"), adrPin},
		{"canonical_sha256 do vetor", find("vetor", "`canonical_sha256` = `([0-9a-f]{64})`"), adrCanonicalSHA256},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("ADR-0011 %s: %q != %q", c.name, c.got, c.want)
		}
	}
}
