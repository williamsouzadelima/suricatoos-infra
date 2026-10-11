package contract

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// adrSection returns the lines of the ADR section that starts with heading, up to the next heading of the same
// or higher level.
func adrSection(t *testing.T, heading string) []string {
	t.Helper()
	b, err := os.ReadFile(adrPath)
	if err != nil {
		t.Fatalf("ADR-0011 ilegível: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	level := strings.Index(heading, " ")
	var out []string
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, heading) {
			in = true
			continue
		}
		if in && strings.HasPrefix(l, "#") {
			if lvl := strings.Index(l, " "); lvl > 0 && lvl <= level {
				break
			}
		}
		if in {
			out = append(out, l)
		}
	}
	if !in {
		t.Fatalf("ADR-0011 sem a seção %q", heading)
	}
	return out
}

// adrTable returns the body rows of the first markdown table of a section, as trimmed cells (an escaped
// pipe inside a cell is kept).
func adrTable(t *testing.T, section []string, columns int) [][]string {
	t.Helper()
	var rows [][]string
	started := false
	for _, l := range section {
		if !strings.HasPrefix(l, "|") {
			if started {
				break
			}
			continue
		}
		started = true
		l = strings.ReplaceAll(l, `\|`, "\x00")
		cells := strings.Split(strings.Trim(l, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(cells[i], "\x00", "|"))
		}
		if len(cells) != columns {
			t.Fatalf("linha de tabela com %d colunas (esperado %d): %q", len(cells), columns, l)
		}
		if strings.HasPrefix(cells[0], "---") {
			continue
		}
		rows = append(rows, cells)
	}
	return rows[1:] // header
}

var backticked = regexp.MustCompile("`([^`]+)`")

// TestReasonClassADRTable: the line and the destination of every reason are those of the ADR table
// "Verificação no nó" (Decisão column), and every reason of the table exists in Go.
func TestReasonClassADRTable(t *testing.T) {
	rows := adrTable(t, adrSection(t, "### Verificação no nó"), 4)
	seen := map[RejectReason]bool{}
	for _, r := range rows {
		line, motive, decision := r[0], r[2], r[3]
		if motive == "—" {
			if line != "2a" {
				t.Errorf("linha sem motivo inesperada: %q", line)
			}
			continue
		}
		m := backticked.FindStringSubmatch(motive)
		if m == nil {
			t.Fatalf("motivo sem código: %q", motive)
		}
		reason := RejectReason(m[1])
		seen[reason] = true
		var class ReasonClass
		switch {
		case strings.Contains(decision, "sem ack"):
			class = ClassUnauthenticated
		case strings.Contains(decision, "`deferred`"):
			class = ClassDeferred
		case strings.Contains(decision, "`rejected`") && strings.Contains(decision, "não gravado"):
			class = ClassFinalNotRecorded
		case strings.Contains(decision, "`rejected`") && strings.Contains(decision, "final"):
			class = ClassFinalRecorded
		default:
			t.Fatalf("decisão não reconhecida para %s: %q", reason, decision)
		}
		if reason.Class() != class || reason.Line() != line {
			t.Errorf("%s: Go (linha %q, classe %d) != ADR (linha %q, classe %d)", reason, reason.Line(), reason.Class(), line, class)
		}
	}
	for _, r := range RejectReasons() {
		if !seen[r] {
			t.Errorf("%s não está na tabela do ADR", r)
		}
	}
	if len(seen) != len(RejectReasons()) {
		t.Errorf("tabela do ADR tem %d motivos, Go tem %d", len(seen), len(RejectReasons()))
	}
}

// TestReasonClassSchema: final_reason / deferred_reason of fleet-result.schema.json, the ack's if/then
// (rejected => final_reason, deferred => deferred_reason, accepted => no reason) and the three unauthenticated
// counters of audit_entry match the Go classification.
func TestReasonClassSchema(t *testing.T) {
	docs := loadSchemas(t)
	defs := docs["fleet-result.schema.json"].obj("$defs")
	var final, deferred, unauth, all []string
	for _, r := range RejectReasons() {
		all = append(all, string(r))
		switch r.Class() {
		case ClassFinalRecorded, ClassFinalNotRecorded:
			final = append(final, string(r))
		case ClassDeferred:
			deferred = append(deferred, string(r))
		case ClassUnauthenticated:
			unauth = append(unauth, string(r))
		}
	}
	check := func(name string, got, want []string) {
		if !slices.Equal(sortedCopy(got), sortedCopy(want)) {
			t.Errorf("%s: schema %v != Go %v", name, got, want)
		}
	}
	check("reject_reason", strList(defs.obj("reject_reason").arr("enum")), all)
	if !slices.Equal(strList(defs.obj("reject_reason").arr("enum")), all) {
		t.Errorf("RejectReasons() fora da ordem do enum do schema")
	}
	check("final_reason", strList(defs.obj("final_reason").arr("enum")), final)
	check("deferred_reason", strList(defs.obj("deferred_reason").arr("enum")), deferred)
	counters := docs["fleet-state.schema.json"].obj("$defs").obj("audit_entry").obj("properties").obj("unauthenticated")
	check("audit_entry.unauthenticated", slices.DeleteFunc(strList(counters.arr("required")), func(s string) bool { return s == "since" }), unauth)

	// ack: decision -> reason class
	for _, c := range defs.obj("ack").arr("allOf") {
		o := c.(*ordObj)
		decision := Decision(o.obj("if").obj("properties").obj("decision").str("const"))
		then := o.obj("then")
		switch decision {
		case DecisionAccepted:
			if strList(then.obj("not").arr("required"))[0] != "reason" {
				t.Errorf("ack accepted não proíbe reason")
			}
		case DecisionRejected, DecisionDeferred:
			ref := then.obj("properties").obj("reason").str("$ref")
			want := map[Decision]string{DecisionRejected: "#/$defs/final_reason", DecisionDeferred: "#/$defs/deferred_reason"}[decision]
			if ref != want || !slices.Contains(strList(then.arr("required")), "reason") {
				t.Errorf("ack %s: reason %q (obrigatório), esperado %q", decision, ref, want)
			}
		default:
			t.Errorf("decisão desconhecida no ack: %q", decision)
		}
	}
	for _, r := range RejectReasons() {
		d, ok := r.Decision()
		switch r.Class() {
		case ClassUnauthenticated:
			if ok {
				t.Errorf("%s não gera ack", r)
			}
		case ClassDeferred:
			if !ok || d != DecisionDeferred || r.Recorded() {
				t.Errorf("%s: deferred, não gravado", r)
			}
		case ClassFinalNotRecorded:
			if !ok || d != DecisionRejected || r.Recorded() {
				t.Errorf("%s: rejected final, não gravado", r)
			}
		case ClassFinalRecorded:
			if !ok || d != DecisionRejected || !r.Recorded() {
				t.Errorf("%s: rejected final, gravado", r)
			}
		}
		if !r.Valid() {
			t.Errorf("%s inválido", r)
		}
	}
	if RejectReason("x").Valid() || RejectReason("x").Class() != 0 {
		t.Error("motivo desconhecido")
	}
	if _, ok := RejectReason("x").Decision(); ok {
		t.Error("motivo desconhecido não tem decisão")
	}
}

// TestSameAck: the hub's idempotency key is (command_id, decision, reason) — received_at and detail do not count.
func TestSameAck(t *testing.T) {
	scope, rate := ReasonScopeDenied, ReasonRateLimited
	d1, d2 := "a", "b"
	a := Ack{SchemaVersion: "1.0.0", CommandID: "c1", NodeID: "n", Decision: DecisionRejected, Reason: &scope, Detail: &d1, ReceivedAt: "2026-10-11T12:00:00Z"}
	b := a
	b.ReceivedAt, b.Detail = "2026-10-11T12:05:00Z", &d2
	if !SameAck(a, b) {
		t.Error("outro received_at/detail é o mesmo ack (204)")
	}
	b.Reason = &rate
	if SameAck(a, b) {
		t.Error("outro motivo é outro ack (409)")
	}
	b.Reason, b.Decision = nil, DecisionAccepted
	if SameAck(a, b) {
		t.Error("outra decisão é outro ack")
	}
	c := Ack{CommandID: "c1", Decision: DecisionAccepted}
	if !SameAck(b, c) {
		t.Error("accepted sem reason nos dois")
	}
	c.CommandID = "c2"
	if SameAck(b, c) {
		t.Error("outro command_id")
	}
}
