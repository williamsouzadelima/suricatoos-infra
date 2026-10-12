package state

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
)

// audit_tail é o audit.Tail() verbatim: as linhas saem byte a byte como estão nos arquivos da auditoria local.
func TestAuditTailVerbatimDaAuditoriaLocal(t *testing.T) {
	dir := t.TempDir()
	log, err := audit.Open(dir, at, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.ConnectorStarted(at, `conector 1.0.0 "central" <lab> & ção`); err != nil {
		t.Fatal(err)
	}
	if err := log.PolicyChanged(at.Add(time.Second), "policy_sha256="+sha([]byte("p"))); err != nil {
		t.Fatal(err)
	}
	cmd := audit.Command{Ref: audit.Ref{CommandID: uuidTask1, Type: contract.TypeTaskStart, Tenant: "acme"},
		IssuedBy: "operador-1", PayloadSHA256: sha([]byte("payload"))}
	if err := log.Rejected(at.Add(2*time.Second), cmd, contract.ReasonReplay, "cache reiniciado"); err != nil {
		t.Fatal(err)
	}
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	cfg.Audit = log
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	got := current(t, c, contract.KindAuditTail).(*contract.DataAuditTail)
	for name, stream := range map[string]contract.AuditStreamTail{audit.ExecFileName: got.Exec, audit.RejectFileName: got.Reject} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if !slices.Equal(stream.Lines, lines) {
			t.Errorf("%s: linhas %q, arquivo %q", name, stream.Lines, lines)
		}
		last := lines[len(lines)-1]
		if stream.HeadSHA256 == nil || *stream.HeadSHA256 != sha([]byte(last)) || *stream.FirstSeq != 1 ||
			*stream.LastSeq != int64(len(lines)) {
			t.Errorf("%s: cabeça %+v", name, stream)
		}
	}
	if want := log.Tail(); !equalTail(got, &want) {
		t.Fatal("o data não é o Tail() verbatim")
	}
}

func equalTail(a *contract.DataAuditTail, b *contract.DataAuditTail) bool {
	x, err1 := contract.MarshalCompact(a)
	y, err2 := contract.MarshalCompact(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func TestAuditTailVazio(t *testing.T) {
	f := newFakes()
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindAuditTail).(*contract.DataAuditTail)
	if len(got.Exec.Lines) != 0 || got.Exec.FirstSeq != nil || len(got.Reject.Lines) != 0 || got.Reject.HeadSHA256 != nil {
		t.Fatalf("tail %+v", got)
	}
	f.audit.tail = contract.DataAuditTail{} // linhas nil: saem como lista vazia, nunca null
	got = current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindAuditTail).(*contract.DataAuditTail)
	if got.Exec.Lines == nil || len(got.Exec.Lines) != 0 {
		t.Fatalf("tail %+v", got)
	}
}

// Uma cauda que o schema (ou a própria cadeia) recusaria não sai: o kind falha e mantém o último retrato.
func TestAuditTailIncoerenteNuncaSai(t *testing.T) {
	line := `{"stream":"exec","seq":1,"at":"2026-10-11T12:00:00Z","event":"connector_started","prev_sha256":"` + strings.Repeat("0", 64) + `"}`
	good := func() contract.AuditStreamTail {
		return contract.AuditStreamTail{Lines: []string{line}, FirstSeq: i64p(1), LastSeq: i64p(1), HeadSHA256: strp(sha([]byte(line)))}
	}
	empty := contract.AuditStreamTail{Lines: []string{}}
	many := good()
	for range maxAuditLines {
		many.Lines = append(many.Lines, line)
	}
	bad := map[string]contract.AuditStreamTail{
		"cabeça que não é a da última linha": func() contract.AuditStreamTail { s := good(); s.HeadSHA256 = strp(sha([]byte("x"))); return s }(),
		"linhas sem seq":                    {Lines: []string{line}},
		"seq sem linhas":                    {Lines: []string{}, FirstSeq: i64p(1)},
		"último antes do primeiro":          func() contract.AuditStreamTail { s := good(); s.FirstSeq = i64p(2); return s }(),
		"seq zero":                          func() contract.AuditStreamTail { s := good(); s.FirstSeq, s.LastSeq = i64p(0), i64p(0); return s }(),
		"mais de 200 linhas":                many,
		"linha com controle":                func() contract.AuditStreamTail { s := good(); s.Lines = []string{line + "\x01"}; return s }(),
		"linha curta":                       {Lines: []string{"{"}, FirstSeq: i64p(1), LastSeq: i64p(1), HeadSHA256: strp(sha([]byte("{")))},
	}
	for name, stream := range bad {
		f := newFakes()
		f.audit.tail = contract.DataAuditTail{Exec: good(), Reject: empty}
		c := collectOnce(t, f, contract.NodeStandalone)
		before, ok := c.Current(contract.KindAuditTail)
		if !ok {
			t.Fatalf("%s: sem o retrato bom de antes", name)
		}
		f.audit.tail = contract.DataAuditTail{Exec: stream, Reject: empty}
		c.Collect(context.Background())
		if after, _ := c.Current(contract.KindAuditTail); !bytes.Equal(after.Data, before.Data) || c.Errors()[contract.KindAuditTail] == nil {
			t.Errorf("%s: a cauda incoerente saiu ou o erro não apareceu", name)
		}
	}
}
