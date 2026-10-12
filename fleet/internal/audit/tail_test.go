package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// entryRules are the value rules of fleet-state.schema.json#/$defs/audit_entry that DecodeStrict (structure only)
// does not check: the "entry_errors" half of the Python validator's audit_chain check.
func entryRules(e contract.AuditEntry) error {
	re := func(p string) *regexp.Regexp { return regexp.MustCompile(p) }
	ok := func(cond bool, what string) error {
		if !cond {
			return errors.New(what)
		}
		return nil
	}
	noControl := func(s string) bool { return utf8.ValidString(s) && !strings.ContainsFunc(s, isControl) }
	checks := []error{
		ok(e.Stream == contract.StreamExec || e.Stream == contract.StreamReject, "stream"),
		ok(e.Seq >= 1, "seq"),
		ok(re(contract.PatternUTCTime).MatchString(e.At), "at"),
		ok(re(contract.PatternSHA256Hex).MatchString(e.PrevSHA256), "prev_sha256"),
		ok(e.CommandID == nil || re(contract.PatternUUID).MatchString(*e.CommandID), "command_id"),
		ok(e.Type == nil || len(*e.Type) <= 64 && re(contract.PatternCommandTypeAny).MatchString(string(*e.Type)), "type"),
		ok(e.Tenant == nil || re(contract.PatternTenant).MatchString(*e.Tenant), "tenant"),
		ok(e.IssuedBy == nil || len(*e.IssuedBy) <= 128 && re(contract.PatternIssuedBy).MatchString(*e.IssuedBy), "issued_by"),
		ok(e.PayloadSHA256 == nil || re(contract.PatternSHA256Hex).MatchString(*e.PayloadSHA256), "payload_sha256"),
		ok(len(e.ObjectIDs) <= MaxObjectIDs, "object_ids maxItems"),
		ok(len(e.Hosts) <= MaxHosts, "hosts maxItems"),
		ok(e.HostsCount == nil || *e.HostsCount >= 0, "hosts_count"),
		ok(e.Status == nil || validStatuses[*e.Status], "status"),
		ok(e.ErrorCode == nil || validErrorCodes[*e.ErrorCode], "error_code"),
		ok(e.Detail == nil || utf8.RuneCountInString(*e.Detail) <= MaxDetailRunes && noControl(*e.Detail), "detail"),
		ok(e.Artifact == nil || e.Artifact.Size >= 1 && e.Artifact.Size <= maxArtifactSize, "artifact.size"),
		ok(e.Unauthenticated == nil || e.Unauthenticated.BadEnvelope >= 0 && e.Unauthenticated.PayloadMismatch >= 0 && e.Unauthenticated.BadSignature >= 0, "unauthenticated"),
		ok(e.Redelivered == nil || e.Redelivered.Count >= 1, "redelivered.count"),
	}
	seen := map[string]bool{}
	for _, id := range e.ObjectIDs {
		checks = append(checks, ok(!seen[id] && id != "" && utf8.RuneCountInString(id) <= maxIDRunes && noControl(id), "object_ids item"))
		seen[id] = true
	}
	for _, h := range e.Hosts {
		checks = append(checks, ok(len(h) >= 2 && len(h) <= 43 && re(contract.PatternIPOrCIDR).MatchString(h), "hosts item"))
	}
	if r := e.Report; r != nil {
		checks = append(checks,
			ok(re(contract.PatternUUID).MatchString(r.ReportID), "report.report_id"),
			ok(r.Format == nil || validFormats[*r.Format], "report.format"),
			ok(r.Lang == nil || validLangs[*r.Lang], "report.lang"),
			ok(r.Variant == nil || validVariants[*r.Variant], "report.variant"),
			ok(r.Filter == nil || *r.Filter != "" && utf8.RuneCountInString(*r.Filter) <= MaxFilterRunes && noControl(*r.Filter), "report.filter"),
			ok(r.MinQoD == nil || *r.MinQoD >= 0 && *r.MinQoD <= 100, "report.min_qod"),
			ok(r.Levels == nil || *r.Levels != "" && re(contract.PatternLevels).MatchString(*r.Levels), "report.levels"))
	}
	// allOf: o evento manda no fluxo; rejected/deferred levam o motivo da classe certa e só eles levam motivo; as
	// linhas de contagem e de versão levam o seu objeto
	execEvent := map[contract.AuditEvent]bool{contract.AuditEventConnectorStarted: true, contract.AuditEventIdentityChanged: true,
		contract.AuditEventPolicyChanged: true, contract.AuditEventReceived: true, contract.AuditEventExecuted: true, contract.AuditEventResult: true}
	checks = append(checks, ok(execEvent[e.Event] == (e.Stream == contract.StreamExec), "event × stream"))
	switch e.Event {
	case contract.AuditEventRejected:
		checks = append(checks, ok(e.Reason != nil && (e.Reason.Class() == contract.ClassFinalRecorded || e.Reason.Class() == contract.ClassFinalNotRecorded), "rejected.reason"))
	case contract.AuditEventDeferred:
		checks = append(checks, ok(e.Reason != nil && e.Reason.Class() == contract.ClassDeferred, "deferred.reason"))
	default:
		checks = append(checks, ok(e.Reason == nil, "reason fora de rejected/deferred"))
	}
	checks = append(checks,
		ok(e.Event != contract.AuditEventUnauthenticated || e.Unauthenticated != nil, "unauthenticated required"),
		ok(e.Event != contract.AuditEventRedelivered || e.Redelivered != nil, "redelivered required"),
		ok(e.Event != contract.AuditEventVersionMismatch || e.Versions != nil, "versions required"))
	return errors.Join(checks...)
}

// chainProblem is schema/examples/validate_fleet_examples.py's chain_problem in Go: "" when both streams of the
// audit_tail data chain the way the hub's witness rule checks them, else the JSON pointer of the first break. It
// also checks the string rules of the tail items and the members of an empty tail.
func chainProblem(d contract.DataAuditTail) string {
	for _, st := range []struct {
		name string
		tail contract.AuditStreamTail
	}{{"exec", d.Exec}, {"reject", d.Reject}} {
		tail := st.tail
		if tail.Lines == nil {
			return "/data/" + st.name + "/lines"
		}
		if len(tail.Lines) == 0 {
			if tail.FirstSeq != nil || tail.LastSeq != nil || tail.HeadSHA256 != nil {
				return "/data/" + st.name
			}
			continue
		}
		if len(tail.Lines) > TailLines || tail.FirstSeq == nil || tail.LastSeq == nil || tail.HeadSHA256 == nil {
			return "/data/" + st.name
		}
		prev := ""
		for i, line := range tail.Lines {
			ptr := fmt.Sprintf("/data/%s/lines/%d", st.name, i)
			var e contract.AuditEntry
			if len(line) < 2 || utf8.RuneCountInString(line) > MaxLineBytes || strings.ContainsFunc(line, isControl) ||
				contract.DecodeStrict([]byte(line), &e) != nil || entryRules(e) != nil ||
				string(e.Stream) != st.name || e.Seq != *tail.FirstSeq+int64(i) {
				return ptr
			}
			want := prev
			if i == 0 {
				want = e.PrevSHA256
				if *tail.FirstSeq == 1 {
					want = zeroSHA256
				}
			}
			if e.PrevSHA256 != want {
				return ptr
			}
			prev = sha(line)
		}
		if *tail.LastSeq != *tail.FirstSeq+int64(len(tail.Lines))-1 {
			return "/data/" + st.name + "/last_seq"
		}
		if *tail.HeadSHA256 != prev {
			return "/data/" + st.name + "/head_sha256"
		}
	}
	return ""
}

// O verificador em Go dá o mesmo veredito que o validador Python nos exemplos do contrato: as caudas válidas
// passam; a cadeia quebrada falha no mesmo ponteiro; a cauda vazia com seq falha; cada audit_entry inválido falha
// (na estrutura ou nas regras de valor) e cada válido passa.
func TestVerificadorDaCaudaConcordaComOValidador(t *testing.T) {
	tailOf := func(rel string) contract.DataAuditTail {
		var snap contract.StateSnapshot
		if err := contract.DecodeStrict(readExample(t, rel), &snap); err != nil {
			t.Fatal(err)
		}
		var d contract.DataAuditTail
		if err := contract.DecodeStrict(snap.Data, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for rel, want := range map[string]string{
		"valid/state/audit-tail.json":                         "",
		"valid/state/audit-tail-empty-reject-stream.json":     "",
		"invalid/state/audit-tail-broken-chain.json":          "/data/exec/lines/4",
		"invalid/state/audit-tail-empty-stream-with-seq.json": "/data/reject",
	} {
		if got := chainProblem(tailOf(rel)); got != want {
			t.Errorf("%s: %q, o validador diz %q", rel, got, want)
		}
	}
	for _, kind := range []string{"valid", "invalid"} {
		files, err := filepath.Glob(filepath.Join(examplesDir, kind, "state", "audit_entry--*.json"))
		if err != nil || len(files) < 10 {
			t.Fatalf("%s: %d exemplos, %v", kind, len(files), err)
		}
		for _, f := range files {
			var e contract.AuditEntry
			err := contract.DecodeStrict(readExample(t, kind+"/state/"+filepath.Base(f)), &e)
			if err == nil {
				err = entryRules(e)
			}
			if (err == nil) != (kind == "valid") {
				t.Errorf("%s/%s: %v", kind, filepath.Base(f), err)
			}
		}
	}
}

// replayExamples feeds a fresh Log, opened at 12:00:00, with the events of the contract's audit_tail examples:
// exec always; reject only when withReject (the other example has an empty reject stream). The calls follow the
// verification clock (never backwards).
func replayExamples(t *testing.T, withReject bool) *Log {
	t.Helper()
	l, _ := openAt(t, t.TempDir(), defaultConfig())
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	taskStart := Ref{CommandID: "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18", Type: contract.TypeTaskStart, Tenant: "acme"}
	export := Ref{CommandID: "256235c9-3661-4e57-b4f3-bbfe17ecb23d", Type: contract.TypeReportExport, Tenant: "acme"}
	report := "4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04"
	task := "2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"
	if withReject {
		must(l.Unauthenticated(at(t, "2026-10-11T12:00:10Z"), contract.ReasonBadEnvelope))
		must(l.Unauthenticated(at(t, "2026-10-11T12:00:20Z"), contract.ReasonBadSignature))
		must(l.Redelivered(at(t, "2026-10-11T12:00:30Z")))
		must(l.Redelivered(at(t, "2026-10-11T12:00:40Z")))
	}
	must(l.ConnectorStarted(at(t, "2026-10-11T12:01:00Z"), "connector 1.0.0 (central)"))
	if withReject {
		must(l.Rejected(at(t, "2026-10-11T12:01:00Z"), Command{
			Ref:           Ref{CommandID: "9c292f96-3ec0-4dc9-9cba-fe75f2560c8b", Type: contract.TypeTargetCreate, Tenant: "acme"},
			IssuedBy:      "op-7f3a",
			PayloadSHA256: "a9a4d1759628b5708691988ce1512e3cbfa6881f90dfc0000d3fea08edcb7d74",
			Hosts:         []string{"198.51.100.0/24"},
		}, contract.ReasonScopeDenied, "198.51.100.0/24 fora do escopo do tenant"))
	}
	must(l.Received(at(t, "2026-10-11T12:02:00Z"), Command{Ref: taskStart, IssuedBy: "op-7f3a",
		PayloadSHA256: "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f", ObjectIDs: []string{task}}))
	if withReject {
		must(l.Deferred(at(t, "2026-10-11T12:02:00Z"), Command{
			Ref:           Ref{CommandID: "fb698477-2b44-4d52-9204-20ba4ebaaa7d", Type: contract.TypeTaskStop, Tenant: "acme"},
			IssuedBy:      "op-7f3a",
			PayloadSHA256: "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f",
			ObjectIDs:     []string{task},
		}, contract.ReasonNotYetValid, ""))
	}
	must(l.Executed(at(t, "2026-10-11T12:03:00Z"), taskStart))
	if withReject {
		// a 3ª recusa não autenticada chega às 12:03, um minuto depois do Open: a contagem do período vai para o fluxo
		must(l.Unauthenticated(at(t, "2026-10-11T12:03:00Z"), contract.ReasonBadSignature))
	}
	must(l.Result(at(t, "2026-10-11T12:04:00Z"), taskStart, Outcome{Status: contract.StatusSucceeded,
		ObjectIDs: []string{task, "e2a4c6e8-0b1d-4f3a-9c5e-7a9b1d3f5e06"}}))
	if withReject {
		must(l.VersionMismatch(at(t, "2026-10-11T12:04:00Z"), []string{"1.0"}, []string{"2.0"}))
	}
	must(l.Received(at(t, "2026-10-11T12:05:00Z"), Command{Ref: export, IssuedBy: "op-7f3a",
		PayloadSHA256: "554cc1ab7d04f934b5b052dfd3bbf9206a2dedc44383ed27bad722804e756ab5", ObjectIDs: []string{report},
		Report: &contract.AuditReport{ReportID: report, Format: ptr(contract.FormatSuricatoosPDF), Lang: ptr(contract.LangPTBR),
			Variant: ptr(contract.VariantTechnical), Filter: ptr("apply_overrides=1 min_qod=70 levels=chml rows=-1")}}))
	if withReject {
		must(l.Flush(at(t, "2026-10-11T12:05:00Z"))) // as duas reentregas do período saem no Flush
	}
	must(l.Executed(at(t, "2026-10-11T12:06:00Z"), export))
	must(l.Result(at(t, "2026-10-11T12:07:00Z"), export, Outcome{Status: contract.StatusSucceeded,
		Artifact: &contract.AuditArtifact{SHA256: "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f", Size: 812345}}))
	return l
}

// A cauda reproduz byte a byte os dois exemplos audit_tail do contrato (o "data" inteiro, logo também o
// content_sha256) quando o Log recebe os mesmos eventos, e cada exemplo audit_entry--*.json é uma das suas linhas.
func TestCaudaReproduzOsExemplos(t *testing.T) {
	var lines []string
	for _, c := range []struct {
		file       string
		withReject bool
	}{{"valid/state/audit-tail.json", true}, {"valid/state/audit-tail-empty-reject-stream.json", false}} {
		var snap contract.StateSnapshot
		if err := contract.DecodeStrict(readExample(t, c.file), &snap); err != nil {
			t.Fatal(err)
		}
		tail := replayExamples(t, c.withReject).Tail()
		got, err := contract.MarshalCompact(tail)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, snap.Data) {
			t.Fatalf("%s: a cauda divergiu\n got %s\nwant %s", c.file, got, snap.Data)
		}
		if sha(string(got)) != snap.ContentSHA256 {
			t.Fatalf("%s: content_sha256", c.file)
		}
		if p := chainProblem(tail); p != "" {
			t.Fatalf("%s: cadeia quebrada em %s", c.file, p)
		}
		lines = append(append(lines, tail.Exec.Lines...), tail.Reject.Lines...)
	}
	files, err := filepath.Glob(filepath.Join(examplesDir, "valid", "state", "audit_entry--*.json"))
	if err != nil || len(files) != 10 {
		t.Fatalf("%d exemplos audit_entry, %v", len(files), err)
	}
	for _, f := range files {
		raw := readExample(t, "valid/state/"+filepath.Base(f))
		if !slices.Contains(lines, string(raw)) {
			t.Errorf("%s não é uma das linhas da cauda gerada", filepath.Base(f))
		}
	}
}

// Uma cauda gerada — com rotação, mais de 200 linhas, contagens, adiamentos, rejeições e resultados — passa nas
// mesmas regras do validador Python (cadeia, seq, head_sha256, cada linha um audit_entry), decodifica como
// contract.DataAuditTail e tem só as últimas 200 linhas de cada fluxo, iguais às do disco.
func TestCaudaPassaNasRegrasDoValidador(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.exec.maxBytes, cfg.reject.maxBytes = 16<<10, 64<<10
	l, _ := openAt(t, dir, cfg)
	c := validCommand()
	for i := range 130 {
		now := testBoot.Add(time.Duration(i) * 20 * time.Second)
		c.CommandID = fmt.Sprintf("6f1c2a9e-3b7d-4c8a-9e21-%012x", i)
		c.Hosts = []string{"198.51.100." + strconv.Itoa(i%250)}
		for _, err := range []error{
			l.Received(now, c),
			l.Executed(now, c.Ref),
			l.Result(now, c.Ref, Outcome{Status: contract.StatusSucceeded, ObjectIDs: []string{"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}}),
			l.Rejected(now, c, contract.ReasonScopeDenied, "fora do escopo"),
			l.Deferred(now, c, contract.ReasonUnavailable, ""),
			l.Unauthenticated(now, contract.ReasonBadSignature),
			l.Redelivered(now),
			l.VersionMismatch(now, []string{"1.0"}, []string{"2.0"}),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	tail := l.Tail()
	if p := chainProblem(tail); p != "" {
		t.Fatalf("cadeia quebrada em %s", p)
	}
	b, err := contract.MarshalCompact(tail)
	if err != nil {
		t.Fatal(err)
	}
	var back contract.DataAuditTail
	if err := contract.DecodeStrict(b, &back); err != nil {
		t.Fatalf("a cauda não decodifica como data_audit_tail: %v", err)
	}
	for _, s := range []struct {
		spec streamSpec
		tail contract.AuditStreamTail
	}{{cfg.exec, tail.Exec}, {cfg.reject, tail.Reject}} {
		disk := allLines(t, dir, s.spec)
		if len(streamFiles(t, dir, s.spec.file)) < 2 {
			t.Fatalf("%s não girou: o teste não cobre a cauda através dos arquivos", s.spec.name)
		}
		if want := disk[max(0, len(disk)-TailLines):]; !slices.Equal(s.tail.Lines, want) || len(want) != TailLines {
			t.Fatalf("%s: a cauda não são as últimas %d linhas do disco (%d na cauda)", s.spec.name, TailLines, len(s.tail.Lines))
		}
	}
	// depois de um reinício a cauda refeita dos arquivos é a mesma, byte a byte
	l2, _ := openAt(t, dir, cfg)
	again, err := contract.MarshalCompact(l2.Tail())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, b) {
		t.Fatal("a cauda refeita no boot difere da que estava na memória")
	}
}

func TestCaudaDeFluxoVazio(t *testing.T) {
	l, _ := openAt(t, t.TempDir(), defaultConfig())
	b, err := contract.MarshalCompact(l.Tail())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"exec":{"lines":[]},"reject":{"lines":[]}}` {
		t.Fatalf("cauda vazia: %s", b)
	}
}

// A cauda sai da memória: só linhas confirmadas. Depois de uma gravação que falhou ela não muda, e um reinício
// a refaz a partir dos arquivos (o mesmo conteúdo).
func TestCaudaSoTemLinhasConfirmadas(t *testing.T) {
	dir := t.TempDir()
	fl := &faults{}
	l, _ := openAt(t, dir, testConfig(fl.ops()))
	for i := 1; i <= 3; i++ {
		policyChanged(t, l, i)
	}
	before := l.Tail()
	fl.failSync = errors.New("EIO simulado")
	if err := l.PolicyChanged(testBoot, "não confirmada"); err == nil {
		t.Fatal("esperava erro")
	}
	if got := l.Tail(); !slices.Equal(got.Exec.Lines, before.Exec.Lines) || *got.Exec.LastSeq != 3 {
		t.Fatalf("a cauda mudou com uma linha não confirmada: %v", got.Exec.Lines)
	}
	fl.failSync, fl.failWrite, fl.failTruncate = nil, errors.New("EIO"), errors.New("EIO no corte")
	if err := l.PolicyChanged(testBoot, "envenena"); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("esperava ErrPoisoned, deu %v", err)
	}
	if got := l.Tail(); !slices.Equal(got.Exec.Lines, before.Exec.Lines) {
		t.Fatal("a cauda de um fluxo envenenado mostra o que não foi confirmado")
	}
	if err := os.Truncate(filepath.Join(dir, ExecFileName), l.exec.size); err != nil { // o operador limpa a meia linha
		t.Fatal(err)
	}
	l2, _ := openAt(t, dir, defaultConfig())
	if got := l2.Tail(); !slices.Equal(got.Exec.Lines, before.Exec.Lines) {
		t.Fatal("o reinício refez outra cauda")
	}
}

// Conteúdo que não é auditoria no lugar de um arquivo da auditoria — a sonda da revisão: um arquivo no formato PEM
// (fictício) — nunca chega à cauda, que vai ao hub: o boot expõe as quebras e a cauda recomeça depois da última
// linha que não é linha de auditoria deste fluxo. Vale também para JSON que tem os campos da cadeia mas não é um
// audit_entry (membro desconhecido) e para a linha do outro fluxo.
func TestCaudaNuncaLevaLinhaQueNaoEAuditoriaDoFluxo(t *testing.T) {
	pem := []string{
		"-----BEGIN CERTIFICATE-----",
		"TUlJQmZpY3RpY2lvLXNvLXBhcmEtby10ZXN0ZS1kYS1hdWRpdG9yaWE=",
		"-----END CERTIFICATE-----",
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ExecFileName), []byte(strings.Join(pem, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _ := openAt(t, dir, defaultConfig())
	st := l.Status().Exec
	if st.Recovery.Breaks != len(pem) || st.Seq != int64(len(pem)) {
		t.Fatalf("recovery %+v, seq %d", st.Recovery, st.Seq)
	}
	if tail := l.Tail().Exec; len(tail.Lines) != 0 || tail.FirstSeq != nil {
		t.Fatalf("a cauda levou %d linhas que não são auditoria: %q", len(tail.Lines), tail.Lines)
	}
	policyChanged(t, l, 1) // segue da última linha (seq 3): o hub vê first_seq 4 e a lacuna
	if tail := l.Tail().Exec; len(tail.Lines) != 1 || *tail.FirstSeq != 4 {
		t.Fatalf("depois de uma linha nova: %d linhas, first_seq %v", len(tail.Lines), tail.FirstSeq)
	}

	// JSON com os campos da cadeia, mas com um membro que o audit_entry não tem, e uma linha do outro fluxo
	dir = t.TempDir()
	l, _ = openAt(t, dir, defaultConfig())
	for i := 1; i <= 3; i++ {
		policyChanged(t, l, i)
	}
	path := filepath.Join(dir, ExecFileName)
	lines := fileLines(t, path)
	forged := strings.Replace(lines[2], `"event":"policy_changed"`, `"event":"policy_changed","segredo":"de outro arquivo"`, 1)
	rewriteLine(t, path, 2, forged)
	l2, _ := openAt(t, dir, defaultConfig())
	for _, line := range l2.Tail().Exec.Lines {
		if strings.Contains(line, "segredo") {
			t.Fatal("uma linha que não decodifica como audit_entry chegou à cauda")
		}
	}
	// e o contrário: a forma do audit_entry, mas um campo da cadeia que não é (prev_sha256 que não é hexadecimal)
	rewriteLine(t, path, 2, strings.Replace(lines[2], `"prev_sha256":"`, `"prev_sha256":"nao-e-hex-`, 1))
	l2, _ = openAt(t, dir, defaultConfig())
	for _, line := range l2.Tail().Exec.Lines {
		if strings.Contains(line, "nao-e-hex") {
			t.Fatal("uma linha cujos campos da cadeia não valem chegou à cauda")
		}
	}
	other := filepath.Join(dir, RejectFileName)
	if err := os.WriteFile(other, []byte(lines[0]+"\n"), 0o600); err != nil { // uma linha do exec no reject
		t.Fatal(err)
	}
	l3, _ := openAt(t, dir, defaultConfig())
	if tail := l3.Tail().Reject; len(tail.Lines) != 0 {
		t.Fatalf("uma linha do outro fluxo chegou à cauda do reject: %q", tail.Lines)
	}
	if l3.Status().Reject.Recovery.Breaks != 1 {
		t.Fatalf("a linha do outro fluxo é quebra: %+v", l3.Status().Reject.Recovery)
	}
}

// Uma linha que a cauda não pode carregar como é (aqui, com um caractere que o no_control recusa) faz a cauda
// recomeçar depois dela: o hub vê a lacuna de seq e alerta, em vez de receber um estado inválido inteiro.
func TestCaudaRecomecaDepoisDeLinhaQueNaoCabe(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	for i := 1; i <= 5; i++ {
		policyChanged(t, l, i)
	}
	path := filepath.Join(dir, ExecFileName)
	lines := fileLines(t, path)
	rewriteLine(t, path, 2, strings.Replace(lines[2], "linha 3", "linha "+string(rune(0xfffe)), 1))
	l2, _ := openAt(t, dir, defaultConfig())
	tail := l2.Tail().Exec
	if len(tail.Lines) != 2 || *tail.FirstSeq != 4 || *tail.LastSeq != 5 {
		t.Fatalf("a cauda devia recomeçar na seq 4: %d linhas, de %v", len(tail.Lines), tail.FirstSeq)
	}
	if l2.Status().Exec.Recovery.Breaks == 0 {
		t.Fatal("a linha alterada também quebra a cadeia")
	}
}
