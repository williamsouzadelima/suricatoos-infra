package audit

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

type member struct {
	name, opts string
	typ        reflect.Type
}

func members(typ reflect.Type) []member {
	var out []member
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		out = append(out, member{name, opts, f.Type})
	}
	return out
}

// A linha gravada é o contract.AuditEntry membro a membro — mesmos nomes JSON, mesmos tipos Go, mesmas opções —,
// só que na ordem dos exemplos do contrato: status e error_code logo depois de payload_sha256 (no struct do
// contrato eles vêm depois de artifact e reason, e os exemplos de result não sairiam byte a byte).
func TestEntryEspelhaOContratoNaOrdemDosExemplos(t *testing.T) {
	got, contractOrder := members(reflect.TypeOf(entry{})), members(reflect.TypeOf(contract.AuditEntry{}))
	byName := func(name string) member {
		for _, m := range contractOrder {
			if m.name == name {
				return m
			}
		}
		t.Fatalf("o contract.AuditEntry não tem %q", name)
		return member{}
	}
	var want []member
	for _, m := range contractOrder {
		if m.name == "status" || m.name == "error_code" {
			continue
		}
		want = append(want, m)
		if m.name == "payload_sha256" {
			want = append(want, byName("status"), byName("error_code"))
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("o espelho divergiu do contrato:\n got %v\nwant %v", got, want)
	}
}

// fromExample builds, from the fields of an example line, the same line through the builders the Log uses — the
// inputs of the public API, not a conversion of the contract type — with the seq and prev_sha256 of the example.
func fromExample(t *testing.T, ex contract.AuditEntry) *entry {
	t.Helper()
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	ref := Ref{CommandID: deref(ex.CommandID), Tenant: deref(ex.Tenant)}
	if ex.Type != nil {
		ref.Type = *ex.Type
	}
	cmd := Command{Ref: ref, IssuedBy: deref(ex.IssuedBy), PayloadSHA256: deref(ex.PayloadSHA256), ObjectIDs: ex.ObjectIDs, Report: ex.Report}
	if ex.HostsCount != nil {
		if int(*ex.HostsCount) != len(ex.Hosts) {
			t.Fatalf("exemplo com mais hosts do que lista: o teste precisaria inventá-los")
		}
		cmd.Hosts = ex.Hosts
	}
	var reason contract.RejectReason
	if ex.Reason != nil {
		reason = *ex.Reason
	}
	var (
		e   *entry
		err error
	)
	switch ex.Event {
	case contract.AuditEventConnectorStarted, contract.AuditEventIdentityChanged, contract.AuditEventPolicyChanged:
		e = newLifecycle(ex.At, ex.Event, deref(ex.Detail))
	case contract.AuditEventReceived:
		e, err = newReceived(ex.At, cmd)
	case contract.AuditEventExecuted:
		e, err = newExecuted(ex.At, ref)
	case contract.AuditEventResult:
		o := Outcome{Status: *ex.Status, ObjectIDs: ex.ObjectIDs, Artifact: ex.Artifact, Detail: deref(ex.Detail)}
		if ex.ErrorCode != nil {
			o.ErrorCode = *ex.ErrorCode
		}
		e, err = newResult(ex.At, ref, o)
	case contract.AuditEventRejected:
		e, err = newRejected(ex.At, cmd, reason, deref(ex.Detail))
	case contract.AuditEventDeferred:
		e, err = newDeferred(ex.At, cmd, reason, deref(ex.Detail))
	case contract.AuditEventUnauthenticated:
		e = newUnauthenticated(ex.At, *ex.Unauthenticated)
	case contract.AuditEventRedelivered:
		e = newRedelivered(ex.At, *ex.Redelivered)
	case contract.AuditEventVersionMismatch:
		e, err = newVersionMismatch(ex.At, ex.Versions.Node, ex.Versions.Hub)
	default:
		t.Fatalf("evento %q sem construtor", ex.Event)
	}
	if err != nil {
		t.Fatalf("%s: %v", ex.Event, err)
	}
	if e.Stream != ex.Stream {
		t.Fatalf("%s: o construtor pôs a linha no fluxo %q, o exemplo está no %q", ex.Event, e.Stream, ex.Stream)
	}
	e.Seq, e.PrevSHA256 = ex.Seq, ex.PrevSHA256
	return e
}

// Cada exemplo audit_entry--*.json sai byte a byte quando os construtores recebem os mesmos campos. A reprodução
// encadeada (o Log gravando as linhas em sequência e a cauda inteira) é TestCaudaReproduzOsExemplos.
func TestLinhaReproduzCadaExemploAPartirDosCampos(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(examplesDir, "valid", "state", "audit_entry--*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 10 {
		t.Fatalf("esperava os 10 exemplos audit_entry--*.json, achei %d", len(files))
	}
	for _, f := range files {
		raw := readExample(t, filepath.ToSlash(filepath.Join("valid", "state", filepath.Base(f))))
		var ex contract.AuditEntry
		if err := contract.DecodeStrict(raw, &ex); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		got, err := encode(fromExample(t, ex))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s divergiu:\n got %s\nwant %s", filepath.Base(f), got, raw)
		}
	}
}

func validCommand() Command {
	return Command{
		Ref:           Ref{CommandID: "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18", Type: contract.TypeTaskStart, Tenant: "acme"},
		IssuedBy:      "op-7f3a",
		PayloadSHA256: "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f",
	}
}

const testAt = "2026-10-11T12:00:00Z"

// object_ids: no máximo 17 ids DISTINTOS (o schema pede uniqueItems), na ordem em que vieram; um id repetido não
// conta duas vezes, e o 18º distinto é erro do chamador (nenhum comando v1 tem mais que 17).
func TestObjectIDsSemRepeticaoEAte17(t *testing.T) {
	ids := []string{"b", "a", "b", "c", "a"}
	c := validCommand()
	c.ObjectIDs = ids
	e, err := newReceived(testAt, c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.ObjectIDs, []string{"b", "a", "c"}) {
		t.Fatalf("object_ids %v", e.ObjectIDs)
	}
	if !slices.Equal(ids, []string{"b", "a", "b", "c", "a"}) {
		t.Fatal("a entrada do chamador não pode mudar")
	}
	var many []string
	for i := range MaxObjectIDs {
		many = append(many, strings.Repeat("x", i+1))
	}
	c.ObjectIDs = slices.Concat(many, many[:1]) // 17 distintos e um repetido
	if _, err := newReceived(testAt, c); err != nil {
		t.Fatalf("17 distintos: %v", err)
	}
	c.ObjectIDs = slices.Concat(many, []string{"outro"})
	if _, err := newReceived(testAt, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("18 distintos: esperava ErrInvalid, deu %v", err)
	}
	for name, id := range map[string]string{
		"vazio":           "",
		"129 caracteres":  strings.Repeat("a", 129),
		"quebra de linha": "a\nb",
		"DEL":             "a\x7fb",
		"U+FFFE":          "a" + string(rune(0xfffe)),
		"UTF-8 inválido":  "a\xffb",
	} {
		c.ObjectIDs = []string{id}
		if _, err := newReceived(testAt, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: esperava ErrInvalid, deu %v", name, err)
		}
	}
	c.ObjectIDs = []string{strings.Repeat(string(rune(0x1d11e)), 128)} // 128 caracteres de 4 bytes
	if _, err := newReceived(testAt, c); err != nil {
		t.Fatalf("128 caracteres (não bytes) é o teto: %v", err)
	}
}

// hosts: a linha guarda os primeiros 64 e o total em hosts_count; sem hosts, nenhum dos dois membros.
func TestHostsGuardaOsPrimeiros64EOTotal(t *testing.T) {
	var hosts []string
	for i := range 100 {
		hosts = append(hosts, "198.51.100."+strings.Repeat("1", 1+i%3))
	}
	for _, n := range []int{100, 65, 64, 1} {
		c := validCommand()
		c.Hosts = hosts[:n]
		e, err := newReceived(testAt, c)
		if err != nil {
			t.Fatal(err)
		}
		if want := min(n, MaxHosts); len(e.Hosts) != want || !slices.Equal(e.Hosts, hosts[:want]) {
			t.Errorf("%d hosts: a linha guardou %d", n, len(e.Hosts))
		}
		if e.HostsCount == nil || *e.HostsCount != int64(n) {
			t.Errorf("%d hosts: hosts_count %v", n, e.HostsCount)
		}
	}
	e, err := newReceived(testAt, validCommand())
	if err != nil || e.Hosts != nil || e.HostsCount != nil {
		t.Fatalf("sem hosts: %v %v %v", e.Hosts, e.HostsCount, err)
	}
	for _, h := range []string{"exemplo.local", "1", "198.51.100.0/24\n", strings.Repeat("1", 44)} {
		c := validCommand()
		c.Hosts = []string{"198.51.100.1", h}
		if _, err := newReceived(testAt, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("host %q: esperava ErrInvalid, deu %v", h, err)
		}
	}
}

// detail é texto do conector (pode vir de uma mensagem de erro do gvmd): sai cortado em 256 caracteres, com cada
// caractere de controle (e U+FFFE/U+FFFF) trocado por espaço e UTF-8 inválido trocado por U+FFFD, porque a linha
// tem de caber no no_control do schema. Vazio não vira membro.
func TestDetailCortadoESemCaractereDeControle(t *testing.T) {
	long := strings.Repeat("é", 300)
	e := newLifecycle(testAt, contract.AuditEventConnectorStarted, long)
	if e.Detail == nil || utf8.RuneCountInString(*e.Detail) != MaxDetailRunes || *e.Detail != strings.Repeat("é", MaxDetailRunes) {
		t.Fatalf("detail de 300 caracteres virou %v", e.Detail)
	}
	dirty := "linha 1\nlinha 2\ttab\x7fdel" + string(rune(0xfffe)) + "fim\xff"
	e = newLifecycle(testAt, contract.AuditEventPolicyChanged, dirty)
	want := "linha 1 linha 2 tab del fim" + string(utf8.RuneError)
	if e.Detail == nil || *e.Detail != want {
		t.Fatalf("detail limpo: %v, esperava %q", e.Detail, want)
	}
	if e := newLifecycle(testAt, contract.AuditEventIdentityChanged, ""); e.Detail != nil {
		t.Fatal("detail vazio não pode virar membro")
	}
}

// O filtro do report.export é cortado em 1024 caracteres (o teto do gmp_filter); caractere de controle nele é erro
// do chamador (o payload validado nunca o traz).
func TestFiltroDoRelatorioCortadoEm1024(t *testing.T) {
	c := validCommand()
	c.Type = contract.TypeReportExport
	c.Report = &contract.AuditReport{ReportID: "4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04", Filter: ptr(strings.Repeat("ç", 2000))}
	e, err := newReceived(testAt, c)
	if err != nil {
		t.Fatal(err)
	}
	if got := utf8.RuneCountInString(*e.Report.Filter); got != MaxFilterRunes {
		t.Fatalf("filtro com %d caracteres", got)
	}
	if utf8.RuneCountInString(*c.Report.Filter) != 2000 {
		t.Fatal("o relatório do chamador não pode mudar")
	}
	c.Report.Filter = ptr("levels=hml\nrows=-1")
	if _, err := newReceived(testAt, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("filtro com quebra de linha: esperava ErrInvalid, deu %v", err)
	}
}

// lineOfSize builds a received line whose encoding has exactly n bytes, with 17 distinct object ids: a letter of
// its own followed by a filler of 1- to 4-byte characters (each id within the 128-character cap).
func lineOfSize(t *testing.T, n int) *entry {
	t.Helper()
	const maxFiller = 507 // 126 characters of 4 bytes + one of 3: with the letter, 128 characters
	build := func(fillers []int) *entry {
		c := validCommand()
		for i, b := range fillers {
			var id strings.Builder
			id.WriteByte(byte('A' + i))
			for range b / 4 {
				id.WriteRune(0x1d11e) // 4 bytes
			}
			switch b % 4 {
			case 1:
				id.WriteByte('a')
			case 2:
				id.WriteRune('ç')
			case 3:
				id.WriteRune('€')
			}
			c.ObjectIDs = append(c.ObjectIDs, id.String())
		}
		e, err := newReceived(testAt, c)
		if err != nil {
			t.Fatal(err)
		}
		e.Stream, e.Seq, e.PrevSHA256 = contract.StreamExec, 1, zeroSHA256
		return e
	}
	fillers := make([]int, MaxObjectIDs)
	b, err := encode(build(fillers))
	if err != nil {
		t.Fatal(err)
	}
	missing := n - len(b)
	for i := range fillers {
		grow := min(missing, maxFiller)
		fillers[i] += grow
		missing -= grow
	}
	if missing != 0 {
		t.Fatalf("não dá para montar uma linha de %d bytes", n)
	}
	return build(fillers)
}

// A linha tem teto de 8 KiB; com todo campo limitado ela ainda pode passar (17 ids de 128 caracteres de 4 bytes),
// e aí é erro do chamador — nunca uma linha cortada no meio do JSON.
func TestLinhaAcimaDe8KiBEErroDoChamador(t *testing.T) {
	e := lineOfSize(t, MaxLineBytes)
	b, err := encode(e)
	if err != nil || len(b) != MaxLineBytes {
		t.Fatalf("linha de exatamente %d bytes: %d, %v", MaxLineBytes, len(b), err)
	}
	if _, err := encode(lineOfSize(t, MaxLineBytes+1)); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("linha de %d bytes: esperava ErrLineTooLong, deu %v", MaxLineBytes+1, err)
	}
}

// Cada entrada fora do contrato é erro do chamador (ErrInvalid) e nada é montado.
func TestEntradaForaDoContratoEErro(t *testing.T) {
	report := func(mut func(*contract.AuditReport)) Command {
		c := validCommand()
		c.Type = contract.TypeReportExport
		r := contract.AuditReport{ReportID: "4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04"}
		mut(&r)
		c.Report = &r
		return c
	}
	commands := map[string]Command{
		"command_id maiúsculo": func() Command { c := validCommand(); c.CommandID = strings.ToUpper(c.CommandID); return c }(),
		"command_id vazio":     func() Command { c := validCommand(); c.CommandID = ""; return c }(),
		"type sem ponto":       func() Command { c := validCommand(); c.Type = "taskstart"; return c }(),
		"type maiúsculo":       func() Command { c := validCommand(); c.Type = "Task.start"; return c }(),
		"type com 65": func() Command {
			c := validCommand()
			c.Type = contract.CommandType("a." + strings.Repeat("b", 63))
			return c
		}(),
		"tenant vazio":              func() Command { c := validCommand(); c.Tenant = ""; return c }(),
		"tenant com espaço":         func() Command { c := validCommand(); c.Tenant = "ac me"; return c }(),
		"tenant com 65":             func() Command { c := validCommand(); c.Tenant = strings.Repeat("a", 65); return c }(),
		"issued_by com @":           func() Command { c := validCommand(); c.IssuedBy = "op@exemplo.test"; return c }(),
		"issued_by vazio":           func() Command { c := validCommand(); c.IssuedBy = ""; return c }(),
		"issued_by com 129":         func() Command { c := validCommand(); c.IssuedBy = strings.Repeat("a", 129); return c }(),
		"payload_sha256 maiúsculo":  func() Command { c := validCommand(); c.PayloadSHA256 = strings.ToUpper(c.PayloadSHA256); return c }(),
		"payload_sha256 curto":      func() Command { c := validCommand(); c.PayloadSHA256 = "abc"; return c }(),
		"report_id inválido":        report(func(r *contract.AuditReport) { r.ReportID = "x" }),
		"formato fora do enum":      report(func(r *contract.AuditReport) { r.Format = ptr(contract.ReportFormat("pdf")) }),
		"idioma fora do enum":       report(func(r *contract.AuditReport) { r.Lang = ptr(contract.ReportLang("pt")) }),
		"edição fora do enum":       report(func(r *contract.AuditReport) { r.Variant = ptr(contract.ReportVariant("full")) }),
		"delta inválido":            report(func(r *contract.AuditReport) { r.DeltaReportID = ptr("x") }),
		"min_qod 101":               report(func(r *contract.AuditReport) { r.MinQoD = ptr(101) }),
		"min_qod negativo":          report(func(r *contract.AuditReport) { r.MinQoD = ptr(-1) }),
		"levels fora de ordem":      report(func(r *contract.AuditReport) { r.Levels = ptr("hc") }),
		"levels com letra estranha": report(func(r *contract.AuditReport) { r.Levels = ptr("x") }),
	}
	for name, c := range commands {
		if e, err := newReceived(testAt, c); !errors.Is(err, ErrInvalid) || e != nil {
			t.Errorf("received, %s: esperava ErrInvalid e nada montado, deu %v", name, err)
		}
		if _, err := newRejected(testAt, c, contract.ReasonScopeDenied, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("rejected, %s: esperava ErrInvalid, deu %v", name, err)
		}
	}
	ref := validCommand().Ref
	outcomes := map[string]struct {
		ref Ref
		o   Outcome
	}{
		"status fora do enum":         {ref, Outcome{Status: "ok"}},
		"status vazio":                {ref, Outcome{}},
		"error_code num succeeded":    {ref, Outcome{Status: contract.StatusSucceeded, ErrorCode: contract.ErrorTimeout}},
		"error_code fora do enum":     {ref, Outcome{Status: contract.StatusFailed, ErrorCode: "boom"}},
		"artefato fora do export":     {ref, Outcome{Status: contract.StatusSucceeded, Artifact: &contract.AuditArtifact{SHA256: validCommand().PayloadSHA256, Size: 1}}},
		"artefato sha256 inválido":    {Ref{ref.CommandID, contract.TypeReportExport, ref.Tenant}, Outcome{Status: contract.StatusSucceeded, Artifact: &contract.AuditArtifact{SHA256: "x", Size: 1}}},
		"artefato vazio":              {Ref{ref.CommandID, contract.TypeReportExport, ref.Tenant}, Outcome{Status: contract.StatusSucceeded, Artifact: &contract.AuditArtifact{SHA256: validCommand().PayloadSHA256, Size: 0}}},
		"artefato acima de 64 MiB":    {Ref{ref.CommandID, contract.TypeReportExport, ref.Tenant}, Outcome{Status: contract.StatusSucceeded, Artifact: &contract.AuditArtifact{SHA256: validCommand().PayloadSHA256, Size: 67108865}}},
		"object_ids com 18 distintos": {ref, Outcome{Status: contract.StatusSucceeded, ObjectIDs: strings.Split("a b c d e f g h i j k l m n o p q r", " ")}},
		"ref inválida no resultado":   {Ref{"x", ref.Type, ref.Tenant}, Outcome{Status: contract.StatusSucceeded}},
	}
	for name, c := range outcomes {
		if _, err := newResult(testAt, c.ref, c.o); !errors.Is(err, ErrInvalid) {
			t.Errorf("result, %s: esperava ErrInvalid, deu %v", name, err)
		}
	}
	if _, err := newExecuted(testAt, Ref{"x", ref.Type, ref.Tenant}); !errors.Is(err, ErrInvalid) {
		t.Errorf("executed com ref inválida: esperava ErrInvalid, deu %v", err)
	}
	// rejected leva um motivo FINAL (linhas 3–9); deferred, um motivo de adiamento; os não autenticados (0–2) só
	// entram na contagem periódica
	for _, r := range contract.RejectReasons() {
		_, rerr := newRejected(testAt, validCommand(), r, "")
		_, derr := newDeferred(testAt, validCommand(), r, "")
		switch r.Class() {
		case contract.ClassFinalRecorded, contract.ClassFinalNotRecorded:
			if rerr != nil || !errors.Is(derr, ErrInvalid) {
				t.Errorf("%s (final): rejected %v, deferred %v", r, rerr, derr)
			}
		case contract.ClassDeferred:
			if derr != nil || !errors.Is(rerr, ErrInvalid) {
				t.Errorf("%s (adiamento): rejected %v, deferred %v", r, rerr, derr)
			}
		default:
			if !errors.Is(rerr, ErrInvalid) || !errors.Is(derr, ErrInvalid) {
				t.Errorf("%s (não autenticado): rejected %v, deferred %v", r, rerr, derr)
			}
		}
	}
	for _, r := range []contract.RejectReason{"", "boom"} {
		if _, err := newRejected(testAt, validCommand(), r, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("motivo %q: esperava ErrInvalid, deu %v", r, err)
		}
	}
	versions := map[string][2][]string{
		"nó vazio":       {nil, {"1.0"}},
		"hub vazio":      {{"1.0"}, {}},
		"repetida":       {{"1.0", "1.0"}, {"2.0"}},
		"com patch":      {{"1.0.0"}, {"2.0"}},
		"sem minor":      {{"1"}, {"2.0"}},
		"nove versões":   {{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8"}, {"2.0"}},
		"quatro dígitos": {{"1000.0"}, {"2.0"}},
	}
	for name, v := range versions {
		if _, err := newVersionMismatch(testAt, v[0], v[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("versões, %s: esperava ErrInvalid, deu %v", name, err)
		}
	}
}

// O único segredo do contrato é a SAÍDA do enroll_token.create: nenhum tipo de entrada da API tem onde pô-la. Os
// tipos só têm os campos abaixo (identificação, evidência limitada, desfecho), nenhum campo livre (interface, mapa,
// bytes, JSON cru) e nenhum campo de saída, token, senha ou chave.
func TestEntradaNaoTemOndePorSegredo(t *testing.T) {
	str, strs := reflect.TypeOf(""), reflect.TypeOf([]string(nil))
	want := map[reflect.Type][]member{
		reflect.TypeOf(Ref{}): {{"CommandID", "", str}, {"Type", "", reflect.TypeOf(contract.CommandType(""))}, {"Tenant", "", str}},
		reflect.TypeOf(Command{}): {{"Ref", "", reflect.TypeOf(Ref{})}, {"IssuedBy", "", str}, {"PayloadSHA256", "", str},
			{"ObjectIDs", "", strs}, {"Hosts", "", strs}, {"Report", "", reflect.TypeOf(&contract.AuditReport{})}},
		reflect.TypeOf(Outcome{}): {{"Status", "", reflect.TypeOf(contract.ResultStatus(""))}, {"ErrorCode", "", reflect.TypeOf(contract.ErrorCode(""))},
			{"ObjectIDs", "", strs}, {"Artifact", "", reflect.TypeOf(&contract.AuditArtifact{})}, {"Detail", "", str}},
	}
	for typ, fields := range want {
		var got []member
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, member{typ.Field(i).Name, "", typ.Field(i).Type})
		}
		if !slices.Equal(got, fields) {
			t.Errorf("%s ganhou ou perdeu campo:\n got %v\nwant %v", typ, got, fields)
		}
	}
	// os tipos do contrato que entram por ponteiro também são fechados: só os membros do audit_entry
	for _, typ := range []reflect.Type{reflect.TypeOf(contract.AuditReport{}), reflect.TypeOf(contract.AuditArtifact{})} {
		for i := 0; i < typ.NumField(); i++ {
			switch k := typ.Field(i).Type.Kind(); {
			case k == reflect.Interface || k == reflect.Map || k == reflect.Slice:
				t.Errorf("%s.%s é um campo livre", typ, typ.Field(i).Name)
			}
		}
	}
}

func enumOf(t *testing.T, node any) []string {
	t.Helper()
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("nó do schema inesperado: %v", node)
	}
	var out []string
	for _, v := range m["enum"].([]any) {
		out = append(out, v.(string))
	}
	slices.Sort(out)
	return out
}

func keysOf[K ~string](m map[K]bool) []string {
	var out []string
	for k := range m {
		out = append(out, string(k))
	}
	slices.Sort(out)
	return out
}

// Os conjuntos fechados que a API confere são os enums do schema (se o contrato ganhar um valor, este teste falha
// antes que a auditoria passe a recusá-lo).
func TestEnumsConferidosSaoOsDoSchema(t *testing.T) {
	cmdDefs := schemaDoc(t, "fleet-command.schema.json")["$defs"].(map[string]any)
	resDefs := schemaDoc(t, "fleet-result.schema.json")["$defs"].(map[string]any)
	stateDefs := schemaDoc(t, "fleet-state.schema.json")["$defs"].(map[string]any)
	entryProps := stateDefs["audit_entry"].(map[string]any)["properties"].(map[string]any)
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"report_format", keysOf(validFormats), enumOf(t, cmdDefs["report_format"])},
		{"report_lang", keysOf(validLangs), enumOf(t, cmdDefs["report_lang"])},
		{"report_variant", keysOf(validVariants), enumOf(t, cmdDefs["report_variant"])},
		{"error_code", keysOf(validErrorCodes), enumOf(t, resDefs["error_code"])},
		{"audit_entry.status", keysOf(validStatuses), enumOf(t, entryProps["status"])},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s: a API confere %v, o schema tem %v", c.name, c.got, c.want)
		}
	}
}

// Um construtor com defeito que montasse uma linha que o contrato não lê (aqui, versões nulas) não chega ao
// disco: o encode confere cada linha com o DecodeStrict no contract.AuditEntry.
func TestEncodeRecusaLinhaQueOContratoNaoLe(t *testing.T) {
	e := &entry{Stream: contract.StreamReject, Seq: 1, At: testAt, Event: contract.AuditEventVersionMismatch,
		Versions: &contract.AuditVersions{}, PrevSHA256: zeroSHA256}
	if _, err := encode(e); err == nil {
		t.Fatal("uma linha com versões nulas deveria ser recusada")
	}
}
