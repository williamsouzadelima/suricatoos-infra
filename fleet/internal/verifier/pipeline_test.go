package verifier

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// Linhas 0–2: envelope não autenticado não gera ack nem linha própria de auditoria; só conta (total do heartbeat e
// a linha periódica unauthenticated). Nada vai ao store.
func TestLinhas0a2SemAckSoContam(t *testing.T) {
	n := newNode(t)
	before := n.storeBytes()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) // outra chave, fictícia
	good := env("a", contract.TypeTaskStart)
	cases := []struct {
		raw  []byte
		want contract.RejectReason
	}{
		{[]byte(`{"não":"é um envelope"}`), contract.ReasonBadEnvelope},
		{bytes.Replace(good, []byte(taskID), []byte("2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a40"), 1), contract.ReasonPayloadMismatch},
		{signWith(other, command("b", contract.TypeTaskStart), payloads[contract.TypeTaskStart]), contract.ReasonBadSignature},
	}
	for i, c := range cases {
		o := n.process(c.raw, tv.Add(time.Duration(i)*time.Second))
		if o.Kind != NoAck || o.Reason != c.want || o.Ack.CommandID != "" || o.Accepted != nil {
			t.Fatalf("%s: desfecho %+v", c.want, o)
		}
	}
	if u, r := n.v.Counters(); u != 3 || r != 0 {
		t.Fatalf("contadores %d/%d", u, r)
	}
	if !bytes.Equal(n.storeBytes(), before) {
		t.Fatal("envelope não autenticado mexeu no store")
	}
	es := n.auditEntries(contract.StreamReject)
	if got := events(es); !slices.Equal(got, []string{"unauthenticated"}) || es[0].Unauthenticated.BadEnvelope != 1 {
		t.Fatalf("auditoria %v", got)
	}
}

// Linha 2a: a mesma forma canônica já gravada recebe o ack gravado (received_at da decisão), sem reavaliar 3–9,
// sem executar de novo, sem linha received e sem consumir orçamento; conta em redeliveries e na linha redelivered.
func TestLinha2aReentregaDevolveAckGravado(t *testing.T) {
	n := newNode(t)
	raw := env("a", contract.TypeTaskStart)
	first := n.process(raw, tv)
	expectAck(t, first, Ack, contract.DecisionAccepted, "")
	store := n.storeBytes()
	again := n.process(raw, tv.Add(5*time.Minute))
	expectAck(t, again, Redelivery, contract.DecisionAccepted, "")
	if again.Ack.ReceivedAt != first.Ack.ReceivedAt || again.Accepted != nil {
		t.Fatalf("reentrega: received_at %s (esperava o gravado %s), accepted %v", again.Ack.ReceivedAt, first.Ack.ReceivedAt, again.Accepted)
	}
	if !bytes.Equal(n.storeBytes(), store) {
		t.Fatal("a reentrega gravou no store")
	}
	if r, _ := n.st.Ledger.Fits(tv.Add(5*time.Minute), contract.TypeTaskStart, budgetLimits(2, 1000)); !r.Total {
		t.Fatal("a reentrega consumiu orçamento (com teto 2, depois de um aceite ainda cabe um)")
	}
	if _, r := n.v.Counters(); r != 1 {
		t.Fatalf("redeliveries %d", r)
	}
	if got := events(n.auditEntries(contract.StreamExec)); !slices.Equal(got, []string{"received"}) {
		t.Fatalf("a reentrega não ganha linha received: %v", got)
	}
	if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"redelivered"}) {
		t.Fatalf("a reentrega conta na linha redelivered: %v", got)
	}
}

// Linha 2a também vale para um replay gravado: a reentrega byte a byte dele recebe o replay gravado.
func TestLinha2aReentregaDeReplayGravado(t *testing.T) {
	n := newNode(t)
	expectAck(t, n.process(env("a", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
	c := command("a", contract.TypeTaskStart)
	c.Nonce = nonceOf("re-assinado")
	raw := signed(c, payloads[contract.TypeTaskStart])
	expectAck(t, n.process(raw, tv), Ack, contract.DecisionRejected, contract.ReasonReplay)
	expectAck(t, n.process(raw, tv.Add(time.Minute)), Redelivery, contract.DecisionRejected, contract.ReasonReplay)
}

// A reentrega depois de not_after recebe a decisão gravada, não expired, enquanto a entrada vive (not_after + 7
// dias); depois disso a mesma reentrega cai na linha 3 e volta expired, que não se grava.
func TestReentregaDepoisDeNotAfterEDepoisDaVida(t *testing.T) {
	n := newNode(t)
	raw := env("a", contract.TypeTaskStart)
	expectAck(t, n.process(raw, tv), Ack, contract.DecisionAccepted, "")
	notAfter := t0.Add(time.Hour)
	expectAck(t, n.process(raw, notAfter.Add(skew+time.Second)), Redelivery, contract.DecisionAccepted, "")
	expectAck(t, n.process(raw, notAfter.Add(replay.EntryGrace)), Redelivery, contract.DecisionAccepted, "")
	before := n.storeBytes()
	expectAck(t, n.process(raw, notAfter.Add(replay.EntryGrace+time.Second)), Ack, contract.DecisionRejected, contract.ReasonExpired)
	if !bytes.Equal(n.storeBytes(), before) {
		t.Fatal("expired não se grava")
	}
}

// Linha 3, bad_window e expired: rejected final e NÃO gravado — o store fica byte a byte igual —, com a linha
// rejected antes do ack e a marca d'água durável antes do ack.
func TestLinha3FinalNaoGravado(t *testing.T) {
	long := command("longa", contract.TypeTaskStart)
	long.NotAfter = contract.FormatUTCTime(t0.Add(24*time.Hour + time.Second))
	for _, c := range []struct {
		name string
		raw  []byte
		at   time.Time
		want contract.RejectReason
	}{
		{"bad_window", signed(long, payloads[contract.TypeTaskStart]), tv, contract.ReasonBadWindow},
		{"expired", env("vencido", contract.TypeTaskStart), t0.Add(time.Hour + skew + time.Second), contract.ReasonExpired},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newNode(t)
			before := n.storeBytes()
			o := n.process(c.raw, c.at)
			expectAck(t, o, Ack, contract.DecisionRejected, c.want)
			if !bytes.Equal(n.storeBytes(), before) {
				t.Fatal("a linha 3 mexeu no store")
			}
			if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"rejected:" + string(c.want)}) {
				t.Fatalf("auditoria %v", got)
			}
			if mark := n.st.Clock().Mark(); !mark.Equal(c.at) {
				t.Fatalf("marca %v", mark)
			}
			if o.PolicyEvent != nil {
				t.Fatal("linha 3 não vira command.rejected_by_policy")
			}
			// a mesma reentrega recalcula a mesma decisão (nada gravado para 2a)
			expectAck(t, n.process(c.raw, c.at.Add(time.Minute)), Ack, contract.DecisionRejected, c.want)
		})
	}
}

// Linha 3, not_yet_valid: adiado, nada gravado; o mesmo envelope, já na janela, é aceito depois.
func TestLinha3NotYetValidAdiado(t *testing.T) {
	n := newNode(t)
	raw := env("cedo", contract.TypeTaskStart)
	before := n.storeBytes()
	o := n.process(raw, t0.Add(-skew-time.Second))
	expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonNotYetValid)
	if !bytes.Equal(n.storeBytes(), before) {
		t.Fatal("adiado não se grava")
	}
	if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"deferred:not_yet_valid"}) {
		t.Fatalf("auditoria %v", got)
	}
	expectAck(t, n.process(raw, t0.Add(-skew)), Ack, contract.DecisionAccepted, "")
}

// Linha 4, wrong_node: rejected final, gravado antes do ack (a reentrega recebe o mesmo); não vira evento.
func TestLinha4WrongNodeGravado(t *testing.T) {
	n := newNode(t)
	c := command("outro nó", contract.TypeTaskStart)
	c.NodeID = "node-lab-0002"
	raw := signed(c, payloads[contract.TypeTaskStart])
	o := n.process(raw, tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonWrongNode)
	if o.PolicyEvent != nil || o.Ack.NodeID != ownNode {
		t.Fatalf("evento %v, node_id do ack %s", o.PolicyEvent, o.Ack.NodeID)
	}
	expectAck(t, n.process(raw, tv.Add(time.Minute)), Redelivery, contract.DecisionRejected, contract.ReasonWrongNode)
}

// Linha 5: replay pelo command_id (outro nonce) e pelo nonce (outro command_id) — rejected final, gravado pela
// própria forma canônica; os índices continuam na primeira.
func TestLinha5ReplayPorCommandIDEPorNonce(t *testing.T) {
	n := newNode(t)
	expectAck(t, n.process(env("original", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
	sameCmd := command("original", contract.TypeTaskStart)
	sameCmd.Nonce = nonceOf("outro nonce")
	sameNonce := command("outro command_id", contract.TypeTaskStart)
	sameNonce.Nonce = nonceOf("original")
	for name, c := range map[string]contract.Command{"command_id": sameCmd, "nonce": sameNonce} {
		o := n.process(signed(c, payloads[contract.TypeTaskStart]), tv)
		expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonReplay)
		if o.PolicyEvent != nil || o.Ack.Detail == nil || *o.Ack.Detail != detailConflict {
			t.Fatalf("%s: %+v", name, o)
		}
	}
}

// Linha 5, piso de replay: issued_at < piso + skew é replay com o detalhe "cache reiniciado", comparado em segundos
// inteiros com o piso arredondado para cima; a partir de piso + skew o comando passa.
func TestLinha5PisoDeReplay(t *testing.T) {
	n := newNode(t)
	floor := t0.Add(-skew - 500*time.Millisecond) // 11:57:59.5 → publicado 11:58:00
	if err := n.st.Store.SetFloor(floor); err != nil {
		t.Fatal(err)
	}
	if got := n.st.Store.ReplayFloor(); got != "2026-10-11T11:58:00Z" {
		t.Fatalf("piso publicado %s", got)
	}
	early := command("antes do piso", contract.TypeTaskStart)
	early.IssuedAt = contract.FormatUTCTime(t0.Add(-time.Second)) // 11:59:59 < 11:58:00 + 2 min
	o := n.process(signed(early, payloads[contract.TypeTaskStart]), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonReplay)
	if *o.Ack.Detail != "cache reiniciado" {
		t.Fatalf("detalhe %q", *o.Ack.Detail)
	}
	edge := command("no piso", contract.TypeTaskStart) // issued_at 12:00:00 = 11:58:00 + 2 min: passa
	expectAck(t, n.process(signed(edge, payloads[contract.TypeTaskStart]), tv), Ack, contract.DecisionAccepted, "")
	// abaixo do piso E com o command_id já gravado: os dois são linha 5 (replay); o detalhe é o do conflito, que
	// vem primeiro
	both := command("antes do piso", contract.TypeTaskStart)
	both.IssuedAt, both.Nonce = contract.FormatUTCTime(t0.Add(-2*time.Second)), nonceOf("outro")
	o = n.process(signed(both, payloads[contract.TypeTaskStart]), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonReplay)
	if *o.Ack.Detail != detailConflict {
		t.Fatalf("detalhe %q", *o.Ack.Detail)
	}
}

// O piso deixa de importar quando nenhuma janela válida alcança issued_at < piso + skew: com t ≥ piso + 24 h + 2·skew,
// todo envelope que passa a linha 3 tem issued_at ≥ t − skew − 24 h ≥ piso + skew. Até lá ele ainda recusa.
func TestPisoDeixaDeImportarDepoisDaJanelaMaxima(t *testing.T) {
	n := newNode(t)
	floor := t0
	if err := n.st.Store.SetFloor(floor); err != nil {
		t.Fatal(err)
	}
	// a janela mais longa que ainda alcança o piso: issued_at = piso + skew − 1 s, not_after = issued_at + 24 h
	c := command("janela máxima", contract.TypeTaskStart)
	issued := floor.Add(skew - time.Second)
	c.IssuedAt, c.NotAfter = contract.FormatUTCTime(issued), contract.FormatUTCTime(issued.Add(24*time.Hour))
	last := issued.Add(24*time.Hour + skew) // o último instante em que a linha 3 ainda o aceita
	expectAck(t, n.process(signed(c, payloads[contract.TypeTaskStart]), last), Ack, contract.DecisionRejected, contract.ReasonReplay)
	if !last.Equal(floor.Add(24*time.Hour + 2*skew - time.Second)) {
		t.Fatalf("conta da borda: %v", last)
	}
	// depois disso, qualquer envelope ainda dentro da janela vem de depois do piso + skew
	later := floor.Add(24*time.Hour + 2*skew)
	c2 := command("depois", contract.TypeTaskStart)
	issued = later.Add(-skew - 24*time.Hour) // o issued_at mais antigo que a linha 3 ainda aceita em later
	c2.IssuedAt, c2.NotAfter = contract.FormatUTCTime(issued), contract.FormatUTCTime(issued.Add(24*time.Hour))
	expectAck(t, n.process(signed(c2, payloads[contract.TypeTaskStart]), later), Ack, contract.DecisionAccepted, "")
}

// Linha 6: tenant desconhecido, desabilitado, ou sem usuário gvmd para uma escrita — tenant_unknown, final, gravado,
// e vira command.rejected_by_policy.
func TestLinha6TenantUnknown(t *testing.T) {
	n := newNode(t)
	for name, c := range map[string]contract.Command{
		"desconhecido": func() contract.Command {
			c := command("t1", contract.TypeTaskStart)
			c.Tenant = "desconhecido"
			return c
		}(),
		"desabilitado":   func() contract.Command { c := command("t2", contract.TypeTaskStart); c.Tenant = "initech"; return c }(),
		"escrita s/ gvm": func() contract.Command { c := command("t3", contract.TypeTaskCreate); c.Tenant = "globex"; return c }(),
	} {
		raw := signed(c, payloads[c.Type])
		o := n.process(raw, tv)
		expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonTenantUnknown)
		if o.PolicyEvent == nil || o.PolicyEvent.Reason != contract.ReasonTenantUnknown || o.PolicyEvent.CommandID != c.CommandID {
			t.Fatalf("%s: evento %+v", name, o.PolicyEvent)
		}
		expectAck(t, n.process(raw, tv.Add(time.Minute)), Redelivery, contract.DecisionRejected, contract.ReasonTenantUnknown)
	}
	// leitura (usuário atual) num tenant sem usuário gvmd de escrita passa da linha 6
	c := command("t4", contract.TypeTaskStart)
	c.Tenant = "globex"
	expectAck(t, n.process(signed(c, payloads[contract.TypeTaskStart]), tv), Ack, contract.DecisionAccepted, "")
}

// Linha 7: tipo fora do catálogo ou do node_kind (unsupported), fora de allow (type_not_allowed), orçamento
// esgotado (rate_limited) — finais, gravados, com evento.
func TestLinha7(t *testing.T) {
	n := newNode(t)
	c := command("tipo estranho", "foo.bar")
	expectAck(t, n.process(signed(c, `{}`), tv), Ack, contract.DecisionRejected, contract.ReasonUnsupported)

	writePolicy(t, n.dir, []contract.CommandType{contract.TypeTaskStart}, 1000, 1)
	expectAck(t, n.process(env("ok", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
	o := n.process(env("sem vaga", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonRateLimited)
	if o.PolicyEvent == nil {
		t.Fatal("rate_limited vira evento")
	}
	expectAck(t, n.process(env("fora de allow", contract.TypeTaskStop), tv), Ack, contract.DecisionRejected, contract.ReasonTypeNotAllowed)

	s := newNode(t)
	s.cfg.NodeKind = contract.NodeSensor
	s.build()
	expectAck(t, s.process(env("só central", contract.TypeAgentScanNow), tv), Ack, contract.DecisionRejected, contract.ReasonUnsupported)
}

// Linha 8: payload inválido para o tipo (bad_payload) e combinação de export não anunciada
// (unsupported_report_variant) — finais, gravados, com evento; o detalhe é fixo, nunca o que o payload trouxe.
func TestLinha8(t *testing.T) {
	n := newNode(t)
	c := command("payload ruim", contract.TypeTaskStart)
	o := n.process(signed(c, `{"task_id":"não é uuid","membro_estranho_do_hub":1}`), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonBadPayload)
	if *o.Ack.Detail != detailBadPayload || o.PolicyEvent == nil {
		t.Fatalf("detalhe %q, evento %v", *o.Ack.Detail, o.PolicyEvent)
	}
	n.formats = []contract.ReportFormatCapability{{Format: contract.FormatSuricatoosPDF, Lang: contract.LangPTBR,
		Variants: []contract.ReportVariant{contract.VariantTechnical}}}
	exp := command("variante", contract.TypeReportExport)
	client := strings.Replace(payloads[contract.TypeReportExport], `"technical"`, `"client"`, 1)
	expectAck(t, n.process(signed(exp, client), tv), Ack, contract.DecisionRejected, contract.ReasonUnsupportedReportVariant)
	expectAck(t, n.process(env("anunciada", contract.TypeReportExport), tv), Ack, contract.DecisionAccepted, "")
}

// Linha 9: hosts fora do escopo (do payload ou lidos no gvmd), objeto que não existe para o tenant, e host não
// literal no target — scope_denied, final, gravado, com evento e detalhe fixo (nunca o texto do portão).
func TestLinha9ScopeDenied(t *testing.T) {
	n := newNode(t)
	tc := command("fora", contract.TypeTargetCreate)
	outside := strings.Replace(payloads[contract.TypeTargetCreate], `"198.51.100.10"`, `"203.0.113.10"`, 1)
	o := n.process(signed(tc, outside), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonScopeDenied)
	if *o.Ack.Detail != detailScopeDenied || strings.Contains(*o.Ack.Detail, "203.0.113") || o.PolicyEvent == nil {
		t.Fatalf("detalhe %q, evento %v", *o.Ack.Detail, o.PolicyEvent)
	}
	rej := n.auditEntries(contract.StreamReject)
	if last := rej[len(rej)-1]; *last.HostsCount != 2 || last.Hosts[1] != "203.0.113.10" {
		t.Fatalf("a linha rejected leva os hosts do payload como evidência: %+v", last)
	}

	n.scope.targets[tgtID] = TargetHosts{Hosts: []string{"192.0.2.0/24", "alvo.exemplo.test"}}
	expectAck(t, n.process(env("não literal", contract.TypeTaskStart), tv), Ack, contract.DecisionRejected, contract.ReasonScopeDenied)

	delete(n.scope.tasks, taskID)
	o = n.process(env("sumiu", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonScopeDenied)
	if *o.Ack.Detail != detailScopeNotFound {
		t.Fatalf("detalhe %q", *o.Ack.Detail)
	}
}

// As linhas de escopo de cada tipo (regra completa do ADR): quais leituras o gvmd recebe e quais hosts o portão
// confere. Tipos sem escopo não leem nada.
func TestLinha9RegraCompleta(t *testing.T) {
	cases := []struct {
		typ     contract.CommandType
		payload string
		reads   []string
	}{
		{contract.TypeTaskStart, payloads[contract.TypeTaskStart], []string{"task " + taskID, "target " + tgtID}},
		{contract.TypeTaskResume, payloads[contract.TypeTaskResume], []string{"task " + taskID, "target " + tgtID}},
		{contract.TypeTaskStop, payloads[contract.TypeTaskStop], nil},
		{contract.TypeTaskDelete, payloads[contract.TypeTaskDelete], nil},
		{contract.TypeTaskCreate, payloads[contract.TypeTaskCreate], []string{"target " + tgtID}},
		{contract.TypeTaskModify, `{"task_id":"` + taskID + `","target_id":"` + tgtID + `"}`, []string{"target " + tgtID}},
		{contract.TypeTaskModify, `{"task_id":"` + taskID + `","schedule_id":"` + schedID + `"}`, []string{"task " + taskID, "target " + tgtID}},
		{contract.TypeTaskModify, `{"task_id":"` + taskID + `","schedule_id":""}`, nil},
		{contract.TypeTaskModify, `{"task_id":"` + taskID + `","name":"novo nome"}`, nil},
		{contract.TypeTaskClone, payloads[contract.TypeTaskClone], []string{"task " + taskID, "target " + tgtID}},
		{contract.TypeScheduleCreate, payloads[contract.TypeScheduleCreate], []string{"task " + taskID, "target " + tgtID}},
		{contract.TypeScheduleCreate, `{"name":"x","icalendar":"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n","timezone":"UTC"}`, nil},
		{contract.TypeScheduleModify, payloads[contract.TypeScheduleModify], []string{"schedule " + schedID, "task " + taskID, "target " + tgtID}},
		{contract.TypeTargetCreate, payloads[contract.TypeTargetCreate], nil},
		{contract.TypeTargetModify, payloads[contract.TypeTargetModify], nil},
		{contract.TypeTargetModify, `{"target_id":"` + tgtID + `","name":"só o nome"}`, []string{"target " + tgtID}},
		{contract.TypeSensorJobEnqueue, payloads[contract.TypeSensorJobEnqueue], nil},
		{contract.TypeReportExport, payloads[contract.TypeReportExport], nil},
		{contract.TypeFeedSyncNow, payloads[contract.TypeFeedSyncNow], nil},
	}
	for i, c := range cases {
		n := newNode(t)
		o := n.process(signed(command(string(c.typ)+string(rune('a'+i)), c.typ), c.payload), tv)
		expectAck(t, o, Ack, contract.DecisionAccepted, "")
		if !slices.Equal(n.scope.reads, c.reads) {
			t.Errorf("%s %s: leituras %v, esperava %v", c.typ, c.payload, n.scope.reads, c.reads)
		}
	}
	// task.clone de tarefa sem agenda não passa pelo portão
	n := newNode(t)
	n.scope.tasks[taskID] = TaskInfo{TargetID: tgtID}
	n.scope.targets[tgtID] = TargetHosts{Hosts: []string{"203.0.113.0/24"}} // fora: não importa, nada se varre
	expectAck(t, n.process(env("clone sem agenda", contract.TypeTaskClone), tv), Ack, contract.DecisionAccepted, "")
}

// Aceito: as listas CANÔNICAS do portão substituem os hosts no payload que o executor recebe, e são as da linha
// received da auditoria.
func TestAceitoEncaminhaSoAsListasCanonicas(t *testing.T) {
	n := newNode(t)
	n.scope.gate.allowed = append(n.scope.gate.allowed, "2001:db8:")
	tc := command("canônico", contract.TypeTargetCreate)
	payload := `{"name":"LAB v6","hosts":["2001:DB8::/64","192.0.2.0/24"],"exclude_hosts":["2001:DB8::1"],"port_range":"T:1-1024"}`
	o := n.process(signed(tc, payload), tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	p, ok := o.Accepted.Payload.(*contract.PayloadTargetCreate)
	want := []string{"2001:db8::/64", "192.0.2.0/24"}
	if !ok || !slices.Equal(p.Hosts, want) || !slices.Equal(p.ExcludeHosts, []string{"2001:db8::1"}) ||
		!slices.Equal(o.Accepted.Hosts, want) || !slices.Equal(o.Accepted.ExcludeHosts, []string{"2001:db8::1"}) {
		t.Fatalf("payload do executor %+v, hosts %v / %v", p, o.Accepted.Hosts, o.Accepted.ExcludeHosts)
	}
	if !bytes.Contains(o.Accepted.Command.Payload, []byte("2001:DB8::/64")) {
		t.Fatal("o Command guarda os bytes crus como recebidos (o hash é deles)")
	}
	exec := n.auditEntries(contract.StreamExec)
	if len(exec) != 1 || !slices.Equal(exec[0].Hosts, want) {
		t.Fatalf("a linha received leva as listas canônicas: %+v", exec)
	}

	// target.modify sem hosts no payload: o portão confere os hosts atuais lidos no gvmd; o executor não recebe
	// hosts (o comando não os muda), mas a linha received leva os canônicos que o portão conferiu
	n.scope.targets[tgtID] = TargetHosts{Hosts: []string{"2001:DB8::/64"}}
	tm := command("modify sem hosts", contract.TypeTargetModify)
	o = n.process(signed(tm, `{"target_id":"`+tgtID+`","name":"só o nome"}`), tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	if pm := o.Accepted.Payload.(*contract.PayloadTargetModify); pm.Hosts != nil || !slices.Equal(o.Accepted.Hosts, []string{"2001:db8::/64"}) {
		t.Fatalf("payload %+v, hosts conferidos %v", pm, o.Accepted.Hosts)
	}
	exec = n.auditEntries(contract.StreamExec)
	if last := exec[len(exec)-1]; !slices.Equal(last.Hosts, []string{"2001:db8::/64"}) {
		t.Fatalf("a linha received do target.modify sem hosts: %+v", last)
	}
}

// Aceito: gravado antes do ack (com journal "recebido"), orçamento consumido, linha received antes do ack, e o
// payload decodificado para o executor.
func TestAceitoGravadoComOrcamentoEAuditoria(t *testing.T) {
	n := newNode(t)
	raw := env("aceito", contract.TypeTaskStart)
	o := n.process(raw, tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	a := o.Accepted
	if a == nil || a.Job.State != replay.StateReceived || a.Job.CommandID != uuidOf("aceito") || !a.At.Equal(tv) ||
		a.Tenant.GVMUser != "tenant-acme" || o.Ack.ReceivedAt != "2026-10-11T12:30:00Z" || o.Ack.Reason != nil || o.Ack.Detail != nil {
		t.Fatalf("aceito %+v, ack %+v", a, o.Ack)
	}
	if _, ok := a.Payload.(*contract.PayloadTaskRef); !ok {
		t.Fatalf("payload %T", a.Payload)
	}
	if l := n.st.Store.Lookup(mustVerify(t, raw), tv); l.Same == nil || l.Same.Decision != contract.DecisionAccepted {
		t.Fatal("o aceite não foi gravado")
	}
	if r, _ := n.st.Ledger.Fits(tv, contract.TypeTaskStart, budgetLimits(1, 1)); r.Total {
		t.Fatal("o aceite não consumiu o orçamento global")
	}
	exec := n.auditEntries(contract.StreamExec)
	if len(exec) != 1 || exec[0].Event != contract.AuditEventReceived || !slices.Equal(exec[0].ObjectIDs, []string{taskID}) {
		t.Fatalf("auditoria exec %+v", exec)
	}
}

func mustVerify(t *testing.T, raw []byte) *contract.Verified {
	t.Helper()
	v, err := contract.Verify(testPub(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
