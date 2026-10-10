package planner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeLLM struct {
	resp   ChatResponse
	err    error
	calls  int
	gotReq ChatRequest
}

func (f *fakeLLM) Chat(_ context.Context, req ChatRequest) (ChatResponse, error) {
	f.calls++
	f.gotReq = req
	return f.resp, f.err
}

type fakeResolver struct {
	prov Provider
	err  error
}

func (f fakeResolver) Resolve(context.Context) (Provider, error) { return f.prov, f.err }

func sampleReq() PlanRequest {
	return PlanRequest{
		FindingID: "f1", CorrelationID: "c1", Type: "package_patch",
		Title: "Patch ausente em blackburn", Severity: "7.5 High", SeverityOrigin: "msrc-cvrf",
		CVEs: []string{"CVE-2024-1234"}, KB: "KB5041580",
		Evidence: "host blackburn (10.0.0.5) sem KB5041580", OS: "Windows 11",
		Host: "blackburn", AgentID: "win-agent-7", Tenant: "acme", IP: "10.0.0.5",
	}
}

const okContent = `{"summary":"Resumo","steps":[{"action":"Aplicar KB5041580","detail":"via WUA em host-1"}],"rationale":"r","prioritization":"p","caveats":"c"}`

func newPlanner(llm LLM, consent bool) *Planner {
	return New(llm, fakeResolver{prov: Provider{Name: "OpenRouter", BaseURL: "https://x/v1", APIKey: "k", Model: "m"}}, Config{ConsentGranted: consent})
}

func TestPlan_ConsentOffRefusesWithoutCalling(t *testing.T) {
	llm := &fakeLLM{resp: ChatResponse{Content: okContent}}
	_, err := newPlanner(llm, false).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrConsentOff) {
		t.Fatalf("esperava ErrConsentOff, veio %v", err)
	}
	if llm.calls != 0 {
		t.Fatal("NENHUM dado pode ir ao modelo sem consentimento")
	}
}

func TestPlan_HappyPathDraft(t *testing.T) {
	llm := &fakeLLM{resp: ChatResponse{Content: okContent, Usage: Usage{PromptTokens: 100, CompletionTokens: 50}}}
	plan, err := newPlanner(llm, true).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !plan.Draft {
		t.Fatal("todo plano é rascunho (Draft=true)")
	}
	if plan.Severity != "7.5 High" || plan.SeverityOrigin != "msrc-cvrf" || len(plan.CVEs) != 1 {
		t.Fatalf("severidade/cve atestados deveriam passar direto: %+v", plan)
	}
	if plan.Provider != "OpenRouter" || len(plan.Steps) == 0 {
		t.Fatalf("plano incompleto: %+v", plan)
	}
}

func TestPlan_PseudonymizesBeforeSend(t *testing.T) {
	llm := &fakeLLM{resp: ChatResponse{Content: okContent}}
	if _, err := newPlanner(llm, true).Plan(context.Background(), sampleReq()); err != nil {
		t.Fatalf("err = %v", err)
	}
	var sent string
	for _, m := range llm.gotReq.Messages {
		sent += m.Content
	}
	for _, raw := range []string{"blackburn", "10.0.0.5", "win-agent-7", "acme"} {
		if strings.Contains(sent, raw) {
			t.Fatalf("identificador cru vazou pro modelo: %q", raw)
		}
	}
	if !strings.Contains(sent, "host-1") {
		t.Fatal("o host deveria ir pseudonimizado (host-1)")
	}
}

func TestPlan_RestoresIdentifiersInDraft(t *testing.T) {
	// Model answers referencing the pseudonym; the operator-facing draft gets the
	// real value back.
	llm := &fakeLLM{resp: ChatResponse{Content: `{"summary":"Corrigir host-1 agora","steps":[{"action":"x"}],"rationale":"","prioritization":"","caveats":""}`}}
	plan, err := newPlanner(llm, true).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(plan.Summary, "blackburn") {
		t.Fatalf("o rascunho deveria restaurar o host real: %q", plan.Summary)
	}
}

func TestPlan_NeverUsesModelSeverity(t *testing.T) {
	// Even if the model emits a severity, it is dropped — the attested one wins.
	llm := &fakeLLM{resp: ChatResponse{Content: `{"summary":"s","severity":"0.0 None","steps":[{"action":"x"}],"rationale":"","prioritization":"","caveats":""}`}}
	plan, err := newPlanner(llm, true).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if plan.Severity != "7.5 High" {
		t.Fatalf("severidade do modelo NÃO pode sobrescrever a atestada: %q", plan.Severity)
	}
}

func TestPlan_LLMErrorPropagates(t *testing.T) {
	llm := &fakeLLM{err: errors.New("502")}
	if _, err := newPlanner(llm, true).Plan(context.Background(), sampleReq()); err == nil {
		t.Fatal("erro do modelo deveria propagar")
	}
}

func TestPlan_BudgetRefusesSecondCall(t *testing.T) {
	llm := &fakeLLM{resp: ChatResponse{Content: okContent, Usage: Usage{PromptTokens: 1000, CompletionTokens: 1000}}}
	// cap muito baixo: a 1ª chamada passa (gasto 0 < cap) e estoura o teto; a 2ª é recusada.
	p := New(llm, fakeResolver{prov: Provider{Name: "p", BaseURL: "b", APIKey: "k", Model: "m"}},
		Config{ConsentGranted: true, MonthlyBudgetUSD: 0.001, USDPer1kTokens: 0.005})
	if _, err := p.Plan(context.Background(), sampleReq()); err != nil {
		t.Fatalf("1ª chamada deveria passar: %v", err)
	}
	if _, err := p.Plan(context.Background(), sampleReq()); !errors.Is(err, ErrBudget) {
		t.Fatalf("2ª chamada deveria ser recusada por orçamento: %v", err)
	}
	if llm.calls != 1 {
		t.Fatalf("só 1 chamada deveria ter ido ao modelo, houve %d", llm.calls)
	}
}

func TestParseDraftRejectsEmpty(t *testing.T) {
	if _, err := parseDraft(`{"summary":"","steps":[]}`); err == nil {
		t.Fatal("plano vazio deveria ser rejeitado")
	}
	if _, err := parseDraft(`não é json`); err == nil {
		t.Fatal("saída não-JSON deveria ser rejeitada")
	}
}
