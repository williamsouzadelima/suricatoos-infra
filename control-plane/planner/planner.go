package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Governance refusals (no model call happens on either).
var (
	ErrConsentOff = errors.New("consentimento de IA desativado para esta finalidade (default off)")
	ErrBudget     = errors.New("orçamento mensal de IA excedido")
)

// Config carries the governance knobs. Consent is OFF by default (a zero Config
// never calls a model); the budget ceiling refuses runaway spend.
type Config struct {
	ConsentGranted   bool    // per-purpose consent; DEFAULT false (born off)
	MonthlyBudgetUSD float64 // <= 0 → no ceiling
	USDPer1kTokens   float64 // estimate used only for the budget gate
}

// Planner drafts advisory remediation plans. It holds the LLM seam, a provider
// resolver, the budget, and the governance config — it owns WHETHER and HOW a
// draft is produced, never WHETHER to apply one.
type Planner struct {
	llm       LLM
	providers ProviderResolver
	budget    *budget
	cfg       Config
}

// New builds a Planner. A missing token rate falls back to a conservative
// placeholder purely for the budget estimate.
func New(llm LLM, providers ProviderResolver, cfg Config) *Planner {
	rate := cfg.USDPer1kTokens
	if rate <= 0 {
		rate = 0.005
	}
	return &Planner{
		llm:       llm,
		providers: providers,
		budget:    newBudget(cfg.MonthlyBudgetUSD, rate, nil),
		cfg:       cfg,
	}
}

// Plan drafts a remediation plan for an attested finding. It refuses (no model
// call) when consent is off or the budget is spent; it pseudonymizes before send,
// restores identifiers in the draft, and ECHOES the attested severity/CVEs (never
// the model's). The returned Plan is always a Draft for human review.
func (p *Planner) Plan(ctx context.Context, req PlanRequest) (*Plan, error) {
	if !p.cfg.ConsentGranted {
		return nil, ErrConsentOff
	}
	prov, err := p.providers.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("provedor: %w", err)
	}
	if !p.budget.allow() {
		return nil, ErrBudget
	}
	ps := newPseudonymizer()
	preq := ps.apply(req)
	resp, err := p.llm.Chat(ctx, ChatRequest{
		BaseURL:  prov.BaseURL,
		APIKey:   prov.APIKey,
		Model:    prov.Model,
		Messages: buildMessages(preq),
		Schema:   planSchema,
	})
	if err != nil {
		return nil, fmt.Errorf("chamada ao modelo: %w", err)
	}
	p.budget.add(resp.Usage)

	draft, err := parseDraft(resp.Content)
	if err != nil {
		return nil, err
	}
	// Restore real identifiers in the operator-facing text.
	draft.Summary = ps.restore(draft.Summary)
	draft.Rationale = ps.restore(draft.Rationale)
	draft.Prioritization = ps.restore(draft.Prioritization)
	draft.Caveats = ps.restore(draft.Caveats)
	for i := range draft.Steps {
		draft.Steps[i].Action = ps.restore(draft.Steps[i].Action)
		draft.Steps[i].Detail = ps.restore(draft.Steps[i].Detail)
	}

	return &Plan{
		FindingID:      req.FindingID,
		CorrelationID:  req.CorrelationID,
		Severity:       req.Severity,       // attested passthrough — NEVER from the model
		SeverityOrigin: req.SeverityOrigin, // attested passthrough
		CVEs:           req.CVEs,           // attested passthrough
		Summary:        draft.Summary,
		Steps:          draft.Steps,
		Rationale:      draft.Rationale,
		Prioritization: draft.Prioritization,
		Caveats:        draft.Caveats,
		Provider:       prov.Name,
		Model:          prov.Model,
		Draft:          true,
	}, nil
}

// parseDraft decodes the model's structured output. llmDraft has no severity/cve
// field, so even if the model emits one it is dropped — the attested values are
// the only source of truth.
func parseDraft(content string) (*llmDraft, error) {
	var d llmDraft
	if err := json.Unmarshal([]byte(content), &d); err != nil {
		return nil, fmt.Errorf("saída do modelo não é o JSON do schema: %w", err)
	}
	if strings.TrimSpace(d.Summary) == "" || len(d.Steps) == 0 {
		return nil, errors.New("plano vazio (sem summary/steps)")
	}
	return &d, nil
}
