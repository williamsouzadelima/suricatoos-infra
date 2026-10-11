package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// Governance refusals (no model call happens on any of them).
var (
	ErrConsentOff   = errors.New("consentimento de IA desativado para esta finalidade (default off)")
	ErrBudget       = errors.New("orçamento mensal de IA excedido")
	ErrNonFreeModel = errors.New("modelo não gratuito recusado (AI_FREE_MODELS_ONLY=true)")
)

// Config carries the governance knobs. Consent is OFF by default (a zero Config
// never calls a model); the budget ceiling refuses runaway spend.
type Config struct {
	ConsentGranted   bool    // per-purpose consent; DEFAULT false (born off)
	MonthlyBudgetUSD float64 // <= 0 → no ceiling
	USDPer1kTokens   float64 // estimate used only for the budget gate
	// FreeModelsOnly refuses (before any network) every model that is not free
	// (aiproviders.IsFreeModel). The control-plane turns it on by default
	// (AI_FREE_MODELS_ONLY); the zero Config leaves it off.
	FreeModelsOnly bool
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
// call) when consent is off; it pseudonymizes before send, restores identifiers in
// the draft, and ECHOES the attested severity/CVEs (never the model's). The
// returned Plan is always a Draft for human review.
//
// The resolved providers are tried in priority order. A provider whose model is
// not free is never called while FreeModelsOnly is on; a paid model is called only
// within the budget, while a FREE model costs 0 (it neither needs nor consumes
// budget). On 429, 5xx, timeout or network error the next provider is tried; any
// other failure (a 4xx is an error in the request, not in the provider) stops.
func (p *Planner) Plan(ctx context.Context, req PlanRequest) (*Plan, error) {
	if !p.cfg.ConsentGranted {
		return nil, ErrConsentOff
	}
	provs, err := p.providers.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("provedor: %w", err)
	}
	ps := newPseudonymizer()
	preq := ps.apply(req)
	msgs := buildMessages(preq)

	var refused, failures []string
	budgetSpent := false
	for _, prov := range provs {
		free := aiproviders.IsFreeModel(prov.Kind, prov.Model)
		if p.cfg.FreeModelsOnly && !free {
			refused = append(refused, fmt.Sprintf("%s (%s)", prov.Name, prov.Model))
			continue
		}
		if !free && !p.budget.allow() {
			budgetSpent = true
			continue
		}
		resp, err := p.llm.Chat(ctx, ChatRequest{
			BaseURL:  prov.BaseURL,
			APIKey:   prov.APIKey,
			Model:    prov.Model,
			Messages: msgs,
			Schema:   planSchema,
		})
		if err != nil {
			if retryable(ctx, err) {
				failures = append(failures, fmt.Sprintf("%s: %v", prov.Name, err))
				continue
			}
			return nil, fmt.Errorf("chamada ao modelo (%s): %w", prov.Name, err)
		}
		if !free {
			p.budget.add(resp.Usage)
		}
		return p.draft(req, ps, prov, resp.Content)
	}

	switch {
	case len(failures) > 0:
		return nil, fmt.Errorf("chamada ao modelo: nenhum provedor respondeu (%s)", strings.Join(failures, "; "))
	case budgetSpent:
		return nil, ErrBudget
	case len(refused) > 0:
		return nil, fmt.Errorf("%w: %s", ErrNonFreeModel, strings.Join(refused, ", "))
	default:
		return nil, errors.New("provedor: nenhum provedor de IA habilitado")
	}
}

// draft validates the model's content (parseDraft — the ONLY bar a draft must
// pass, whatever response format produced it) and builds the operator's Plan.
func (p *Planner) draft(req PlanRequest, ps *pseudonymizer, prov Provider, content string) (*Plan, error) {
	draft, err := parseDraft(content)
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

// retryable reports whether a failed call should move on to the next provider:
// 429, 5xx, timeout or network error. Not when the caller's own context is done
// (the operator's request went away), and not on any other error.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	var ne net.Error // *url.Error from the HTTP client: timeout or transport failure
	return errors.As(err, &ne)
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
