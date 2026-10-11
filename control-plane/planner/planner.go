package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// Governance refusals (no model call happens on any of them).
var (
	ErrConsentOff   = errors.New("consentimento de IA desativado para esta finalidade (default off)")
	ErrBudget       = errors.New("orçamento mensal de IA excedido")
	ErrNonFreeModel = errors.New("recusado pela regra de modelos gratuitos (AI_FREE_MODELS_ONLY=true)")
	// ErrUngoverned: with the free-models rule off, every candidate failed the
	// governance bar at use time (neither UE + ZDR nor a free model acknowledged).
	ErrUngoverned = errors.New("provedor fora da régua de governança da IA")
	// ErrTimeout: the planner's overall time budget (Config.Timeout, all providers
	// and formats together) ran out; the remaining attempts were not made.
	ErrTimeout = errors.New("tempo total do planner esgotado (AI_PLANNER_TIMEOUT)")
)

// defaultTimeout is the overall budget of one Plan when Config.Timeout is unset.
const defaultTimeout = 5 * time.Minute

// Config carries the governance knobs. Consent is OFF by default (a zero Config
// never calls a model); the budget ceiling refuses runaway spend.
type Config struct {
	ConsentGranted   bool    // per-purpose consent; DEFAULT false (born off)
	MonthlyBudgetUSD float64 // <= 0 → no ceiling
	USDPer1kTokens   float64 // estimate used only for the budget gate
	// FreeModelsOnly selects the governance bar every provider must meet at use
	// time, before any network (aiproviders.GovernanceRefusal): on, only a free
	// model on its router's official endpoint, acknowledged by the operator; off,
	// UE + ZDR or such a free model acknowledged. The control-plane turns it on by
	// default (AI_FREE_MODELS_ONLY); the zero Config leaves it off.
	FreeModelsOnly bool
	// Timeout is the OVERALL budget of one Plan — every provider and every
	// response-format attempt together (AI_PLANNER_TIMEOUT). <= 0 → 5 minutes.
	Timeout time.Duration
}

// Planner drafts advisory remediation plans. It holds the LLM seam, a provider
// resolver, the budget, and the governance config — it owns WHETHER and HOW a
// draft is produced, never WHETHER to apply one.
type Planner struct {
	llm       LLM
	providers ProviderResolver
	budget    *budget
	cfg       Config
	timeout   time.Duration
}

// New builds a Planner. A missing token rate falls back to a conservative
// placeholder purely for the budget estimate; a missing overall timeout to 5 min.
func New(llm LLM, providers ProviderResolver, cfg Config) *Planner {
	rate := cfg.USDPer1kTokens
	if rate <= 0 {
		rate = 0.005
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Planner{
		llm:       llm,
		providers: providers,
		budget:    newBudget(cfg.MonthlyBudgetUSD, rate, nil),
		cfg:       cfg,
		timeout:   timeout,
	}
}

// Timeout is the overall time budget of one Plan (the plan route sizes its write
// deadline from it).
func (p *Planner) Timeout() time.Duration { return p.timeout }

// Plan drafts a remediation plan for an attested finding. It refuses (no model
// call) when consent is off; it pseudonymizes before send, restores identifiers in
// the draft, and ECHOES the attested severity/CVEs (never the model's). The
// returned Plan is always a Draft for human review.
//
// The resolved providers are tried in priority order. A provider is never called
// unless it meets, right now, the same governance bar the registry applies to
// enable one (refusal): one that fails it is skipped, with the reason in the log.
// A paid model is called only within the budget, while a FREE model (on its
// router's official endpoint) costs 0 (it neither needs nor consumes budget). On
// any non-2xx answer, timeout or network error the next provider is tried; an
// error with no status (a 2xx without usable content) stops. When all fail, the
// error lists each attempt (status and a short, sanitized excerpt; never a key).
// Everything — every provider and every response-format attempt — runs inside ONE
// overall budget (Config.Timeout): when it runs out the current attempt is
// cancelled and no other one starts (ErrTimeout).
func (p *Planner) Plan(ctx context.Context, req PlanRequest) (*Plan, error) {
	if !p.cfg.ConsentGranted {
		return nil, ErrConsentOff
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
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
		if why := p.refusal(prov); why != "" {
			// Name and settings only — never a key.
			log.Printf("remediation-planner: provedor %q pulado: %s", prov.Name, why)
			refused = append(refused, fmt.Sprintf("%s (%s)", prov.Name, why))
			continue
		}
		free := aiproviders.IsFree(prov.Kind, prov.BaseURL, prov.Model)
		if !free && !p.budget.allow() {
			budgetSpent = true
			continue
		}
		if ctx.Err() != nil {
			break // overall budget gone: no new attempt starts
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
				// The error carries the status and, at most, a short sanitized
				// excerpt of the provider's body (StatusError) — never the key.
				log.Printf("remediation-planner: provedor %q falhou, tentando o próximo: %v", prov.Name, err)
				failures = append(failures, fmt.Sprintf("%s: %v", prov.Name, err))
				continue
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("%w: %s: %v", ErrTimeout, prov.Name, err)
			}
			return nil, fmt.Errorf("chamada ao modelo (%s): %w", prov.Name, err)
		}
		if !free {
			p.budget.add(resp.Usage)
		}
		return p.draft(req, ps, prov, resp.Content)
	}

	skipped := ""
	if len(refused) > 0 {
		skipped = "; pulados: " + strings.Join(refused, "; ")
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && len(failures) > 0:
		return nil, fmt.Errorf("%w (%s)", ErrTimeout, strings.Join(failures, "; "))
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, ErrTimeout
	case ctx.Err() != nil:
		return nil, fmt.Errorf("pedido cancelado antes do rascunho: %w", ctx.Err())
	case len(failures) > 0:
		return nil, fmt.Errorf("chamada ao modelo: nenhum provedor respondeu (%s)%s", strings.Join(failures, "; "), skipped)
	case budgetSpent:
		return nil, ErrBudget
	case len(refused) > 0 && p.cfg.FreeModelsOnly:
		return nil, fmt.Errorf("%w: %s", ErrNonFreeModel, strings.Join(refused, "; "))
	case len(refused) > 0:
		return nil, fmt.Errorf("%w: %s", ErrUngoverned, strings.Join(refused, "; "))
	default:
		return nil, errors.New("provedor: nenhum provedor de IA habilitado")
	}
}

// refusal says why prov may not be called at all ("" = it may): the SAME
// governance bar the registry applies to enable a provider
// (aiproviders.GovernanceRefusal), checked again at use time. A record stored
// under the other rule, before a rule existed, or rewritten by an older image
// (which drops the acknowledgment) never reaches the network on the strength of
// its "enabled" flag alone; with the rule on, a stored key only ever goes to the
// router's official endpoint, where ":free" means zero cost.
func (p *Planner) refusal(prov Provider) string {
	return aiproviders.GovernanceRefusal(aiproviders.Terms{
		Kind: prov.Kind, BaseURL: prov.BaseURL, Model: prov.Model,
		EURegion: prov.EURegion, ZDR: prov.ZDR, DataPolicyAck: prov.DataPolicyAck,
	}, p.cfg.FreeModelsOnly)
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
// ANY non-2xx answer — the provider's own response-format fallback already ran
// (HTTPLLM.Chat) — and any timeout or network error. One router's 4xx (a model
// gone from its catalog, a data-policy mismatch, a key it refuses) says nothing
// about the next router. Not when the caller's own context is done (the
// operator's request went away, or the overall budget ran out), and not on an
// error with no status (a 2xx without usable content).
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return true
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
