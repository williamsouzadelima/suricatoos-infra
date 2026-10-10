// Package planner is the governed AI that drafts a remediation plan from an
// ATTESTED finding. It is strictly advisory (ADR-0010 / reports governance):
//
//   - It NEVER originates a finding or a severity. The severity/CVEs come verbatim
//     from the attested finding (PlanRequest) and are passed through to the Plan;
//     the model only writes prose/steps. The output schema has no severity field.
//   - It NEVER decides, approves, or applies. A Plan is a DRAFT a human reviews
//     before anything is enqueued/approved. Draft is always true.
//   - It pseudonymizes identifying context (host/agent/tenant/IP) before any data
//     leaves the process, enforces per-purpose consent (default OFF) and a spend
//     budget, and talks to the LLM only through an injected seam.
//
// THIS slice (core) ships NO network client — the LLM is an interface a later,
// separately-reviewed slice implements against the configured provider.
package planner

// PlanRequest is the attested finding the planner drafts a plan for. The technical
// facts (title/severity/cve/rule_ref/kb/evidence/os) are passed through verbatim;
// the identifying fields (host/agent/tenant/ip) are pseudonymized before send.
type PlanRequest struct {
	FindingID      string
	CorrelationID  string
	Type           string   // "package_patch" | "config_hardening" (hint for the plan)
	Title          string   // attested finding title (verbatim)
	Severity       string   // attested severity (verbatim; the planner NEVER changes it)
	SeverityOrigin string   // provenance, e.g. "msrc-cvrf" (audit)
	CVEs           []string // verbatim
	RuleRef        string   // CIS rule number (config_hardening)
	KB             string   // Windows KB (package_patch)
	Evidence       string   // e.g. "current=0 expected=1" or "missing KB5041580"
	OS             string   // os family/version (kept; not identifying)

	// Identifying context — PSEUDONYMIZED before anything is sent to the model.
	Host    string
	AgentID string
	Tenant  string
	IP      string
}

// PlanStep is one ordered action in the drafted plan.
type PlanStep struct {
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
}

// Plan is the drafted remediation plan returned to the operator for review. The
// attested fields (Severity/SeverityOrigin/CVEs) are echoed from the request, not
// produced by the model.
type Plan struct {
	FindingID      string     `json:"finding_id"`
	CorrelationID  string     `json:"correlation_id"`
	Severity       string     `json:"severity"`        // attested passthrough
	SeverityOrigin string     `json:"severity_origin"` // attested passthrough
	CVEs           []string   `json:"cves,omitempty"`  // attested passthrough
	Summary        string     `json:"summary"`
	Steps          []PlanStep `json:"steps"`
	Rationale      string     `json:"rationale,omitempty"`
	Prioritization string     `json:"prioritization,omitempty"`
	Caveats        string     `json:"caveats,omitempty"`
	Provider       string     `json:"provider"` // which provider drafted it (audit)
	Model          string     `json:"model"`
	Draft          bool       `json:"draft"` // always true — advisory, needs human review
}

// llmDraft is the model's structured output. It deliberately has NO severity/CVE
// field — those are the attested finding's, never the model's to set.
type llmDraft struct {
	Summary        string     `json:"summary"`
	Steps          []PlanStep `json:"steps"`
	Rationale      string     `json:"rationale"`
	Prioritization string     `json:"prioritization"`
	Caveats        string     `json:"caveats"`
}
