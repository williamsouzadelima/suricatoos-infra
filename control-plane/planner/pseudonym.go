package planner

import (
	"fmt"
	"sort"
	"strings"
)

// pseudonymizer replaces identifying values with stable opaque tokens (host-1,
// ip-1, …) before anything is sent to the model, and restores them in the model's
// output. The mapping lives only for the duration of one Plan call (in memory).
type pseudonymizer struct {
	fwd      map[string]string // real → token
	rev      map[string]string // token → real
	counters map[string]int
}

func newPseudonymizer() *pseudonymizer {
	return &pseudonymizer{fwd: map[string]string{}, rev: map[string]string{}, counters: map[string]int{}}
}

// token returns (creating if needed) the opaque token for a real value under a
// prefix. Empty input yields empty output (nothing to pseudonymize).
func (p *pseudonymizer) token(real, prefix string) string {
	real = strings.TrimSpace(real)
	if real == "" {
		return ""
	}
	if t, ok := p.fwd[real]; ok {
		return t
	}
	p.counters[prefix]++
	t := fmt.Sprintf("%s-%d", prefix, p.counters[prefix])
	p.fwd[real] = t
	p.rev[t] = real
	return t
}

// scrub replaces every registered real value found in s with its token. Longer
// values are replaced first so a short value can't partially mangle a longer one.
func (p *pseudonymizer) scrub(s string) string {
	if s == "" {
		return s
	}
	keys := make([]string, 0, len(p.fwd))
	for k := range p.fwd {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, real := range keys {
		s = strings.ReplaceAll(s, real, p.fwd[real])
	}
	return s
}

// restore replaces every token found in s with its real value (for the operator's
// copy of the drafted plan).
func (p *pseudonymizer) restore(s string) string {
	if s == "" {
		return s
	}
	keys := make([]string, 0, len(p.rev))
	for k := range p.rev {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, tok := range keys {
		s = strings.ReplaceAll(s, tok, p.rev[tok])
	}
	return s
}

// apply returns a copy of req with identifying fields tokenized and free-text
// fields scrubbed, so NO raw identifier reaches the model.
func (p *pseudonymizer) apply(req PlanRequest) PlanRequest {
	// Register identifiers first so scrub() also catches them inside free text.
	host := p.token(req.Host, "host")
	agent := p.token(req.AgentID, "agent")
	tenant := p.token(req.Tenant, "tenant")
	ip := p.token(req.IP, "ip")

	out := req
	out.Host, out.AgentID, out.Tenant, out.IP = host, agent, tenant, ip
	out.Title = p.scrub(req.Title)
	out.Evidence = p.scrub(req.Evidence)
	return out
}
