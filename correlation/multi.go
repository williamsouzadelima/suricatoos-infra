package correlation

// MultiCorrelator runs several correlators over the same inventory and
// concatenates their findings into one report. It lets a single OS family be
// served by more than one source — on Windows, MSRC (CVE/patch) AND the CIS L1
// hardening ruleset — without either correlator knowing about the other.
//
// A nil member is skipped. The first error aborts (a correlator failing is a
// real fault, not an empty result).
type MultiCorrelator struct {
	correlators []Correlator
}

// NewMultiCorrelator builds a MultiCorrelator from the given correlators (order
// preserved; nils tolerated).
func NewMultiCorrelator(cs ...Correlator) *MultiCorrelator {
	return &MultiCorrelator{correlators: cs}
}

// Correlate merges the findings of every member correlator. The report envelope
// (agent/host/collected_at) comes from the first member that runs; with no
// members it is still a valid empty report for the inventory.
func (m *MultiCorrelator) Correlate(inv Inventory) (*FindingReport, error) {
	var out *FindingReport
	for _, c := range m.correlators {
		if c == nil {
			continue
		}
		rep, err := c.Correlate(inv)
		if err != nil {
			return nil, err
		}
		if out == nil {
			out = rep
			continue
		}
		out.Findings = append(out.Findings, rep.Findings...)
	}
	if out == nil {
		out = &FindingReport{
			SchemaVersion: "1.0.0",
			AgentID:       inv.Agent.AgentID,
			Host:          inv.Agent.Hostname,
			CollectedAt:   inv.CollectedAt,
		}
	}
	return out, nil
}
