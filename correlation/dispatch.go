package correlation

import "strings"

// Dispatcher routes an inventory to the right Correlator by OS family, so one
// pipeline handles deb/rpm (Notus) and Windows (MSRC) without either path
// knowing about the other. Linux stays exactly as before (zero regression);
// Windows now reaches the MSRC correlator.
//
// A family with no registered correlator yields an empty report (never an
// error, never a fabricated finding) — e.g. macOS, which collects inventory
// but has no correlation source yet.
type Dispatcher struct {
	byFamily map[string]Correlator
}

// NewDispatcher builds a Dispatcher. Family keys are matched case-insensitively.
func NewDispatcher(byFamily map[string]Correlator) *Dispatcher {
	norm := make(map[string]Correlator, len(byFamily))
	for fam, c := range byFamily {
		norm[strings.ToLower(fam)] = c
	}
	return &Dispatcher{byFamily: norm}
}

// Correlate dispatches on inv.OS.Family. An unregistered family returns an empty
// report scoped to the agent (no findings).
func (d *Dispatcher) Correlate(inv Inventory) (*FindingReport, error) {
	if c, ok := d.byFamily[strings.ToLower(inv.OS.Family)]; ok && c != nil {
		return c.Correlate(inv)
	}
	return &FindingReport{
		SchemaVersion: "1.0.0",
		AgentID:       inv.Agent.AgentID,
		Host:          inv.Agent.Hostname,
		CollectedAt:   inv.CollectedAt,
	}, nil
}
