package correlation

import "testing"

func winHardeningInv(states []CISStateInfo) Inventory {
	return Inventory{
		SchemaVersion: "1.2.0",
		Agent:         AgentInfo{AgentID: "win1", Hostname: "w1"},
		OS:            OSInfo{Family: "windows", Distro: "windows", Release: "22H2"},
		CISState:      states,
	}
}

func findingByProduct(rep *FindingReport) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range rep.Findings {
		m[f.Product] = f
	}
	return m
}

func TestHardening_FlagsOnlyMeasuredNonCompliant(t *testing.T) {
	inv := winHardeningInv([]CISStateInfo{
		{Source: "secedit", Key: "MinimumPasswordLength", Value: "8"},        // < 14 → finding
		{Source: "secedit", Key: "PasswordComplexity", Value: "1"},           // compliant → none
		{Source: "registry", Key: "UAC.EnableLUA", Value: "0"},               // disabled → finding
		{Source: "registry", Key: "Lsa.NoLMHash", Value: "1"},                // compliant → none
		{Source: "service", Key: "RemoteRegistry", Value: "2"},               // not disabled → finding
		{Source: "auditpol", Key: "Credential Validation", Value: "Success"}, // not both → finding
		// SeDenyNetworkLogonRight NOT measured → must NOT produce a finding
	})
	rep, err := NewHardeningCorrelator().Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 4 {
		t.Fatalf("want 4 findings, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	byProd := findingByProduct(rep)
	f := byProd["Password shorter than 14 characters"]
	if f.SeverityOrigin != "suricatoos-hardening-baseline" {
		t.Errorf("severity_origin = %q", f.SeverityOrigin)
	}
	if f.Severity != 6.0 {
		t.Errorf("severity = %v (fixed rule property)", f.Severity)
	}
	if f.Evidence.Source != "cis-hardening" || f.Evidence.MatchedAdvisory != "CIS 1.1.4" {
		t.Errorf("evidence = %+v", f.Evidence)
	}
	if f.PackageObserved != "MinimumPasswordLength=8" || f.PackageFixed != "14 or more" {
		t.Errorf("observed/expected = %q / %q", f.PackageObserved, f.PackageFixed)
	}
	for _, f := range rep.Findings {
		if f.OID == "" || f.OID[:len(hardeningOIDArc)] != hardeningOIDArc {
			t.Errorf("OID not in hardening arc: %q", f.OID)
		}
	}
}

func TestHardening_NotMeasuredNeverFabricates(t *testing.T) {
	// A compliant/empty host must produce nothing, and a non-Windows host too.
	if rep, _ := NewHardeningCorrelator().Correlate(winHardeningInv(nil)); len(rep.Findings) != 0 {
		t.Error("no cis_state → no findings")
	}
	linux := Inventory{OS: OSInfo{Family: "linux"}, CISState: []CISStateInfo{{Source: "secedit", Key: "MinimumPasswordLength", Value: "1"}}}
	if rep, _ := NewHardeningCorrelator().Correlate(linux); len(rep.Findings) != 0 {
		t.Error("non-windows → no hardening findings")
	}
}

func TestHardening_OIDsAreUniquePerRule(t *testing.T) {
	seen := map[string]string{}
	for _, r := range cisL1Rules {
		oid := oidForHardening(r.source + "/" + r.key)
		if prev, dup := seen[oid]; dup {
			t.Fatalf("OID collision %s: %s/%s vs %s", oid, r.source, r.key, prev)
		}
		seen[oid] = r.source + "/" + r.key
	}
}

func TestMultiCorrelator_MergesFindings(t *testing.T) {
	a := &fakeCorrelator{tag: "a"}
	b := &fakeCorrelator{tag: "b"}
	rep, err := NewMultiCorrelator(a, nil, b).Correlate(Inventory{OS: OSInfo{Family: "windows"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("want 2 merged findings, got %d", len(rep.Findings))
	}
	oids := map[string]bool{}
	for _, f := range rep.Findings {
		oids[f.OID] = true
	}
	if !oids["a"] || !oids["b"] {
		t.Errorf("both correlators' findings must be present: %+v", rep.Findings)
	}
}

func TestMultiCorrelator_EmptyStillValid(t *testing.T) {
	rep, err := NewMultiCorrelator().Correlate(Inventory{Agent: AgentInfo{AgentID: "x", Hostname: "h"}})
	if err != nil || rep == nil || len(rep.Findings) != 0 || rep.AgentID != "x" {
		t.Fatalf("empty multi must yield a valid empty report: %+v err=%v", rep, err)
	}
}
