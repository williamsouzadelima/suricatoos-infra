package correlation

import (
	"os"
	"path/filepath"
	"testing"
)

func loadSampleDoc(t *testing.T) *csafDoc {
	t.Helper()
	raw, err := os.ReadFile("testdata/msrc_cve-sample.json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	doc, err := parseCSAF(raw)
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return doc
}

func entriesByBuild(entries []msrcEntry) map[string]msrcEntry {
	m := map[string]msrcEntry{}
	for _, e := range entries {
		m[e.build] = e
	}
	return m
}

func TestWindowsEntries_Extraction(t *testing.T) {
	entries := windowsEntries(loadSampleDoc(t))
	if len(entries) != 2 {
		t.Fatalf("want 2 entries (build 19045 + 22631), got %d: %+v", len(entries), entries)
	}
	byBuild := entriesByBuild(entries)
	e10, ok := byBuild["19045"]
	if !ok {
		t.Fatal("missing build 19045 entry")
	}
	if e10.cve != "CVE-2024-38063" || e10.kb != "KB5041580" || e10.severity != 9.8 {
		t.Errorf("19045 entry wrong: %+v", e10)
	}
	if got := versionString(e10.threshold); got != "10.0.19045.4780" {
		t.Errorf("19045 threshold = %q, want 10.0.19045.4780", got)
	}
	if e10.productName != "Windows 10 Version 22H2 for x64-based Systems" {
		t.Errorf("19045 product = %q", e10.productName)
	}
	if e22, ok := byBuild["22631"]; !ok || e22.kb != "KB5041585" {
		t.Errorf("22631 entry wrong: %+v", e22)
	}
}

func winInv(build, ubr string) Inventory {
	return Inventory{
		Agent:         AgentInfo{AgentID: "win1", Hostname: "w1"},
		OS:            OSInfo{Family: "windows", Distro: "windows", Release: "22H2", Build: build, UBR: ubr},
		SchemaVersion: "1.1.0",
	}
}

func sampleCorrelator(t *testing.T) *MSRCCorrelator {
	return newMSRCCorrelatorFromEntries(windowsEntries(loadSampleDoc(t)))
}

func TestMSRC_Correlate_Vulnerable(t *testing.T) {
	c := sampleCorrelator(t)
	rep, err := c.Correlate(winInv("19045", "4291")) // below 4780 → vulnerable
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	f := rep.Findings[0]
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2024-38063" {
		t.Errorf("cve = %v", f.CVE)
	}
	if f.Severity != 9.8 || f.SeverityOrigin != "msrc-csaf" {
		t.Errorf("severity = %v / %q (must come verbatim from CSAF)", f.Severity, f.SeverityOrigin)
	}
	if f.OID != "1.3.6.1.4.1.55683.2.2024.38063" {
		t.Errorf("oid = %q", f.OID)
	}
	if f.PackageObserved != "10.0.19045.4291" {
		t.Errorf("observed = %q", f.PackageObserved)
	}
	if f.PackageFixed != "10.0.19045.4780 (KB5041580)" {
		t.Errorf("fixed = %q", f.PackageFixed)
	}
	if f.Product != "Windows 10 Version 22H2 for x64-based Systems" {
		t.Errorf("product = %q", f.Product)
	}
	if f.Evidence.Source != "msrc" {
		t.Errorf("evidence source = %q", f.Evidence.Source)
	}
}

func TestMSRC_Correlate_Patched(t *testing.T) {
	c := sampleCorrelator(t)
	for _, ubr := range []string{"4780", "5000"} { // at or above the fix → clean
		rep, _ := c.Correlate(winInv("19045", ubr))
		if len(rep.Findings) != 0 {
			t.Errorf("ubr %s should be patched, got %d findings", ubr, len(rep.Findings))
		}
	}
}

func TestMSRC_Correlate_BuildScope(t *testing.T) {
	c := sampleCorrelator(t)
	// A build not in the index → no findings (no cross-release false positives).
	if rep, _ := c.Correlate(winInv("26100", "100")); len(rep.Findings) != 0 {
		t.Errorf("unknown build must yield 0 findings, got %d", len(rep.Findings))
	}
	// The 22631 line below its own threshold → the 22631 finding only.
	rep, _ := c.Correlate(winInv("22631", "4000"))
	if len(rep.Findings) != 1 || rep.Findings[0].Product != "Windows 11 Version 23H2 for x64-based Systems" {
		t.Errorf("22631/4000 want 1 win11 finding, got %+v", rep.Findings)
	}
	if rep2, _ := c.Correlate(winInv("22631", "4037")); len(rep2.Findings) != 0 {
		t.Errorf("22631/4037 is patched, got %d", len(rep2.Findings))
	}
}

func TestMSRC_Correlate_NotAssessable(t *testing.T) {
	c := sampleCorrelator(t)
	cases := []Inventory{
		{OS: OSInfo{Family: "linux", Distro: "debian", Release: "12"}}, // not windows
		{OS: OSInfo{Family: "windows", Build: "", UBR: "4291"}},        // no build
		{OS: OSInfo{Family: "windows", Build: "19045", UBR: ""}},       // no ubr
		{OS: OSInfo{Family: "windows", Build: "nonnumeric", UBR: "x"}}, // unparseable
	}
	for i, inv := range cases {
		if rep, err := c.Correlate(inv); err != nil || len(rep.Findings) != 0 {
			t.Errorf("case %d: want (0 findings, nil), got (%d, %v)", i, len(rep.Findings), err)
		}
	}
}

func TestOIDForCVE(t *testing.T) {
	if got := oidForCVE("CVE-2024-38063"); got != "1.3.6.1.4.1.55683.2.2024.38063" {
		t.Errorf("standard CVE oid = %q", got)
	}
	// Non-standard id still yields a numeric OID (schema requires ^[0-9.]+$).
	got := oidForCVE("ADV990001")
	if got != "1.3.6.1.4.1.55683.2.990001" {
		t.Errorf("fallback oid = %q", got)
	}
}

func TestKBFromURL(t *testing.T) {
	cases := map[string]string{
		"https://support.microsoft.com/help/5041580":   "KB5041580",
		"https://support.microsoft.com/help/KB5041585": "KB5041585",
		"https://support.microsoft.com/help/5041580/":  "KB5041580",
		"https://msrc.microsoft.com/update-guide/vuln": "", // no KB
		"": "",
	}
	for in, want := range cases {
		if got := kbFromURL(in); got != want {
			t.Errorf("kbFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersionLess(t *testing.T) {
	less := func(a, b string) bool { return versionLess(parseVersion(a), parseVersion(b)) }
	if !less("10.0.19045.4291", "10.0.19045.4780") {
		t.Error("4291 < 4780")
	}
	if less("10.0.19045.4780", "10.0.19045.4780") {
		t.Error("equal is not less")
	}
	if less("10.0.19045.5000", "10.0.19045.4780") {
		t.Error("5000 not < 4780")
	}
	if versionLess(nil, parseVersion("10.0.0.1")) {
		t.Error("empty is not less than anything")
	}
}

// fakeCorrelator records whether it was called and returns a sentinel finding.
type fakeCorrelator struct {
	tag    string
	called bool
}

func (f *fakeCorrelator) Correlate(inv Inventory) (*FindingReport, error) {
	f.called = true
	return &FindingReport{Findings: []Finding{{OID: f.tag}}}, nil
}

func TestDispatcher_RoutesByFamily(t *testing.T) {
	linux := &fakeCorrelator{tag: "linux"}
	win := &fakeCorrelator{tag: "windows"}
	d := NewDispatcher(map[string]Correlator{"linux": linux, "windows": win})

	rep, _ := d.Correlate(Inventory{OS: OSInfo{Family: "Windows"}}) // case-insensitive
	if !win.called || linux.called || len(rep.Findings) != 1 || rep.Findings[0].OID != "windows" {
		t.Errorf("windows inventory must route to the MSRC correlator: %+v", rep.Findings)
	}

	linux.called, win.called = false, false
	rep, _ = d.Correlate(Inventory{OS: OSInfo{Family: "linux"}})
	if !linux.called || win.called || rep.Findings[0].OID != "linux" {
		t.Errorf("linux inventory must route to the Notus correlator")
	}

	rep, _ = d.Correlate(Inventory{OS: OSInfo{Family: "darwin"}, Agent: AgentInfo{AgentID: "m"}})
	if len(rep.Findings) != 0 {
		t.Errorf("unregistered family must yield an empty report, got %+v", rep.Findings)
	}
}

func TestNewMSRCCorrelator_LoadsDir(t *testing.T) {
	// Copy the golden into a nested temp dir to exercise the recursive walk.
	dir := t.TempDir()
	sub := filepath.Join(dir, "2024")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/msrc_cve-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "msrc_cve-2024-38063.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := NewMSRCCorrelator(dir)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	rep, _ := c.Correlate(winInv("19045", "4291"))
	if len(rep.Findings) != 1 || rep.Findings[0].CVE[0] != "CVE-2024-38063" {
		t.Fatalf("dir-loaded correlator should find the CVE, got %+v", rep.Findings)
	}
}
