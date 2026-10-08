package correlation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// MSRCCorrelator correlates a Windows host's precise patch level
// (10.0.<build>.<ubr>) against Microsoft MSRC CSAF advisories. A CVE applies
// when the host's build matches an advisory's affected build line AND the
// host's version is below the advisory's fixed threshold. Severity and CVE come
// verbatim from the CSAF document — never fabricated, never from an LLM
// (ADR-0001 D1, ADR-0008).
//
// It implements Correlator and is selected for OS.Family == "windows" by the
// Dispatcher; the Notus path (deb/rpm) is untouched.
type MSRCCorrelator struct {
	// byBuild indexes entries by Windows build number (the scope key), so a host
	// is only ever compared to advisories for its own release line.
	byBuild map[string][]msrcEntry
}

// NewMSRCCorrelator loads every *.json CSAF advisory under dir (recursively) and
// builds the build-keyed index. A document that fails to parse is skipped (a
// single malformed file never poisons the whole feed); the count of usable
// entries is what matters.
func NewMSRCCorrelator(dir string) (*MSRCCorrelator, error) {
	idx := map[string][]msrcEntry{}
	// The mirror directory may not exist yet (feed dark, or the first sync is
	// still pending): that is NOT an error — an empty index means a Windows host
	// simply gets no findings until the mirror fills. Only a real read failure
	// of an existing tree propagates.
	if _, serr := os.Stat(dir); os.IsNotExist(serr) {
		return &MSRCCorrelator{byBuild: idx}, nil
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // unreadable file: skip, don't abort the whole load
		}
		doc, perr := parseCSAF(raw)
		if perr != nil {
			return nil // malformed CSAF: skip
		}
		for _, e := range windowsEntries(doc) {
			idx[e.build] = append(idx[e.build], e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &MSRCCorrelator{byBuild: idx}, nil
}

// newMSRCCorrelatorFromEntries builds a correlator from pre-extracted entries
// (test helper / in-memory construction).
func newMSRCCorrelatorFromEntries(entries []msrcEntry) *MSRCCorrelator {
	idx := map[string][]msrcEntry{}
	for _, e := range entries {
		idx[e.build] = append(idx[e.build], e)
	}
	return &MSRCCorrelator{byBuild: idx}
}

// Correlate returns the Windows findings for a host. It is a no-op (empty
// report, no error) for any inventory that is not Windows or lacks a precise
// build.ubr — absence of a patch level is "cannot assess", never "clean".
func (c *MSRCCorrelator) Correlate(inv Inventory) (*FindingReport, error) {
	report := &FindingReport{
		SchemaVersion: "1.0.0",
		AgentID:       inv.Agent.AgentID,
		Host:          inv.Agent.Hostname,
		CollectedAt:   inv.CollectedAt,
	}
	if !strings.EqualFold(inv.OS.Family, "windows") || inv.OS.Build == "" || inv.OS.UBR == "" {
		return report, nil
	}
	hostVer := parseVersion("10.0." + inv.OS.Build + "." + inv.OS.UBR)
	if len(hostVer) == 0 {
		return report, nil
	}
	observed := "10.0." + inv.OS.Build + "." + inv.OS.UBR
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	for _, e := range c.byBuild[inv.OS.Build] {
		if !versionLess(hostVer, e.threshold) {
			continue // host is at or above the fixed build revision → patched
		}
		if seen[e.cve] {
			continue
		}
		seen[e.cve] = true

		fixed := versionString(e.threshold)
		if e.kb != "" {
			fixed += " (" + e.kb + ")"
		}
		report.Findings = append(report.Findings, Finding{
			OID:             oidForCVE(e.cve),
			CVE:             []string{e.cve},
			Severity:        e.severity,
			SeverityOrigin:  "msrc-csaf",
			PackageObserved: observed,
			PackageFixed:    fixed,
			Specifier:       ">=",
			Product:         e.productName,
			Evidence: Evidence{
				Source:          "msrc",
				MatchedAdvisory: e.cve,
			},
			DetectedAt: now,
		})
	}
	return report, nil
}

const msrcOIDArc = "1.3.6.1.4.1.55683.2" // Suricatoos PEN, MSRC-Windows sub-arc

// oidForCVE mints a stable numeric OID for a CVE in the Suricatoos private arc,
// so the finding satisfies finding.schema.json's numeric-OID rule even when no
// Greenbone NVT OID exists for it. "CVE-2024-38063" → "<arc>.2024.38063".
// A non-standard id falls back to its digit runs so the OID stays numeric.
func oidForCVE(cve string) string {
	rest := strings.TrimPrefix(strings.ToUpper(cve), "CVE-")
	parts := strings.Split(rest, "-")
	if len(parts) == 2 && isDigits(parts[0]) && isDigits(parts[1]) {
		return msrcOIDArc + "." + parts[0] + "." + parts[1]
	}
	var b strings.Builder
	for _, c := range cve {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return msrcOIDArc + ".0"
	}
	return msrcOIDArc + "." + b.String()
}

// versionString renders a parsed version back to dotted form.
func versionString(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}
