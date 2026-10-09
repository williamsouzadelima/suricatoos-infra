package correlation

import (
	"hash/fnv"
	"strconv"
	"strings"
	"time"
)

// HardeningCorrelator evaluates a Windows host's neutral security-configuration
// readings (Inventory.CISState) against an AUTHORED CIS L1 ruleset and emits a
// finding per non-compliant setting (ADR-0009).
//
// Non-fabrication: a finding needs a MEASURED value (a rule whose setting the
// agent did not report yields nothing). Severity is a FIXED editorial property
// of the rule, never computed per host and never from an LLM. The rule titles
// and remediation text are our own prose; only the CIS rule NUMBER is cited
// (a reference, carried in evidence.matched_advisory).
type HardeningCorrelator struct {
	rules []hardeningRule
}

// hardeningRule is one authored CIS L1 check.
type hardeningRule struct {
	source    string
	key       string
	ref       string // CIS rule number, reference only
	title     string // our own short description
	expected  string // human-readable expectation (evidence)
	severity  float64
	compliant func(value string) bool
}

func num(v string) (int, bool) {
	x, err := strconv.Atoi(strings.TrimSpace(v))
	return x, err == nil
}

func atLeast(n int) func(string) bool {
	return func(v string) bool { x, ok := num(v); return ok && x >= n }
}
func between(lo, hi int) func(string) bool {
	return func(v string) bool { x, ok := num(v); return ok && x >= lo && x <= hi }
}
func equals(want string) func(string) bool {
	return func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), want) }
}
func hasLabel(label string) func(string) bool {
	return func(v string) bool {
		for _, p := range strings.Split(v, ",") {
			if strings.TrimSpace(p) == label {
				return true
			}
		}
		return false
	}
}
func auditSuccessAndFailure() func(string) bool {
	return func(v string) bool {
		s := strings.ToLower(v)
		return strings.Contains(s, "success") && strings.Contains(s, "failure")
	}
}

// cisL1Rules is the authored CIS L1 ruleset (seed set). Severities are our own
// editorial calls. Expand over time; the correlator only ever acts on a rule
// whose setting the agent actually measured.
var cisL1Rules = []hardeningRule{
	{"secedit", "PasswordHistorySize", "CIS 1.1.1", "Password history too short", "24 or more", 4.0, atLeast(24)},
	{"secedit", "MaximumPasswordAge", "CIS 1.1.2", "Maximum password age does not force expiry", "1 to 365 days", 4.0, between(1, 365)},
	{"secedit", "MinimumPasswordAge", "CIS 1.1.3", "Minimum password age allows immediate reuse", "1 or more", 4.0, atLeast(1)},
	{"secedit", "MinimumPasswordLength", "CIS 1.1.4", "Password shorter than 14 characters", "14 or more", 6.0, atLeast(14)},
	{"secedit", "PasswordComplexity", "CIS 1.1.5", "Password complexity disabled", "1 (enabled)", 6.0, equals("1")},
	{"secedit", "ClearTextPassword", "CIS 1.1.7", "Reversible password encryption enabled", "0 (disabled)", 8.0, equals("0")},
	{"secedit", "LockoutBadCount", "CIS 1.2.2", "Account lockout threshold unset or too high", "1 to 5 (not 0)", 5.0, between(1, 5)},
	{"secedit", "SeDenyNetworkLogonRight", "CIS 2.2", "Guests not denied network logon", "includes Guests", 5.0, hasLabel("Guests")},
	{"registry", "UAC.EnableLUA", "CIS 2.3.17", "User Account Control disabled", "1 (enabled)", 8.0, equals("1")},
	{"registry", "Lsa.NoLMHash", "CIS 2.3.11", "LAN Manager hash storage not prevented", "1 (enabled)", 7.0, equals("1")},
	{"registry", "Lsa.LimitBlankPasswordUse", "CIS 2.3.1", "Blank passwords permitted beyond console", "1 (enabled)", 6.0, equals("1")},
	{"registry", "SMB.Server.RequireSecuritySignature", "CIS 2.3.9", "SMB server packet signing not required", "1 (required)", 6.0, equals("1")},
	{"service", "RemoteRegistry", "CIS 5", "Remote Registry service not disabled", "4 (disabled)", 6.0, equals("4")},
	{"auditpol", "Credential Validation", "CIS 17.1.1", "Credential Validation auditing incomplete", "Success and Failure", 4.0, auditSuccessAndFailure()},
	{"auditpol", "Logon", "CIS 17.5", "Logon auditing incomplete", "Success and Failure", 4.0, auditSuccessAndFailure()},
}

// NewHardeningCorrelator returns a correlator over the authored CIS L1 ruleset.
func NewHardeningCorrelator() *HardeningCorrelator {
	return &HardeningCorrelator{rules: cisL1Rules}
}

// Correlate emits a finding per non-compliant, MEASURED setting on a Windows
// host. Non-Windows or no cis_state → empty report.
func (h *HardeningCorrelator) Correlate(inv Inventory) (*FindingReport, error) {
	report := &FindingReport{
		SchemaVersion: "1.0.0",
		AgentID:       inv.Agent.AgentID,
		Host:          inv.Agent.Hostname,
		CollectedAt:   inv.CollectedAt,
	}
	if !strings.EqualFold(inv.OS.Family, "windows") || len(inv.CISState) == 0 {
		return report, nil
	}
	measured := make(map[string]string, len(inv.CISState))
	for _, s := range inv.CISState {
		measured[s.Source+"\x00"+s.Key] = s.Value
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range h.rules {
		val, ok := measured[r.source+"\x00"+r.key]
		if !ok {
			continue // not measured → no finding (non-fabrication)
		}
		if r.compliant(val) {
			continue // compliant → no finding
		}
		report.Findings = append(report.Findings, Finding{
			OID:             oidForHardening(r.source + "/" + r.key),
			Severity:        r.severity,
			SeverityOrigin:  "suricatoos-hardening-baseline",
			PackageObserved: r.key + "=" + val,
			PackageFixed:    r.expected,
			Specifier:       "==",
			Product:         r.title,
			Evidence:        Evidence{Source: "cis-hardening", MatchedAdvisory: r.ref},
			DetectedAt:      now,
		})
	}
	return report, nil
}

const hardeningOIDArc = "1.3.6.1.4.1.55683.3" // Suricatoos PEN, CIS-hardening sub-arc

// oidForHardening mints a stable, unique, numeric OID per rule (keyed by
// source/key, not the CIS number, so distinct rules never collide).
func oidForHardening(sourceKey string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sourceKey))
	return hardeningOIDArc + "." + strconv.FormatUint(uint64(h.Sum32()), 10)
}
