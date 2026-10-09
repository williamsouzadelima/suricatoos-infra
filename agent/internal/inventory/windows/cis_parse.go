// CIS L1 posture parsers (build-tag-free so they unit-test on every CI platform,
// including ubuntu where `go test -race` runs). The Windows-only bits — running
// secedit/auditpol and reading the registry — live in the //go:build windows
// file and feed their raw text/results here.
//
// Output is NEUTRAL evidence: source + key + current value, no pass/fail and no
// CIS rule mapping (the server owns the benchmark ruleset, ADR-0009). Privilege
// Rights accounts are scrubbed to well-known SIDs so no arbitrary username or SID
// leaves the host (LGPD minimization).
package windows

import (
	"encoding/csv"
	"sort"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// wellKnownSIDs maps the SIDs CIS privilege-rights rules reference to a stable,
// non-identifying label. Anything not here is reduced to "custom-sid" /
// "custom-account" so no host-specific principal is ever reported.
var wellKnownSIDs = map[string]string{
	"S-1-0-0":      "Null",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-5-6":      "Service",
	"S-1-5-9":      "EnterpriseDomainControllers",
	"S-1-5-11":     "AuthenticatedUsers",
	"S-1-5-18":     "LocalSystem",
	"S-1-5-19":     "LocalService",
	"S-1-5-20":     "NetworkService",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "PowerUsers",
	"S-1-5-32-551": "BackupOperators",
	"S-1-5-32-555": "RemoteDesktopUsers",
	"S-1-5-32-559": "PerfLogUsers",
	"S-1-5-113":    "LocalAccount",
	"S-1-5-114":    "LocalAccountAndAdmin",
}

// scrubSID reduces one token to a non-identifying label. A leading "*" (secedit's
// SID marker) is stripped by the caller. Known SID → its label; any other SID →
// "custom-sid"; any non-SID token (a bare account name) → "custom-account".
func scrubSID(tok string) string {
	if label, ok := wellKnownSIDs[tok]; ok {
		return label
	}
	if strings.HasPrefix(tok, "S-1-") {
		return "custom-sid"
	}
	return "custom-account"
}

// scrubSIDList scrubs, de-dupes and SORTS a secedit privilege-rights value
// ("*S-1-5-32-544,*S-1-5-32-551"), returning a deterministic, non-identifying
// string ("Administrators,BackupOperators"). Sorting makes the reading stable
// regardless of enumeration order (good for dedupe hashing and comparison).
func scrubSIDList(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	seen := map[string]bool{}
	var labels []string
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(tok), "*"))
		if tok == "" {
			continue
		}
		label := scrubSID(tok)
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}
	sort.Strings(labels)
	return strings.Join(labels, ",")
}

// parseSeceditINF parses a `secedit /export` INF and returns the [System Access]
// (password/lockout policy) and [Privilege Rights] entries as neutral readings.
// Other sections are ignored. Privilege-rights values are SID-scrubbed.
func parseSeceditINF(text string) []inventory.CISState {
	var out []inventory.CISState
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}
		switch section {
		case "system access":
			out = append(out, inventory.CISState{Source: "secedit", Key: key, Value: val})
		case "privilege rights":
			out = append(out, inventory.CISState{Source: "secedit", Key: key, Value: scrubSIDList(val)})
		}
	}
	return out
}

// parseAuditpolCSV parses `auditpol /get /category:* /r` CSV output into neutral
// readings keyed by audit subcategory (value = inclusion setting). The machine
// name column is deliberately dropped (not reported).
func parseAuditpolCSV(text string) []inventory.CISState {
	var out []inventory.CISState
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return out
	}
	sub, inc := -1, -1
	for i, h := range rows[0] {
		switch strings.TrimSpace(h) {
		case "Subcategory":
			sub = i
		case "Inclusion Setting":
			inc = i
		}
	}
	if sub < 0 || inc < 0 {
		return out
	}
	for _, row := range rows[1:] {
		if len(row) <= sub || len(row) <= inc {
			continue
		}
		key := strings.TrimSpace(row[sub])
		val := strings.TrimSpace(row[inc])
		// Skip category header rows (no subcategory) and any stray repeat header.
		if key == "" || key == "Subcategory" || val == "" {
			continue
		}
		out = append(out, inventory.CISState{Source: "auditpol", Key: key, Value: val})
	}
	return out
}

// assembleCISFromText parses the secedit INF and auditpol CSV into one slice.
// Registry and service readings (Windows-only) are appended by the collector.
func assembleCISFromText(seceditINF, auditpolCSV string) []inventory.CISState {
	out := parseSeceditINF(seceditINF)
	out = append(out, parseAuditpolCSV(auditpolCSV)...)
	return out
}
