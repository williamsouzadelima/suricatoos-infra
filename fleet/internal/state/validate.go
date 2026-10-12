package state

import (
	"net"
	"regexp"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// The item caps of the schema (fleet-state.schema.json maxItems; a test compares them with the file).
const (
	maxTasks         = 5000
	maxTargets       = 5000
	maxSchedules     = 2000
	maxReports       = 2000
	maxAgents        = 20000
	maxTokens        = 5000
	maxSensors       = 1000
	maxScanRequests  = 5000
	maxRemediation   = 5000
	maxScopeItems    = 1000
	maxTargetHosts   = 256
	maxScheduleTasks = 256
	maxScopeEntries  = 1024
	maxFeeds         = 8
	maxAuditLines    = 200
	maxVariants      = 3
)

// The two patterns of fleet-state.schema.json that fleet/contract does not export.
const (
	patternGVMStatus = `^[A-Za-z][A-Za-z ]*$` // $defs/gvm_status
	patternJobID     = `^[A-Za-z0-9_-]+$`     // job_id of data_scan_requests and data_remediation
)

// rule mirrors one string definition of the schemas: its length in runes (JSON Schema counts code points), its
// pattern and its set of forbidden characters — no_control (C0, DEL, U+FFFE, U+FFFF) or, for the iCalendar, the
// same set minus TAB, CR and LF. Every string the state sends goes through one, so a value the schema would refuse
// never leaves: the item that carries it is dropped and counted instead. check, when set, is a test the schema
// cannot express (a real calendar instant; an IP/CIDR that really is a literal, not a hostname made of hex digits).
type rule struct {
	min, max int // max -1 = no maximum
	pattern  string
	ical     bool
	re       *regexp.Regexp
	check    func(string) bool
}

func newRule(min, max int, pattern string, check func(string) bool) rule {
	r := rule{min: min, max: max, pattern: pattern, check: check}
	if pattern != "" {
		r.re = regexp.MustCompile(pattern)
	}
	return r
}

var (
	ruleUUID        = newRule(36, 36, contract.PatternUUID, nil)
	ruleTenant      = newRule(1, 64, contract.PatternTenant, nil)
	ruleName        = newRule(1, 128, "", nil)
	ruleStatus      = newRule(1, 32, patternGVMStatus, nil)
	ruleUTC         = newRule(20, 20, contract.PatternUTCTime, realInstant)
	ruleVersion     = newRule(1, 64, contract.PatternVersionString, nil)
	ruleIPOrCIDR    = newRule(2, 43, contract.PatternIPOrCIDR, isLiteral)
	ruleAgentID     = newRule(1, 128, contract.PatternAgentID, nil)
	ruleTokenID     = newRule(8, 64, contract.PatternTokenID, nil)
	ruleJobID       = newRule(1, 64, patternJobID, nil)
	ruleTimezone    = newRule(1, 64, contract.PatternIANATimezone, nil)
	ruleSHA256      = newRule(64, 64, contract.PatternSHA256Hex, nil)
	ruleAliveTest   = newRule(0, 64, "", nil)
	ruleOSArch      = newRule(0, 32, "", nil)
	ruleTokenPolicy = newRule(0, 64, "", nil)
	ruleAuditLine   = newRule(2, 8192, "", nil)
	ruleCommandType = newRule(3, 64, contract.PatternCommandTypeAny, nil) // command_type_any (the events)
	ruleDetail      = newRule(0, 512, "", nil)                            // data_command_rejected.detail (the events)
	ruleICalendar   = func() rule {
		r := newRule(15, 8192, contract.PatternICalendar, nil)
		r.ical = true
		return r
	}()
)

// ok reports whether s satisfies the rule: valid UTF-8, the length, the forbidden characters, the pattern and check.
func (r rule) ok(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < r.min || (r.max >= 0 && n > r.max) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == 0xfffe || c == 0xffff {
			if !r.ical || (c != '\t' && c != '\r' && c != '\n') {
				return false
			}
		}
	}
	if r.re != nil && !r.re.MatchString(s) {
		return false
	}
	return r.check == nil || r.check(s)
}

// opt applies the rule to an optional member: absent is fine.
func (r rule) opt(s *string) bool { return s == nil || r.ok(*s) }

// The string rules the other packages of the connector check the contract values they send with — the events
// (package events) use the same rules as the state, each compared with the schema files by a test.
func ValidUUID(s string) bool        { return ruleUUID.ok(s) }        // uuid
func ValidTenant(s string) bool      { return ruleTenant.ok(s) }      // tenant
func ValidGVMStatus(s string) bool   { return ruleStatus.ok(s) }      // gvm_status
func ValidUTCTime(s string) bool     { return ruleUTC.ok(s) }         // utc_time, a real calendar instant
func ValidVersion(s string) bool     { return ruleVersion.ok(s) }     // version_string
func ValidAgentID(s string) bool     { return ruleAgentID.ok(s) }     // agent_id
func ValidJobID(s string) bool       { return ruleJobID.ok(s) }       // job_id of the ADR-0010 and ADR-0007 jobs
func ValidSHA256(s string) bool      { return ruleSHA256.ok(s) }      // sha256_hex
func ValidCommandType(s string) bool { return ruleCommandType.ok(s) } // command_type_any
func ValidDetail(s string) bool      { return ruleDetail.ok(s) }      // data_command_rejected.detail

func realInstant(s string) bool {
	_, err := contract.ParseUTCTime(s)
	return err == nil
}

// isLiteral reports whether s is an IP or CIDR LITERAL with the grammar of the scope gate (net.ParseIP /
// net.ParseCIDR: no hostname, range, port or zone). The schema's pattern alone lets through hostnames made only
// of hex digits, dots and colons ("cafe.be"), which must be counted, never listed.
func isLiteral(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
