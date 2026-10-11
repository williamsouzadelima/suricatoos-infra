package enroll

import (
	"strings"
	"testing"
)

// ValidateAgentID is the single definition of a valid agent id (the command queue
// reuses it), so its edges are pinned here, where it lives.
func TestValidateAgentID(t *testing.T) {
	for _, id := range []string{
		"a", "agent-1", "srv-01.example_net", "Ünï-çode", "with space",
		strings.Repeat("a", 128), // the limit is in bytes...
		strings.Repeat("é", 64),  // ...so 64 two-byte runes still fit
	} {
		if err := ValidateAgentID(id); err != nil {
			t.Errorf("ValidateAgentID(%q) = %v, want ok", id, err)
		}
	}
	for name, id := range map[string]string{
		"empty":               "",
		"129 bytes":           strings.Repeat("a", 129),
		"130 bytes, 65 runes": strings.Repeat("é", 65),
		"comma":               "a,b",
		"equals":              "a=b",
		"plus":                "a+b",
		"double quote":        `a"b`,
		"backslash":           `a\b`,
		"semicolon":           "a;b",
		"less-than":           "a<b",
		"greater-than":        "a>b",
		"NUL":                 "a\x00b",
		"unit separator":      "a\x1fb",
		"DEL":                 "a\x7fb",
		"newline":             "a\nb",
		"tab":                 "a\tb",
	} {
		if err := ValidateAgentID(id); err == nil {
			t.Errorf("%s: ValidateAgentID(%q) accepted an invalid id", name, id)
		}
	}
}
