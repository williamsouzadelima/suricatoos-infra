package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"unicode/utf16"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

func TestParseWUAUpdates_Array(t *testing.T) {
	ups, err := parseWUAUpdates(readGolden(t, "wua-updates.json"), "microsoft-update")
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("want 2 updates, got %d", len(ups))
	}
	u0 := ups[0]
	if u0.KB != "KB5036892" {
		t.Errorf("kb normalized = %q, want KB5036892", u0.KB)
	}
	if u0.MSRCSeverity != "Important" {
		t.Errorf("severity = %q, want Important (verbatim from source)", u0.MSRCSeverity)
	}
	if !u0.RebootRequired {
		t.Error("reboot_required should be true for u0")
	}
	if u0.Source != "microsoft-update" {
		t.Errorf("source = %q, want microsoft-update", u0.Source)
	}
	if len(u0.Categories) != 1 || u0.Categories[0] != "Security Updates" {
		t.Errorf("categories = %v", u0.Categories)
	}
	if u0.UpdateID == "" {
		t.Error("update_id must be preserved")
	}
	if ups[1].KB != "KB5037768" || ups[1].MSRCSeverity != "Critical" {
		t.Errorf("second update mismapped: %+v", ups[1])
	}
}

func TestParseWUAUpdates_SingleObjectCollapse(t *testing.T) {
	// PowerShell 5.1 emits a bare object (not a 1-element array) — must still parse.
	ups, err := parseWUAUpdates(readGolden(t, "wua-single.json"), "wsus")
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 {
		t.Fatalf("want 1 update from single object, got %d", len(ups))
	}
	if ups[0].KB != "KB5037768" || ups[0].Source != "wsus" {
		t.Errorf("single update mismapped: %+v", ups[0])
	}
}

func TestParseWUAUpdates_EmptyNullArray(t *testing.T) {
	for _, in := range []string{"", "   ", "null"} {
		if ups, err := parseWUAUpdates([]byte(in), "microsoft-update"); err != nil || len(ups) != 0 {
			t.Errorf("parse %q = (%v, %v), want (empty, nil)", in, ups, err)
		}
	}
	if ups, err := parseWUAUpdates([]byte("[]"), "microsoft-update"); err != nil || len(ups) != 0 {
		t.Errorf("parse [] = (%v, %v), want (empty, nil)", ups, err)
	}
}

func TestNormalizeKB(t *testing.T) {
	cases := map[string]string{
		"5036892":           "KB5036892",
		"KB5036892":         "KB5036892",
		"kb5036892":         "KB5036892",
		"  5036892  ":       "KB5036892",
		"5036892,5036893":   "KB5036892", // keep the first
		"":                  "",
		"SecurityIntel-def": "SecurityIntel-def", // non-numeric, no KB prefix → unchanged
	}
	for in, want := range cases {
		if got := normalizeKB(in); got != want {
			t.Errorf("normalizeKB(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseManagement(t *testing.T) {
	m, err := parseManagement(readGolden(t, "management.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("management should not be nil")
	}
	if !m.DomainJoined || !m.WSUSConfigured || m.WSUSURL == "" || m.IntuneEnrolled {
		t.Errorf("management mismapped: %+v", m)
	}
}

func TestParseManagement_EmptyNull(t *testing.T) {
	for _, in := range []string{"", "null"} {
		if m, err := parseManagement([]byte(in)); err != nil || m != nil {
			t.Errorf("parseManagement(%q) = (%v, %v), want (nil, nil)", in, m, err)
		}
	}
}

func TestSourceFor(t *testing.T) {
	if got := sourceFor(nil); got != "microsoft-update" {
		t.Errorf("sourceFor(nil) = %q, want microsoft-update", got)
	}
	if got := sourceFor(&inventory.Management{WSUSConfigured: true}); got != "wsus" {
		t.Errorf("sourceFor(wsus) = %q, want wsus", got)
	}
	if got := sourceFor(&inventory.Management{}); got != "microsoft-update" {
		t.Errorf("sourceFor(no-wsus) = %q, want microsoft-update", got)
	}
}

func TestCollectMissingUpdates_StampsSourceAndCallsPowerShell(t *testing.T) {
	golden := readGolden(t, "wua-updates.json")
	var gotName string
	var gotArgs []string
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return golden, nil
	}
	ups, err := collectMissingUpdates(context.Background(), run, "wsus")
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 || ups[0].Source != "wsus" {
		t.Fatalf("collect mapped wrong: %+v", ups)
	}
	if gotName != "powershell.exe" {
		t.Errorf("ran %q, want powershell.exe", gotName)
	}
	if len(gotArgs) < 6 || gotArgs[0] != "-NoProfile" || gotArgs[4] != "-EncodedCommand" {
		t.Fatalf("unexpected args: %v", gotArgs)
	}
	if decoded := decodePowerShellEncoded(t, gotArgs[5]); decoded != wuaMissingScript {
		t.Errorf("encoded command did not round-trip to the WUA script")
	}
}

func TestCollectMissingUpdates_RunnerErrorPropagates(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("powershell exited 1")
	}
	if _, err := collectMissingUpdates(context.Background(), run, "microsoft-update"); err == nil {
		t.Fatal("a runner error must propagate (caller decides to omit, non-fatally)")
	}
}

func TestCollectManagement_FakeRunner(t *testing.T) {
	golden := readGolden(t, "management.json")
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return golden, nil
	}
	m, err := collectManagement(context.Background(), run)
	if err != nil || m == nil || !m.DomainJoined {
		t.Fatalf("collectManagement = (%+v, %v)", m, err)
	}
}

func TestEncodePowerShellRoundTrip(t *testing.T) {
	if got := decodePowerShellEncoded(t, encodePowerShellCommand(managementScript)); got != managementScript {
		t.Error("UTF-16LE/base64 round-trip corrupted the script")
	}
}

// decodePowerShellEncoded reverses encodePowerShellCommand for assertions.
func decodePowerShellEncoded(t *testing.T, enc string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u))
}
