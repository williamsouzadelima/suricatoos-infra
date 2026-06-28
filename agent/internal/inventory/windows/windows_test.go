//go:build windows

package windows

import (
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

func fixture() []winEntry {
	return []winEntry{
		{name: "Git for Windows", version: "2.47.1", arch: "x86_64"},
		{name: "Mozilla Firefox", version: "132.0", arch: "x86_64"},
		{name: "Java 8 Update 421 (64-bit)", version: "8.0.4210.7", arch: "x86_64"},
		// Same package in 32-bit view (WOW6432Node) — should be deduped.
		{name: "Mozilla Firefox", version: "132.0", arch: "x86"},
		// Missing version — should be skipped.
		{name: "IncompleteApp", version: "", arch: "x86_64"},
	}
}

func TestCollect_Dedup(t *testing.T) {
	c := &Collector{
		enumKeys: func() ([]winEntry, error) { return fixture(), nil },
		osInfo:   func() (string, string, error) { return "22H2 (build 22621)", "amd64", nil },
	}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	// fixture has 5 entries, 1 empty-version skip + 1 cross-arch dedup → 3 unique
	if len(inv.Packages) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(inv.Packages), inv.Packages)
	}
	for _, p := range inv.Packages {
		if p.Source != inventory.SourceRegistry {
			t.Errorf("source = %q, want registry", p.Source)
		}
		if p.Name == "IncompleteApp" {
			t.Error("package with empty version must be excluded")
		}
	}
}

func TestCollect_OSInfo(t *testing.T) {
	c := &Collector{
		enumKeys: func() ([]winEntry, error) { return nil, nil },
		osInfo:   func() (string, string, error) { return "23H2 (build 22631)", "amd64", nil },
	}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Family != "windows" {
		t.Errorf("family = %q", inv.OS.Family)
	}
	if inv.OS.Release != "23H2 (build 22631)" {
		t.Errorf("release = %q", inv.OS.Release)
	}
}

func TestCollect_CycleHash(t *testing.T) {
	c := &Collector{
		enumKeys: func() ([]winEntry, error) { return fixture(), nil },
		osInfo:   func() (string, string, error) { return "22H2", "amd64", nil },
	}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.CycleHash) != 64 {
		t.Errorf("cycle_hash len = %d", len(inv.CycleHash))
	}
}
