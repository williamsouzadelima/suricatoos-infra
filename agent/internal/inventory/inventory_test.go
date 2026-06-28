package inventory

import (
	"encoding/json"
	"testing"
	"time"
)

func baseInventory() *Inventory {
	return &Inventory{
		SchemaVersion: SchemaVersion,
		Agent:         Agent{AgentID: "abc", AgentVersion: "0.1.0", Hostname: "h1"},
		CollectedAt:   time.Unix(1700000000, 0).UTC(),
		OS:            OS{Family: Linux, Distro: "debian", Release: "12", Arch: "amd64"},
		Packages: []Package{
			{Name: "openssl", Version: "3.0.11-1~deb12u1", Arch: "amd64", Source: SourceDpkg},
			{Name: "bash", Version: "5.2.15-1", Arch: "amd64", Source: SourceDpkg},
		},
	}
}

func TestComputeCycleHashIsOrderIndependent(t *testing.T) {
	inv := baseInventory()
	h1 := inv.ComputeCycleHash()

	reordered := baseInventory()
	reordered.Packages[0], reordered.Packages[1] = reordered.Packages[1], reordered.Packages[0]
	if got := reordered.ComputeCycleHash(); got != h1 {
		t.Fatalf("hash must be order-independent: %s != %s", got, h1)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64-hex SHA-256, got %d chars", len(h1))
	}
}

func TestComputeCycleHashIgnoresTimestamp(t *testing.T) {
	inv := baseInventory()
	h1 := inv.ComputeCycleHash()
	inv.CollectedAt = inv.CollectedAt.Add(48 * time.Hour)
	if got := inv.ComputeCycleHash(); got != h1 {
		t.Fatalf("timestamp must not affect cycle hash: %s != %s", got, h1)
	}
}

func TestComputeCycleHashChangesOnPackageChange(t *testing.T) {
	h1 := baseInventory().ComputeCycleHash()
	patched := baseInventory()
	patched.Packages[0].Version = "3.0.11-1~deb12u2" // a security update landed
	if got := patched.ComputeCycleHash(); got == h1 {
		t.Fatal("hash must change when an observed package version changes")
	}
}

func TestInventoryJSONRoundTrip(t *testing.T) {
	inv := baseInventory()
	inv.Packages[0].FullName = "openssl-3.0.11-1~deb12u1.amd64"
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Inventory
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SchemaVersion != SchemaVersion || len(got.Packages) != 2 || got.Packages[0].Name != "openssl" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Packages[0].FullName != "openssl-3.0.11-1~deb12u1.amd64" {
		t.Fatalf("full_name not preserved: %q", got.Packages[0].FullName)
	}
}
