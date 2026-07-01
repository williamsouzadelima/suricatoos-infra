package ingest

import (
	"encoding/json"
	"testing"
)

func TestToCorrelationInventory_Conversion(t *testing.T) {
	rawPkg := json.RawMessage(`{"name":"openssl","version":"1.1.1n-0+deb11u3","arch":"amd64","source":"dpkg","full_name":"openssl-1.1.1n-0+deb11u3.amd64"}`)
	inv := Inventory{
		SchemaVersion: "1.0.0",
		Agent: struct {
			AgentID  string `json:"agent_id"`
			Hostname string `json:"hostname"`
		}{AgentID: "a1", Hostname: "host1"},
		OS: struct {
			Family  string `json:"family"`
			Distro  string `json:"distro"`
			Release string `json:"release"`
		}{Family: "linux", Distro: "debian", Release: "11"},
		Packages: []json.RawMessage{rawPkg},
	}

	ci := toCorrelationInventory(inv)
	if ci.Agent.AgentID != "a1" {
		t.Errorf("AgentID = %q", ci.Agent.AgentID)
	}
	if ci.OS.Family != "linux" || ci.OS.Distro != "debian" {
		t.Errorf("OS = %+v", ci.OS)
	}
	if len(ci.Packages) != 1 {
		t.Fatalf("want 1 package, got %d", len(ci.Packages))
	}
	p := ci.Packages[0]
	if p.Name != "openssl" || p.Version != "1.1.1n-0+deb11u3" || p.Source != "dpkg" {
		t.Errorf("package = %+v", p)
	}
}

func TestToCorrelationInventory_MalformedPackageSkipped(t *testing.T) {
	inv := Inventory{
		Packages: []json.RawMessage{
			json.RawMessage(`{"name":"ok","version":"1.0","source":"dpkg"}`),
			json.RawMessage(`not json at all`),
		},
	}
	ci := toCorrelationInventory(inv)
	if len(ci.Packages) != 1 {
		t.Errorf("want 1 (malformed skipped), got %d", len(ci.Packages))
	}
}

func TestPipelineSink_Put_NoBridge(t *testing.T) {
	// Uses the correlation test data to verify end-to-end: a vulnerable package
	// is detected, logged, and NOT sent to bridge (BRIDGE_SCRIPT empty).
	ps, err := NewPipelineSink(PipelineConfig{
		NotusDir: "../correlation/testdata",
	})
	if err != nil {
		t.Fatalf("NewPipelineSink: %v", err)
	}

	rawPkg := json.RawMessage(`{"name":"chromium","version":"110.0.5481.100-1","arch":"amd64","source":"dpkg"}`)
	inv := Inventory{
		SchemaVersion: "1.0.0",
		Agent: struct {
			AgentID  string `json:"agent_id"`
			Hostname string `json:"hostname"`
		}{AgentID: "test-agent", Hostname: "testhost"},
		OS: struct {
			Family  string `json:"family"`
			Distro  string `json:"distro"`
			Release string `json:"release"`
		}{Family: "linux", Distro: "debian", Release: "12"},
		Packages: []json.RawMessage{rawPkg},
	}

	// Put must not error even when findings exist (bridge not configured).
	if err := ps.Put(inv); err != nil {
		t.Errorf("Put: %v", err)
	}
}

func TestPipelineSink_Put_NoFindings(t *testing.T) {
	ps, err := NewPipelineSink(PipelineConfig{
		NotusDir: "../correlation/testdata",
	})
	if err != nil {
		t.Fatalf("NewPipelineSink: %v", err)
	}

	// Up-to-date chromium — no findings expected.
	rawPkg := json.RawMessage(`{"name":"chromium","version":"999.0.9999.99","source":"dpkg"}`)
	inv := Inventory{
		SchemaVersion: "1.0.0",
		Agent: struct {
			AgentID  string `json:"agent_id"`
			Hostname string `json:"hostname"`
		}{AgentID: "clean-host"},
		OS: struct {
			Family  string `json:"family"`
			Distro  string `json:"distro"`
			Release string `json:"release"`
		}{Family: "linux", Distro: "debian", Release: "12"},
		Packages: []json.RawMessage{rawPkg},
	}

	if err := ps.Put(inv); err != nil {
		t.Errorf("Put: %v", err)
	}
}

func TestPipelineSink_CycleDedup(t *testing.T) {
	s := &PipelineSink{lastCycle: map[string]string{}, inflight: map[string]bool{}}

	if !s.beginCycle("a", "h1") {
		t.Fatal("first delivery of a cycle must proceed")
	}
	if s.beginCycle("a", "h1") {
		t.Fatal("concurrent in-flight duplicate must be skipped")
	}
	s.endCycle("a", "h1", true)
	if s.beginCycle("a", "h1") {
		t.Fatal("already-completed cycle must be skipped (retry/unchanged)")
	}
	if !s.beginCycle("a", "h2") {
		t.Fatal("a new cycle for the same agent must proceed")
	}
	s.endCycle("a", "h2", true)

	// empty cycle_hash disables dedup (always proceeds)
	if !s.beginCycle("a", "") || !s.beginCycle("a", "") {
		t.Fatal("empty cycle_hash must always proceed")
	}

	// a failed cycle is not recorded → it stays retryable
	if !s.beginCycle("b", "h3") {
		t.Fatal("first delivery must proceed")
	}
	s.endCycle("b", "h3", false)
	if !s.beginCycle("b", "h3") {
		t.Fatal("a failed cycle must remain retryable")
	}
}

func TestPipelineSink_Force_BypassesDedup(t *testing.T) {
	ps, err := NewPipelineSink(PipelineConfig{NotusDir: "../correlation/testdata"})
	if err != nil {
		t.Fatalf("NewPipelineSink: %v", err)
	}
	base := Inventory{
		SchemaVersion: "1.0.0",
		Agent: struct {
			AgentID  string `json:"agent_id"`
			Hostname string `json:"hostname"`
		}{AgentID: "fa"},
		OS: struct {
			Family  string `json:"family"`
			Distro  string `json:"distro"`
			Release string `json:"release"`
		}{Family: "linux", Distro: "debian", Release: "12"},
		CycleHash: "h1",
	}
	// A normal report records the cycle in the dedup state.
	if err := ps.Put(base); err != nil {
		t.Fatalf("Put(normal): %v", err)
	}
	if ps.lastCycle["fa"] != "h1" {
		t.Fatalf("normal import should record lastCycle, got %q", ps.lastCycle["fa"])
	}
	// A forced (scan_now) report for a fresh agent imports WITHOUT recording the
	// cycle — proving it took the bypass path (else lastCycle would be set) and
	// leaves periodic dedup intact.
	fb := base
	fb.Agent.AgentID = "fb"
	fb.CycleHash = "h2"
	fb.Force = true
	if err := ps.Put(fb); err != nil {
		t.Fatalf("Put(force): %v", err)
	}
	if ps.lastCycle["fb"] != "" {
		t.Fatalf("force must not record lastCycle, got %q", ps.lastCycle["fb"])
	}
	if !ps.beginCycle("fb", "h2") {
		t.Fatal("a periodic report after a forced scan must still process (not pre-deduped)")
	}
}
