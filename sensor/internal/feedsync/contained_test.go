package feedsync

import "testing"

// TestContainedRejectsTraversal is the regression guard for the path-traversal ->
// root-RCE blocker (ADR-0007 risk #2): a validly-signed manifest whose path escapes
// FeedDir must be refused before any write, so a compromised cloud cannot overwrite
// scan_bridge.py or the sensor binary.
func TestContainedRejectsTraversal(t *testing.T) {
	root := "/var/lib/suricatoos-sensor/feed"

	bad := []string{
		"../scan_bridge.py",
		"../../usr/local/bin/sensor-agent",
		"/etc/passwd",
		"plugins/../../../etc/cron.d/x",
		"a/../../b",
		"..",
		"",
	}
	for _, p := range bad {
		if contained(root, p) {
			t.Errorf("path malicioso deveria ser REJEITADO: %q", p)
		}
	}

	good := []string{
		"plugins/1.2.3.nasl",
		"notus/products/debian_12.notus",
		"version.json",
		"a/b/c.xml",
	}
	for _, p := range good {
		if !contained(root, p) {
			t.Errorf("path legítimo deveria ser ACEITO: %q", p)
		}
	}
}
