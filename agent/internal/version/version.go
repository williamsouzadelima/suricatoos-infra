// Package version exposes build metadata, injected at link time via
// -ldflags "-X .../version.Version=... -X .../version.Commit=... -X .../version.BuildDate=...".
package version

import "fmt"

var (
	// Version is the semantic version of the agent.
	Version = "0.0.0-dev"
	// Commit is the short git SHA the binary was built from.
	Commit = "none"
	// BuildDate is the RFC3339 build timestamp.
	BuildDate = "unknown"
)

// String renders a single human-readable version line.
func String() string {
	return fmt.Sprintf("suricatoos-agent %s (commit %s, built %s)", Version, Commit, BuildDate)
}
