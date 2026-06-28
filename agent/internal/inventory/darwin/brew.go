//go:build darwin

package darwin

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// brewPaths are the standard Homebrew binary locations, checked in order.
var brewPaths = []string{
	"/opt/homebrew/bin/brew", // Apple Silicon (default since Homebrew 3.0)
	"/usr/local/bin/brew",    // Intel (traditional)
}

// defaultBrewList runs `brew list --versions --formula` and returns stdout.
// Returns (nil, nil) if Homebrew is not installed.
func defaultBrewList() ([]byte, error) {
	brew := findBrew()
	if brew == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, brew, "list", "--versions", "--formula").Output()
}

// findBrew returns the first Homebrew binary found in brewPaths, or "".
func findBrew() string {
	for _, p := range brewPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// parseBrewOutput parses `brew list --versions --formula` output.
// Format per line: "<name> <version> [<version2> ...]" — we take the first version.
func parseBrewOutput(data []byte) []inventory.Package {
	var pkgs []inventory.Package
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:    fields[0],
			Version: fields[1],
			Source:  inventory.SourceHomebrew,
		})
	}
	return pkgs
}
