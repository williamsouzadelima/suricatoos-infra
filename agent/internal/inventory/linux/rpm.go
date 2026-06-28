package linux

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// rpmQueryFormat emits one tab-separated "name<TAB>version-release<TAB>arch" line
// per package — a stable, STRUCTURED format (not fragile free-form parsing).
const rpmQueryFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"

// defaultRPMList runs `rpm -qa` with a fixed query format. rpm reads its own
// database (BDB/NDB/SQLite) authoritatively, so results are robust without
// vendoring a heavy rpmdb/SQLite reader. See docs/adr/0005-coletor-rpm.md.
func defaultRPMList() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "rpm", "-qa", "--qf", rpmQueryFormat).Output()
}

// parseRPMOutput parses the tab-separated output of `rpm -qa --qf rpmQueryFormat`.
// gpg-pubkey entries (imported GPG keys, not software) are skipped.
func parseRPMOutput(r io.Reader) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		name, version, arch := parts[0], parts[1], parts[2]
		if name == "" || name == "gpg-pubkey" {
			continue
		}
		if arch == "(none)" {
			arch = ""
		}
		pkgs = append(pkgs, inventory.Package{
			Name:     name,
			Version:  version,
			Arch:     arch,
			Source:   inventory.SourceRPM,
			FullName: fullName(name, version, arch),
		})
	}
	return pkgs, sc.Err()
}
