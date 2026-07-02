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

// rpmQueryFormat emits one tab-separated "name<TAB>[epoch:]version-release<TAB>arch"
// line per package — a stable, STRUCTURED format (not fragile free-form parsing).
//
// The EPOCH is prefixed as "E:" only when present, via rpm's conditional query
// idiom %|EPOCH?{...}:{...}|. This is required for correct correlation: Notus
// rpm advisories encode the epoch in their fixed version (e.g. "1:2.06-70.el9_3"
// for grub2), and comparing an epoch-less installed version against an
// epoch-bearing fixed version makes rpmvercmp read the installed epoch as 0 < 1,
// flagging an already-patched host as vulnerable (a false positive). Emitting the
// real epoch keeps the comparison symmetric. Packages without an epoch produce no
// prefix, matching advisories that omit the (zero) epoch.
const rpmQueryFormat = "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n"

// rpmListRooted returns an rpm lister reading the package db under `root`. Empty
// reads the running host (`rpm -qa`); a non-empty root (e.g. "/host" when the agent
// runs in a container bind-mounting the host) adds `--root <root>` so rpm reads the
// HOST's db at <root>/var/lib/rpm instead of the container's. rpm reads its own
// database (BDB/NDB/SQLite) authoritatively. See docs/adr/0005-coletor-rpm.md.
func rpmListRooted(root string) func() ([]byte, error) {
	return func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := make([]string, 0, 6)
		if root != "" {
			args = append(args, "--root", root)
		}
		args = append(args, "-qa", "--qf", rpmQueryFormat)
		return exec.CommandContext(ctx, "rpm", args...).Output()
	}
}

// defaultRPMList reads the running host's rpm db (root = "").
func defaultRPMList() ([]byte, error) { return rpmListRooted("")() }

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
