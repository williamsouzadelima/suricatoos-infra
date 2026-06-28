package linux

import (
	"bufio"
	"io"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// parseDpkgStatus parses the dpkg "status" database — a sequence of RFC822-like
// stanzas separated by blank lines — and returns only packages whose Status
// state is "installed" (i.e. fully installed, not config-files/not-installed).
// It reads the database directly; it never shells out to dpkg.
func parseDpkgStatus(r io.Reader) ([]inventory.Package, error) {
	var pkgs []inventory.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var name, version, arch, status string
	flush := func() {
		if name != "" && statusInstalled(status) {
			pkgs = append(pkgs, inventory.Package{
				Name:     name,
				Version:  version,
				Arch:     arch,
				Source:   inventory.SourceDpkg,
				FullName: fullName(name, version, arch),
			})
		}
		name, version, arch, status = "", "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a folded field; not needed for our keys
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Package":
			name = strings.TrimSpace(val)
		case "Version":
			version = strings.TrimSpace(val)
		case "Architecture":
			arch = strings.TrimSpace(val)
		case "Status":
			status = strings.TrimSpace(val)
		}
	}
	flush() // the final stanza may not be followed by a blank line
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// statusInstalled reports whether a dpkg Status line ("<want> <flag> <state>")
// marks the package as fully installed (state == "installed").
func statusInstalled(status string) bool {
	f := strings.Fields(status)
	return len(f) >= 3 && f[len(f)-1] == "installed"
}
