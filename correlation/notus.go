package correlation

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// notusFixed describes one fixed package entry in a Notus advisory.
// deb files use name + full_version; rpm files use full_name only.
type notusFixed struct {
	Name        string `json:"name"`         // deb only
	FullVersion string `json:"full_version"` // deb only
	FullName    string `json:"full_name"`    // rpm only
	Specifier   string `json:"specifier"`
}

type notusEntry struct {
	OID           string       `json:"oid"`
	FixedPackages []notusFixed `json:"fixed_packages"`
}

type notusFile struct {
	PackageType string       `json:"package_type"` // "deb" | "rpm"
	ProductName string       `json:"product_name"`
	Advisories  []notusEntry `json:"advisories"`
}

// advisoryMatch is an indexed candidate produced when loading .notus files.
type advisoryMatch struct {
	oid          string
	fixedVersion string // version string for comparison
	fixedFullPkg string // human-readable fixed package (for Finding.PackageFixed)
	specifier    string
	productName  string
	fileName     string       // advisory file name (for Evidence.MatchedAdvisory)
	pkgType      string       // "deb" | "rpm"
	scope        productScope // (distro, release) the advisory applies to
}

// NotusCorrelator loads Notus advisory files from a directory and correlates
// inventories against them. Safe for concurrent use after construction.
type NotusCorrelator struct {
	// index maps package name → list of match candidates across all loaded files.
	index map[string][]advisoryMatch
	// unclassified records product_name strings whose distro could not be
	// recognized at load time. Advisories with an unrecognized product never
	// match any host (their scope.distro is ""), so surfacing this set lets an
	// operator extend canonicalDistro instead of silently missing findings.
	unclassified map[string]bool
}

// NewNotusCorrelator loads all *.notus files from dir and builds an in-memory
// index keyed by package name for O(1) per-package lookups during correlation.
func NewNotusCorrelator(dir string) (*NotusCorrelator, error) {
	c := &NotusCorrelator{
		index:        make(map[string][]advisoryMatch),
		unclassified: make(map[string]bool),
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".notus") {
			return err
		}
		data, ferr := os.ReadFile(path)
		if ferr != nil {
			return ferr
		}
		var f notusFile
		if jerr := json.Unmarshal(data, &f); jerr != nil {
			return fmt.Errorf("parsing %s: %w", path, jerr)
		}
		c.indexFile(f, filepath.Base(path))
		return nil
	})
	return c, err
}

// UnclassifiedProducts returns the sorted set of advisory product_name strings
// whose distro family canonicalDistro could not recognize. A non-empty result
// means those advisories will never match any host — the caller should log it
// and extend canonicalDistro so the corresponding findings are not missed.
func (c *NotusCorrelator) UnclassifiedProducts() []string {
	out := make([]string, 0, len(c.unclassified))
	for p := range c.unclassified {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// indexFile adds all advisory entries from f into the correlator's index.
func (c *NotusCorrelator) indexFile(f notusFile, fileName string) {
	scope := advisoryScope(f.ProductName)
	if !scope.known() {
		c.unclassified[f.ProductName] = true
	}
	for _, entry := range f.Advisories {
		for _, fp := range entry.FixedPackages {
			pkgName, fixedVer, fixedFullPkg := extractFixedPkg(f.PackageType, fp)
			if pkgName == "" || fixedVer == "" {
				continue
			}
			c.index[pkgName] = append(c.index[pkgName], advisoryMatch{
				oid:          entry.OID,
				fixedVersion: fixedVer,
				fixedFullPkg: fixedFullPkg,
				specifier:    fp.Specifier,
				productName:  f.ProductName,
				fileName:     fileName,
				pkgType:      f.PackageType,
				scope:        scope,
			})
		}
	}
}

// extractFixedPkg returns (pkgName, fixedVersion, fixedFullPkg) from an advisory
// fixed_packages entry. Returns empty strings if the entry is malformed.
func extractFixedPkg(pkgType string, fp notusFixed) (name, version, fullPkg string) {
	switch pkgType {
	case "deb":
		// Greenbone's Notus loader reads full_name FIRST, then falls back to
		// name + full_version. Mirror that precedence — a deb advisory written
		// in the full_name-only form was previously dropped silently, blinding
		// the engine to every Debian/Ubuntu finding in such a file.
		if fp.FullName != "" {
			if n, v, ok := splitDebFullName(fp.FullName); ok {
				return n, v, fp.FullName
			}
		}
		if fp.Name == "" || fp.FullVersion == "" {
			return "", "", ""
		}
		return fp.Name, fp.FullVersion, fp.Name + "-" + fp.FullVersion
	case "rpm":
		if fp.FullName == "" {
			return "", "", ""
		}
		n, v, ok := splitRPMFullName(fp.FullName)
		if !ok {
			return "", "", ""
		}
		return n, v, fp.FullName
	}
	return "", "", ""
}

// Correlate matches packages in inv against loaded advisories.
// Each returned Finding is traceable to a collected package + advisory OID.
func (c *NotusCorrelator) Correlate(inv Inventory) (*FindingReport, error) {
	report := &FindingReport{
		SchemaVersion: "1.0.0",
		AgentID:       inv.Agent.AgentID,
		Host:          inv.Agent.Hostname,
		CollectedAt:   inv.CollectedAt,
	}

	now := time.Now().UTC().Format(time.RFC3339)
	// dedup key = oid + "|" + package_observed to avoid duplicate findings when
	// the same advisory OID appears in multiple .notus files for the same package.
	seen := make(map[string]bool)

	// Scope advisories to the host's distro+release so a host is never matched
	// against another product's advisories (cross-distro false positive).
	host := hostScope(inv.OS)

	for _, pkg := range inv.Packages {
		candidates := c.index[pkg.Name]
		for _, m := range candidates {
			if !sourcePkgTypeMatch(pkg.Source, m.pkgType) {
				continue
			}
			if !m.scope.appliesTo(host) {
				continue
			}
			vuln, err := isVulnerable(m.pkgType, pkg.Version, m.fixedVersion, m.specifier)
			if err != nil || !vuln {
				continue
			}
			obs := pkg.FullName
			if obs == "" {
				obs = pkg.Name + "-" + pkg.Version
				if pkg.Arch != "" {
					obs += "." + pkg.Arch
				}
			}
			key := m.oid + "|" + obs
			if seen[key] {
				continue
			}
			seen[key] = true
			report.Findings = append(report.Findings, Finding{
				OID:             m.oid,
				PackageObserved: obs,
				PackageFixed:    m.fixedFullPkg,
				Specifier:       m.specifier,
				Product:         m.productName,
				Evidence: Evidence{
					Source:          pkg.Source,
					MatchedAdvisory: m.fileName,
				},
				DetectedAt: now,
			})
		}
	}
	return report, nil
}

// sourcePkgTypeMatch reports whether a collector source maps to an advisory
// package type: "dpkg" → "deb", "rpm" → "rpm".
func sourcePkgTypeMatch(source, pkgType string) bool {
	return (pkgType == "deb" && source == "dpkg") ||
		(pkgType == "rpm" && source == "rpm")
}

// knownArches is the set of package architecture suffixes used in Notus full_name
// for rpm-type advisories. It must be reasonably complete: an arch missing here
// is left glued to the release component and inflates the version string, which
// flags an already-patched host as vulnerable (false positive). The list mirrors
// the rpm/yum canonical arch set (rpmrc plus common cross arches).
var knownArches = map[string]bool{
	// x86
	"x86_64": true, "amd64": true, "i386": true, "i486": true, "i586": true, "i686": true,
	"athlon": true, "geode": true, "pentium3": true, "pentium4": true,
	// arm
	"aarch64": true, "arm64": true, "armhf": true,
	"armv5tel": true, "armv5tejl": true, "armv6l": true, "armv6hl": true,
	"armv7l": true, "armv7hl": true, "armv7hnl": true,
	// power
	"ppc": true, "ppc64": true, "ppc64le": true, "ppc64p7": true,
	// ibm Z
	"s390": true, "s390x": true,
	// sparc
	"sparc": true, "sparcv8": true, "sparcv9": true, "sparc64": true,
	// mips
	"mips": true, "mipsel": true, "mips64": true, "mips64el": true,
	// newer / niche
	"riscv64": true, "loongarch64": true, "alpha": true, "ia64": true, "sh4": true,
	// pseudo-arches
	"noarch": true, "all": true, "src": true, "nosrc": true,
}

// splitRPMFullName splits an RPM Notus full_name (e.g. "bash-5.1.8-6.el9.x86_64")
// into (name="bash", version="5.1.8-6.el9", ok=true), where version is the
// VERSION-RELEASE string (matching the agent's %{VERSION}-%{RELEASE} format).
//
// An rpm full_name is NAME-VERSION-RELEASE[.ARCH]. The rpm format forbids '-'
// inside the VERSION and RELEASE fields, so the parse is unambiguous from the
// RIGHT: RELEASE is after the last '-', VERSION after the second-to-last '-',
// and NAME is everything before — even when NAME itself contains hyphens or
// digits (e.g. "java-1.8.0-openjdk", "libpng16-16", "rust-hyper-rustls+default-devel").
//
// The trailing ".ARCH" suffix is stripped first when the final dot-segment is a
// known arch; an unknown arch is left in place (the name is still parsed
// correctly, but the version may carry the arch — see knownArches).
// debFullNameRe / debFullNameNoRevRe parse a Debian Notus full_name. A deb
// full_name is NAME-[EPOCH:]UPSTREAM[-REVISION] with NO arch suffix. The name is
// the greedy prefix before the version, which starts with an optional "epoch:"
// then a digit. The revision (when present) carries no hyphen, and the required
// trailing "-revision" in the first pattern disambiguates names that themselves
// contain a hyphen-then-digit segment (e.g. "gcc-12"). Mirrors greenbone
// notus-scanner's deb parser.
var (
	debFullNameRe      = regexp.MustCompile(`^([a-z0-9][a-z0-9.+-]+)-(?:\d*:)?\d[\w.+~-]*-[\w.+~]*$`)
	debFullNameNoRevRe = regexp.MustCompile(`^([a-z0-9][a-z0-9.+-]+)-(?:\d*:)?\d[\w.+~]*$`)
)

// splitDebFullName splits a deb Notus full_name into (name, version), where
// version is the "[epoch:]upstream[-revision]" string compared by go-deb-version.
// Examples: "openssl-3.0.11-1~deb12u2" → ("openssl","3.0.11-1~deb12u2");
// "gcc-12-12.2.0-14" → ("gcc-12","12.2.0-14"); "package-1.0" → ("package","1.0").
func splitDebFullName(fullName string) (name, version string, ok bool) {
	if m := debFullNameRe.FindStringSubmatch(fullName); m != nil {
		return m[1], fullName[len(m[1])+1:], true
	}
	if m := debFullNameNoRevRe.FindStringSubmatch(fullName); m != nil {
		return m[1], fullName[len(m[1])+1:], true
	}
	return "", "", false
}

func splitRPMFullName(fullName string) (name, version string, ok bool) {
	s := fullName
	if idx := strings.LastIndex(s, "."); idx >= 0 && knownArches[s[idx+1:]] {
		s = s[:idx]
	}
	lastDash := strings.LastIndex(s, "-")
	if lastDash <= 0 {
		return "", "", false
	}
	secondDash := strings.LastIndex(s[:lastDash], "-")
	if secondDash <= 0 {
		return "", "", false
	}
	return s[:secondDash], s[secondDash+1:], true
}
