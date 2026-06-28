package correlation

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	fileName     string // advisory file name (for Evidence.MatchedAdvisory)
	pkgType      string // "deb" | "rpm"
}

// NotusCorrelator loads Notus advisory files from a directory and correlates
// inventories against them. Safe for concurrent use after construction.
type NotusCorrelator struct {
	// index maps package name → list of match candidates across all loaded files.
	index map[string][]advisoryMatch
}

// NewNotusCorrelator loads all *.notus files from dir and builds an in-memory
// index keyed by package name for O(1) per-package lookups during correlation.
func NewNotusCorrelator(dir string) (*NotusCorrelator, error) {
	c := &NotusCorrelator{index: make(map[string][]advisoryMatch)}
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

// indexFile adds all advisory entries from f into the correlator's index.
func (c *NotusCorrelator) indexFile(f notusFile, fileName string) {
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
			})
		}
	}
}

// extractFixedPkg returns (pkgName, fixedVersion, fixedFullPkg) from an advisory
// fixed_packages entry. Returns empty strings if the entry is malformed.
func extractFixedPkg(pkgType string, fp notusFixed) (name, version, fullPkg string) {
	switch pkgType {
	case "deb":
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

	for _, pkg := range inv.Packages {
		candidates := c.index[pkg.Name]
		for _, m := range candidates {
			if !sourcePkgTypeMatch(pkg.Source, m.pkgType) {
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
// for rpm-type advisories.
var knownArches = map[string]bool{
	"x86_64": true, "amd64": true, "aarch64": true, "arm64": true,
	"i386": true, "i586": true, "i686": true, "armhf": true,
	"armv7hl": true, "ppc64le": true, "ppc64": true, "s390x": true,
	"noarch": true, "all": true, "src": true,
}

// splitRPMFullName splits an RPM Notus full_name (e.g. "bash-5.1.8-6.el9.x86_64")
// into (name="bash", version="5.1.8-6.el9", ok=true).
//
// Strategy: strip the trailing arch suffix (last ".segment" when the segment is
// a known arch), then find the first hyphen followed by a digit — everything
// before is the name, everything after is the version-release string.
func splitRPMFullName(fullName string) (name, version string, ok bool) {
	s := fullName
	if idx := strings.LastIndex(s, "."); idx >= 0 && knownArches[s[idx+1:]] {
		s = s[:idx]
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
