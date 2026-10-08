package correlation

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file parses Microsoft MSRC CSAF 2.0 advisories (one JSON document per
// CVE, as published at https://msrc.microsoft.com/csaf/advisories) into the
// minimal entries the Windows correlator needs. We model only the subset we
// consume; unknown fields are ignored.
//
// Windows OS CVEs encode, per affected product, a product_version_range branch
// whose name is "<10.0.<build>.<ubr>" (affected below that build revision) and a
// sibling product_version branch whose name is the fixed "10.0.<build>.<ubr>".
// The authoritative "is this host patched?" test is therefore a VERSION compare
// of the host's 10.0.build.ubr against the threshold, scoped by build number —
// no KB-supersedence graph required. The KB is the remediation artifact.

// csafDoc is the subset of a CSAF 2.0 document we read.
type csafDoc struct {
	Document struct {
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches []csafBranch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
	Product  *struct {
		Name      string `json:"name"`
		ProductID string `json:"product_id"`
	} `json:"product"`
}

type csafVuln struct {
	CVE           string `json:"cve"`
	ProductStatus struct {
		KnownAffected []string `json:"known_affected"`
		Fixed         []string `json:"fixed"`
	} `json:"product_status"`
	Remediations []struct {
		Category   string   `json:"category"`
		ProductIDs []string `json:"product_ids"`
		URL        string   `json:"url"`
	} `json:"remediations"`
	Scores []struct {
		CVSSv3 struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvss_v3"`
		Products []string `json:"products"`
	} `json:"scores"`
}

// productPair is one Windows product_name branch resolved to its affected range
// and (optional) fixed version. build is the 3rd version component, used as the
// correlation scope key (unique per Windows release line).
type productPair struct {
	productName string
	build       string // e.g. "19045"
	threshold   []int  // parsed "<a.b.build.ubr" → [a,b,build,ubr]; affected if host < this
	rangeID     string // product_id of the product_version_range (∈ known_affected)
	fixedID     string // product_id of the sibling product_version (fix), may be ""
}

// msrcEntry is one (CVE, affected Windows build) the correlator indexes.
type msrcEntry struct {
	build       string
	threshold   []int
	cve         string
	productName string
	kb          string  // "KB5043050" from the vendor_fix remediation, may be ""
	severity    float64 // CVSS v3 base score; 0 if the doc carries none
}

// parseCSAF decodes a single CSAF document.
func parseCSAF(raw []byte) (*csafDoc, error) {
	var d csafDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// windowsEntries extracts the indexable Windows entries from one CSAF document:
// every (affected-range product ∈ known_affected) paired with the CVE, the fix
// KB, and the doc's CVSS severity. Non-Windows / version-less products yield no
// entry (non-fabrication: an entry needs a concrete build threshold).
func windowsEntries(d *csafDoc) []msrcEntry {
	pairs := collectProductPairs(d.ProductTree.Branches)
	byID := make(map[string]productPair, len(pairs))
	for _, p := range pairs {
		if p.rangeID != "" {
			byID[p.rangeID] = p
		}
	}
	var out []msrcEntry
	for _, v := range d.Vulnerabilities {
		cve := v.CVE
		if cve == "" {
			cve = d.Document.Tracking.ID
		}
		sev := maxCVSS(v)
		affected := make(map[string]bool, len(v.ProductStatus.KnownAffected))
		for _, id := range v.ProductStatus.KnownAffected {
			affected[id] = true
		}
		for id, p := range byID {
			if !affected[id] || p.build == "" || len(p.threshold) == 0 {
				continue
			}
			out = append(out, msrcEntry{
				build:       p.build,
				threshold:   p.threshold,
				cve:         cve,
				productName: p.productName,
				kb:          kbForProduct(v, p.fixedID),
				severity:    sev,
			})
		}
	}
	return out
}

// collectProductPairs walks the product_tree, pairing each product_name branch's
// product_version_range (affected) with its product_version (fixed) sibling.
func collectProductPairs(branches []csafBranch) []productPair {
	var out []productPair
	for _, b := range branches {
		if b.Category == "product_name" {
			out = append(out, pairFromProductName(b))
			continue
		}
		// Not a product_name node: keep descending (the tree starts at vendor).
		out = append(out, collectProductPairs(b.Branches)...)
	}
	return out
}

// pairFromProductName resolves one product_name branch to a productPair by
// reading its range/fixed children.
func pairFromProductName(b csafBranch) productPair {
	p := productPair{productName: b.Name}
	for _, child := range b.Branches {
		switch child.Category {
		case "product_version_range":
			if child.Product != nil {
				p.rangeID = child.Product.ProductID
				p.threshold = parseVersion(strings.TrimPrefix(child.Name, "<"))
				p.build = buildComponent(p.threshold)
			}
		case "product_version":
			if child.Product != nil {
				p.fixedID = child.Product.ProductID
				if p.build == "" {
					p.build = buildComponent(parseVersion(child.Name))
				}
			}
		}
	}
	return p
}

// kbForProduct returns the KB id of the vendor_fix remediation covering fixedID.
func kbForProduct(v csafVuln, fixedID string) string {
	for _, r := range v.Remediations {
		if r.Category != "vendor_fix" {
			continue
		}
		if fixedID == "" || containsID(r.ProductIDs, fixedID) {
			if kb := kbFromURL(r.URL); kb != "" {
				return kb
			}
		}
	}
	return ""
}

// maxCVSS returns the highest CVSS v3 base score across a vulnerability's scores
// (0 when the doc carries none). We never invent a score; 0 means "unscored".
func maxCVSS(v csafVuln) float64 {
	max := 0.0
	for _, s := range v.Scores {
		if s.CVSSv3.BaseScore > max {
			max = s.CVSSv3.BaseScore
		}
	}
	return max
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// kbFromURL extracts the KB article number from a support URL
// (".../help/5043050" or ".../KB5043050") and returns it as "KB<n>", or "".
func kbFromURL(u string) string {
	u = strings.TrimRight(u, "/")
	i := strings.LastIndexByte(u, '/')
	if i < 0 {
		return ""
	}
	last := u[i+1:]
	last = strings.TrimPrefix(last, "KB")
	last = strings.TrimPrefix(last, "kb")
	if last != "" && isDigits(last) {
		return "KB" + last
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseVersion parses "a.b.c.d" into []int. Non-numeric or missing components
// yield a nil slice (the entry is then skipped — no fabrication from garbage).
func parseVersion(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// buildComponent returns the 3rd version component (the Windows build number)
// as a string, or "" when the version is too short.
func buildComponent(v []int) string {
	if len(v) < 3 {
		return ""
	}
	return strconv.Itoa(v[2])
}

// versionLess reports whether a < b component-by-component (missing components
// compare as 0). Both must be non-empty, else it returns false.
func versionLess(a, b []int) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai != bi {
			return ai < bi
		}
	}
	return false
}
