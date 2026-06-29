package correlation

import "strings"

// productScope is the (distro, release) an advisory or a host normalizes to, used
// to ensure a Notus advisory is only ever evaluated against hosts it applies to.
//
// The correlator loads advisories for MANY products (Debian, Ubuntu, RHEL,
// openSUSE, ...) into one name-keyed index. Without scoping, a host would be
// matched against advisories from the wrong distro/release purely because a
// package name collides — fabricating findings that do not apply to the host
// (a non-fabrication violation, ADR-0001). Scoping is the guard that prevents it.
type productScope struct {
	distro  string // canonical family token, e.g. "debian", "rhel", "opensuse-leap"; "" = unknown
	release string // version key: VERSION_ID for the host, the numeric token for an advisory
}

// known reports whether the scope was classified to a known distro family.
func (s productScope) known() bool { return s.distro != "" }

// appliesTo reports whether an advisory with scope s applies to a host with
// scope host. Both must classify to the SAME distro family, and the advisory's
// release must be a dot-component prefix of the host's release. The prefix rule
// reconciles per-major advisory products with minor-versioned hosts (advisory
// "9" applies to RHEL host "9.4") while still separating distinct releases
// (advisory "11" does NOT apply to Debian host "12"; "22.04" only to "22.04").
func (s productScope) appliesTo(host productScope) bool {
	if !s.known() || !host.known() || s.distro != host.distro {
		return false
	}
	return releaseComponentsPrefix(s.release, host.release)
}

// releaseComponentsPrefix reports whether adv is a dot-component prefix of host.
// "9" ⊑ "9.4" → true; "12" ⊑ "12" → true; "11" ⊑ "12" → false; "2" ⊑ "22.04" → false.
func releaseComponentsPrefix(adv, host string) bool {
	if adv == "" || host == "" {
		return false
	}
	a := strings.Split(adv, ".")
	h := strings.Split(host, ".")
	if len(a) > len(h) {
		return false
	}
	for i := range a {
		if a[i] != h[i] {
			return false
		}
	}
	return true
}

// hostScope derives the scope of an inventory from its os-release fields:
// OS.Distro is the os-release ID, OS.Release the VERSION_ID.
func hostScope(os OSInfo) productScope {
	return productScope{distro: canonicalDistro(os.Distro), release: os.Release}
}

// advisoryScope derives the scope of a Notus advisory from its product_name
// (e.g. "Debian 12", "openSUSE Leap 15.6", "Red Hat Enterprise Linux 9").
func advisoryScope(productName string) productScope {
	return productScope{distro: canonicalDistro(productName), release: extractProductRelease(productName)}
}

// canonicalDistro maps either an os-release ID (e.g. "opensuse-leap", "rhel",
// "amzn") or a Notus product_name prefix (e.g. "openSUSE Leap 15.6", "Red Hat
// Enterprise Linux 9") to a single canonical distro-family token. Returns "" for
// distros it does not recognize — callers treat that as "do not match" and the
// load-time set of unrecognized advisory products is surfaced for follow-up
// (see NotusCorrelator.UnclassifiedProducts), so a gap is observable, not silent.
func canonicalDistro(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	// Exact os-release ID values first.
	switch t {
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "opensuse-leap":
		return "opensuse-leap"
	case "opensuse-tumbleweed":
		return "opensuse-tumbleweed"
	case "sles", "sled", "sles_sap", "sle-micro", "sle_hpc":
		return "sles"
	case "rhel":
		return "rhel"
	case "centos":
		return "centos"
	case "fedora":
		return "fedora"
	case "rocky":
		return "rocky"
	case "almalinux":
		return "alma"
	case "ol":
		return "oracle"
	case "amzn":
		return "amazon"
	case "mageia":
		return "mageia"
	case "euleros":
		return "euleros"
	case "slackware":
		return "slackware"
	}
	// Notus product_name prefixes (human strings carrying a trailing version).
	switch {
	case strings.HasPrefix(t, "debian"):
		return "debian"
	case strings.HasPrefix(t, "ubuntu"):
		return "ubuntu"
	case strings.HasPrefix(t, "opensuse leap"):
		return "opensuse-leap"
	case strings.HasPrefix(t, "opensuse tumbleweed"):
		return "opensuse-tumbleweed"
	case strings.HasPrefix(t, "suse linux enterprise"):
		return "sles"
	case strings.HasPrefix(t, "red hat enterprise linux"), strings.HasPrefix(t, "red hat"):
		return "rhel"
	case strings.HasPrefix(t, "centos"):
		return "centos"
	case strings.HasPrefix(t, "fedora"):
		return "fedora"
	case strings.HasPrefix(t, "rocky"):
		return "rocky"
	case strings.HasPrefix(t, "almalinux"), strings.HasPrefix(t, "alma linux"):
		return "alma"
	case strings.HasPrefix(t, "oracle linux"):
		return "oracle"
	case strings.HasPrefix(t, "amazon linux"):
		return "amazon"
	case strings.HasPrefix(t, "mageia"):
		return "mageia"
	case strings.HasPrefix(t, "euleros"):
		return "euleros"
	case strings.HasPrefix(t, "slackware"):
		return "slackware"
	}
	return ""
}

// extractProductRelease returns the first version-like token in a Notus
// product_name: "Debian 12" → "12", "openSUSE Leap 15.6" → "15.6",
// "Ubuntu 22.04 LTS" → "22.04", "Red Hat Enterprise Linux 9" → "9",
// "Amazon Linux 2023" → "2023". Returns "" when no numeric token is present.
func extractProductRelease(productName string) string {
	for _, tok := range strings.Fields(productName) {
		if tok != "" && tok[0] >= '0' && tok[0] <= '9' {
			// Keep digits and dots; stop at anything else (e.g. trailing "LTS").
			end := 0
			for end < len(tok) && (tok[end] == '.' || (tok[end] >= '0' && tok[end] <= '9')) {
				end++
			}
			return tok[:end]
		}
	}
	return ""
}
