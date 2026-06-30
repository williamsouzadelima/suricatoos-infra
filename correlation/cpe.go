package correlation

import (
	"sort"
	"strings"
)

// cpeProduct maps a package name to its CPE 2.2 "vendor:product" identity. Only
// packages with a confident mapping are emitted as CPEs: gvmd's CVE scanner
// matches these against the SCAP/CVE feed, and feeding it guessed CPEs would
// produce noise. This table is intentionally curated (high-value, network- and
// crypto-exposed software); the precise per-distro correlation stays with Notus.
//
// Keys are the OS package names (Debian/Ubuntu AND RHEL/SUSE variants point to
// the same CPE). Values are "vendor:product" in NVD's canonical form.
var cpeProduct = map[string]string{
	// crypto / transport
	"openssl":         "openssl:openssl",
	"libssl3":         "openssl:openssl",
	"libssl1.1":       "openssl:openssl",
	"openssl-libs":    "openssl:openssl",
	"openssh":         "openbsd:openssh",
	"openssh-server":  "openbsd:openssh",
	"openssh-client":  "openbsd:openssh",
	"openssh-clients": "openbsd:openssh",
	"gnutls":          "gnu:gnutls",
	"libgnutls30":     "gnu:gnutls",
	"openvpn":         "openvpn:openvpn",
	"libgcrypt20":     "gnupg:libgcrypt",
	// web / proxy / app servers
	"apache2":     "apache:http_server",
	"apache2-bin": "apache:http_server",
	"httpd":       "apache:http_server",
	"nginx":       "nginx:nginx",
	"nginx-core":  "nginx:nginx",
	"lighttpd":    "lighttpd:lighttpd",
	"haproxy":     "haproxy:haproxy",
	"tomcat9":     "apache:tomcat",
	"squid":       "squid-cache:squid",
	// languages / runtimes
	"python3":                 "python:python",
	"perl":                    "perl:perl",
	"ruby":                    "ruby-lang:ruby",
	"php":                     "php:php",
	"nodejs":                  "nodejs:node.js",
	"golang":                  "golang:go",
	"openjdk-17-jre-headless": "oracle:openjdk",
	"openjdk-11-jre-headless": "oracle:openjdk",
	// databases
	"mariadb-server": "mariadb:mariadb",
	"mysql-server":   "oracle:mysql",
	"postgresql":     "postgresql:postgresql",
	"redis-server":   "redis:redis",
	"mongodb-server": "mongodb:mongodb",
	"libsqlite3-0":   "sqlite:sqlite",
	"sqlite3":        "sqlite:sqlite",
	// system / core libraries
	"libc6":     "gnu:glibc",
	"glibc":     "gnu:glibc",
	"bash":      "gnu:bash",
	"systemd":   "systemd_project:systemd",
	"sudo":      "sudo_project:sudo",
	"zlib1g":    "zlib:zlib",
	"libxml2":   "xmlsoft:libxml2",
	"libexpat1": "libexpat_project:libexpat",
	"tar":       "gnu:tar",
	"gzip":      "gnu:gzip",
	"vim":       "vim:vim",
	"git":       "git:git",
	"gnupg":     "gnupg:gnupg",
	// transfer / dns / mail / dir / print
	"curl":         "haxx:curl",
	"libcurl4":     "haxx:curl",
	"wget":         "gnu:wget",
	"bind9":        "isc:bind",
	"dnsmasq":      "thekelleys:dnsmasq",
	"postfix":      "postfix:postfix",
	"exim4":        "exim:exim",
	"dovecot-core": "dovecot:dovecot",
	"samba":        "samba:samba",
	"slapd":        "openldap:openldap",
	"cups":         "apple:cups",
	"openldap":     "openldap:openldap",
}

// cpePrefix maps a package-name prefix to a CPE "vendor:product" for families
// whose package names carry a variable suffix (kernel ABI, versioned runtimes).
var cpePrefix = []struct{ prefix, product string }{
	{"linux-image-", "linux:linux_kernel"},
	{"openjdk-", "oracle:openjdk"},
	{"python3.", "python:python"},
	{"libssl", "openssl:openssl"},
}

// GenerateCPEs maps an inventory's packages to deduplicated CPE 2.2 URIs
// (cpe:/a:vendor:product:version) for gvmd's CVE scanner. Only packages with a
// curated vendor:product mapping are emitted; unmapped packages are skipped so
// the CVE scanner is never fed guessed identities. The result is sorted for
// determinism.
func GenerateCPEs(inv Inventory) []string {
	seen := make(map[string]struct{})
	for _, p := range inv.Packages {
		vp := lookupCPEProduct(p.Name)
		if vp == "" {
			continue
		}
		ver := upstreamVersion(p.Version)
		if ver == "" {
			continue
		}
		part := "a"
		if vp == "linux:linux_kernel" {
			part = "o"
		}
		seen["cpe:/"+part+":"+vp+":"+ver] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// lookupCPEProduct returns the "vendor:product" for a package name, or "".
func lookupCPEProduct(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if vp, ok := cpeProduct[n]; ok {
		return vp
	}
	for _, pre := range cpePrefix {
		if strings.HasPrefix(n, pre.prefix) {
			return pre.product
		}
	}
	return ""
}

// upstreamVersion extracts the upstream version from a dpkg/rpm version string:
// it strips a leading "epoch:", the Debian revision / RPM release (everything
// from the first '-'), and Debian "~"/"+" suffixes. e.g. "1:3.0.2-0ubuntu1.10"
// -> "3.0.2"; "8.9p1-3" -> "8.9p1"; "3.0.7-18.el9" -> "3.0.7".
func upstreamVersion(v string) string {
	v = strings.TrimSpace(v)
	// epoch: leading digits followed by ':'
	if i := strings.IndexByte(v, ':'); i > 0 {
		if isAllDigits(v[:i]) {
			v = v[i+1:]
		}
	}
	for _, sep := range []byte{'-', '~', '+', ' '} {
		if i := strings.IndexByte(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
