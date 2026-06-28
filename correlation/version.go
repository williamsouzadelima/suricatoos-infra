package correlation

import (
	"fmt"

	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

// isVulnerable reports whether an installed package version is vulnerable given
// the fixed version and comparison specifier from a Notus advisory entry.
//
// Notus uses specifier ">=" to mean "fixed at fixedVersion or later", so a
// package is vulnerable iff installedVersion < fixedVersion (strict less-than).
// Other specifiers are not used in practice; they return (false, error) to
// avoid false positives.
func isVulnerable(pkgType, installed, fixed, specifier string) (bool, error) {
	if specifier != ">=" {
		return false, fmt.Errorf("unsupported specifier %q (installed=%s, fixed=%s)", specifier, installed, fixed)
	}
	switch pkgType {
	case "deb":
		return debLessThan(installed, fixed)
	case "rpm":
		return rpmLessThan(installed, fixed)
	default:
		return false, fmt.Errorf("unsupported package type %q", pkgType)
	}
}

// debLessThan reports whether deb version a is strictly less than b.
// Handles epochs, tilde pre-release markers, and Debian revision components
// per Debian Policy §5.6.12, using github.com/knqyf263/go-deb-version.
func debLessThan(a, b string) (bool, error) {
	va, err := debversion.NewVersion(a)
	if err != nil {
		return false, fmt.Errorf("parsing deb version %q: %w", a, err)
	}
	vb, err := debversion.NewVersion(b)
	if err != nil {
		return false, fmt.Errorf("parsing deb version %q: %w", b, err)
	}
	return va.LessThan(vb), nil
}

// rpmLessThan reports whether rpm version-release string a is strictly less
// than b, using the rpmvercmp algorithm (rpm/lib/rpmvercmp.c) via
// github.com/knqyf263/go-rpm-version. Epoch is supported when present as
// "EPOCH:VERSION-RELEASE".
func rpmLessThan(a, b string) (bool, error) {
	va := rpmversion.NewVersion(a)
	vb := rpmversion.NewVersion(b)
	return va.LessThan(vb), nil
}
