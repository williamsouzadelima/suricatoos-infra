//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"
)

const (
	uninstallKey64   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallKey32   = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	ntCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
)

// defaultEnumKeys reads both the 64-bit and 32-bit Uninstall registry keys and
// returns one winEntry per installed product.
func defaultEnumKeys() ([]winEntry, error) {
	var entries []winEntry
	if e, err := readUninstallKey(uninstallKey64, "x86_64"); err == nil {
		entries = append(entries, e...)
	}
	if e, err := readUninstallKey(uninstallKey32, "x86"); err == nil {
		entries = append(entries, e...)
	}
	return entries, nil
}

// readUninstallKey opens a single Uninstall registry key path and returns one
// winEntry per subkey that has both a DisplayName and a DisplayVersion value.
func readUninstallKey(path, arch string) ([]winEntry, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subNames, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var entries []winEntry
	for _, sub := range subNames {
		sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := sk.GetStringValue("DisplayName")
		version, _, _ := sk.GetStringValue("DisplayVersion")
		sk.Close()
		if name == "" || version == "" {
			continue
		}
		entries = append(entries, winEntry{name: name, version: version, arch: arch})
	}
	return entries, nil
}

// defaultOSInfo reads the Windows NT CurrentVersion key to get the OS release.
func defaultOSInfo() (release, arch string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ntCurrentVersion, registry.QUERY_VALUE)
	if err != nil {
		return "", "", err
	}
	defer k.Close()

	// DisplayVersion is like "22H2"; CurrentBuildNumber is like "22621".
	// We compose them for a meaningful release string.
	displayVer, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")

	switch {
	case displayVer != "" && build != "":
		release = displayVer + " (build " + build + ")"
	case build != "":
		release = "build " + build
	default:
		release = "unknown"
	}
	return release, "", nil
}
