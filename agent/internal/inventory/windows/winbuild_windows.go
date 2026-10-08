//go:build windows

package windows

import (
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// defaultOSBuild reads the Windows build number (CurrentBuildNumber) and the
// Update Build Revision (UBR) from the NT CurrentVersion key. Together they form
// the precise patch level (e.g. "19045" + "4291" → 19045.4291) that MSRC
// correlation compares to tell a patched host from an unpatched one. A missing
// value returns an empty string; this read is best-effort and non-fatal.
func defaultOSBuild() (build, ubr string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ntCurrentVersion, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	build, _, _ = k.GetStringValue("CurrentBuildNumber")
	if v, _, err := k.GetIntegerValue("UBR"); err == nil {
		ubr = strconv.FormatUint(v, 10)
	}
	return build, ubr
}
