//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// scanApps walks dir (normally /Applications) and collects one Package per
// *.app bundle whose Contents/Info.plist contains a CFBundleShortVersionString.
// The converter func converts any plist to XML (used to handle binary plists).
func scanApps(dir string, converter func(string) ([]byte, error)) ([]inventory.Package, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var pkgs []inventory.Package
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".app") {
			continue
		}
		plistPath := filepath.Join(dir, e.Name(), "Contents", "Info.plist")
		if _, err := os.Stat(plistPath); err != nil {
			continue
		}
		data, err := converter(plistPath)
		if err != nil {
			continue
		}
		kv, err := parsePlistDict(bytes.NewReader(data))
		if err != nil {
			continue
		}
		version := kv["CFBundleShortVersionString"]
		if version == "" {
			continue // no version → skip; not useful for correlation
		}
		name := kv["CFBundleIdentifier"]
		if name == "" {
			name = kv["CFBundleName"]
		}
		if name == "" {
			name = strings.TrimSuffix(e.Name(), ".app")
		}
		pkgs = append(pkgs, inventory.Package{
			Name:    name,
			Version: version,
			Source:  inventory.SourceAppBundle,
		})
	}
	return pkgs, nil
}

// defaultPlistConverter uses plutil to convert any plist format (XML or binary)
// to XML and returns the resulting bytes. plutil is always present on macOS.
func defaultPlistConverter(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "plutil", "-convert", "xml1", "-o", "-", path).Output()
}
