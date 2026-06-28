//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// readReceipts reads pkgutil receipts from dir (normally /var/db/receipts).
// Each *.plist file in that directory is an XML plist with PackageIdentifier
// and PackageVersion fields. The directory is always XML (never binary) so we
// parse it directly without shelling out to plutil.
func readReceipts(dir string) ([]inventory.Package, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var pkgs []inventory.Package
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		kv, err := parsePlistDict(f)
		f.Close()
		if err != nil {
			continue
		}
		name := kv["PackageIdentifier"]
		version := kv["PackageVersion"]
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, inventory.Package{
			Name:    name,
			Version: version,
			Source:  inventory.SourcePkgutil,
		})
	}
	return pkgs, nil
}
