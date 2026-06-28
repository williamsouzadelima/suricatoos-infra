//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const receiptXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PackageFileName</key>
	<string>CLTools_SDK_macOS14.pkg</string>
	<key>PackageIdentifier</key>
	<string>com.apple.pkg.CLTools_SDK_macOS14</string>
	<key>PackageVersion</key>
	<string>15.3.0.0.1.1708646388</string>
	<key>PackageWrapper</key>
	<string>no</string>
	<key>InstallDate</key>
	<date>2024-03-20T20:00:00Z</date>
</dict>
</plist>`

const infoPlistXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.googlecode.iterm2</string>
	<key>CFBundleName</key>
	<string>iTerm2</string>
	<key>CFBundleShortVersionString</key>
	<string>3.5.4</string>
	<key>CFBundleVersion</key>
	<string>3.5.4</string>
</dict>
</plist>`

const noBundleIDPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>CFBundleName</key>
	<string>MyApp</string>
	<key>CFBundleShortVersionString</key>
	<string>2.0.0</string>
</dict></plist>`

func TestParsePlistDict_Receipt(t *testing.T) {
	kv, err := parsePlistDict(strings.NewReader(receiptXML))
	if err != nil {
		t.Fatal(err)
	}
	if kv["PackageIdentifier"] != "com.apple.pkg.CLTools_SDK_macOS14" {
		t.Errorf("PackageIdentifier = %q", kv["PackageIdentifier"])
	}
	if kv["PackageVersion"] != "15.3.0.0.1.1708646388" {
		t.Errorf("PackageVersion = %q", kv["PackageVersion"])
	}
	// Non-string fields (date) must not bleed into the map.
	if _, ok := kv["InstallDate"]; ok {
		t.Error("date-type field must not appear in string map")
	}
}

func TestParsePlistDict_InfoPlist(t *testing.T) {
	kv, err := parsePlistDict(strings.NewReader(infoPlistXML))
	if err != nil {
		t.Fatal(err)
	}
	if kv["CFBundleIdentifier"] != "com.googlecode.iterm2" {
		t.Errorf("CFBundleIdentifier = %q", kv["CFBundleIdentifier"])
	}
	if kv["CFBundleShortVersionString"] != "3.5.4" {
		t.Errorf("CFBundleShortVersionString = %q", kv["CFBundleShortVersionString"])
	}
}

func TestReadReceipts(t *testing.T) {
	dir := t.TempDir()
	// Valid receipt.
	if err := os.WriteFile(filepath.Join(dir, "com.apple.pkg.CLTools_SDK_macOS14.plist"), []byte(receiptXML), 0o644); err != nil {
		t.Fatal(err)
	}
	// Receipt missing PackageVersion — must be skipped.
	noVersion := `<plist version="1.0"><dict><key>PackageIdentifier</key><string>com.foo.bar</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(dir, "com.foo.bar.plist"), []byte(noVersion), 0o644); err != nil {
		t.Fatal(err)
	}
	// Non-plist file — must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "com.foo.bar.bom"), []byte("bom"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := readReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("want 1 package, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "com.apple.pkg.CLTools_SDK_macOS14" || pkgs[0].Version != "15.3.0.0.1.1708646388" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
	if pkgs[0].Source != "pkgutil" {
		t.Errorf("source = %q, want pkgutil", pkgs[0].Source)
	}
}

func TestReadReceipts_NonExistentDir(t *testing.T) {
	pkgs, err := readReceipts("/does/not/exist")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected empty, got %+v", pkgs)
	}
}

func TestScanApps(t *testing.T) {
	dir := t.TempDir()

	// App with bundle ID.
	appContents := filepath.Join(dir, "iTerm2.app", "Contents")
	if err := os.MkdirAll(appContents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appContents, "Info.plist"), []byte(infoPlistXML), 0o644); err != nil {
		t.Fatal(err)
	}

	// App without bundle ID — should fall back to CFBundleName.
	app2Contents := filepath.Join(dir, "MyApp.app", "Contents")
	if err := os.MkdirAll(app2Contents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app2Contents, "Info.plist"), []byte(noBundleIDPlist), 0o644); err != nil {
		t.Fatal(err)
	}

	// App without Contents/Info.plist — must be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "NoInfo.app"), 0o755); err != nil {
		t.Fatal(err)
	}

	converter := func(path string) ([]byte, error) { return os.ReadFile(path) }
	pkgs, err := scanApps(dir, converter)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(pkgs), pkgs)
	}

	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
		if p.Source != "app-bundle" {
			t.Errorf("source = %q, want app-bundle", p.Source)
		}
	}
	if byName["com.googlecode.iterm2"] != "3.5.4" {
		t.Errorf("iterm2 version wrong: %+v", byName)
	}
	if byName["MyApp"] != "2.0.0" {
		t.Errorf("MyApp version wrong: %+v", byName)
	}
}

func TestParseBrewOutput(t *testing.T) {
	input := "bash 5.2.37\ngit 2.47.1\nopenssl@3 3.4.1\npython@3.13 3.13.2 3.12.9\n"
	pkgs := parseBrewOutput([]byte(input))
	if len(pkgs) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.2.37" || pkgs[0].Source != "homebrew" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
	// Multi-version formula: take first version only.
	if pkgs[3].Name != "python@3.13" || pkgs[3].Version != "3.13.2" {
		t.Errorf("multi-version: %+v", pkgs[3])
	}
}

func TestCollect_WithMocks(t *testing.T) {
	receiptDir := t.TempDir()
	appsDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(receiptDir, "com.apple.pkg.Test.plist"), []byte(receiptXML), 0o644); err != nil {
		t.Fatal(err)
	}
	appContents := filepath.Join(appsDir, "iTerm2.app", "Contents")
	if err := os.MkdirAll(appContents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appContents, "Info.plist"), []byte(infoPlistXML), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Collector{
		receiptsDir:    receiptDir,
		appsDir:        appsDir,
		swVers:         func() (string, string, error) { return "macos", "14.5.0", nil },
		brewList:       func() ([]byte, error) { return []byte("bash 5.2.37\n"), nil },
		uname:          func() (string, error) { return "24.5.0", nil },
		plistConverter: func(path string) ([]byte, error) { return os.ReadFile(path) },
	}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Family != "darwin" {
		t.Errorf("family = %q", inv.OS.Family)
	}
	if inv.OS.Release != "14.5.0" {
		t.Errorf("release = %q", inv.OS.Release)
	}
	if inv.OS.Kernel != "24.5.0" {
		t.Errorf("kernel = %q", inv.OS.Kernel)
	}
	// 1 receipt + 1 app-bundle + 1 brew
	if len(inv.Packages) != 3 {
		t.Errorf("want 3 packages, got %d: %+v", len(inv.Packages), inv.Packages)
	}
	if len(inv.CycleHash) != 64 {
		t.Errorf("cycle_hash len = %d", len(inv.CycleHash))
	}
}
