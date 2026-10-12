package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var (
	schemaDir   = filepath.Join("..", "..", "..", "schema")
	examplesDir = filepath.Join(schemaDir, "examples", "fleet")
)

// readExample returns a file of schema/examples/fleet without the trailing newline (CRLF in a Windows checkout).
func readExample(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b, " \t\r\n")
}

// schemaDoc reads one of the fleet schemas as generic JSON.
func schemaDoc(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(schemaDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// at parses a utc_time of the tests.
func at(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := contract.ParseUTCTime(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
