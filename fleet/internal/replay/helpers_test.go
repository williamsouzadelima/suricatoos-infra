package replay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// t0 is the instant of the tests: the window of every envelope below is 12:00–13:00 of this day.
var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// testKey is a FICTITIOUS command key derived from a public text — not the golden key, not a production key.
var testKey = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("suricatoos-fleet-replay/chave-de-teste-ficticia"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

func testPub() ed25519.PublicKey { return testKey.Public().(ed25519.PublicKey) }

// uuidOf derives a lowercase v4 UUID from a name.
func uuidOf(name string) string {
	s := sha256.Sum256([]byte("uuid/" + name))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// nonceOf derives a 64-hex nonce from a name.
func nonceOf(name string) string {
	s := sha256.Sum256([]byte("nonce/" + name))
	return hex.EncodeToString(s[:])
}

// command is the envelope of the tests, named: its command_id and nonce come from the name.
func command(name string) contract.Command {
	return contract.Command{SchemaVersion: contract.SchemaVersion, CommandID: uuidOf(name), NodeID: "node-lab-0001",
		Tenant: "acme", Type: contract.TypeTaskStart, IssuedBy: "op-7f3a", IssuedAt: "2026-10-11T12:00:00Z",
		NotAfter: "2026-10-11T13:00:00Z", Nonce: nonceOf(name)}
}

const taskPayload = `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`

// signRaw builds the envelope bytes the way contract.Sign does, but WITHOUT its fail-closed window check: a test
// needs envelopes with a window Sign refuses to emit.
func signRaw(c contract.Command, payload string) []byte {
	sum := sha256.Sum256([]byte(payload))
	c.PayloadSHA256 = hex.EncodeToString(sum[:])
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, contract.Canonical(&c)))
	q := func(s string) string { b, _ := contract.MarshalCompact(s); return string(b) }
	var b strings.Builder
	fmt.Fprintf(&b, `{"schema_version":%s,"command_id":%s,"node_id":%s,"tenant":%s,"type":%s,"issued_by":%s,"issued_at":%s,"not_after":%s,"nonce":%s,"payload_sha256":%s,"payload":%s,"signature":%s}`,
		q(c.SchemaVersion), q(c.CommandID), q(c.NodeID), q(c.Tenant), q(string(c.Type)), q(c.IssuedBy), q(c.IssuedAt),
		q(c.NotAfter), q(c.Nonce), q(c.PayloadSHA256), payload, q(c.Signature))
	return []byte(b.String())
}

// verified signs c and returns what contract.Verify authenticated.
func verified(t *testing.T, c contract.Command, payload string) *contract.Verified {
	t.Helper()
	v, err := contract.Verify(testPub(), signRaw(c, payload))
	if err != nil {
		t.Fatalf("envelope de teste não autenticou: %v", err)
	}
	return v
}

// env is verified(command(name), taskPayload).
func env(t *testing.T, name string) *contract.Verified {
	t.Helper()
	return verified(t, command(name), taskPayload)
}

var accepted = Decision{Decision: contract.DecisionAccepted}

func rejected(r contract.RejectReason) Decision {
	return Decision{Decision: contract.DecisionRejected, Reason: r}
}

// logSink collects what the store logs.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := strings.TrimSpace(l.buf.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// opened is a store under test with what it logged.
type opened struct {
	*Store
	sink *logSink
}

// openWith opens the store in dir at now with the given options and test config, closing it at the end of the test.
func openWith(t *testing.T, dir string, now time.Time, opts Options, cfg config) opened {
	t.Helper()
	sink := &logSink{}
	opts.Logger = slog.New(slog.NewTextHandler(sink, nil))
	s, err := open(dir, now, opts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return opened{s, sink}
}

// openAt opens the store of a node that already has its identity (the strict case) with the default config.
func openAt(t *testing.T, dir string, now time.Time) opened {
	t.Helper()
	return openWith(t, dir, now, Options{IdentityExists: true}, defaultConfig())
}

// firstBoot opens a fresh store as on the very first start of a node (no identity yet: no floor).
func firstBoot(t *testing.T) (opened, string) {
	t.Helper()
	dir := t.TempDir()
	return openWith(t, dir, t0, Options{}, defaultConfig()), dir
}

func mustRecord(t *testing.T, s *Store, v *contract.Verified, d Decision, at time.Time) Entry {
	t.Helper()
	e, err := s.Record(v, d, at)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return e
}

func storeBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// storeLines returns the lines of the store file, without their '\n'.
func storeLines(t *testing.T, dir string) []string {
	t.Helper()
	s := string(storeBytes(t, dir))
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// kinds returns the kind of every line of the store file.
func kinds(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, line := range storeLines(t, dir) {
		r, err := decodeLine([]byte(line))
		if err != nil {
			t.Fatalf("linha ilegível no store: %v (%q)", err, line)
		}
		out = append(out, r.K)
	}
	return out
}
