package ca

import (
	"fmt"
	"math/big"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// spellSerial writes n in one of the spellings a serial reaches the CA in: the CA's
// own lower-case hex, upper case (nginx), leading zeros, a 0x prefix, ':' between
// bytes, surrounding spaces.
func spellSerial(n *big.Int, kind int) string {
	h := n.Text(16)
	switch kind % 6 {
	case 0:
		return h
	case 1:
		return strings.ToUpper(h)
	case 2:
		return "000" + h
	case 3:
		return "0x" + h
	case 4:
		if len(h)%2 == 1 {
			h = "0" + h
		}
		var pairs []string
		for i := 0; i < len(h); i += 2 {
			pairs = append(pairs, strings.ToUpper(h[i:i+2]))
		}
		return strings.Join(pairs, ":")
	default:
		return "  " + h + " "
	}
}

// The revocation list's index answers exactly what comparing the numbers answered:
// a serial matches whatever its spelling (hex case, leading zeros, 0x, ':' separators,
// surrounding spaces), and a different number never does — in IsRevoked, in the batch
// dedupe and when a file is loaded.
func TestRevocationIndexIsNumericEquality(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	path := filepath.Join(t.TempDir(), "crl.json")
	c, _ := NewEphemeral(now)
	if err := c.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	rng := mathrand.New(mathrand.NewPCG(1, 2))
	random128 := func() *big.Int {
		n := new(big.Int).SetUint64(rng.Uint64())
		return n.Lsh(n, 64).Or(n, new(big.Int).SetUint64(rng.Uint64()))
	}
	var revoked, others []*big.Int
	for i := range 1000 {
		if i%2 == 0 {
			revoked = append(revoked, random128())
		} else {
			others = append(others, random128())
		}
	}
	// Small numbers, where leading zeros are most of the spelling.
	revoked = append(revoked, big.NewInt(0xa), big.NewInt(0x1b))
	others = append(others, big.NewInt(0xa0), big.NewInt(0x1))

	batch := make([]string, len(revoked))
	for i, n := range revoked {
		batch[i] = spellSerial(n, i)
	}
	added, invalid, err := c.RevokeCertSerials(batch, now)
	if err != nil || added != len(revoked) || len(invalid) != 0 {
		t.Fatalf("batch in mixed spellings: added=%d invalid=%v err=%v, want %d, none, nil", added, invalid, err, len(revoked))
	}
	for i, n := range revoked { // the same numbers, spelled differently: nothing new
		batch[i] = spellSerial(n, i+1)
	}
	if added, invalid, err := c.RevokeCertSerials(batch, now); err != nil || added != 0 || len(invalid) != 0 {
		t.Fatalf("same numbers respelled: added=%d invalid=%v err=%v, want 0, none, nil", added, invalid, err)
	}
	if got := servedEntries(t, c, now); len(got) != len(revoked) {
		t.Fatalf("served CRL has %d entries, want %d", len(got), len(revoked))
	}

	fresh, _ := NewEphemeral(now) // the file round trip answers the same
	if err := fresh.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	for _, authority := range []*CA{c, fresh} {
		for i, n := range revoked {
			for kind := range 6 {
				if s := spellSerial(n, kind); !authority.IsRevoked(s) {
					t.Fatalf("revoked serial #%d spelled %q: IsRevoked = false", i, s)
				}
			}
		}
		for i, n := range others {
			for kind := range 6 {
				if s := spellSerial(n, kind); authority.IsRevoked(s) {
					t.Fatalf("serial #%d spelled %q was never revoked: IsRevoked = true", i, s)
				}
			}
		}
	}
}

// A hand-edited (or pre-dedupe) CRL file with one serial spelled three ways loads as
// one entry, and the next save writes it once.
func TestLoadCRLFileDeduplicatesSerials(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	path := filepath.Join(t.TempDir(), "crl.json")
	file := `[{"serial":"0a1b","revoked_at":"2023-11-14T22:13:20Z"},` +
		`{"serial":"0A1B","revoked_at":"2023-11-15T00:00:00Z"},` +
		`{"serial":"000a1b","revoked_at":"2023-11-16T00:00:00Z"},` +
		`{"serial":"0c1d","revoked_at":"2023-11-14T22:13:20Z"}]`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := NewEphemeral(now)
	if err := c.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	got := servedEntries(t, c, now)
	if len(got) != 2 || !got[0].RevocationTime.Equal(now) {
		t.Fatalf("served CRL = %+v, want 2 entries, the first keeping the first revocation time", got)
	}
	if !c.IsRevoked("a1b") || !c.IsRevoked("C1D") {
		t.Fatal("both serials must be revoked")
	}
	if err := c.RevokeCertSerial("0c1d", now); err != nil {
		t.Fatal(err)
	}
	if on := readCRLFile(t, path); len(on) != 2 {
		t.Fatalf("crl.json = %+v after a save, want 2 entries", on)
	}
}

// The revocation list is indexed: a batch and the boot reconciliation cost O(1) per
// serial instead of a scan of the whole list per serial, all under the CA lock that
// every poll/ack/renew/enroll takes. Measured before the index: 84 s to reconcile 100k
// serials at boot (listener not up yet) and a 25 s IsRevoked stall behind a DELETE of
// 50k certificates. The bound is generous so a slow runner does not flake — the
// quadratic version takes minutes.
func TestRevocationListScalesTo100kSerials(t *testing.T) {
	const n = 100_000
	bound := 5 * time.Second
	if raceDetector {
		bound = 30 * time.Second
	}
	now := time.Unix(1700000000, 0).UTC()
	path := filepath.Join(t.TempDir(), "crl.json")
	serials := make([]string, n)
	for i := range serials { // distinct: multiplying by an odd constant is a bijection
		serials[i] = fmt.Sprintf("%032x", uint64(i)*0x9E3779B97F4A7C15+1)
	}

	c, _ := NewEphemeral(now)
	if err := c.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	added, invalid, err := c.RevokeCertSerials(serials, now) // a DELETE of a token with 100k certificates
	cold := time.Since(start)
	if err != nil || added != n || len(invalid) != 0 {
		t.Fatalf("cold batch: added=%d invalid=%d err=%v, want %d, 0, nil", added, len(invalid), err, n)
	}

	boot, _ := NewEphemeral(now) // the restart: load the file, then the reconciliation finds every serial
	start = time.Now()
	if err := boot.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	added, _, err = boot.RevokeCertSerials(serials, now)
	reboot := time.Since(start)
	if err != nil || added != 0 {
		t.Fatalf("boot reconciliation: added=%d err=%v, want 0, nil", added, err)
	}
	if !boot.IsRevoked(serials[n-1]) || boot.IsRevoked("abcdef") {
		t.Fatal("index answers wrong after the reload")
	}
	t.Logf("100k serials: batch %v, load + reconciliation %v (bound %v)", cold, reboot, bound)
	if cold > bound || reboot > bound {
		t.Fatalf("batch %v / load + reconciliation %v, want both under %v", cold, reboot, bound)
	}
}
