package replay

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// chained puts, under the lock, n entries under v's nonce (each with its own command_id) and m entries under v's
// command_id (each with its own nonce), plus one entry under BOTH keys — the chains a compromised hub grows by
// re-signing (line 5 records every replay, before any budget).
func chained(t testing.TB, s *Store, v *contract.Verified, n, m int) {
	t.Helper()
	c := v.Command()
	nonce, cmd := canonKey(c.Nonce), cmdKey(c.CommandID)
	key := func(i int) (k [32]byte) { binary.BigEndian.PutUint64(k[:], uint64(i)+1); return k }
	id := func(i int) (k [16]byte) { binary.BigEndian.PutUint64(k[:], uint64(i)+1); return k }
	alive := t0.Add(30 * 24 * time.Hour).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range n {
		s.insertLocked(entry{canon: key(i), nonce: nonce, cmd: id(i), at: t0.UnixNano(), expires: alive,
			decision: contract.DecisionRejected, reason: contract.ReasonReplay})
	}
	for i := range m {
		s.insertLocked(entry{canon: key(n + i), nonce: key(n + i), cmd: cmd, at: t0.UnixNano(), expires: alive,
			decision: contract.DecisionRejected, reason: contract.ReasonReplay})
	}
	s.insertLocked(entry{canon: key(n + m), nonce: nonce, cmd: cmd, at: t0.UnixNano(), expires: alive,
		decision: contract.DecisionRejected, reason: contract.ReasonReplay})
}

// O Lookup é linear no comprimento das cadeias (sonda P3 da revisão): cada forma gravada sob o nonce OU o
// command_id aparece uma vez — a entrada que está nas duas cadeias também —, sem a deduplicação quadrática que, com
// ~10⁵ replays numa chave, segurava o mutex do store (e o do pipeline) por segundos a cada envelope.
func TestLookupLinearNaCadeia(t *testing.T) {
	s, _ := firstBoot(t)
	v := env(t, "x")
	const n, m = 100_000, 3
	chained(t, s.Store, v, n, m)
	start := time.Now()
	l := s.Lookup(v, t0)
	took := time.Since(start)
	if l.Same != nil || len(l.Recorded) != n+m+1 {
		t.Fatalf("Recorded com %d formas, esperava %d (sem repetição nem falta)", len(l.Recorded), n+m+1)
	}
	seen := make(map[string]bool, len(l.Recorded))
	for _, r := range l.Recorded {
		if seen[r] {
			t.Fatalf("forma repetida em Recorded: %s", r)
		}
		seen[r] = true
	}
	// linear: milissegundos (dezenas com -race); a deduplicação quadrática levava ~10 s nesse tamanho
	if took > 2*time.Second {
		t.Fatalf("Lookup numa cadeia de %d entradas levou %v: não é linear", n, took)
	}
	if got := contract.ClassifyReplay(v.CanonicalSHA256(), l.Recorded); got != contract.ReplayConflict {
		t.Fatalf("ClassifyReplay = %v", got)
	}
}

func BenchmarkLookupCadeiaLonga(b *testing.B) {
	dir := b.TempDir()
	s, err := open(dir, t0, Options{}, defaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	v := envB(b, "x")
	chained(b, s, v, 50_000, 50_000)
	b.ResetTimer()
	for b.Loop() {
		s.Lookup(v, t0)
	}
}

// envB is env for a benchmark.
func envB(b *testing.B, name string) *contract.Verified {
	b.Helper()
	v, err := contract.Verify(testPub(), signRaw(command(name), taskPayload))
	if err != nil {
		b.Fatal(err)
	}
	return v
}
