package contract

import "testing"

// TestClassifyReplay: the pure rule the persisted store reuses — the SAME canonical form already recorded is a
// redelivery (line 2a, before the window), another canonical form recorded under the same nonce or command_id
// is a replay (line 5), nothing recorded is fresh.
func TestClassifyReplay(t *testing.T) {
	a := adrCanonicalSHA256
	b := sha256hex([]byte("outra forma canônica"))
	cases := []struct {
		name     string
		current  string
		recorded []string
		want     ReplayClass
	}{
		{"nada gravado", a, nil, ReplayFresh},
		{"lista vazia", a, []string{}, ReplayFresh},
		{"mesma forma gravada: reentrega", a, []string{a}, ReplayRedelivery},
		{"outra forma sob o nonce ou command_id: replay", a, []string{b}, ReplayConflict},
		{"forma gravada como replay também é reentrega", b, []string{a, b}, ReplayRedelivery},
		{"comparação exata (maiúsculas não casam)", a, []string{upper(a)}, ReplayConflict},
	}
	for _, c := range cases {
		if got := ClassifyReplay(c.current, c.recorded); got != c.want {
			t.Errorf("%s: %v, esperado %v", c.name, got, c.want)
		}
	}
	for c, s := range map[ReplayClass]string{ReplayFresh: "fresh", ReplayRedelivery: "redelivery", ReplayConflict: "replay"} {
		if c.String() != s {
			t.Errorf("String(%d) = %q", c, c.String())
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
