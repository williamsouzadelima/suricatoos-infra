package scopegate

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxEcho bounds how much of an arbitrary input an error message repeats.
const maxEcho = 64

// CheckTarget is the fleet's gate on a gvmd target (ADR-0011, "Escopo, regra
// completa"; a failure is scope_denied). Every hosts entry must be an IP/CIDR
// literal (no hostname or range), lie within the allow-set, stay out of
// degenerate space, and neither be nor contain a self-deny IP (own + hub): this
// last rule is always enforced here, whatever LogSelfDenyCIDR says, and no
// excludeHosts entry saves such a CIDR. Each excludeHosts entry only has to be
// an IP/CIDR literal — excluding never widens. An empty hosts list is refused.
//
// The grammar is stricter than CheckHost's, so that gvm-libs reads exactly what
// was checked: ASCII only, and a prefix length spelled as strconv.Itoa (gvm-libs
// reads "/025" as /2). On success it returns, in order, the canonical form of
// every hosts and excludeHosts entry: the connector forwards exactly those to
// gvmd. On refusal it returns no hosts at all.
func (s *Scope) CheckTarget(hosts, excludeHosts []string) (canonHosts, canonExclude []string, err error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("alvo sem hosts")
	}
	for i, h := range hosts {
		p, bare, err := strictLiteral(h)
		if err != nil {
			return nil, nil, fmt.Errorf("hosts[%d]: %w", i, err)
		}
		canonical, containsSelf, err := s.gate(p, bare)
		if err == nil && containsSelf {
			err = fmt.Errorf("CIDR %s negado: %s", canonical, reasonSelfDenyCIDR)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("hosts[%d]: %w", i, err)
		}
		canonHosts = append(canonHosts, canonical)
	}
	for i, h := range excludeHosts {
		p, bare, err := strictLiteral(h)
		if err != nil {
			return nil, nil, fmt.Errorf("exclude_hosts[%d]: %w", i, err)
		}
		canonExclude = append(canonExclude, canonicalForm(p, bare))
	}
	return canonHosts, canonExclude, nil
}

// strictLiteral is literal() for what the fleet forwards to gvmd: no byte outside
// ASCII (so only ASCII whitespace is trimmed, like gvm-libs' g_strstrip, where Go
// would also trim Unicode spaces) and the prefix length written exactly as
// strconv.Itoa of its bits (no leading zeros, which gvm-libs misreads).
func strictLiteral(s string) (p netip.Prefix, bare bool, err error) {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return netip.Prefix{}, false, fmt.Errorf("%s contém byte não-ASCII", echo(s))
		}
	}
	t := strings.TrimSpace(s)
	p, bare, ok := literal(t)
	if !ok {
		return netip.Prefix{}, false, fmt.Errorf("%s não é IP/CIDR literal", echo(s))
	}
	if _, bits, isCIDR := strings.Cut(t, "/"); isCIDR && bits != strconv.Itoa(p.Bits()) {
		return netip.Prefix{}, false, fmt.Errorf("%s: o prefixo tem de ser /%d, sem zero à esquerda", echo(s), p.Bits())
	}
	return p, bare, nil
}

// echo renders arbitrary input for an error message: cut to maxEcho bytes and
// %q-quoted, so a hostile value can neither flood a log nor inject a line.
func echo(s string) string {
	if len(s) > maxEcho {
		return fmt.Sprintf("%q…", s[:maxEcho])
	}
	return fmt.Sprintf("%q", s)
}
