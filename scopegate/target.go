package scopegate

import (
	"errors"
	"fmt"
	"strings"
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
func (s *Scope) CheckTarget(hosts, excludeHosts []string) error {
	if len(hosts) == 0 {
		return errors.New("alvo sem hosts")
	}
	for i, h := range hosts {
		canonical, containsSelf, err := s.gate(h)
		if err == nil && containsSelf {
			err = fmt.Errorf("CIDR %s negado: %s", canonical, reasonSelfDenyCIDR)
		}
		if err != nil {
			return fmt.Errorf("hosts[%d]: %w", i, err)
		}
	}
	for i, h := range excludeHosts {
		if _, _, ok := literal(strings.TrimSpace(h)); !ok {
			return fmt.Errorf("exclude_hosts[%d]: %s não é IP/CIDR literal", i, echo(h))
		}
	}
	return nil
}

// echo renders arbitrary input for an error message: cut to maxEcho bytes and
// %q-quoted, so a hostile value can neither flood a log nor inject a line.
func echo(s string) string {
	if len(s) > maxEcho {
		return fmt.Sprintf("%q…", s[:maxEcho])
	}
	return fmt.Sprintf("%q", s)
}
