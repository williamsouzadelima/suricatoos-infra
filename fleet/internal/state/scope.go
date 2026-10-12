package state

import (
	"net"
	"net/netip"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var scopeSources = []contract.ScopeSource{contract.ScopeTenantsRegistry, contract.ScopeLocalEnv}

var scopeSpec = listSpec[contract.ScopeItem]{
	max:    maxScopeItems,
	tenant: func(i *contract.ScopeItem) string { return i.Tenant },
	// more than 1 024 entries: the first ones go, and the cut — which has no count of its own — marks truncated
	prepare: func(i *contract.ScopeItem) bool {
		if len(i.Scope) > maxScopeEntries {
			i.Scope = i.Scope[:maxScopeEntries]
			return true
		}
		return false
	},
	valid: func(i *contract.ScopeItem) bool {
		return len(i.Scope) <= maxScopeEntries && all(i.Scope, ruleIPOrCIDR.ok) &&
			(i.Source == scopeSources[0] || i.Source == scopeSources[1])
	},
	key: func(i *contract.ScopeItem) string { return i.Tenant },
	wrap: func(items []contract.ScopeItem, tr bool, u int64) any {
		return contract.DataScope{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

// collectScope is the scope kind (read-only, D2): per known tenant, whether it is enabled, its CIDRs, whether a
// write is possible (a gvmd user AND a password) and where it comes from — never the name of the gvmd user nor the
// password, which are only looked at here. A name outside the tenant pattern is only counted.
func (c *Collector) collectScope(cyc *cycle) ([]byte, error) {
	list, err := c.listing(cyc)
	if err != nil {
		return nil, err
	}
	withPassword, err := c.cfg.Tenants.WithPassword()
	if err != nil {
		return nil, err
	}
	source := contract.ScopeLocalEnv
	if c.cfg.NodeKind == contract.NodeCentral {
		source = contract.ScopeTenantsRegistry
	}
	items := make([]contract.ScopeItem, 0, len(list))
	for _, l := range list {
		items = append(items, contract.ScopeItem{Tenant: l.Name, Enabled: l.Enabled, Scope: scopeEntries(l.Scope),
			GMPUserConfigured: l.GVMUser != "" && withPassword[l.Name], Source: source})
	}
	return finishList(scopeSpec, items, false, 0, ruleTenant.ok, c.dataLimit)
}

// scopeEntries is a tenant's scope as the scope gate (scopegate, slice F2.4a) reads it: tokens separated by commas,
// spaces, tabs or newlines, trimmed (a token left empty — a blank CRLF line, a lone CR, VT or no-break space — is
// skipped, as scopegate's fields does), each an IP or CIDR literal, in the gate's canonical form. One token that is
// not a literal makes the gate refuse the whole scope — nothing passes —, and that is what the state says: an empty
// scope, never just the good entries.
func scopeEntries(spec string) []string {
	out := []string{}
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if tok = strings.TrimSpace(tok); tok == "" {
			continue
		}
		canonical, ok := canonicalLiteral(tok)
		if !ok {
			return []string{}
		}
		out = append(out, canonical)
	}
	return out
}

// canonicalLiteral mirrors scopegate's literal + canonicalForm: the grammar of net.ParseIP / net.ParseCIDR (no
// hostname, range, port or zone); a bare IP is its address — an IPv4-mapped one as IPv4 —, a CIDR the masked prefix
// in the family it was written in.
func canonicalLiteral(tok string) (string, bool) {
	if ip := net.ParseIP(tok); ip != nil {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return "", false
		}
		return a.Unmap().String(), true
	}
	_, n, err := net.ParseCIDR(tok)
	if err != nil {
		return "", false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return "", false
	}
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a, bits).String(), true
}
