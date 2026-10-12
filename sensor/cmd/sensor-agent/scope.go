package main

import (
	"fmt"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/scopegate"
)

// newScope builds the baked scope from SCAN_SCOPE and SCAN_SELF_DENY_IPS.
// SCAN_SELF_DENY_CIDR_MODE picks what happens to a target CIDR that CONTAINS a
// self-deny IP (e.g. the /24 of the LAN the sensor lives in): "log" (default — the
// rule is new, ADR-0011 D7: it is scanned as before and logf gets one warning line
// with only the CIDR and the reason) or "enforce" (denied). Any other value is an
// error, so a typo never silently picks a mode. A SCAN_SELF_DENY_IPS token the
// sensor cannot use (not a single IP, an IPv4 /32 or an IPv6 /128) gets one warning line at
// start-up and is skipped — never fatal (D7).
func newScope(getenv func(string) string, logf func(format string, args ...any)) (*scopegate.Scope, error) {
	opts := []scopegate.Option{scopegate.OnIgnoredSelfDeny(func(token string) {
		logf("scope: AVISO: SCAN_SELF_DENY_IPS ignora o token %s: não é IP isolado nem /32 (IPv4) ou /128 (IPv6)", token)
	})}
	switch mode := strings.TrimSpace(getenv("SCAN_SELF_DENY_CIDR_MODE")); mode {
	case "", "log":
		opts = append(opts, scopegate.LogSelfDenyCIDR(func(cidr, reason string) {
			logf("scope: AVISO: alvo %s %s — varrido mesmo assim (SCAN_SELF_DENY_CIDR_MODE=log; enforce nega)", cidr, reason)
		}))
	case "enforce":
	default:
		return nil, fmt.Errorf("SCAN_SELF_DENY_CIDR_MODE inválido %q (use log ou enforce)", mode)
	}
	return scopegate.New(getenv("SCAN_SCOPE"), getenv("SCAN_SELF_DENY_IPS"), opts...)
}
