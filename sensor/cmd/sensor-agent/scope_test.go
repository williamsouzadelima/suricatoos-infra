package main

import (
	"fmt"
	"strings"
	"testing"
)

// scopeEnv is a getenv over a fixed map: the sensor on a documentation LAN
// (RFC 5737), living at 192.0.2.10.
func scopeEnv(mode string) func(string) string {
	env := map[string]string{
		"SCAN_SCOPE":               "192.0.2.0/24",
		"SCAN_SELF_DENY_IPS":       "192.0.2.10",
		"SCAN_SELF_DENY_CIDR_MODE": mode,
	}
	return func(k string) string { return env[k] }
}

// logLines captures what newScope logs, one entry per call.
type logLines []string

func (l *logLines) printf(format string, args ...any) {
	*l = append(*l, fmt.Sprintf(format, args...))
}

func TestScopeCIDRModeLogScansLANAndWarnsOnce(t *testing.T) {
	for _, mode := range []string{"", "log"} { // "" = variável ausente: padrão log
		var logs logLines
		sc, err := newScope(scopeEnv(mode), logs.printf)
		if err != nil {
			t.Fatalf("mode=%q: %v", mode, err)
		}
		if got, err := sc.CheckHost("192.0.2.0/24"); err != nil || got != "192.0.2.0/24" {
			t.Fatalf("mode=%q: o /24 da LAN segue varrido em log, got %q err=%v", mode, got, err)
		}
		if len(logs) != 1 || !strings.Contains(logs[0], "192.0.2.0/24") {
			t.Fatalf("mode=%q: esperada UMA linha de aviso com o CIDR, veio %q", mode, logs)
		}
		if strings.Contains(logs[0], "192.0.2.10") {
			t.Fatalf("mode=%q: o aviso não pode expor o IP do self-deny: %q", mode, logs[0])
		}
	}
}

func TestScopeCIDRModeEnforceDeniesLAN(t *testing.T) {
	var logs logLines
	sc, err := newScope(scopeEnv("enforce"), logs.printf)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sc.CheckHost("192.0.2.0/24"); err == nil {
		t.Fatalf("enforce deveria negar o /24 que contém o sensor, passou como %q", got)
	}
	if len(logs) != 0 {
		t.Fatalf("enforce não loga aviso de modo log: %q", logs)
	}
}

func TestScopeCIDRModeInvalidIsAnError(t *testing.T) {
	var logs logLines
	if _, err := newScope(scopeEnv("deny"), logs.printf); err == nil ||
		!strings.Contains(err.Error(), "SCAN_SELF_DENY_CIDR_MODE") {
		t.Fatalf("valor inválido deveria falhar citando a variável, err=%v", err)
	}
}
