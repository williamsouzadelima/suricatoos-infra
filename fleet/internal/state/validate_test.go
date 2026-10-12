package state

import (
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Cada regra de texto do estado é a do schema, lida do arquivo: tamanho em runas, padrão e o conjunto de
// caracteres de controle (no_control, ou o do icalendar).
func TestRegrasDeTextoConferemComOSchema(t *testing.T) {
	cases := []struct {
		ref  string
		rule rule
	}{
		{"fleet-command.schema.json#/$defs/uuid", ruleUUID},
		{"fleet-command.schema.json#/$defs/tenant", ruleTenant},
		{"fleet-command.schema.json#/$defs/gvm_name", ruleName},
		{"fleet-command.schema.json#/$defs/version_string", ruleVersion},
		{"fleet-command.schema.json#/$defs/ip_or_cidr", ruleIPOrCIDR},
		{"fleet-command.schema.json#/$defs/agent_id", ruleAgentID},
		{"fleet-command.schema.json#/$defs/token_id", ruleTokenID},
		{"fleet-command.schema.json#/$defs/iana_timezone", ruleTimezone},
		{"fleet-command.schema.json#/$defs/icalendar", ruleICalendar},
		{"fleet-command.schema.json#/$defs/sha256_hex", ruleSHA256},
		{"fleet-command.schema.json#/$defs/utc_time", ruleUTC},
		{"fleet-state.schema.json#/$defs/gvm_status", ruleStatus},
		{"fleet-state.schema.json#/$defs/data_scan_requests/properties/items/items/properties/job_id", ruleJobID},
		{"fleet-state.schema.json#/$defs/data_remediation/properties/items/items/properties/job_id", ruleJobID},
		{"fleet-state.schema.json#/$defs/data_targets/properties/items/items/properties/alive_test", ruleAliveTest},
		{"fleet-state.schema.json#/$defs/data_agents/properties/items/items/properties/os", ruleOSArch},
		{"fleet-state.schema.json#/$defs/data_agents/properties/items/items/properties/arch", ruleOSArch},
		{"fleet-state.schema.json#/$defs/data_tokens/properties/items/items/properties/policy", ruleTokenPolicy},
		{"fleet-state.schema.json#/$defs/audit_stream_tail/properties/lines/items", ruleAuditLine},
	}
	for _, c := range cases {
		s := schemaAt(t, c.ref)
		if s["type"] != "string" {
			t.Errorf("%s: type %v", c.ref, s["type"])
		}
		minLen, maxLen := 0, -1
		if v, ok := s["minLength"].(float64); ok {
			minLen = int(v)
		}
		if v, ok := s["maxLength"].(float64); ok {
			maxLen = int(v)
		}
		pattern, _ := s["pattern"].(string)
		if c.rule.min != minLen || c.rule.max != maxLen || c.rule.pattern != pattern {
			t.Errorf("%s: schema {min %d, max %d, %q}, Go {min %d, max %d, %q}", c.ref, minLen, maxLen, pattern,
				c.rule.min, c.rule.max, c.rule.pattern)
		}
		_, ical := s["not"]
		noControl := false
		if all, ok := s["allOf"].([]any); ok {
			for _, a := range all {
				if m, ok := a.(map[string]any); ok {
					if ref, _ := m["$ref"].(string); strings.HasSuffix(ref, "#/$defs/no_control") {
						noControl = true
					}
				}
			}
		}
		if ical != c.rule.ical {
			t.Errorf("%s: o schema tem o not do icalendar = %v, Go = %v", c.ref, ical, c.rule.ical)
		}
		if !ical && !noControl && c.rule.pattern == "" {
			t.Errorf("%s: texto livre sem no_control no schema", c.ref)
		}
	}
}

// Os tetos de itens das listas são os do schema.
func TestTetosDeItensConferemComOSchema(t *testing.T) {
	cases := []struct {
		ref string
		max int
	}{
		{"fleet-state.schema.json#/$defs/data_tasks/properties/items", maxTasks},
		{"fleet-state.schema.json#/$defs/data_targets/properties/items", maxTargets},
		{"fleet-state.schema.json#/$defs/data_schedules/properties/items", maxSchedules},
		{"fleet-state.schema.json#/$defs/data_reports/properties/items", maxReports},
		{"fleet-state.schema.json#/$defs/data_agents/properties/items", maxAgents},
		{"fleet-state.schema.json#/$defs/data_tokens/properties/items", maxTokens},
		{"fleet-state.schema.json#/$defs/data_sensors/properties/items", maxSensors},
		{"fleet-state.schema.json#/$defs/data_scan_requests/properties/items", maxScanRequests},
		{"fleet-state.schema.json#/$defs/data_remediation/properties/items", maxRemediation},
		{"fleet-state.schema.json#/$defs/data_scope/properties/items", maxScopeItems},
		{"fleet-state.schema.json#/$defs/data_targets/properties/items/items/properties/hosts", maxTargetHosts},
		{"fleet-state.schema.json#/$defs/data_schedules/properties/items/items/properties/task_ids", maxScheduleTasks},
		{"fleet-state.schema.json#/$defs/data_scope/properties/items/items/properties/scope", maxScopeEntries},
		{"fleet-state.schema.json#/$defs/data_node/properties/feeds", maxFeeds},
		{"fleet-state.schema.json#/$defs/audit_stream_tail/properties/lines", maxAuditLines},
		{"fleet-state.schema.json#/$defs/data_node/properties/capabilities/properties/report_formats/items/properties/variants", maxVariants},
	}
	for _, c := range cases {
		if got, ok := schemaAt(t, c.ref)["maxItems"].(float64); !ok || int(got) != c.max {
			t.Errorf("%s: maxItems do schema %v, Go %d", c.ref, schemaAt(t, c.ref)["maxItems"], c.max)
		}
	}
}

// O teto de 16 MiB é do corpo inteiro do PUT: o data fica abaixo dele com folga para o envelope.
func TestTetoDoDataCabeNoCorpo(t *testing.T) {
	if maxDataBytes+bodyReserve != contract.MaxStateBytes || bodyReserve < 512 {
		t.Fatalf("maxDataBytes %d + reserva %d != %d", maxDataBytes, bodyReserve, contract.MaxStateBytes)
	}
}

func TestRegrasDeTexto(t *testing.T) {
	ctrl := string(rune(0x01))
	nonchar := string(rune(0xfffe))
	cases := []struct {
		name string
		rule rule
		in   string
		ok   bool
	}{
		{"uuid", ruleUUID, uuidTask1, true},
		{"uuid maiúsculo", ruleUUID, strings.ToUpper(uuidScanner), false},
		{"tenant", ruleTenant, "acme.lab_1-x", true},
		{"tenant com espaço", ruleTenant, "acme corp", false},
		{"tenant começando com hífen", ruleTenant, "-acme", false},
		{"tenant de 65", ruleTenant, strings.Repeat("a", 65), false},
		{"nome com <>& e acento", ruleName, `Rede <LAB> & "matriz" é`, true},
		{"nome vazio", ruleName, "", false},
		{"nome com controle", ruleName, "a" + ctrl, false},
		{"nome com U+FFFE", ruleName, "a" + nonchar, false},
		{"nome com quebra de linha", ruleName, "a\n", false},
		{"nome de 128 runas multibyte", ruleName, strings.Repeat("é", 128), true},
		{"nome de 129 runas", ruleName, strings.Repeat("é", 129), false},
		{"nome com UTF-8 inválido", ruleName, "a\xff", false},
		{"status", ruleStatus, "Stop Requested", true},
		{"status com dígito", ruleStatus, "Done2", false},
		{"utc", ruleUTC, "2026-10-11T12:00:00Z", true},
		{"utc 30 de fevereiro", ruleUTC, "2026-02-30T12:00:00Z", false},
		{"utc com fração", ruleUTC, "2026-10-11T12:00:00.5Z", false},
		{"ip", ruleIPOrCIDR, "192.0.2.10", true},
		{"cidr", ruleIPOrCIDR, "192.0.2.0/24", true},
		{"ipv6", ruleIPOrCIDR, "2001:db8::1", true},
		{"cidr ipv6", ruleIPOrCIDR, "2001:db8::/32", true},
		// hostnames que casam o padrão de ip_or_cidr (só hex, ponto e dois-pontos): o padrão não basta
		{"hostname só com hex", ruleIPOrCIDR, "cafe.be", false},
		{"hostname hex com barra", ruleIPOrCIDR, "dead.beef/24", false},
		{"hostname", ruleIPOrCIDR, "srv01.exemplo.com.br", false},
		{"faixa", ruleIPOrCIDR, "192.0.2.1-192.0.2.9", false},
		{"zona", ruleIPOrCIDR, "fe80::1%eth0", false},
		{"prefixo além do tamanho", ruleIPOrCIDR, "192.0.2.0/33", false},
		{"agent_id", ruleAgentID, "DESKTOP-ACME-01", true},
		{"agent_id com vírgula", ruleAgentID, "a,b", false},
		{"token_id", ruleTokenID, "tok_ABCdef12", true},
		{"token_id curto", ruleTokenID, "tok", false},
		{"job_id", ruleJobID, "job-01_A", true},
		{"job_id com ponto", ruleJobID, "job.1", false},
		{"fuso", ruleTimezone, "America/Sao_Paulo", true},
		{"fuso com espaço", ruleTimezone, "America/Sao Paulo", false},
		{"icalendar", ruleICalendar, ical, true},
		{"icalendar com tab", ruleICalendar, ical + "\t", true},
		{"icalendar sem prefixo", ruleICalendar, "VERSION:2.0" + ical, false},
		{"icalendar com controle", ruleICalendar, ical + ctrl, false},
		{"alive_test vazio", ruleAliveTest, "", true},
		{"alive_test", ruleAliveTest, "ICMP, TCP-SYN Service & ARP Ping", true},
		{"linha de auditoria de 1", ruleAuditLine, "{", false},
	}
	for _, c := range cases {
		if got := c.rule.ok(c.in); got != c.ok {
			t.Errorf("%s: ok(%q) = %v, esperava %v", c.name, c.in, got, c.ok)
		}
	}
}
