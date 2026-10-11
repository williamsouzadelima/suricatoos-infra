package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const (
	uuidA = "2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"
	uuidB = "9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35"
	uuidC = "daba56c8-73ec-11df-a475-002264764cea"
)

// documentationIP is the i-th address of the RFC 5737 documentation ranges (192.0.2.0/24, then 198.51.100.0/24).
func documentationIP(i int) string {
	if i < 256 {
		return "192.0.2." + strconv.Itoa(i)
	}
	return "198.51.100." + strconv.Itoa(i-256)
}

// export builds a valid report.export payload with the given filter (JSON-escaped).
func export(filter string) string {
	f, _ := json.Marshal(filter)
	return `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"en","variant":"technical","filter":` + string(f) + `}`
}

func jsonList(n int, item func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"` + item(i) + `"`
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// TestValidatePayload covers every constraint of the payload $defs (line 8), with the JSON Schema keyword and
// path a schema validator reports for that single defect.
func TestValidatePayload(t *testing.T) {
	ctrl := `\` + `u0001` // a JSON escape of U+0001 inside a string (valid JSON, refused by no_control)
	ical := `BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261011T020000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n`
	cases := []struct {
		name    string
		typ     CommandType
		in      string
		keyword string
		path    string
	}{
		{"task_ref", TypeTaskStart, `{"task_id":"` + uuidA + `"}`, "", ""},
		{"task_ref uuid maiúsculo", TypeTaskStop, `{"task_id":"` + strings.ToUpper(uuidA) + `"}`, "pattern", "/task_id"},
		{"task_ref membro a mais", TypeTaskResume, `{"task_id":"` + uuidA + `","x":1}`, "additionalProperties", ""},
		{"task_ref vazio", TypeTaskDelete, `{}`, "required", ""},
		{"task_ref null", TypeTaskStart, `{"task_id":null}`, "type", "/task_id"},
		{"payload não é objeto", TypeTaskStart, `[]`, "type", ""},
		{"chave duplicada", TypeTaskStart, `{"task_id":"` + uuidA + `","task_id":"` + uuidA + `"}`, "duplicate_key", "/task_id"},

		{"state.resync", TypeStateResync, `{"kinds":["tasks","targets"]}`, "", ""},
		{"state.resync sem kinds", TypeStateResync, `{"kinds":[]}`, "minItems", "/kinds"},
		{"state.resync repetido", TypeStateResync, `{"kinds":["tasks","tasks"]}`, "uniqueItems", "/kinds"},
		{"state.resync kind desconhecido", TypeStateResync, `{"kinds":["findings"]}`, "enum", "/kinds/0"},
		{"state.resync 13 itens", TypeStateResync, `{"kinds":` + jsonList(13, func(int) string { return "x" }) + `}`, "maxItems", "/kinds"},

		{"task.create", TypeTaskCreate, `{"name":"Varredura","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "", ""},
		{"task.create nome vazio", TypeTaskCreate, `{"name":"","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "minLength", "/name"},
		{"task.create nome 129", TypeTaskCreate, `{"name":"` + strings.Repeat("a", 129) + `","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "maxLength", "/name"},
		{"task.create nome de 128 letras acentuadas", TypeTaskCreate, `{"name":"` + strings.Repeat("ã", 128) + `","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "", ""},
		{"task.create nome com controle", TypeTaskCreate, `{"name":"a` + ctrl + `b","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "not", "/name"},
		{"task.create comentário vazio", TypeTaskCreate, `{"name":"x","comment":"","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "", ""},
		{"task.create comentário 401", TypeTaskCreate, `{"name":"x","comment":"` + strings.Repeat("c", 401) + `","target_id":"` + uuidB + `","scan_config_id":"` + uuidC + `"}`, "maxLength", "/comment"},
		{"task.create sem scan_config_id", TypeTaskCreate, `{"name":"x","target_id":"` + uuidB + `"}`, "required", ""},

		{"task.modify só task_id", TypeTaskModify, `{"task_id":"` + uuidA + `"}`, "minProperties", ""},
		{"task.modify desvincula agenda", TypeTaskModify, `{"task_id":"` + uuidA + `","schedule_id":""}`, "", ""},
		{"task.modify agenda inválida", TypeTaskModify, `{"task_id":"` + uuidA + `","schedule_id":"x"}`, "anyOf", "/schedule_id"},
		{"task.clone", TypeTaskClone, `{"task_id":"` + uuidA + `","name":"Cópia"}`, "", ""},

		{"target.create", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.0/24","2001:db8::1"],"exclude_hosts":["192.0.2.1"],"port_range":"T:1-1024,8080","alive_test":"ICMP Ping"}`, "", ""},
		{"target.create sem forma de porta", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.0/24"]}`, "oneOf", ""},
		{"target.create duas formas de porta", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.0/24"],"port_list_id":"` + uuidC + `","port_range":"T:1-10"}`, "oneOf", ""},
		{"target.create hostname", TypeTargetCreate, `{"name":"LAB","hosts":["scanner.example.com"],"port_range":"T:1-10"}`, "pattern", "/hosts/0"},
		{"target.create sem hosts", TypeTargetCreate, `{"name":"LAB","hosts":[],"port_range":"T:1-10"}`, "minItems", "/hosts"},
		{"target.create host repetido", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.1","192.0.2.1"],"port_range":"T:1-10"}`, "uniqueItems", "/hosts"},
		{"target.create 257 hosts", TypeTargetCreate, `{"name":"LAB","hosts":` + jsonList(257, documentationIP) + `,"port_range":"T:1-10"}`, "maxItems", "/hosts"},
		{"target.create CIDR de 44 caracteres", TypeTargetCreate, `{"name":"LAB","hosts":["2001:0db8:0000:0000:0000:0000:0000:00001/128"],"port_range":"T:1-10"}`, "maxLength", "/hosts/0"},
		{"target.create alive test desconhecido", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.1"],"port_range":"T:1-10","alive_test":"Ping"}`, "enum", "/alive_test"},
		{"target.create port_range inválido", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.1"],"port_range":"T:1-10;"}`, "pattern", "/port_range"},
		{"target.create exclusão vazia", TypeTargetCreate, `{"name":"LAB","hosts":["192.0.2.1"],"exclude_hosts":[],"port_range":"T:1-10"}`, "", ""},

		{"target.modify", TypeTargetModify, `{"target_id":"` + uuidB + `","name":"LAB 2"}`, "", ""},
		{"target.modify zera exclusões", TypeTargetModify, `{"target_id":"` + uuidB + `","exclude_hosts":[]}`, "", ""},
		{"target.modify troca a lista de portas", TypeTargetModify, `{"target_id":"` + uuidB + `","port_list_id":"` + uuidC + `"}`, "", ""},
		{"target.modify não muda port_range", TypeTargetModify, `{"target_id":"` + uuidB + `","port_range":"T:1-10"}`, "additionalProperties", ""},
		{"target.modify alive test fora da tabela", TypeTargetModify, `{"target_id":"` + uuidB + `","alive_test":"ICMP, ARP & TCP-SYN Service Ping"}`, "enum", "/alive_test"},
		{"target.modify sem mudança", TypeTargetModify, `{"target_id":"` + uuidB + `"}`, "minProperties", ""},
		{"target.delete", TypeTargetDelete, `{"target_id":"` + uuidB + `"}`, "", ""},

		{"schedule.create", TypeScheduleCreate, `{"name":"Semanal","icalendar":"` + ical + `","timezone":"America/Sao_Paulo","task_ids":["` + uuidA + `"]}`, "", ""},
		{"schedule.create sem BEGIN", TypeScheduleCreate, `{"name":"Semanal","icalendar":"X` + ical + `","timezone":"UTC"}`, "pattern", "/icalendar"},
		{"schedule.create controle no icalendar", TypeScheduleCreate, `{"name":"Semanal","icalendar":"` + ical + ctrl + `","timezone":"UTC"}`, "not", "/icalendar"},
		{"schedule.create fuso com espaço", TypeScheduleCreate, `{"name":"Semanal","icalendar":"` + ical + `","timezone":"America/Sao Paulo"}`, "pattern", "/timezone"},
		{"schedule.create 17 tarefas", TypeScheduleCreate, `{"name":"S","icalendar":"` + ical + `","timezone":"UTC","task_ids":` + jsonList(17, func(i int) string { return uuidA[:34] + fmt.Sprintf("%02d", i) }) + `}`, "maxItems", "/task_ids"},
		{"schedule.modify sem mudança", TypeScheduleModify, `{"schedule_id":"` + uuidA + `"}`, "minProperties", ""},
		{"schedule.delete", TypeScheduleDelete, `{"schedule_id":"` + uuidA + `"}`, "", ""},

		{"report.export", TypeReportExport, `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"pt_BR","variant":"executive","filter":"apply_overrides=1 min_qod=70 levels=chml rows=-1"}`, "", ""},
		{"filtro do export em qualquer ordem", TypeReportExport, export(`levels=hmlf min_qod=0 apply_overrides=0 rows=100 first=1`), "", ""},
		{"filtro do export com f e espaços extras", TypeReportExport, export(`  apply_overrides=1  min_qod=100 levels=f `), "", ""},
		{"filtro do export em branco", TypeReportExport, export(` `), "export_filter", "/filter"},
		{"filtro do export sem overrides e qod", TypeReportExport, export(`levels=chmlg rows=-1`), "export_filter", "/filter"},
		{"filtro do export sem levels", TypeReportExport, export(`apply_overrides=1 min_qod=70`), "export_filter", "/filter"},
		{"filtro do export min_qod 101", TypeReportExport, export(`apply_overrides=1 min_qod=101 levels=c`), "export_filter", "/filter"},
		{"filtro do export min_qod com zero à esquerda", TypeReportExport, export(`apply_overrides=1 min_qod=07 levels=c`), "export_filter", "/filter"},
		{"filtro do export levels repetido", TypeReportExport, export(`apply_overrides=1 min_qod=70 levels=cc`), "export_filter", "/filter"},
		{"filtro do export levels vazio", TypeReportExport, export(`apply_overrides=1 min_qod=70 levels=`), "export_filter", "/filter"},
		{"filtro do export chave duas vezes", TypeReportExport, export(`apply_overrides=1 apply_overrides=1 min_qod=0 levels=c`), "export_filter", "/filter"},
		{"filtro do export relação que não é =", TypeReportExport, export(`apply_overrides=1 min_qod>70 levels=c`), "export_filter", "/filter"},
		{"filtro do export chave sem relação", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels`), "export_filter", "/filter"},
		// the key ALONE belongs to the key too (a bare word would be a gvmd search term narrowing the export)
		{"filtro do export levels solto depois do válido", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml levels`), "export_filter", "/filter"},
		{"filtro do export levels solto antes do válido", TypeReportExport, export(`levels apply_overrides=1 min_qod=0 levels=hml`), "export_filter", "/filter"},
		{"filtro do export min_qod solto", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml min_qod`), "export_filter", "/filter"},
		{"filtro do export overrides 2", TypeReportExport, export(`apply_overrides=2 min_qod=0 levels=c`), "export_filter", "/filter"},
		// no double quote at all (amendment 3): gvmd's split_filter reads a part that starts with one (also after
		// = or ~) as ONE term up to the next, hiding the keywords — even when the three tokens look valid
		{"aspas em volta de um token do export", TypeReportExport, export(`"levels=c" apply_overrides=1 min_qod=0`), "export_filter", "/filter"},
		{"aspas numa frase que esconde as chaves", TypeReportExport, export(`"x apply_overrides=1 min_qod=0 levels=hml x"`), "export_filter", "/filter"},
		{"aspas no valor de levels", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels="hml"`), "export_filter", "/filter"},
		{"aspas num termo extra", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml "x"`), "export_filter", "/filter"},
		{"aspas depois de ~ num termo extra", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml name~"x y"`), "export_filter", "/filter"},
		{"aspas sozinhas no fim", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml "`), "export_filter", "/filter"},
		{"apóstrofo não é aspa", TypeReportExport, export(`apply_overrides=1 min_qod=0 levels=hml name~o'x`), "", ""},
		{"prefixo maior não é a chave", TypeReportExport, export(`xlevels=cc apply_overrides=1 min_qod=0 levels=c`), "", ""},
		{"report.export gvm em pt_BR", TypeReportExport, `{"report_id":"` + uuidA + `","format":"gvm-xml","lang":"pt_BR","variant":"technical","filter":"rows=-1"}`, "const", "/lang"},
		{"report.export gvm client", TypeReportExport, `{"report_id":"` + uuidA + `","format":"gvm-pdf","lang":"en","variant":"client","filter":"rows=-1"}`, "const", "/variant"},
		{"report.export variante full", TypeReportExport, `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"en","variant":"full","filter":"rows=-1"}`, "enum", "/variant"},
		{"report.export sem filtro", TypeReportExport, `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"en","variant":"technical"}`, "required", ""},
		{"report.export filtro vazio", TypeReportExport, `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"en","variant":"technical","filter":""}`, "minLength", "/filter"},
		{"report.export delta inválido", TypeReportExport, `{"report_id":"` + uuidA + `","format":"suricatoos-pdf","lang":"en","variant":"technical","delta_report_id":"x","filter":"rows=-1"}`, "pattern", "/delta_report_id"},

		{"report.summary", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":70,"apply_overrides":true,"levels":"chml"}`, "", ""},
		{"report.summary min_qod 101", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":101,"apply_overrides":true,"levels":"c"}`, "maximum", "/min_qod"},
		{"report.summary min_qod -1", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":-1,"apply_overrides":true,"levels":"c"}`, "minimum", "/min_qod"},
		{"report.summary min_qod 70.0", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":70.0,"apply_overrides":true,"levels":"c"}`, "integer_lexical", "/min_qod"},
		{"report.summary min_qod gigante", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":100000000000000000000,"apply_overrides":true,"levels":"c"}`, "maximum", "/min_qod"},
		{"report.summary níveis fora de ordem", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":0,"apply_overrides":false,"levels":"hc"}`, "pattern", "/levels"},
		{"report.summary níveis vazios", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":0,"apply_overrides":false,"levels":""}`, "minLength", "/levels"},
		{"report.summary overrides string", TypeReportSummary, `{"report_id":"` + uuidA + `","min_qod":0,"apply_overrides":"true","levels":"c"}`, "type", "/apply_overrides"},

		{"agent.scan_now", TypeAgentScanNow, `{"agent_id":"win-lab-0001"}`, "", ""},
		{"agent.scan_now id com vírgula", TypeAgentScanNow, `{"agent_id":"win,lab"}`, "pattern", "/agent_id"},
		{"agent.revoke motivo 257", TypeAgentRevoke, `{"agent_id":"win-lab-0001","reason":"` + strings.Repeat("r", 257) + `"}`, "maxLength", "/reason"},

		{"enroll_token.create deployment", TypeEnrollTokenCreate, `{"token_type":"deployment","policy":"agent-endpoint","ttl_hours":72,"max_uses":50}`, "", ""},
		{"deployment sem max_uses", TypeEnrollTokenCreate, `{"token_type":"deployment","policy":"agent-endpoint","ttl_hours":72}`, "required", ""},
		{"single_host com max_uses 2", TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1,"max_uses":2}`, "const", "/max_uses"},
		{"single_host com max_uses 1", TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1,"max_uses":1}`, "", ""},
		{"single_host sem max_uses", TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1}`, "", ""},
		{"ttl de 169 h", TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":169}`, "maximum", "/ttl_hours"},
		{"token scanner-sensor", TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"scanner-sensor","ttl_hours":1}`, "const", "/policy"},
		{"deployment com 1001 usos", TypeEnrollTokenCreate, `{"token_type":"deployment","policy":"agent-endpoint","ttl_hours":1,"max_uses":1001}`, "maximum", "/max_uses"},
		{"tipo de token desconhecido", TypeEnrollTokenCreate, `{"token_type":"forever","policy":"agent-endpoint","ttl_hours":1}`, "enum", "/token_type"},
		{"enroll_token.revoke id curto", TypeEnrollTokenRevoke, `{"token_id":"abc"}`, "minLength", "/token_id"},

		{"sensor_job.enqueue", TypeSensorJobEnqueue, `{"targets":["192.0.2.0/28"],"ports":"T:22,80,443"}`, "", ""},
		{"sensor_job.enqueue com alive test", TypeSensorJobEnqueue, `{"targets":["192.0.2.0/28"],"alive_test":"ICMP Ping"}`, "additionalProperties", ""},
		{"feed.sync_now", TypeFeedSyncNow, `{}`, "", ""},
		{"feed.sync_now com parâmetro", TypeFeedSyncNow, `{"force":true}`, "maxProperties", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kw, path := violationOf(t, ValidatePayload(c.typ, []byte(c.in)))
			if kw != c.keyword || path != c.path {
				t.Fatalf("got (%q, %q), want (%q, %q)", kw, path, c.keyword, c.path)
			}
		})
	}
}

// TestDecodePayload returns the typed payload with presence preserved: the connector hands EXACTLY these
// values to fleet_ops.py, never the raw JSON.
func TestDecodePayload(t *testing.T) {
	p, err := DecodePayload(TypeTaskModify, []byte(`{"task_id":"`+uuidA+`","schedule_id":""}`))
	if err != nil {
		t.Fatal(err)
	}
	m := p.(*PayloadTaskModify)
	if m.ScheduleID == nil || *m.ScheduleID != "" || m.Name != nil {
		t.Fatalf("presença: %+v", m)
	}
	p, err = DecodePayload(TypeTargetModify, []byte(`{"target_id":"`+uuidB+`","exclude_hosts":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if tm := p.(*PayloadTargetModify); tm.ExcludeHosts == nil || len(tm.ExcludeHosts) != 0 || tm.Hosts != nil {
		t.Fatalf("[] presente x ausente: %+v", tm)
	}
	if _, ok := p.(*PayloadTargetModify); !ok {
		t.Fatalf("tipo %T", p)
	}
	if err := ValidatePayload("tenant.scope_set", []byte(`{}`)); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("tipo fora do catálogo: %v", err)
	}
	big := []byte(`{"task_id":"` + uuidA + `"` + strings.Repeat(" ", MaxPayloadBytes) + `}`)
	if kw, _ := violationOf(t, ValidatePayload(TypeTaskStart, big)); kw != "size" {
		t.Fatalf("payload acima de 48 KiB: %q", kw)
	}
}
