package contract

import "reflect"

var (
	uuidRef      = "#/$defs/uuid"
	gvmName      = ref("#/$defs/gvm_name")
	gvmComment   = ref("#/$defs/gvm_comment")
	ipOrCIDRList = func(min int) *node {
		n := &node{Type: "array", MaxItems: intp(256), UniqueItems: true, Items: ref("#/$defs/ip_or_cidr")}
		if min > 0 {
			n.MinItems = intp(min)
		}
		return n
	}
)

// payloadSpecList mirrors every fleet-command.schema.json#/$defs/payload_* (verification line 8). Their
// object-level combinators are kept as the schema's JSON (compared by TestParityRules) and implemented by the
// cross functions below.
var payloadSpecList = []*objectSpec{
	{Name: "payload_state_resync", Closed: true, Required: []string{"kinds"}, Props: []prop{
		{"kinds", &node{Type: "array", MinItems: intp(1), MaxItems: intp(12), UniqueItems: true, Items: ref("fleet-state.schema.json#/$defs/state_kind")}},
	}},
	{Name: "payload_task_ref", Closed: true, Required: []string{"task_id"}, Props: []prop{
		{"task_id", ref(uuidRef)},
	}},
	{Name: "payload_task_create", Closed: true, Required: []string{"name", "target_id", "scan_config_id"}, Props: []prop{
		{"name", gvmName},
		{"comment", gvmComment},
		{"target_id", ref(uuidRef)},
		{"scan_config_id", ref(uuidRef)},
		{"scanner_id", ref(uuidRef)},
		{"schedule_id", ref(uuidRef)},
	}},
	{Name: "payload_task_modify", Closed: true, Required: []string{"task_id"}, MinProps: intp(2), Props: []prop{
		{"task_id", ref(uuidRef)},
		{"name", gvmName},
		{"comment", gvmComment},
		{"target_id", ref(uuidRef)},
		{"scan_config_id", ref(uuidRef)},
		{"schedule_id", &node{AnyOf: []*node{ref(uuidRef), {Const: strp("")}}}},
	}},
	{Name: "payload_task_clone", Closed: true, Required: []string{"task_id"}, Props: []prop{
		{"task_id", ref(uuidRef)},
		{"name", gvmName},
	}},
	{Name: "payload_target_create", Closed: true, Required: []string{"name", "hosts"}, Props: []prop{
		{"name", gvmName},
		{"comment", gvmComment},
		{"hosts", ipOrCIDRList(1)},
		{"exclude_hosts", ipOrCIDRList(0)},
		{"port_list_id", ref(uuidRef)},
		{"port_range", ref("#/$defs/port_range")},
		{"alive_test", ref("#/$defs/alive_test")},
	},
		Combinators: map[string]string{"oneOf": `[{"required":["port_list_id"]},{"required":["port_range"]}]`},
		cross:       exactlyOnePortForm,
	},
	// target.modify changes ports only through port_list_id: gvmd's modify_target has no port_range
	{Name: "payload_target_modify", Closed: true, Required: []string{"target_id"}, MinProps: intp(2), Props: []prop{
		{"target_id", ref(uuidRef)},
		{"name", gvmName},
		{"comment", gvmComment},
		{"hosts", ipOrCIDRList(1)},
		{"exclude_hosts", ipOrCIDRList(0)},
		{"port_list_id", ref(uuidRef)},
		{"alive_test", ref("#/$defs/alive_test")},
	}},
	{Name: "payload_target_ref", Closed: true, Required: []string{"target_id"}, Props: []prop{
		{"target_id", ref(uuidRef)},
	}},
	{Name: "payload_schedule_create", Closed: true, Required: []string{"name", "icalendar", "timezone"}, Props: []prop{
		{"name", gvmName},
		{"comment", gvmComment},
		{"icalendar", ref("#/$defs/icalendar")},
		{"timezone", ref("#/$defs/iana_timezone")},
		{"task_ids", &node{Type: "array", MaxItems: intp(16), UniqueItems: true, Items: ref(uuidRef)}},
	}},
	{Name: "payload_schedule_modify", Closed: true, Required: []string{"schedule_id"}, MinProps: intp(2), Props: []prop{
		{"schedule_id", ref(uuidRef)},
		{"name", gvmName},
		{"comment", gvmComment},
		{"icalendar", ref("#/$defs/icalendar")},
		{"timezone", ref("#/$defs/iana_timezone")},
	}},
	{Name: "payload_schedule_ref", Closed: true, Required: []string{"schedule_id"}, Props: []prop{
		{"schedule_id", ref(uuidRef)},
	}},
	{Name: "payload_report_export", Closed: true, Required: []string{"report_id", "format", "lang", "variant", "filter"}, Props: []prop{
		{"report_id", ref(uuidRef)},
		{"format", ref("#/$defs/report_format")},
		{"lang", ref("#/$defs/report_lang")},
		{"variant", ref("#/$defs/report_variant")},
		{"delta_report_id", ref(uuidRef)},
		{"filter", ref("#/$defs/gmp_filter")},
	},
		Combinators: map[string]string{"allOf": `[{"if":{"properties":{"format":{"const":"suricatoos-pdf"}},"required":["format"]},"else":{"properties":{"lang":{"const":"en"},"variant":{"const":"technical"}}}}]`},
		cross:       gvmFormatsTechnicalEnglish,
	},
	{Name: "payload_report_summary", Closed: true, Required: []string{"report_id", "min_qod", "apply_overrides", "levels"}, Props: []prop{
		{"report_id", ref(uuidRef)},
		{"min_qod", &node{Type: "integer", Minimum: int64p(0), Maximum: int64p(100)}},
		{"apply_overrides", &node{Type: "boolean"}},
		{"levels", &node{Type: "string", MinLength: intp(1), MaxLength: intp(5), Pattern: PatternLevels, AllOf: noControl}},
	}},
	{Name: "payload_agent_ref", Closed: true, Required: []string{"agent_id"}, Props: []prop{
		{"agent_id", ref("#/$defs/agent_id")},
	}},
	{Name: "payload_agent_revoke", Closed: true, Required: []string{"agent_id"}, Props: []prop{
		{"agent_id", ref("#/$defs/agent_id")},
		{"reason", &node{Type: "string", MaxLength: intp(256), AllOf: noControl}},
	}},
	{Name: "payload_enroll_token_create", Closed: true, Required: []string{"token_type", "policy", "ttl_hours"}, Props: []prop{
		{"token_type", &node{Enum: enumOf(TokenSingleHost, TokenDeployment)}},
		{"policy", &node{Const: strp(string(PolicyAgentEndpoint))}},
		{"ttl_hours", &node{Type: "integer", Minimum: int64p(1), Maximum: int64p(168)}},
		{"max_uses", &node{Type: "integer", Minimum: int64p(1), Maximum: int64p(1000)}},
	},
		Combinators: map[string]string{"allOf": `[{"if":{"properties":{"token_type":{"const":"deployment"}},"required":["token_type"]},"then":{"required":["max_uses"]},"else":{"properties":{"max_uses":{"const":1}}}}]`},
		cross:       deploymentNeedsMaxUses,
	},
	{Name: "payload_enroll_token_revoke", Closed: true, Required: []string{"token_id"}, Props: []prop{
		{"token_id", ref("#/$defs/token_id")},
	}},
	{Name: "payload_sensor_job_enqueue", Closed: true, Required: []string{"targets"}, Props: []prop{
		{"targets", ipOrCIDRList(1)},
		{"ports", ref("#/$defs/port_range")},
	}},
	// feed.sync_now: {"type":"object","maxProperties":0} — the empty object (no additionalProperties keyword)
	{Name: "payload_empty", MaxProps: intp(0)},
}

// payloadSpecs indexes payloadSpecList by $defs name; payloadTypes gives each one's Go type.
var (
	payloadSpecs = map[string]*objectSpec{}
	payloadTypes = map[string]reflect.Type{
		"payload_state_resync":        reflect.TypeOf(PayloadStateResync{}),
		"payload_task_ref":            reflect.TypeOf(PayloadTaskRef{}),
		"payload_task_create":         reflect.TypeOf(PayloadTaskCreate{}),
		"payload_task_modify":         reflect.TypeOf(PayloadTaskModify{}),
		"payload_task_clone":          reflect.TypeOf(PayloadTaskClone{}),
		"payload_target_create":       reflect.TypeOf(PayloadTargetCreate{}),
		"payload_target_modify":       reflect.TypeOf(PayloadTargetModify{}),
		"payload_target_ref":          reflect.TypeOf(PayloadTargetRef{}),
		"payload_schedule_create":     reflect.TypeOf(PayloadScheduleCreate{}),
		"payload_schedule_modify":     reflect.TypeOf(PayloadScheduleModify{}),
		"payload_schedule_ref":        reflect.TypeOf(PayloadScheduleRef{}),
		"payload_report_export":       reflect.TypeOf(PayloadReportExport{}),
		"payload_report_summary":      reflect.TypeOf(PayloadReportSummary{}),
		"payload_agent_ref":           reflect.TypeOf(PayloadAgentRef{}),
		"payload_agent_revoke":        reflect.TypeOf(PayloadAgentRevoke{}),
		"payload_enroll_token_create": reflect.TypeOf(PayloadEnrollTokenCreate{}),
		"payload_enroll_token_revoke": reflect.TypeOf(PayloadEnrollTokenRevoke{}),
		"payload_sensor_job_enqueue":  reflect.TypeOf(PayloadSensorJobEnqueue{}),
		"payload_empty":               reflect.TypeOf(PayloadEmpty{}),
	}
)

func init() {
	for _, s := range payloadSpecList {
		if payloadTypes[s.Name] == nil {
			panic("contract: payload sem tipo Go: " + s.Name)
		}
		payloadSpecs[s.Name] = s
	}
}

// exactlyOnePortForm implements payload_target_create's oneOf: exactly one of port_list_id | port_range.
func exactlyOnePortForm(v reflect.Value, path string) *Violation {
	p := v.Interface().(PayloadTargetCreate)
	if (p.PortListID != nil) == (p.PortRange != nil) {
		return &Violation{Keyword: "oneOf", Path: path, Detail: "exatamente um entre port_list_id e port_range"}
	}
	return nil
}

// gvmFormatsTechnicalEnglish implements payload_report_export's if/else: a gvm-* format exists only as lang en
// and variant technical.
func gvmFormatsTechnicalEnglish(v reflect.Value, path string) *Violation {
	p := v.Interface().(PayloadReportExport)
	if p.Format == FormatSuricatoosPDF {
		return nil
	}
	if p.Lang != LangEN {
		return &Violation{Keyword: "const", Path: path + "/lang", Detail: "formatos gvm-* só existem em en"}
	}
	if p.Variant != VariantTechnical {
		return &Violation{Keyword: "const", Path: path + "/variant", Detail: "formatos gvm-* só existem como technical"}
	}
	return nil
}

// deploymentNeedsMaxUses implements payload_enroll_token_create's if/then/else: a deployment token needs an
// explicit max_uses; any other token type has max_uses 1 when present.
func deploymentNeedsMaxUses(v reflect.Value, path string) *Violation {
	p := v.Interface().(PayloadEnrollTokenCreate)
	if p.TokenType == TokenDeployment {
		if p.MaxUses == nil {
			return &Violation{Keyword: "required", Path: path, Detail: "token deployment exige max_uses"}
		}
		return nil
	}
	if p.MaxUses != nil && *p.MaxUses != 1 {
		return &Violation{Keyword: "const", Path: path + "/max_uses", Detail: "token single_host tem max_uses 1"}
	}
	return nil
}
