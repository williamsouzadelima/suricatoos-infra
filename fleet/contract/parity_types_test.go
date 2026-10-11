package contract

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// typeRegistry maps every object definition of the six schemas to its Go type. The parity test walks each one
// and fails on any drift in either direction.
var typeRegistry = []struct {
	ptr string
	typ reflect.Type
}{
	{"fleet-command.schema.json#/$defs/command", reflect.TypeOf(Command{})},
	{"fleet-command.schema.json#/$defs/envelope", reflect.TypeOf(Command{})},
	{"fleet-command.schema.json#/$defs/poll_response", reflect.TypeOf(PollResponse{})},
	{"fleet-command.schema.json#/$defs/payload_state_resync", reflect.TypeOf(PayloadStateResync{})},
	{"fleet-command.schema.json#/$defs/payload_task_ref", reflect.TypeOf(PayloadTaskRef{})},
	{"fleet-command.schema.json#/$defs/payload_task_create", reflect.TypeOf(PayloadTaskCreate{})},
	{"fleet-command.schema.json#/$defs/payload_task_modify", reflect.TypeOf(PayloadTaskModify{})},
	{"fleet-command.schema.json#/$defs/payload_task_clone", reflect.TypeOf(PayloadTaskClone{})},
	{"fleet-command.schema.json#/$defs/payload_target_create", reflect.TypeOf(PayloadTargetCreate{})},
	{"fleet-command.schema.json#/$defs/payload_target_modify", reflect.TypeOf(PayloadTargetModify{})},
	{"fleet-command.schema.json#/$defs/payload_target_ref", reflect.TypeOf(PayloadTargetRef{})},
	{"fleet-command.schema.json#/$defs/payload_schedule_create", reflect.TypeOf(PayloadScheduleCreate{})},
	{"fleet-command.schema.json#/$defs/payload_schedule_modify", reflect.TypeOf(PayloadScheduleModify{})},
	{"fleet-command.schema.json#/$defs/payload_schedule_ref", reflect.TypeOf(PayloadScheduleRef{})},
	{"fleet-command.schema.json#/$defs/payload_report_export", reflect.TypeOf(PayloadReportExport{})},
	{"fleet-command.schema.json#/$defs/payload_report_summary", reflect.TypeOf(PayloadReportSummary{})},
	{"fleet-command.schema.json#/$defs/payload_agent_ref", reflect.TypeOf(PayloadAgentRef{})},
	{"fleet-command.schema.json#/$defs/payload_agent_revoke", reflect.TypeOf(PayloadAgentRevoke{})},
	{"fleet-command.schema.json#/$defs/payload_enroll_token_create", reflect.TypeOf(PayloadEnrollTokenCreate{})},
	{"fleet-command.schema.json#/$defs/payload_enroll_token_revoke", reflect.TypeOf(PayloadEnrollTokenRevoke{})},
	{"fleet-command.schema.json#/$defs/payload_sensor_job_enqueue", reflect.TypeOf(PayloadSensorJobEnqueue{})},
	{"fleet-command.schema.json#/$defs/payload_empty", reflect.TypeOf(PayloadEmpty{})},

	{"fleet-result.schema.json#/$defs/result", reflect.TypeOf(Result{})},
	{"fleet-result.schema.json#/$defs/ack", reflect.TypeOf(Ack{})},
	{"fleet-result.schema.json#/$defs/error", reflect.TypeOf(ResultError{})},
	{"fleet-result.schema.json#/$defs/artifact", reflect.TypeOf(Artifact{})},
	{"fleet-result.schema.json#/$defs/output_state_resync", reflect.TypeOf(OutputStateResync{})},
	{"fleet-result.schema.json#/$defs/output_task_action", reflect.TypeOf(OutputTaskAction{})},
	{"fleet-result.schema.json#/$defs/output_task_create", reflect.TypeOf(OutputTaskCreate{})},
	{"fleet-result.schema.json#/$defs/output_task_modify", reflect.TypeOf(OutputTaskModify{})},
	{"fleet-result.schema.json#/$defs/output_task_clone", reflect.TypeOf(OutputTaskClone{})},
	{"fleet-result.schema.json#/$defs/output_trash", reflect.TypeOf(OutputTrash{})},
	{"fleet-result.schema.json#/$defs/output_target_create", reflect.TypeOf(OutputTargetCreate{})},
	{"fleet-result.schema.json#/$defs/output_target_modify", reflect.TypeOf(OutputTargetModify{})},
	{"fleet-result.schema.json#/$defs/output_schedule_create", reflect.TypeOf(OutputScheduleCreate{})},
	{"fleet-result.schema.json#/$defs/output_schedule_modify", reflect.TypeOf(OutputScheduleModify{})},
	{"fleet-result.schema.json#/$defs/output_report_export", reflect.TypeOf(OutputReportExport{})},
	{"fleet-result.schema.json#/$defs/output_report_summary", reflect.TypeOf(OutputReportSummary{})},
	{"fleet-result.schema.json#/$defs/output_agent_scan_now", reflect.TypeOf(OutputAgentScanNow{})},
	{"fleet-result.schema.json#/$defs/output_agent_revoke", reflect.TypeOf(OutputAgentRevoke{})},
	{"fleet-result.schema.json#/$defs/output_enroll_token_create", reflect.TypeOf(OutputEnrollTokenCreate{})},
	{"fleet-result.schema.json#/$defs/output_enroll_token_revoke", reflect.TypeOf(OutputEnrollTokenRevoke{})},
	{"fleet-result.schema.json#/$defs/output_sensor_job_enqueue", reflect.TypeOf(OutputSensorJobEnqueue{})},
	{"fleet-result.schema.json#/$defs/output_feed_sync_now", reflect.TypeOf(OutputFeedSyncNow{})},

	{"fleet-enroll.schema.json#/$defs/enroll_request", reflect.TypeOf(EnrollRequest{})},
	{"fleet-enroll.schema.json#/$defs/renew_request", reflect.TypeOf(RenewRequest{})},
	{"fleet-enroll.schema.json#/$defs/enroll_response", reflect.TypeOf(EnrollResponse{})},

	{"fleet-heartbeat.schema.json#/$defs/heartbeat_request", reflect.TypeOf(HeartbeatRequest{})},
	{"fleet-heartbeat.schema.json#/$defs/heartbeat_response", reflect.TypeOf(HeartbeatResponse{})},
	{"fleet-heartbeat.schema.json#/$defs/version_unsupported", reflect.TypeOf(VersionUnsupported{})},

	{"fleet-state.schema.json", reflect.TypeOf(StateSnapshot{})},
	{"fleet-state.schema.json#/$defs/severity_counts", reflect.TypeOf(SeverityCounts{})},
	{"fleet-state.schema.json#/$defs/data_node", reflect.TypeOf(DataNode{})},
	{"fleet-state.schema.json#/$defs/data_tasks", reflect.TypeOf(DataTasks{})},
	{"fleet-state.schema.json#/$defs/data_targets", reflect.TypeOf(DataTargets{})},
	{"fleet-state.schema.json#/$defs/data_schedules", reflect.TypeOf(DataSchedules{})},
	{"fleet-state.schema.json#/$defs/data_reports", reflect.TypeOf(DataReports{})},
	{"fleet-state.schema.json#/$defs/data_agents", reflect.TypeOf(DataAgents{})},
	{"fleet-state.schema.json#/$defs/data_tokens", reflect.TypeOf(DataTokens{})},
	{"fleet-state.schema.json#/$defs/data_sensors", reflect.TypeOf(DataSensors{})},
	{"fleet-state.schema.json#/$defs/data_scan_requests", reflect.TypeOf(DataScanRequests{})},
	{"fleet-state.schema.json#/$defs/data_remediation", reflect.TypeOf(DataRemediation{})},
	{"fleet-state.schema.json#/$defs/data_scope", reflect.TypeOf(DataScope{})},
	{"fleet-state.schema.json#/$defs/data_audit_tail", reflect.TypeOf(DataAuditTail{})},
	{"fleet-state.schema.json#/$defs/audit_stream_tail", reflect.TypeOf(AuditStreamTail{})},
	{"fleet-state.schema.json#/$defs/audit_entry", reflect.TypeOf(AuditEntry{})},

	{"fleet-event.schema.json", reflect.TypeOf(EventBatch{})},
	{"fleet-event.schema.json#/$defs/event", reflect.TypeOf(Event{})},
	{"fleet-event.schema.json#/$defs/data_connector_started", reflect.TypeOf(DataConnectorStarted{})},
	{"fleet-event.schema.json#/$defs/data_task_status_changed", reflect.TypeOf(DataTaskStatusChanged{})},
	{"fleet-event.schema.json#/$defs/data_report_completed", reflect.TypeOf(DataReportCompleted{})},
	{"fleet-event.schema.json#/$defs/data_agent_presence", reflect.TypeOf(DataAgentPresence{})},
	{"fleet-event.schema.json#/$defs/data_feed_stale", reflect.TypeOf(DataFeedStale{})},
	{"fleet-event.schema.json#/$defs/data_feed_updated", reflect.TypeOf(DataFeedUpdated{})},
	{"fleet-event.schema.json#/$defs/data_remediation_pending", reflect.TypeOf(DataRemediationPending{})},
	{"fleet-event.schema.json#/$defs/data_command_rejected", reflect.TypeOf(DataCommandRejected{})},
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// enumSubsets are the schema locations whose enum is, by design, a strict subset of their Go type's constants.
var enumSubsets = map[string]func() []string{
	// command.rejected_by_policy carries only the policy reasons (lines 6–9).
	"fleet-event.schema.json#/$defs/data_command_rejected/reason": func() []string {
		var out []string
		for _, r := range RejectReasons() {
			if r.PolicyEvent() {
				out = append(out, string(r))
			}
		}
		return out
	},
}

// enumUse is one schema location that constrains a named Go string type.
type enumUse struct {
	loc      string
	values   []string
	constant bool // a "const" (the value must be one of the type's constants), not an "enum" (the exact set)
}

type typeParity struct {
	t     *testing.T
	docs  map[string]*ordObj
	byPtr map[string]reflect.Type
	enums map[string][]enumUse // Go type name -> uses
}

type goField struct {
	name     string
	field    reflect.StructField
	optional bool
}

func jsonFields(t reflect.Type) []goField {
	var out []goField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !ok || !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		out = append(out, goField{name: name, field: f, optional: opts != ""})
	}
	return out
}

func nilable(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		return true
	}
	return false
}

func (p *typeParity) object(file string, node *ordObj, t reflect.Type, loc string) {
	if t.Kind() != reflect.Struct {
		p.t.Errorf("%s: objeto do schema, mas o tipo Go %v não é struct", loc, t)
		return
	}
	props := node.obj("properties")
	var keys []string
	if props != nil {
		keys = props.keys
		if ap, ok := node.get("additionalProperties").(bool); !ok || ap {
			p.t.Errorf("%s: objeto com properties sem additionalProperties:false — o decode estrito do Go seria mais estrito que o schema", loc)
		}
	}
	fields := jsonFields(t)
	var names []string
	for _, f := range fields {
		names = append(names, f.name)
	}
	if !slices.Equal(keys, names) {
		p.t.Errorf("%s: propriedades %v != campos json de %v %v (mesma ordem)", loc, keys, t, names)
		return
	}
	required := sortedCopy(strList(node.arr("required")))
	var goRequired []string
	for _, f := range fields {
		if !f.optional {
			goRequired = append(goRequired, f.name)
		} else {
			if tag := f.field.Tag.Get("json"); !strings.HasSuffix(tag, ",omitzero") {
				p.t.Errorf("%s/%s: campo opcional deve usar exatamente a opção omitzero (tag %q)", loc, f.name, tag)
			}
			if !nilable(f.field.Type) {
				p.t.Errorf("%s/%s: campo opcional precisa de tipo nil-ável (ponteiro, slice ou map), %v não é", loc, f.name, f.field.Type)
			}
		}
		if !f.optional && f.field.Type.Kind() == reflect.Pointer {
			p.t.Errorf("%s/%s: campo obrigatório não deve ser ponteiro", loc, f.name)
		}
	}
	sort.Strings(goRequired)
	if !slices.Equal(required, goRequired) {
		p.t.Errorf("%s: required %v != campos sem omitzero %v", loc, required, goRequired)
	}
	for _, f := range fields {
		p.value(file, props.obj(f.name), f.field.Type, loc+"/"+f.name)
	}
}

// view is a schema node seen through its $ref chain: the referring node's own keywords win.
type view struct {
	file     string  // file of the innermost node
	node     *ordObj // innermost node (where properties/items/additionalProperties live)
	refPtr   string  // the last "$ref" followed, as "file#/$defs/name"
	enum     []string
	hasConst bool
	constVal any
	typ      string
	anyOf    []any
}

func (p *typeParity) view(file string, node *ordObj) view {
	v := view{file: file, node: node}
	cur, curFile := node, file
	for {
		if v.enum == nil && cur.has("enum") {
			v.enum = strList(cur.arr("enum"))
		}
		if !v.hasConst && cur.has("const") {
			v.hasConst, v.constVal = true, cur.get("const")
		}
		if v.typ == "" && cur.has("type") {
			v.typ = cur.str("type")
		}
		if v.anyOf == nil && cur.has("anyOf") {
			v.anyOf = cur.arr("anyOf")
		}
		ref := cur.str("$ref")
		if ref == "" {
			return v
		}
		curFile, cur = resolveRef(p.t, p.docs, curFile, ref)
		_, frag, _ := strings.Cut(ref, "#")
		v.refPtr, v.file, v.node = curFile+"#"+frag, curFile, cur
	}
}

func isStringType(t reflect.Type) bool { return t.Kind() == reflect.String }

func (p *typeParity) value(file string, node *ordObj, t reflect.Type, loc string) {
	if node == nil {
		p.t.Errorf("%s: sem nó no schema", loc)
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	v := p.view(file, node)
	switch {
	case v.node.has("properties") || (v.refPtr != "" && p.byPtr[v.refPtr] != nil && v.typ == "object"):
		if v.refPtr != "" && p.byPtr[v.refPtr] != nil {
			if p.byPtr[v.refPtr] != t {
				p.t.Errorf("%s: %s é o tipo Go %v, mas o campo tem %v", loc, v.refPtr, p.byPtr[v.refPtr], t)
			}
			return // walked through its own registry entry
		}
		p.object(v.file, v.node, t, loc)
	case v.typ == "object" && v.node.obj("additionalProperties") != nil:
		if t.Kind() != reflect.Map {
			p.t.Errorf("%s: objeto-mapa no schema, %v no Go", loc, t)
			return
		}
		if names := v.node.obj("propertyNames"); names != nil {
			p.value(v.file, names, t.Key(), loc+"/<chave>")
		}
		p.value(v.file, v.node.obj("additionalProperties"), t.Elem(), loc+"/<valor>")
	case v.typ == "object":
		if t != rawMessageType {
			p.t.Errorf("%s: objeto livre no schema deve ser json.RawMessage no Go (bytes exatos), é %v", loc, t)
		}
	case v.typ == "array":
		if t.Kind() != reflect.Slice || t == rawMessageType {
			p.t.Errorf("%s: array no schema, %v no Go", loc, t)
			return
		}
		items := v.node.obj("items")
		if loc == "fleet-command.schema.json#/$defs/poll_response/commands" {
			// each envelope stays raw: it goes through the verification lines on its own
			if t.Elem() != rawMessageType || items.str("$ref") != "#/$defs/command" {
				p.t.Errorf("%s: os comandos do long-poll devem ser []json.RawMessage de #/$defs/command", loc)
			}
			return
		}
		p.value(v.file, items, t.Elem(), loc+"/items")
	case len(v.enum) > 0:
		if !isStringType(t) || t.Name() == "string" || t.PkgPath() == "" {
			p.t.Errorf("%s: enum %v exige um tipo Go nomeado com constantes, é %v", loc, v.enum, t)
			return
		}
		p.enums[t.Name()] = append(p.enums[t.Name()], enumUse{loc: loc, values: v.enum})
	case v.hasConst:
		switch c := v.constVal.(type) {
		case string:
			if !isStringType(t) {
				p.t.Errorf("%s: const string, %v no Go", loc, t)
			} else if t.Name() != "string" {
				p.enums[t.Name()] = append(p.enums[t.Name()], enumUse{loc: loc, values: []string{c}, constant: true})
			}
		case bool:
			if t.Kind() != reflect.Bool {
				p.t.Errorf("%s: const booleano, %v no Go", loc, t)
			}
		default:
			p.t.Errorf("%s: const de tipo não tratado %T", loc, c)
		}
	case len(v.anyOf) > 0:
		for i, alt := range v.anyOf {
			p.value(v.file, alt.(*ordObj), t, loc+"/anyOf/"+string(rune('0'+i)))
		}
	case v.typ == "string":
		if !isStringType(t) {
			p.t.Errorf("%s: string no schema, %v no Go", loc, t)
		} else if t.Name() != "string" && !(t == reflect.TypeOf(CommandType("")) && strings.HasSuffix(v.refPtr, "#/$defs/command_type_any")) {
			// a named type stands for an enum; the only open use is a command type AS RECEIVED
			p.t.Errorf("%s: string sem enum (%s) não deve usar o tipo nomeado %v", loc, v.refPtr, t)
		}
	case v.typ == "integer":
		switch t.Kind() {
		case reflect.Int, reflect.Int64:
		default:
			p.t.Errorf("%s: integer no schema, %v no Go", loc, t)
		}
	case v.typ == "number":
		if t.Kind() != reflect.Float64 {
			p.t.Errorf("%s: number no schema, %v no Go", loc, t)
		}
	case v.typ == "boolean":
		if t.Kind() != reflect.Bool {
			p.t.Errorf("%s: boolean no schema, %v no Go", loc, t)
		}
	default:
		p.t.Errorf("%s: nó do schema sem tratamento no teste de paridade: %v", loc, node.keys)
	}
}

// TestParityTypes: for every object of the six schemas, the property set and order == the json tags of its Go
// struct, required == the fields without omitzero, every nested shape matches, and every enum location is a
// named Go type whose constants are exactly the enum.
func TestParityTypes(t *testing.T) {
	docs := loadSchemas(t)
	p := &typeParity{t: t, docs: docs, byPtr: map[string]reflect.Type{}, enums: map[string][]enumUse{}}
	for _, r := range typeRegistry {
		if prev, dup := p.byPtr[r.ptr]; dup {
			t.Fatalf("registro duplicado %s (%v)", r.ptr, prev)
		}
		p.byPtr[r.ptr] = r.typ
	}
	for _, r := range typeRegistry {
		file, node := defNode(t, docs, r.ptr)
		p.object(file, node, r.typ, r.ptr)
	}

	// every object definition of the schemas is registered
	for _, f := range schemaFiles {
		doc := docs[f]
		if doc.has("properties") {
			if p.byPtr[f] == nil {
				t.Errorf("raiz de %s (objeto) sem tipo Go no registro", f)
			}
		}
		defs := doc.obj("$defs")
		for _, name := range defs.keys {
			d := defs.obj(name)
			if d.has("properties") || d.str("type") == "object" {
				if ptr := f + "#/$defs/" + name; p.byPtr[ptr] == nil {
					t.Errorf("%s (objeto) sem tipo Go no registro", ptr)
				}
			}
		}
	}

	// enums == Go constants
	consts := goStringConstants(t)
	for name, uses := range p.enums {
		got := consts[name]
		for _, u := range uses {
			if u.constant {
				if !slices.Contains(got, u.values[0]) {
					t.Errorf("%s: const %q não é constante de %s %v", u.loc, u.values[0], name, got)
				}
				continue
			}
			want := got
			if sub, ok := enumSubsets[u.loc]; ok {
				want = sub()
			}
			if !slices.Equal(sortedCopy(u.values), sortedCopy(want)) {
				t.Errorf("%s: enum %v != constantes Go de %s %v", u.loc, u.values, name, want)
			}
		}
	}
	for _, name := range goStringTypes(t) {
		if len(p.enums[name]) == 0 {
			t.Errorf("tipo Go %s (string nomeada) não corresponde a nenhum enum/const dos schemas", name)
		}
		if len(consts[name]) == 0 {
			t.Errorf("tipo Go %s sem constantes", name)
		}
	}
}
