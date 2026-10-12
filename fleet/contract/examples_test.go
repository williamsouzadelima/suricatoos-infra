package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type exampleExpect struct {
	Keyword string `json:"keyword"`
	Check   string `json:"check"`
	Path    string `json:"path"`
}

type exampleCase struct {
	File   string         `json:"file"`
	Target string         `json:"target"`
	Expect *exampleExpect `json:"expect"`
}

func loadIndex(t *testing.T) []exampleCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Cases []exampleCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Cases) == 0 {
		t.Fatal("index.json sem casos")
	}
	return idx.Cases
}

func readExample(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *exampleExpect) String() string {
	if e == nil {
		return "válido"
	}
	if e.Check != "" {
		return "check " + e.Check + " em " + strconv.Quote(e.Path)
	}
	return e.Keyword + " em " + strconv.Quote(e.Path)
}

// lexicalChecks are the index.json checks that a JSON parser (not a schema validator) reports; Python can only
// place json_syntax and duplicate_key at the document, "". export_filter is the other check of the index: the
// semantic rule of report.export's filter (line 8), reported with its path.
var lexicalChecks = map[string]bool{"json_syntax": true, "duplicate_key": true, "integer_lexical": true}

func violationVerdict(v *Violation, prefix string) *exampleExpect {
	switch v.Keyword {
	case "json_syntax", "duplicate_key":
		return &exampleExpect{Check: v.Keyword, Path: ""}
	case "integer_lexical", "export_filter":
		return &exampleExpect{Check: v.Keyword, Path: prefix + v.Path}
	}
	return &exampleExpect{Keyword: v.Keyword, Path: prefix + v.Path}
}

func rejectVerdict(t *testing.T, err error, prefix string) *exampleExpect {
	t.Helper()
	var re *RejectError
	if !errors.As(err, &re) {
		t.Fatalf("erro inesperado: %v", err)
	}
	switch re.Reason {
	case ReasonBadEnvelope:
		return violationVerdict(re.Violation, prefix)
	case ReasonPayloadMismatch:
		return &exampleExpect{Check: "payload_sha256", Path: prefix}
	case ReasonBadSignature:
		return &exampleExpect{Check: "signature", Path: prefix}
	}
	t.Fatalf("motivo fora das linhas 0–2: %s", re.Reason)
	return nil
}

// commandVerdict is the Go side's verdict on a full command (schema root): lines 0–2 with the golden test key,
// then the catalog (type in command_type) and the per-type payload (line 8).
func commandVerdict(t *testing.T, raw []byte, prefix string) *exampleExpect {
	v, err := Verify(goldenPub, raw)
	if err != nil {
		return rejectVerdict(t, err, prefix)
	}
	cmd := v.Command()
	if _, ok := LookupType(cmd.Type); !ok {
		return &exampleExpect{Keyword: "enum", Path: prefix + "/type"}
	}
	if err := ValidatePayload(cmd.Type, cmd.Payload); err != nil {
		var viol *Violation
		if !errors.As(err, &viol) {
			t.Fatalf("payload: %v", err)
		}
		return violationVerdict(viol, prefix+"/payload")
	}
	return nil
}

// goVerdict answers, for one example of schema/examples/fleet/command, what the Python contract test answers.
func goVerdict(t *testing.T, target string, raw []byte) *exampleExpect {
	switch target {
	case "fleet-command.schema.json":
		return commandVerdict(t, raw, "")
	case "fleet-command.schema.json#/$defs/envelope":
		if _, err := Verify(goldenPub, raw); err != nil {
			return rejectVerdict(t, err, "")
		}
		return nil
	case "fleet-command.schema.json#/$defs/poll_response":
		cmds, err := DecodePollResponse(raw)
		if err != nil {
			var viol *Violation
			if !errors.As(err, &viol) {
				t.Fatalf("poll: %v", err)
			}
			return violationVerdict(viol, "")
		}
		for i, c := range cmds {
			if v := commandVerdict(t, c, "/commands/"+strconv.Itoa(i)); v != nil {
				return v
			}
		}
		return nil
	case "fleet-command.schema.json#/$defs/schema_version_wire":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return &exampleExpect{Keyword: "type", Path: ""}
		}
		if _, err := ParseWireVersion(s); err != nil {
			return &exampleExpect{Keyword: "pattern", Path: ""}
		}
		return nil
	}
	t.Fatalf("alvo sem verdito Go: %s", target)
	return nil
}

// TestCommandExamplesParity runs EVERY example of schema/examples/fleet/command (valid and invalid, as listed
// in index.json) through the Go contract: a valid example passes; an invalid one fails with exactly the
// keyword (or check) and path the index expects. A disagreement in either direction fails.
func TestCommandExamplesParity(t *testing.T) {
	n := 0
	for _, c := range loadIndex(t) {
		if !strings.Contains(c.File, "/command/") {
			continue
		}
		n++
		t.Run(c.File, func(t *testing.T) {
			got := goVerdict(t, c.Target, readExample(t, c.File))
			valid := strings.HasPrefix(c.File, "valid/")
			switch {
			case valid && got != nil:
				t.Fatalf("Python aceita, Go recusa: %v", got)
			case !valid && got == nil:
				t.Fatalf("Python recusa (%v), Go aceita", c.Expect)
			case !valid && *got != *c.Expect:
				t.Fatalf("Go recusa com %v, index espera %v", got, c.Expect)
			}
		})
	}
	if n < 60 {
		t.Fatalf("só %d exemplos de comando", n)
	}
}

// TestSignReproducesExamples: Sign rebuilds every valid signed example (signed by the independent Python
// generator with the golden test key) byte for byte — member order, literal UTF-8, '<', '>', '&' and U+2028.
func TestSignReproducesExamples(t *testing.T) {
	n := 0
	for _, c := range loadIndex(t) {
		if !strings.HasPrefix(c.File, "valid/command/") || (c.Target != "fleet-command.schema.json" && c.Target != "fleet-command.schema.json#/$defs/envelope") {
			continue
		}
		n++
		raw := bytes.TrimRight(readExample(t, c.File), " \t\r\n")
		v, err := Verify(goldenPub, raw)
		if err != nil {
			t.Fatalf("%s: %v", c.File, err)
		}
		got, err := Sign(goldenPriv, v.Command(), v.Command().Payload)
		if err != nil {
			t.Fatalf("%s: %v", c.File, err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s: Sign divergiu\n got %s\nwant %s", c.File, got, raw)
		}
	}
	if n < 25 {
		t.Fatalf("só %d envelopes", n)
	}
}

// Go types of the targets of the other five schemas (the oneOf roots try each alternative).
var bodyTypes = map[string][]reflect.Type{
	"fleet-enroll.schema.json":                               {reflect.TypeOf(EnrollRequest{}), reflect.TypeOf(RenewRequest{}), reflect.TypeOf(EnrollResponse{})},
	"fleet-enroll.schema.json#/$defs/enroll_request":         {reflect.TypeOf(EnrollRequest{})},
	"fleet-enroll.schema.json#/$defs/renew_request":          {reflect.TypeOf(RenewRequest{})},
	"fleet-enroll.schema.json#/$defs/enroll_response":        {reflect.TypeOf(EnrollResponse{})},
	"fleet-heartbeat.schema.json":                            {reflect.TypeOf(HeartbeatRequest{}), reflect.TypeOf(HeartbeatResponse{}), reflect.TypeOf(VersionUnsupported{})},
	"fleet-heartbeat.schema.json#/$defs/heartbeat_request":   {reflect.TypeOf(HeartbeatRequest{})},
	"fleet-heartbeat.schema.json#/$defs/heartbeat_response":  {reflect.TypeOf(HeartbeatResponse{})},
	"fleet-heartbeat.schema.json#/$defs/version_unsupported": {reflect.TypeOf(VersionUnsupported{})},
	"fleet-state.schema.json":                                {reflect.TypeOf(StateSnapshot{})},
	"fleet-state.schema.json#/$defs/audit_entry":             {reflect.TypeOf(AuditEntry{})},
	"fleet-event.schema.json":                                {reflect.TypeOf(EventBatch{})},
	"fleet-result.schema.json":                               {reflect.TypeOf(Result{})},
	"fleet-result.schema.json#/$defs/ack":                    {reflect.TypeOf(Ack{})},
}

var stateDataTypes = map[StateKind]reflect.Type{
	KindNode: reflect.TypeOf(DataNode{}), KindTasks: reflect.TypeOf(DataTasks{}), KindTargets: reflect.TypeOf(DataTargets{}),
	KindSchedules: reflect.TypeOf(DataSchedules{}), KindReports: reflect.TypeOf(DataReports{}), KindAgents: reflect.TypeOf(DataAgents{}),
	KindTokens: reflect.TypeOf(DataTokens{}), KindSensors: reflect.TypeOf(DataSensors{}), KindScanRequests: reflect.TypeOf(DataScanRequests{}),
	KindRemediation: reflect.TypeOf(DataRemediation{}), KindScope: reflect.TypeOf(DataScope{}), KindAuditTail: reflect.TypeOf(DataAuditTail{}),
}

var eventDataTypes = map[EventType]reflect.Type{
	EventConnectorStarted: reflect.TypeOf(DataConnectorStarted{}), EventTaskStatusChanged: reflect.TypeOf(DataTaskStatusChanged{}),
	EventReportCompleted: reflect.TypeOf(DataReportCompleted{}), EventAgentOnline: reflect.TypeOf(DataAgentPresence{}),
	EventAgentOffline: reflect.TypeOf(DataAgentPresence{}), EventFeedStale: reflect.TypeOf(DataFeedStale{}),
	EventFeedUpdated: reflect.TypeOf(DataFeedUpdated{}), EventRemediationPendingApproval: reflect.TypeOf(DataRemediationPending{}),
	EventCommandRejectedByPolicy: reflect.TypeOf(DataCommandRejected{}),
}

var outputTypes = map[string]reflect.Type{}

func init() {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(OutputStateResync{}), reflect.TypeOf(OutputTaskAction{}), reflect.TypeOf(OutputTaskCreate{}),
		reflect.TypeOf(OutputTaskModify{}), reflect.TypeOf(OutputTaskClone{}), reflect.TypeOf(OutputTrash{}),
		reflect.TypeOf(OutputTargetCreate{}), reflect.TypeOf(OutputTargetModify{}), reflect.TypeOf(OutputScheduleCreate{}),
		reflect.TypeOf(OutputScheduleModify{}), reflect.TypeOf(OutputReportExport{}), reflect.TypeOf(OutputReportSummary{}),
		reflect.TypeOf(OutputAgentScanNow{}), reflect.TypeOf(OutputAgentRevoke{}), reflect.TypeOf(OutputEnrollTokenCreate{}),
		reflect.TypeOf(OutputEnrollTokenRevoke{}), reflect.TypeOf(OutputSensorJobEnqueue{}), reflect.TypeOf(OutputFeedSyncNow{}),
	} {
		var name strings.Builder
		for i, r := range typ.Name() {
			if i > 0 && r >= 'A' && r <= 'Z' {
				name.WriteByte('_')
			}
			name.WriteString(strings.ToLower(string(r)))
		}
		outputTypes[name.String()] = typ
	}
}

func strictInto(typ reflect.Type, raw []byte) (any, *Violation) {
	p := reflect.New(typ)
	if err := DecodeStrict(raw, p.Interface()); err != nil {
		var v *Violation
		errors.As(err, &v)
		return nil, v
	}
	return p.Elem().Interface(), nil
}

// structural decodes one body into its Go type and then its free objects (state data by kind, event data by
// type, result output by type): the first violation, with its JSON pointer from the body's root.
func structural(t *testing.T, typ reflect.Type, raw []byte) *Violation {
	v, viol := strictInto(typ, raw)
	if viol != nil {
		return viol
	}
	sub := func(path string, typ reflect.Type, raw []byte) *Violation {
		if typ == nil {
			return nil
		}
		if _, viol := strictInto(typ, raw); viol != nil {
			viol.Path = path + viol.Path
			return viol
		}
		return nil
	}
	switch b := v.(type) {
	case StateSnapshot:
		if got := sha256hex(b.Data); got != b.ContentSHA256 {
			return &Violation{Keyword: "content_sha256"}
		}
		return sub("/data", stateDataTypes[b.Kind], b.Data)
	case EventBatch:
		for i, e := range b.Events {
			if viol := sub("/events/"+strconv.Itoa(i)+"/data", eventDataTypes[e.Type], e.Data); viol != nil {
				return viol
			}
		}
	case Result:
		if e, ok := LookupType(b.Type); ok && b.Output != nil {
			return sub("/output", outputTypes[e.Output], b.Output)
		}
	}
	return nil
}

// TestBodyExamplesStructure decodes every example of the other five schemas with DecodeStrict into the Go
// types: each valid one decodes (a oneOf root into exactly one alternative; content_sha256 recomputed over the
// raw data bytes); each invalid one whose defect is STRUCTURAL (unknown member, JSON type, duplicate key,
// integer lexical, JSON syntax) fails with the same keyword and path; a required member fails at the same
// path when it is unconditionally required in Go; value constraints (patterns, enums...) are not the types'
// job, so those decode.
func TestBodyExamplesStructure(t *testing.T) {
	n := 0
	for _, c := range loadIndex(t) {
		if strings.Contains(c.File, "/command/") {
			continue
		}
		types, ok := bodyTypes[c.Target]
		if !ok {
			t.Errorf("%s: alvo %s sem tipo Go", c.File, c.Target)
			continue
		}
		n++
		t.Run(c.File, func(t *testing.T) {
			raw := readExample(t, c.File)
			var decoded int
			var viol *Violation
			for _, typ := range types {
				if v := structural(t, typ, raw); v == nil {
					decoded++
				} else if len(types) == 1 {
					viol = v
				}
			}
			if strings.HasPrefix(c.File, "valid/") {
				if decoded != 1 {
					t.Fatalf("válido: %d alternativas decodificam (esperado 1); %v", decoded, viol)
				}
				return
			}
			e := c.Expect
			switch {
			case e.Check == "content_sha256":
				if viol == nil || viol.Keyword != "content_sha256" {
					t.Fatalf("content_sha256 recalculado sobre os bytes crus de data deveria divergir: %v", viol)
				}
			case lexicalChecks[e.Check] || e.Keyword == "additionalProperties" || e.Keyword == "type":
				want := e.Keyword + e.Check
				if viol == nil || viol.Keyword != want || (e.Check != "json_syntax" && e.Check != "duplicate_key" && viol.Path != e.Path) {
					t.Fatalf("estrutural: Go %v, index %v", viol, e)
				}
			case e.Keyword == "required":
				if viol != nil && (viol.Path != e.Path || (viol.Keyword != "required" && viol.Keyword != "additionalProperties")) {
					t.Fatalf("required: Go %v, index %v", viol, e)
				}
			default:
				if viol != nil {
					t.Fatalf("defeito de valor (%v) não é dos tipos, mas o decode falhou: %v", e, viol)
				}
			}
		})
	}
	if n < 100 {
		t.Fatalf("só %d exemplos", n)
	}
}
