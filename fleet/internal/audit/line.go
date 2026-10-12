package audit

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// The bounds of one line (fleet-state.schema.json#/$defs/audit_entry and ADR-0011 "Limites").
const (
	// MaxLineBytes caps one line, without its '\n'. The tail item's maxLength (8192 characters) is never less.
	MaxLineBytes = 8192
	// MaxObjectIDs is the schema's maxItems of object_ids: no v1 command acts on more distinct objects.
	MaxObjectIDs = 17
	// MaxHosts hosts of a command are listed; hosts_count carries the total.
	MaxHosts = 64
	// MaxDetailRunes caps the connector's short message (detail).
	MaxDetailRunes = 256
	// MaxFilterRunes is the cap of a GMP filter (gmp_filter).
	MaxFilterRunes  = 1024
	maxArtifactSize = 67108864
	maxIDRunes      = 128
)

var (
	// ErrInvalid: an input the contract does not allow — a caller's bug. Nothing is written.
	ErrInvalid = errors.New("audit: entrada fora do contrato")
	// ErrLineTooLong: the line, with every field already bounded, is still over MaxLineBytes. It is the caller's
	// error and nothing is written: a line is never cut in the middle of its JSON.
	ErrLineTooLong = errors.New("audit: linha acima do teto de 8 KiB")
)

// invalid wraps ErrInvalid. The message names the field and the rule, never the value: the value is input.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// zeroSHA256 is the prev_sha256 of the first line of a stream.
var zeroSHA256 = strings.Repeat("0", 64)

// entry is one audit line as it is written: the members of contract.AuditEntry — same JSON names, Go types and
// options (TestEntryEspelhaOContratoNaOrdemDosExemplos) — in the order of the contract's examples, with status and
// error_code right after payload_sha256, so that every example comes out byte for byte. The order of the members is
// not normative (the chain hashes whatever bytes the node writes); it only has to be one. encode checks every line
// against contract.AuditEntry with DecodeStrict before it is written.
type entry struct {
	Stream          contract.AuditStream           `json:"stream"`
	Seq             int64                          `json:"seq"`
	At              string                         `json:"at"`
	Event           contract.AuditEvent            `json:"event"`
	CommandID       *string                        `json:"command_id,omitzero"`
	Type            *contract.CommandType          `json:"type,omitzero"`
	Tenant          *string                        `json:"tenant,omitzero"`
	IssuedBy        *string                        `json:"issued_by,omitzero"`
	PayloadSHA256   *string                        `json:"payload_sha256,omitzero"`
	Status          *contract.ResultStatus         `json:"status,omitzero"`
	ErrorCode       *contract.ErrorCode            `json:"error_code,omitzero"`
	ObjectIDs       []string                       `json:"object_ids,omitzero"`
	Hosts           []string                       `json:"hosts,omitzero"`
	HostsCount      *int64                         `json:"hosts_count,omitzero"`
	Report          *contract.AuditReport          `json:"report,omitzero"`
	Artifact        *contract.AuditArtifact        `json:"artifact,omitzero"`
	Reason          *contract.RejectReason         `json:"reason,omitzero"`
	Unauthenticated *contract.AuditUnauthenticated `json:"unauthenticated,omitzero"`
	Redelivered     *contract.AuditRedelivered     `json:"redelivered,omitzero"`
	Versions        *contract.AuditVersions        `json:"versions,omitzero"`
	Detail          *string                        `json:"detail,omitzero"`
	PrevSHA256      string                         `json:"prev_sha256"`
}

// encode serializes e with contract.MarshalCompact (compact, no HTML escaping, U+2028/U+2029 literal, the same bytes
// on every Go toolchain) and refuses a line over MaxLineBytes or one that does not decode, strictly, as a
// contract.AuditEntry.
func encode(e *entry) ([]byte, error) {
	b, err := contract.MarshalCompact(e)
	if err != nil {
		return nil, fmt.Errorf("audit: serializar a linha: %w", err)
	}
	if len(b) > MaxLineBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrLineTooLong, len(b))
	}
	var check contract.AuditEntry
	if err := contract.DecodeStrict(b, &check); err != nil {
		return nil, fmt.Errorf("audit: a linha montada não é um audit_entry do contrato: %w", err)
	}
	return b, nil
}

// Ref names a command on its executed and result lines.
type Ref struct {
	CommandID string               // the envelope's command_id
	Type      contract.CommandType // the type as received (outside the v1 catalog only on an "unsupported" rejection)
	Tenant    string
}

// Command is a verified command as its received, rejected and deferred lines record it: who issued it, the hash of
// its payload and the bounded WHAT of ADR-0011 "Auditoria local". There is no field for the payload, for an output
// or for a secret — the only secret of the contract is in the OUTPUT of enroll_token.create —, so none can reach
// the audit.
type Command struct {
	Ref
	IssuedBy      string
	PayloadSHA256 string
	// ObjectIDs are the objects the command acts on: task, target, schedule, report and delta report ids, agent_id,
	// token_id, sensor job id. A repeated id counts once; more than MaxObjectIDs distinct ids is ErrInvalid.
	ObjectIDs []string
	// Hosts are ALL the hosts/targets of a target.* or sensor_job.enqueue command (the canonical list the scope
	// gate checked): the line keeps the first MaxHosts and their total in hosts_count.
	Hosts []string
	// Report is the parameters of a report.export (format, lang, variant, delta, filter) or report.summary
	// (min_qod, apply_overrides, levels). The filter is cut to MaxFilterRunes.
	Report *contract.AuditReport
}

// Outcome is how an accepted command ended, as its result line records it — never the command's output.
type Outcome struct {
	Status    contract.ResultStatus
	ErrorCode contract.ErrorCode      // only with StatusFailed; "" = none
	ObjectIDs []string                // the objects the command created or acted on (same rules as Command's)
	Artifact  *contract.AuditArtifact // report.export only: sha256 and size of what left the node
	Detail    string                  // short, connector-generated; never finding data; dropped for enroll_token.create
}

var (
	reUUID     = regexp.MustCompile(contract.PatternUUID)
	reTenant   = regexp.MustCompile(contract.PatternTenant)
	reIssuedBy = regexp.MustCompile(contract.PatternIssuedBy)
	reSHA256   = regexp.MustCompile(contract.PatternSHA256Hex)
	reType     = regexp.MustCompile(contract.PatternCommandTypeAny)
	reHost     = regexp.MustCompile(contract.PatternIPOrCIDR)
	reLevels   = regexp.MustCompile(contract.PatternLevels)
	reVersion  = regexp.MustCompile(contract.PatternSchemaVersionsItem)

	// The closed sets the API checks: the schema's enums (TestEnumsConferidosSaoOsDoSchema).
	validFormats = map[contract.ReportFormat]bool{
		contract.FormatSuricatoosPDF: true, contract.FormatGVMXML: true, contract.FormatGVMCSVResults: true, contract.FormatGVMPDF: true,
	}
	validLangs    = map[contract.ReportLang]bool{contract.LangEN: true, contract.LangPTBR: true, contract.LangES: true}
	validVariants = map[contract.ReportVariant]bool{
		contract.VariantTechnical: true, contract.VariantClient: true, contract.VariantExecutive: true,
	}
	validStatuses   = map[contract.ResultStatus]bool{contract.StatusSucceeded: true, contract.StatusFailed: true}
	validErrorCodes = map[contract.ErrorCode]bool{
		contract.ErrorNotFound: true, contract.ErrorConflict: true, contract.ErrorGVM: true, contract.ErrorTimeout: true,
		contract.ErrorInterrupted: true, contract.ErrorUnavailable: true, contract.ErrorArtifactTooLarge: true,
		contract.ErrorArtifactUploadFailed: true, contract.ErrorSecretLost: true, contract.ErrorInternal: true,
	}
)

func ptr[T any](v T) *T { return &v }

// isControl is the no_control set of the schema: the C0 controls, DEL and the noncharacters U+FFFE and U+FFFF.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f || r == 0xfffe || r == 0xffff }

func hasControl(s string) bool { return strings.ContainsFunc(s, isControl) }

// cutRunes returns the first n characters of s.
func cutRunes(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// cleanText makes a connector text fit no_control and its cap: each control character becomes a space, each byte
// of invalid UTF-8 becomes U+FFFD (strings.Map does that by itself), and only the first max characters stay. "" is
// no member at all.
func cleanText(s string, max int) *string {
	if s == "" {
		return nil
	}
	s = strings.Map(func(r rune) rune {
		if isControl(r) {
			return ' '
		}
		return r
	}, s)
	return ptr(cutRunes(s, max))
}

func (r Ref) check() error {
	switch {
	case !reUUID.MatchString(r.CommandID):
		return invalid("command_id não é um UUID minúsculo")
	case len(r.Type) > 64 || !reType.MatchString(string(r.Type)):
		return invalid("type fora da forma tipo.ação (até 64 caracteres)")
	case !reTenant.MatchString(r.Tenant):
		return invalid("tenant fora do padrão de nome de tenant")
	}
	return nil
}

func (r Ref) fill(e *entry) {
	e.CommandID, e.Type, e.Tenant = ptr(r.CommandID), ptr(r.Type), ptr(r.Tenant)
}

// fill checks c and writes its members into e.
func (c Command) fill(e *entry) error {
	if err := c.Ref.check(); err != nil {
		return err
	}
	if len(c.IssuedBy) > 128 || !reIssuedBy.MatchString(c.IssuedBy) {
		return invalid("issued_by fora do padrão (pseudônimo de até 128 caracteres)")
	}
	if !reSHA256.MatchString(c.PayloadSHA256) {
		return invalid("payload_sha256 não é um sha256 hexadecimal minúsculo")
	}
	ids, err := objectIDs(c.ObjectIDs)
	if err != nil {
		return err
	}
	hosts, count, err := hostList(c.Hosts)
	if err != nil {
		return err
	}
	report, err := reportParams(c.Report)
	if err != nil {
		return err
	}
	c.Ref.fill(e)
	e.IssuedBy, e.PayloadSHA256 = ptr(c.IssuedBy), ptr(c.PayloadSHA256)
	e.ObjectIDs, e.Hosts, e.HostsCount, e.Report = ids, hosts, count, report
	return nil
}

// objectIDs returns the distinct ids in their order; more than MaxObjectIDs distinct ones is the caller's error.
func objectIDs(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	var out []string
	for _, id := range in {
		if n := utf8.RuneCountInString(id); n < 1 || n > maxIDRunes || !utf8.ValidString(id) || hasControl(id) {
			return nil, invalid("object_ids: id vazio, acima de %d caracteres ou com caractere de controle", maxIDRunes)
		}
		if slices.Contains(out, id) {
			continue
		}
		if len(out) == MaxObjectIDs {
			return nil, invalid("object_ids: mais de %d ids distintos", MaxObjectIDs)
		}
		out = append(out, id)
	}
	return out, nil
}

// hostList returns the first MaxHosts hosts and the total; no hosts, no member.
func hostList(in []string) ([]string, *int64, error) {
	if len(in) == 0 {
		return nil, nil, nil
	}
	out := slices.Clone(in[:min(len(in), MaxHosts)])
	for _, h := range out {
		if len(h) < 2 || len(h) > 43 || !reHost.MatchString(h) {
			return nil, nil, invalid("hosts: entrada que não é IP nem CIDR literal")
		}
	}
	return out, ptr(int64(len(in))), nil
}

// reportParams checks a copy of the report parameters; an empty filter or levels is no member.
func reportParams(r *contract.AuditReport) (*contract.AuditReport, error) {
	if r == nil {
		return nil, nil
	}
	out := contract.AuditReport{ReportID: r.ReportID}
	if !reUUID.MatchString(r.ReportID) {
		return nil, invalid("report.report_id não é um UUID minúsculo")
	}
	if r.Format != nil {
		if !validFormats[*r.Format] {
			return nil, invalid("report.format fora do enum")
		}
		out.Format = ptr(*r.Format)
	}
	if r.Lang != nil {
		if !validLangs[*r.Lang] {
			return nil, invalid("report.lang fora do enum")
		}
		out.Lang = ptr(*r.Lang)
	}
	if r.Variant != nil {
		if !validVariants[*r.Variant] {
			return nil, invalid("report.variant fora do enum")
		}
		out.Variant = ptr(*r.Variant)
	}
	if r.DeltaReportID != nil {
		if !reUUID.MatchString(*r.DeltaReportID) {
			return nil, invalid("report.delta_report_id não é um UUID minúsculo")
		}
		out.DeltaReportID = ptr(*r.DeltaReportID)
	}
	if r.Filter != nil && *r.Filter != "" {
		if !utf8.ValidString(*r.Filter) || hasControl(*r.Filter) {
			return nil, invalid("report.filter com caractere de controle ou UTF-8 inválido")
		}
		out.Filter = ptr(cutRunes(*r.Filter, MaxFilterRunes))
	}
	if r.MinQoD != nil {
		if *r.MinQoD < 0 || *r.MinQoD > 100 {
			return nil, invalid("report.min_qod fora de 0..100")
		}
		out.MinQoD = ptr(*r.MinQoD)
	}
	if r.ApplyOverrides != nil {
		out.ApplyOverrides = ptr(*r.ApplyOverrides)
	}
	if r.Levels != nil && *r.Levels != "" {
		if !reLevels.MatchString(*r.Levels) {
			return nil, invalid("report.levels fora da forma c?h?m?l?g?")
		}
		out.Levels = ptr(*r.Levels)
	}
	return &out, nil
}

// newLifecycle is a connector_started, identity_changed or policy_changed line.
func newLifecycle(at string, ev contract.AuditEvent, detail string) *entry {
	return &entry{Stream: contract.StreamExec, At: at, Event: ev, Detail: cleanText(detail, MaxDetailRunes)}
}

func newReceived(at string, c Command) (*entry, error) {
	e := &entry{Stream: contract.StreamExec, At: at, Event: contract.AuditEventReceived}
	if err := c.fill(e); err != nil {
		return nil, err
	}
	return e, nil
}

func newExecuted(at string, r Ref) (*entry, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	e := &entry{Stream: contract.StreamExec, At: at, Event: contract.AuditEventExecuted}
	r.fill(e)
	return e, nil
}

func newResult(at string, r Ref, o Outcome) (*entry, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if !validStatuses[o.Status] {
		return nil, invalid("status fora do enum")
	}
	e := &entry{Stream: contract.StreamExec, At: at, Event: contract.AuditEventResult, Status: ptr(o.Status)}
	if o.ErrorCode != "" {
		if o.Status != contract.StatusFailed {
			return nil, invalid("error_code só num resultado failed")
		}
		if !validErrorCodes[o.ErrorCode] {
			return nil, invalid("error_code fora do enum")
		}
		e.ErrorCode = ptr(o.ErrorCode)
	}
	ids, err := objectIDs(o.ObjectIDs)
	if err != nil {
		return nil, err
	}
	if a := o.Artifact; a != nil {
		switch {
		case r.Type != contract.TypeReportExport:
			return nil, invalid("artifact só no resultado de report.export")
		case !reSHA256.MatchString(a.SHA256):
			return nil, invalid("artifact.sha256 não é um sha256 hexadecimal minúsculo")
		case a.Size < 1 || a.Size > maxArtifactSize:
			return nil, invalid("artifact.size fora de 1..%d", maxArtifactSize)
		}
		e.Artifact = &contract.AuditArtifact{SHA256: a.SHA256, Size: a.Size}
	}
	r.fill(e)
	e.ObjectIDs = ids
	if r.Type != contract.TypeEnrollTokenCreate { // its output is the only secret of the contract: no free text
		e.Detail = cleanText(o.Detail, MaxDetailRunes)
	}
	return e, nil
}

func newRejected(at string, c Command, reason contract.RejectReason, detail string) (*entry, error) {
	if cl := reason.Class(); cl != contract.ClassFinalRecorded && cl != contract.ClassFinalNotRecorded {
		return nil, invalid("rejected só com motivo final (linhas 3–9)")
	}
	return newRefusal(at, contract.AuditEventRejected, c, reason, detail)
}

func newDeferred(at string, c Command, reason contract.RejectReason, detail string) (*entry, error) {
	if reason.Class() != contract.ClassDeferred {
		return nil, invalid("deferred só com motivo de adiamento (not_yet_valid, unavailable)")
	}
	return newRefusal(at, contract.AuditEventDeferred, c, reason, detail)
}

func newRefusal(at string, ev contract.AuditEvent, c Command, reason contract.RejectReason, detail string) (*entry, error) {
	e := &entry{Stream: contract.StreamReject, At: at, Event: ev, Reason: ptr(reason), Detail: cleanText(detail, MaxDetailRunes)}
	if err := c.fill(e); err != nil {
		return nil, err
	}
	return e, nil
}

// newUnauthenticated is the periodic count of the envelopes refused at verification lines 0–2.
func newUnauthenticated(at string, n contract.AuditUnauthenticated) *entry {
	return &entry{Stream: contract.StreamReject, At: at, Event: contract.AuditEventUnauthenticated, Unauthenticated: &n}
}

// newRedelivered is the periodic count of the redeliveries recognized at verification line 2a.
func newRedelivered(at string, n contract.AuditRedelivered) *entry {
	return &entry{Stream: contract.StreamReject, At: at, Event: contract.AuditEventRedelivered, Redelivered: &n}
}

// newVersionMismatch is the line of the node entering blocked_version, with both announcements.
func newVersionMismatch(at string, node, hub []string) (*entry, error) {
	if err := versionList(node); err != nil {
		return nil, err
	}
	if err := versionList(hub); err != nil {
		return nil, err
	}
	return &entry{Stream: contract.StreamReject, At: at, Event: contract.AuditEventVersionMismatch,
		Versions: &contract.AuditVersions{Node: slices.Clone(node), Hub: slices.Clone(hub)}}, nil
}

// versionList checks a schema_versions announcement: 1 to 8 distinct MAJOR.MINOR.
func versionList(v []string) error {
	if len(v) < 1 || len(v) > 8 {
		return invalid("versions: de 1 a 8 versões")
	}
	for i, s := range v {
		if len(s) > 7 || !reVersion.MatchString(s) {
			return invalid("versions: versão fora da forma MAJOR.MINOR")
		}
		if slices.Contains(v[:i], s) {
			return invalid("versions: versão repetida")
		}
	}
	return nil
}
