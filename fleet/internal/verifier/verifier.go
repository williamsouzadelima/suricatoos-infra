// Package verifier is the fleet node's verification pipeline (ADR-0011 "Verificação no nó (ordem fixa,
// fail-closed)"): one function, Process, takes the raw bytes of an envelope and the wall clock, runs lines 0–9 in the
// ADR's order, stopping at the first failure, and returns the outcome:
//
//	no ack       lines 0–2 (bad_envelope, payload_mismatch, bad_signature): only counted — heartbeat total and the
//	             periodic "unauthenticated" audit line; also a decision whose audit line could not be written
//	ack          a new decision: rejected (final; recorded for lines 4–9, not for line 3), deferred (not_yet_valid,
//	             unavailable: nothing recorded) or accepted (recorded, budget consumed)
//	redelivery   line 2a: the canonical form is already recorded — also as a replay —, so the recorded ack and
//	             result go back, lines 3–9 are not evaluated again and nothing runs again
//
// # Order and durability
//
//	0–2  contract.Verify with the PINNED command key (its only call in the package; never the golden test key)
//	2a   replay.Store.Lookup + contract.ClassifyReplay == ReplayRedelivery
//	3–4  Verified.CheckAt at the verification clock t (max(now, watermark): package clock)
//	5    ClassifyReplay == ReplayConflict, then the replay floor: issued_at < floor + skew, in whole seconds
//	6–7  tenant.Source.Resolve, policy.Load, admission.Check (tenant, catalog and node kind, allow, budgets)
//	8    contract.DecodePayload; report.export's (format, lang, variant) in capabilities.report_formats
//	9    the scope gate (an interface with scopegate.CheckTarget's shape, wired by the connector) and the gvmd reads
//
// Before any ack its audit line is written (Rejected or Deferred in the reject stream, Received in the exec one): an
// audit line that cannot be written means NO ack. A final decision of lines 4–9 is recorded in the anti-replay store
// after its audit line and before its ack; one of line 3 (bad_window, expired) is not recorded, but the watermark is
// made durable before its ack, so a clock that goes back cannot turn it into a different answer. To accept, the
// budget is consumed first (budget.ErrOverBudget there is rate_limited), then the received line is written, then the
// decision is recorded: the command runs only if all three succeeded, and a failure after the consumption loses the
// budget slot (fail-closed). Any local dependency that fails — the store (unconfirmed writes included, ErrNotDurable
// among them), the watermark of a line-3 decision, the budget's write, the re-read of the tenants, of the secrets or of
// the policy, the report formats, a gvmd read of line 9 — is unavailable: deferred, nothing recorded.
//
// The detail of an ack is always a fixed text of the connector, never built from the envelope, from gvmd or from an
// error message. Process handles one envelope at a time.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// Config is what the connector (F2.6) gives the pipeline, besides the local state (State).
type Config struct {
	// CommandKey is the PINNED command key (FLEET_COMMAND_KEY_PIN): the only key Process verifies with. The public
	// golden test key is refused.
	CommandKey ed25519.PublicKey
	// NodeID is the CN of the node's own fleet certificate (line 4).
	NodeID string
	// NodeKind is this node's kind (line 7).
	NodeKind contract.NodeKind
	// Skew is FLEET_CLOCK_SKEW (clock.ParseSkew): 0 to 10 min, in whole seconds — the replay floor is compared in whole
	// seconds (line 5), so a fraction would move it below the instant it marks.
	Skew time.Duration
	// StateDir is FLEET_STATE_DIR, where policy.json is read for every command (lines 6–7).
	StateDir string
	// Tenants answers line 6 (tenant.Open).
	Tenants tenant.Source
	// ReportFormats returns capabilities.report_formats of the node's state (line 8, report.export). An error is
	// unavailable.
	ReportFormats func() ([]contract.ReportFormatCapability, error)
	// Scope is line 9: the scope gate of each tenant and the gvmd reads.
	Scope Scope
	// Logger receives the local failures the outcome cannot carry. nil discards them.
	Logger *slog.Logger
}

// Kind is the destination of an outcome.
type Kind int

const (
	// NoAck: nothing goes to the hub — lines 0–2 (Reason says which; only counted), or a decision whose audit line
	// could not be written (Err says why).
	NoAck Kind = iota + 1
	// Ack: a new decision; send Ack.
	Ack
	// Redelivery: line 2a; send the recorded Ack and, when Result is set, the recorded result again.
	Redelivery
)

func (k Kind) String() string {
	switch k {
	case NoAck:
		return "sem ack"
	case Ack:
		return "ack"
	case Redelivery:
		return "reentrega"
	}
	return "?"
}

// Outcome is what Process decided, and everything the connector needs to act on it.
type Outcome struct {
	Kind Kind
	// Ack is the body of the ack (Kind Ack and Redelivery).
	Ack contract.Ack
	// Reason is the reason of lines 0–2 for NoAck (empty when the cause is a local failure).
	Reason contract.RejectReason
	// Err explains a NoAck (diagnostics; never sent to the hub).
	Err error
	// Result is the recorded result to send again (Redelivery); nil when there is none — always for
	// enroll_token.create, whose result is never kept (only the ack goes again).
	Result *replay.Result
	// Accepted is set when the decision is accepted: what the executor runs.
	Accepted *Accepted
	// PolicyEvent is the data of the event command.rejected_by_policy, for a final rejection of lines 6–9 (package
	// events sends it; this is only the signal), and PolicyEventTenant the envelope's tenant, which that tenant-scoped
	// event carries — also for tenant_unknown, where it is the tenant the hub signed. Both are empty otherwise.
	PolicyEvent       *contract.DataCommandRejected
	PolicyEventTenant string
}

// Accepted is a command the pipeline accepted: recorded, budget consumed, audited as received.
type Accepted struct {
	// Command is the authenticated envelope (a copy; Payload holds the raw bytes as received).
	Command contract.Command
	// Payload is contract.DecodePayload's struct (e.g. *contract.PayloadTargetCreate) with the canonical lists line 9
	// returned in place of the hosts of target.create, target.modify and sensor_job.enqueue: exactly what the
	// executor forwards — never the raw JSON, never the raw hosts.
	Payload any
	// Hosts and ExcludeHosts are the canonical lists line 9 checked for target.create, target.modify (the current
	// hosts of the target when the payload brings none) and sensor_job.enqueue; nil for the other types.
	Hosts, ExcludeHosts []string
	// Tenant is line 6's answer (scope and gvmd user; never a password).
	Tenant tenant.Standing
	// Job is the key of the command in the journal (Begin, Finish).
	Job replay.Job
	// At is the verification clock of the decision.
	At time.Time
}

// Store is what the pipeline uses of the anti-replay store and journal (*replay.Store).
type Store interface {
	Lookup(v *contract.Verified, t time.Time) replay.Lookup
	Record(v *contract.Verified, d replay.Decision, t time.Time) (replay.Entry, error)
	Floor() (time.Time, bool)
	Result(j replay.Job, t time.Time) (replay.Result, bool, error)
	MarkExecuting(j replay.Job, t time.Time) error
	RecordResult(j replay.Job, r replay.Result, t time.Time) error
}

// Clock is the verification clock (*clock.Clock).
type Clock interface {
	Now(now time.Time) time.Time
	Persist() error
}

// Ledger is the pair of budgets (*budget.Ledger): asked at line 7, consumed on acceptance.
type Ledger interface {
	Fits(t time.Time, typ contract.CommandType, lim budget.Limits) (budget.Room, error)
	Consume(t time.Time, typ contract.CommandType, lim budget.Limits) error
}

// Auditor is the local audit (*audit.Log).
type Auditor interface {
	Unauthenticated(t time.Time, reason contract.RejectReason) error
	Redelivered(t time.Time) error
	Rejected(t time.Time, c audit.Command, reason contract.RejectReason, detail string) error
	Deferred(t time.Time, c audit.Command, reason contract.RejectReason, detail string) error
	Received(t time.Time, c audit.Command) error
	Executed(t time.Time, r audit.Ref) error
	Result(t time.Time, r audit.Ref, o audit.Outcome) error
}

var (
	_ Store   = (*replay.Store)(nil)
	_ Ledger  = (*budget.Ledger)(nil)
	_ Auditor = (*audit.Log)(nil)
)

// deps are the local state the pipeline reads and writes.
type deps struct {
	store  Store
	clock  Clock
	ledger Ledger
	audit  Auditor
	policy func() (policy.Snapshot, error)
}

// Verifier is the verification pipeline of one node.
type Verifier struct {
	key     ed25519.PublicKey // the pinned command key
	nodeID  string
	kind    contract.NodeKind
	skew    time.Duration
	tenants tenant.Source
	formats func() ([]contract.ReportFormatCapability, error)
	scope   Scope
	d       deps
	log     *slog.Logger

	mu              sync.Mutex // one envelope at a time
	unauthenticated atomic.Int64
	redeliveries    atomic.Int64
}

var reNodeID = regexp.MustCompile(contract.PatternNodeID)

// New builds the pipeline over the node's local state. It refuses a configuration the connector cannot run with —
// and the public golden test key as the command key.
func New(cfg Config, st *State) (*Verifier, error) {
	if st == nil || st.Store == nil || st.Ledger == nil || st.Audit == nil {
		return nil, errors.New("verifier: estado local ausente (OpenState)")
	}
	stateDir, kind := cfg.StateDir, cfg.NodeKind
	return newVerifier(cfg, deps{
		store: st.Store, clock: st.Store.Clock(), ledger: st.Ledger, audit: st.Audit,
		policy: func() (policy.Snapshot, error) { return policy.Load(stateDir, kind) },
	}, false)
}

// newVerifier builds the pipeline over any deps. allowGoldenKey is true only for the golden vectors test, which runs
// the pipeline with the public test key.
func newVerifier(cfg Config, d deps, allowGoldenKey bool) (*Verifier, error) {
	switch {
	case len(cfg.CommandKey) != ed25519.PublicKeySize:
		return nil, contract.ErrInvalidPublicKey
	case contract.IsGoldenTestKey(cfg.CommandKey) && !allowGoldenKey:
		return nil, errors.New("verifier: a chave de teste pública dos golden vectors nunca é a chave de comando de um nó")
	case !reNodeID.MatchString(cfg.NodeID):
		return nil, fmt.Errorf("verifier: node_id %.64q fora do padrão", cfg.NodeID)
	case cfg.NodeKind != contract.NodeCentral && cfg.NodeKind != contract.NodeStandalone && cfg.NodeKind != contract.NodeSensor:
		return nil, fmt.Errorf("verifier: node_kind %.16q inválido", cfg.NodeKind)
	case cfg.Skew < 0 || cfg.Skew > contract.MaxClockSkew:
		return nil, contract.ErrInvalidSkew
	case cfg.Skew%time.Second != 0:
		return nil, fmt.Errorf("%w: %v não é um número inteiro de segundos", contract.ErrInvalidSkew, cfg.Skew)
	case cfg.StateDir == "":
		return nil, errors.New("verifier: FLEET_STATE_DIR vazio")
	case cfg.Tenants == nil || cfg.ReportFormats == nil || cfg.Scope == nil:
		return nil, errors.New("verifier: tenants, capacidades de relatório e escopo são obrigatórios")
	case d.store == nil || d.clock == nil || d.ledger == nil || d.audit == nil || d.policy == nil:
		return nil, errors.New("verifier: estado local incompleto")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Verifier{key: bytes.Clone(cfg.CommandKey), nodeID: cfg.NodeID, kind: cfg.NodeKind, skew: cfg.Skew,
		tenants: cfg.Tenants, formats: cfg.ReportFormats, scope: cfg.Scope, d: d, log: logger}, nil
}

// Counters are the heartbeat's unauthenticated_rejections and redeliveries since this pipeline started.
func (v *Verifier) Counters() (unauthenticatedRejections, redeliveries int64) {
	return v.unauthenticated.Load(), v.redeliveries.Load()
}

// Process verifies one envelope as received (its raw bytes) at the wall clock now, and returns the outcome. It runs
// one envelope at a time; see the package documentation for the order and what is durable before the outcome.
func (v *Verifier) Process(raw []byte, now time.Time) Outcome {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.d.clock.Now(now)

	// lines 0–2
	ver, err := contract.Verify(v.key, raw)
	if err != nil {
		return v.unauthenticatedOutcome(t, err)
	}
	c := &check{v: v, ver: ver, cmd: ver.Command(), t: t}

	// line 2a — from a store that confirmed on disk what it holds: what the boot read and could not confirm is never
	// acked, not even again
	look := v.d.store.Lookup(ver, t)
	if look.Unconfirmed != nil {
		return c.unavailable(detailStore, look.Unconfirmed)
	}
	if contract.ClassifyReplay(ver.CanonicalSHA256(), look.Recorded) == contract.ReplayRedelivery {
		if look.Same == nil {
			return c.unavailable(detailStore, errors.New("o store achou a forma canônica sem a entrada"))
		}
		return c.redelivery(look.Same)
	}
	return c.run(look.Recorded)
}

func (v *Verifier) unauthenticatedOutcome(t time.Time, err error) Outcome {
	reason, ok := contract.ReasonOf(err)
	if !ok { // ErrInvalidPublicKey: New refuses such a key, so this is unreachable
		return Outcome{Kind: NoAck, Err: err}
	}
	v.unauthenticated.Add(1)
	if aerr := v.d.audit.Unauthenticated(t, reason); aerr != nil {
		v.log.Warn("verificação: a contagem de envelope não autenticado não foi à auditoria (o total do heartbeat conta)",
			"motivo", string(reason), "erro", aerr.Error())
	}
	return Outcome{Kind: NoAck, Reason: reason, Err: err}
}

// The fixed details of the acks. None is built from the envelope, from gvmd or from an error message.
const (
	detailConflict      = "nonce ou command_id já gravado com outra forma canônica"
	detailFloor         = "cache reiniciado"
	detailBadPayload    = "payload inválido para o tipo"
	detailVariant       = "combinação format/lang/variant não anunciada em capabilities.report_formats"
	detailOverBudget    = "orçamento esgotado (reconferido ao consumir)"
	detailStore         = "store anti-replay/journal não gravável"
	detailClock         = "marca d'água do relógio de verificação não gravável"
	detailTenants       = "registro de tenants ou arquivo de segredos ilegível"
	detailPolicy        = "política local ilegível"
	detailBudgets       = "orçamentos locais indisponíveis"
	detailBudgetWrite   = "consumo do orçamento não gravado"
	detailFormats       = "capacidades de relatório indisponíveis"
	detailScopeGate     = "portão de escopo indisponível"
	detailScopeRead     = "leitura no gvmd da linha 9 falhou"
	detailScopeDenied   = "host fora do escopo do tenant, não literal ou contendo IP do nó ou do hub"
	detailScopeNotFound = "objeto não encontrado no gvmd para o tenant: o escopo não pôde ser provado"
	maxDetailRunes      = 512
)

// cleanDetail keeps a detail inside the contract (no_control, at most 512 characters) whatever its source.
func cleanDetail(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffe || r == 0xffff {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	if utf8.RuneCountInString(s) > maxDetailRunes {
		s = string([]rune(s)[:maxDetailRunes])
	}
	return s
}
