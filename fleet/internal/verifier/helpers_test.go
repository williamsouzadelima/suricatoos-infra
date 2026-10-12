package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// t0 is the issued_at of the test envelopes (window 12:00–13:00); tv is the instant they are verified at.
var (
	t0   = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	tv   = t0.Add(30 * time.Minute)
	boot = t0.Add(-2 * time.Hour) // the node starts before every instant of the tests (the clock never goes back)
	skew = contract.DefaultClockSkew
)

// testKey is a FICTITIOUS command key derived from a public text — neither the golden key nor a production key.
var testKey = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("suricatoos-fleet-verifier/chave-de-teste-ficticia"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

func testPub() ed25519.PublicKey { return testKey.Public().(ed25519.PublicKey) }

func uuidOf(name string) string {
	s := sha256.Sum256([]byte("uuid/" + name))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func nonceOf(name string) string {
	s := sha256.Sum256([]byte("nonce/" + name))
	return hex.EncodeToString(s[:])
}

const (
	ownNode = "node-lab-0001"
	taskID  = "2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"
	tgtID   = "9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35"
	schedID = "5c3e9a71-2b8d-4f06-9e1a-7d4c2b8f6a03"
)

// payloads has one valid payload per type of the catalog (the golden vectors' ones), with the hosts inside the
// scope of the tenant acme of the tests (192.0.2.0/24, 198.51.100.0/24).
var payloads = map[contract.CommandType]string{
	contract.TypeStateResync:       `{"kinds":["tasks","targets"]}`,
	contract.TypeTaskStart:         `{"task_id":"` + taskID + `"}`,
	contract.TypeTaskStop:          `{"task_id":"` + taskID + `"}`,
	contract.TypeTaskResume:        `{"task_id":"` + taskID + `"}`,
	contract.TypeTaskCreate:        `{"name":"Varredura semanal LAB","target_id":"` + tgtID + `","scan_config_id":"daba56c8-73ec-11df-a475-002264764cea","schedule_id":"` + schedID + `"}`,
	contract.TypeTaskModify:        `{"task_id":"` + taskID + `","schedule_id":"` + schedID + `"}`,
	contract.TypeTaskClone:         `{"task_id":"` + taskID + `","name":"Varredura semanal LAB (cópia)"}`,
	contract.TypeTaskDelete:        `{"task_id":"` + taskID + `"}`,
	contract.TypeTargetCreate:      `{"name":"LAB DMZ","hosts":["192.0.2.0/24","198.51.100.10"],"exclude_hosts":["192.0.2.1"],"port_range":"T:1-1024","alive_test":"ICMP, TCP-SYN Service & ARP Ping"}`,
	contract.TypeTargetModify:      `{"target_id":"` + tgtID + `","hosts":["192.0.2.0/25"],"alive_test":"ICMP, TCP-ACK Service & ARP Ping"}`,
	contract.TypeTargetDelete:      `{"target_id":"` + tgtID + `"}`,
	contract.TypeScheduleCreate:    `{"name":"Semanal LAB","icalendar":"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20261012T020000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=MO\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n","timezone":"America/Sao_Paulo","task_ids":["` + taskID + `"]}`,
	contract.TypeScheduleModify:    `{"schedule_id":"` + schedID + `","timezone":"UTC"}`,
	contract.TypeScheduleDelete:    `{"schedule_id":"` + schedID + `"}`,
	contract.TypeReportExport:      `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","format":"suricatoos-pdf","lang":"pt_BR","variant":"technical","filter":"apply_overrides=1 min_qod=70 levels=chmlg rows=-1"}`,
	contract.TypeReportSummary:     `{"report_id":"4b8d0f2a-6c1e-4a3b-8d5f-7e9a1c3b5d04","min_qod":70,"apply_overrides":true,"levels":"chml"}`,
	contract.TypeAgentScanNow:      `{"agent_id":"win-lab-0001"}`,
	contract.TypeAgentRevoke:       `{"agent_id":"win-lab-0001","reason":"máquina descomissionada"}`,
	contract.TypeEnrollTokenCreate: `{"token_type":"deployment","policy":"agent-endpoint","ttl_hours":72,"max_uses":50}`,
	contract.TypeEnrollTokenRevoke: `{"token_id":"Ab3dEf6hIj9k"}`,
	contract.TypeSensorJobEnqueue:  `{"targets":["192.0.2.0/28"],"ports":"T:22,80,443"}`,
	contract.TypeFeedSyncNow:       `{}`,
}

// command is a test envelope: its command_id and nonce come from the name.
func command(name string, typ contract.CommandType) contract.Command {
	return contract.Command{SchemaVersion: contract.SchemaVersion, CommandID: uuidOf(name), NodeID: ownNode,
		Tenant: "acme", Type: typ, IssuedBy: "op-7f3a", IssuedAt: contract.FormatUTCTime(t0),
		NotAfter: contract.FormatUTCTime(t0.Add(time.Hour)), Nonce: nonceOf(name)}
}

// signed builds the envelope bytes as contract.Sign does, without its window check (a test needs bad windows).
func signed(c contract.Command, payload string) []byte {
	return signWith(testKey, c, payload)
}

func signWith(priv ed25519.PrivateKey, c contract.Command, payload string) []byte {
	sum := sha256.Sum256([]byte(payload))
	c.PayloadSHA256 = hex.EncodeToString(sum[:])
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, contract.Canonical(&c)))
	q := func(s string) string { b, _ := contract.MarshalCompact(s); return string(b) }
	var b strings.Builder
	fmt.Fprintf(&b, `{"schema_version":%s,"command_id":%s,"node_id":%s,"tenant":%s,"type":%s,"issued_by":%s,"issued_at":%s,"not_after":%s,"nonce":%s,"payload_sha256":%s,"payload":%s,"signature":%s}`,
		q(c.SchemaVersion), q(c.CommandID), q(c.NodeID), q(c.Tenant), q(string(c.Type)), q(c.IssuedBy), q(c.IssuedAt),
		q(c.NotAfter), q(c.Nonce), q(c.PayloadSHA256), payload, q(c.Signature))
	return []byte(b.String())
}

// env is the signed envelope of a valid command of type typ.
func env(name string, typ contract.CommandType) []byte {
	return signed(command(name, typ), payloads[typ])
}

// allTypes lists the catalog in order.
func allTypes() []contract.CommandType {
	var out []contract.CommandType
	for _, e := range contract.Catalog() {
		out = append(out, e.Type)
	}
	return out
}

// writePolicy writes FLEET_STATE_DIR/policy.json.
func writePolicy(t *testing.T, dir string, allow []contract.CommandType, sensitive, total int) {
	t.Helper()
	b, err := json.Marshal(contract.Policy{Allow: allow, SensitivePerHour: sensitive, TotalPerHour: total})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, policy.FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTenants writes a central registry (acme: enabled, with gvmd user and password; globex: no gvmd user;
// initech: disabled) and its secrets file — FICTITIOUS values.
func writeTenants(t *testing.T, dir string) tenant.Config {
	t.Helper()
	reg := `[{"name":"acme","scope":"192.0.2.0/24, 198.51.100.0/24","gmp_user":"tenant-acme","enabled":true},` +
		`{"name":"globex","scope":"203.0.113.0/24","enabled":true},` +
		`{"name":"initech","scope":"192.0.2.0/25","gmp_user":"tenant-initech","enabled":false}]`
	cfg := tenant.Config{TenantsFile: filepath.Join(dir, "tenants.json"), SecretsFile: filepath.Join(dir, "segredos.json")}
	if err := os.WriteFile(cfg.TenantsFile, []byte(reg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SecretsFile, []byte(`{"acme":"senha-ficticia-de-teste"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// allFormats advertises every (format, lang, variant).
func allFormats() []contract.ReportFormatCapability {
	var out []contract.ReportFormatCapability
	for _, f := range []contract.ReportFormat{contract.FormatSuricatoosPDF, contract.FormatGVMXML, contract.FormatGVMCSVResults, contract.FormatGVMPDF} {
		for _, l := range []contract.ReportLang{contract.LangEN, contract.LangPTBR, contract.LangES} {
			out = append(out, contract.ReportFormatCapability{Format: f, Lang: l,
				Variants: []contract.ReportVariant{contract.VariantTechnical, contract.VariantClient, contract.VariantExecutive}})
		}
	}
	return out
}

// fakeGate checks hosts against a list of allowed prefixes of the TEXT (enough for the tests) and canonicalizes by
// lowercasing and trimming — so the tests see that the CANONICAL lists, not the raw ones, reach the executor.
type fakeGate struct {
	allowed []string
	calls   [][2][]string
}

func (g *fakeGate) CheckTarget(hosts, exclude []string) ([]string, []string, error) {
	g.calls = append(g.calls, [2][]string{hosts, exclude})
	if len(hosts) == 0 {
		return nil, nil, errors.New("sem hosts")
	}
	canon := func(in []string) ([]string, error) {
		var out []string
		for _, h := range in {
			c := strings.ToLower(strings.TrimSpace(h))
			if strings.ContainsAny(c, "abcdefghijklmnopqrstuvwxyz") && !strings.Contains(c, ":") {
				return nil, errors.New("não literal")
			}
			out = append(out, c)
		}
		return out, nil
	}
	h, err := canon(hosts)
	if err != nil {
		return nil, nil, err
	}
	for _, x := range h {
		ok := false
		for _, a := range g.allowed {
			ok = ok || strings.HasPrefix(x, a)
		}
		if !ok {
			return nil, nil, fmt.Errorf("%s fora do escopo", x)
		}
	}
	x, err := canon(exclude)
	if err != nil {
		return nil, nil, err
	}
	return h, x, nil
}

// fakeScope is line 9's node side: a gate per tenant and gvmd as maps.
type fakeScope struct {
	mu        sync.Mutex
	gate      *fakeGate
	gateErr   error
	readErr   error
	targets   map[string]TargetHosts
	tasks     map[string]TaskInfo
	schedules map[string][]string
	reads     []string
}

func newFakeScope() *fakeScope {
	return &fakeScope{
		gate:      &fakeGate{allowed: []string{"192.0.2.", "198.51.100."}},
		targets:   map[string]TargetHosts{tgtID: {Hosts: []string{"192.0.2.0/24"}, ExcludeHosts: []string{"192.0.2.1"}}},
		tasks:     map[string]TaskInfo{taskID: {TargetID: tgtID, ScheduleID: schedID}},
		schedules: map[string][]string{schedID: {taskID}},
	}
}

func (s *fakeScope) Gate(st tenant.Standing) (Gate, error) {
	if s.gateErr != nil {
		return nil, s.gateErr
	}
	return s.gate, nil
}

func (s *fakeScope) Target(tn, id string) (TargetHosts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, "target "+id)
	if s.readErr != nil {
		return TargetHosts{}, s.readErr
	}
	th, ok := s.targets[id]
	if !ok {
		return TargetHosts{}, ErrNotFound
	}
	return th, nil
}

func (s *fakeScope) Task(tn, id string) (TaskInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, "task "+id)
	if s.readErr != nil {
		return TaskInfo{}, s.readErr
	}
	ti, ok := s.tasks[id]
	if !ok {
		return TaskInfo{}, ErrNotFound
	}
	return ti, nil
}

func (s *fakeScope) ScheduleTasks(tn, id string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, "schedule "+id)
	if s.readErr != nil {
		return nil, s.readErr
	}
	ids, ok := s.schedules[id]
	if !ok {
		return nil, ErrNotFound
	}
	return ids, nil
}

// logSink collects what the pipeline logs.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// node is a pipeline under test over a real local state in a temporary FLEET_STATE_DIR.
type node struct {
	t       *testing.T
	v       *Verifier
	st      *State
	dir     string
	scope   *fakeScope
	formats []contract.ReportFormatCapability
	fmtErr  error
	logs    *logSink
	d       deps // what the pipeline uses (wrappers can be swapped in before build)
	cfg     Config
}

// newNode prepares a central node: every type allowed, wide budgets, the tenants of writeTenants, every report
// format, no replay floor (first boot). Call build() after changing anything.
func newNode(t *testing.T) *node {
	t.Helper()
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 1000, 3600)
	st, err := OpenState(dir, boot, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return newNodeOver(t, dir, st)
}

// newNodeOver is newNode over a local state already open in dir (closed at the end of the test).
func newNodeOver(t *testing.T, dir string, st *State) *node {
	t.Helper()
	tcfg := writeTenants(t, dir)
	src, err := tenant.Open(contract.NodeCentral, tcfg)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logSink{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	t.Cleanup(func() { st.Close() })
	n := &node{t: t, st: st, dir: dir, scope: newFakeScope(), formats: allFormats(), logs: logs}
	n.cfg = Config{CommandKey: testPub(), NodeID: ownNode, NodeKind: contract.NodeCentral, Skew: skew, StateDir: dir,
		Tenants: src, Scope: n.scope, Logger: logger,
		ReportFormats: func() ([]contract.ReportFormatCapability, error) { return n.formats, n.fmtErr }}
	n.d = deps{store: st.Store, clock: st.Store.Clock(), ledger: st.Ledger, audit: st.Audit,
		policy: func() (policy.Snapshot, error) { return policy.Load(dir, contract.NodeCentral) }}
	return n.build()
}

func (n *node) build() *node {
	n.t.Helper()
	v, err := newVerifier(n.cfg, n.d, false)
	if err != nil {
		n.t.Fatal(err)
	}
	n.v = v
	return n
}

func (n *node) process(raw []byte, at time.Time) Outcome { return n.v.Process(raw, at) }

// storeBytes is the anti-replay store file.
func (n *node) storeBytes() []byte {
	n.t.Helper()
	b, err := os.ReadFile(filepath.Join(n.dir, replay.FileName))
	if err != nil {
		n.t.Fatal(err)
	}
	return b
}

// auditEntries decodes the lines of one stream of the audit.
func (n *node) auditEntries(stream contract.AuditStream) []contract.AuditEntry {
	n.t.Helper()
	tail := n.st.Audit.Tail()
	lines := tail.Exec.Lines
	if stream == contract.StreamReject {
		lines = tail.Reject.Lines
	}
	var out []contract.AuditEntry
	for _, l := range lines {
		var e contract.AuditEntry
		if err := contract.DecodeStrict([]byte(l), &e); err != nil {
			n.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func events(es []contract.AuditEntry) []string {
	var out []string
	for _, e := range es {
		s := string(e.Event)
		if e.Reason != nil {
			s += ":" + string(*e.Reason)
		}
		out = append(out, s)
	}
	return out
}

// reasonOf is the reason of an outcome's ack ("" for none).
func reasonOf(o Outcome) contract.RejectReason {
	if o.Ack.Reason == nil {
		return ""
	}
	return *o.Ack.Reason
}

// expectAck checks an outcome's destination: kind, decision and reason.
func expectAck(t *testing.T, o Outcome, kind Kind, d contract.Decision, r contract.RejectReason) {
	t.Helper()
	if o.Kind != kind || o.Ack.Decision != d || reasonOf(o) != r {
		t.Fatalf("desfecho %v %s %s (err %v), esperava %v %s %s", o.Kind, o.Ack.Decision, reasonOf(o), o.Err, kind, d, r)
	}
}

// --- failure-injecting wrappers of the local state ---

// failingAudit makes the chosen methods of the audit fail.
type failingAudit struct {
	Auditor
	fail map[string]error
}

func (a *failingAudit) err(m string) error { return a.fail[m] }

func (a *failingAudit) Rejected(t time.Time, c audit.Command, r contract.RejectReason, d string) error {
	if err := a.err("Rejected"); err != nil {
		return err
	}
	return a.Auditor.Rejected(t, c, r, d)
}

func (a *failingAudit) Deferred(t time.Time, c audit.Command, r contract.RejectReason, d string) error {
	if err := a.err("Deferred"); err != nil {
		return err
	}
	return a.Auditor.Deferred(t, c, r, d)
}

func (a *failingAudit) Received(t time.Time, c audit.Command) error {
	if err := a.err("Received"); err != nil {
		return err
	}
	return a.Auditor.Received(t, c)
}

func (a *failingAudit) Executed(t time.Time, r audit.Ref) error {
	if err := a.err("Executed"); err != nil {
		return err
	}
	return a.Auditor.Executed(t, r)
}

func (a *failingAudit) Result(t time.Time, r audit.Ref, o audit.Outcome) error {
	if err := a.err("Result"); err != nil {
		return err
	}
	return a.Auditor.Result(t, r, o)
}

// failingStore makes Record (and the journal steps) fail, and records the order of the calls.
type failingStore struct {
	Store
	recordErr, journalErr error
	calls                 *[]string
}

func (s *failingStore) Record(v *contract.Verified, d replay.Decision, t time.Time) (replay.Entry, error) {
	*s.calls = append(*s.calls, "store.Record:"+string(d.Decision))
	if s.recordErr != nil {
		return replay.Entry{}, s.recordErr
	}
	return s.Store.Record(v, d, t)
}

func (s *failingStore) MarkExecuting(j replay.Job, t time.Time) error {
	*s.calls = append(*s.calls, "store.MarkExecuting")
	if s.journalErr != nil {
		return s.journalErr
	}
	return s.Store.MarkExecuting(j, t)
}

// orderedLedger records the order of Consume relative to the other calls, and can fail it.
type orderedLedger struct {
	Ledger
	consumeErr error
	calls      *[]string
}

func (l *orderedLedger) Consume(t time.Time, typ contract.CommandType, lim budget.Limits) error {
	*l.calls = append(*l.calls, "ledger.Consume")
	if l.consumeErr != nil {
		return l.consumeErr
	}
	return l.Ledger.Consume(t, typ, lim)
}

// orderedAudit records the order of the audit lines relative to the other calls.
type orderedAudit struct {
	Auditor
	calls *[]string
}

func (a *orderedAudit) Rejected(t time.Time, c audit.Command, r contract.RejectReason, d string) error {
	*a.calls = append(*a.calls, "audit.Rejected:"+string(r))
	return a.Auditor.Rejected(t, c, r, d)
}

func (a *orderedAudit) Deferred(t time.Time, c audit.Command, r contract.RejectReason, d string) error {
	*a.calls = append(*a.calls, "audit.Deferred:"+string(r))
	return a.Auditor.Deferred(t, c, r, d)
}

func (a *orderedAudit) Received(t time.Time, c audit.Command) error {
	*a.calls = append(*a.calls, "audit.Received")
	return a.Auditor.Received(t, c)
}

// failingClock makes Persist fail.
type failingClock struct {
	Clock
	err error
}

func (c *failingClock) Persist() error {
	if c.err != nil {
		return c.err
	}
	return c.Clock.Persist()
}

// budgetLimits are the limits of a policy with total and sensitive commands per hour.
func budgetLimits(total, sensitive int) budget.Limits {
	return budget.Limits{Total: total, Sensitive: sensitive}
}
