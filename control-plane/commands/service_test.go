package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/enroll"
)

// callHistory invokes the history handler the way the mux would for
// GET /api/v1/agents/{id}/commands.
func callHistory(svc *Service, secret, auth, agent string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/v1/agents/"+agent+"/commands", nil)
	r.SetPathValue("id", agent)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	svc.HistoryHandler(secret)(w, r)
	return w
}

// agentPoll / agentAck play the agent: identity comes from the forwarded client-cert DN.
func agentPoll(svc *Service, cn string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/commands", nil)
	r.Header.Set("X-Client-Cert-DN", "CN="+cn+",O=suricatoos")
	w := httptest.NewRecorder()
	svc.PollHandler()(w, r)
	return w
}

func agentAck(svc *Service, cn, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/commands/ack", strings.NewReader(body))
	r.Header.Set("X-Client-Cert-DN", "CN="+cn+",O=suricatoos")
	w := httptest.NewRecorder()
	svc.AckHandler()(w, r)
	return w
}

func keysOf(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestHistoryHandlerListsNewestFirst(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", 0, clk)
	svc := NewService(q, nil)

	c1 := mustEnqueue(t, q, "agent-1")
	clk.Advance(time.Minute)
	c2 := mustEnqueue(t, q, "agent-1") // supersedes c1
	q.Poll("agent-1")
	clk.Advance(time.Minute)
	q.Ack("agent-1", c2.ID)
	clk.Advance(time.Minute)
	c3 := mustEnqueue(t, q, "agent-1")
	mustEnqueue(t, q, "agent-2") // another agent: must not leak into agent-1's history

	w := callHistory(svc, "s3cret", "Bearer s3cret", "agent-1")
	if w.Code != http.StatusOK {
		t.Fatalf("history = %d, want 200: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		AgentID  string   `json:"agent_id"`
		Commands []Record `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}
	if body.AgentID != "agent-1" {
		t.Fatalf("agent_id = %q, want agent-1", body.AgentID)
	}
	got := body.Commands
	if len(got) != 3 || got[0].ID != c3.ID || got[1].ID != c2.ID || got[2].ID != c1.ID {
		t.Fatalf("order = %+v, want [c3, c2, c1] (newest first)", got)
	}
	if got[0].State != StatePending || got[1].State != StateAcked || got[2].State != StateSuperseded {
		t.Fatalf("states = %s/%s/%s, want PENDING/ACKED/SUPERSEDED", got[0].State, got[1].State, got[2].State)
	}
	if got[1].DeliveredAt.IsZero() || got[1].AckedAt.IsZero() {
		t.Fatalf("the acked command must carry its delivery and ack times: %+v", got[1])
	}

	// Times that never happened are omitted, not rendered as year 0001.
	var raw struct {
		Commands []json.RawMessage `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if k := strings.Join(keysOf(t, raw.Commands[0]), ","); k != "created_at,id,state,type,updated_at" {
		t.Fatalf("PENDING record keys = %s, want created_at,id,state,type,updated_at", k)
	}
	if k := strings.Join(keysOf(t, raw.Commands[1]), ","); k != "acked_at,created_at,delivered_at,id,state,type,updated_at" {
		t.Fatalf("ACKED record keys = %s", k)
	}
}

func TestHistoryHandlerRequiresTheAdminBearer(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	mustEnqueue(t, q, "agent-1")
	svc := NewService(q, nil)

	for name, auth := range map[string]string{
		"no header":             "",
		"wrong secret":          "Bearer wrong",
		"scheme only":           "Bearer",
		"empty token":           "Bearer ",
		"other scheme":          "Basic s3cret",
		"secret without scheme": "s3cret",
		"lowercase scheme":      "bearer s3cret",
		"trailing junk":         "Bearer s3cret ",
		"prefix of the secret":  "Bearer s3cre",
	} {
		w := callHistory(svc, "s3cret", auth, "agent-1")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: history = %d, want 401", name, w.Code)
		}
		if strings.Contains(w.Body.String(), "agent-1") {
			t.Errorf("%s: a 401 must not disclose anything: %s", name, w.Body)
		}
	}
	if w := callHistory(svc, "s3cret", "Bearer s3cret", "agent-1"); w.Code != http.StatusOK {
		t.Fatalf("valid bearer = %d, want 200", w.Code)
	}
}

// A service built with an empty admin secret must fail closed: "Bearer " with an
// empty token would otherwise match the empty secret.
func TestBearerRoutesFailClosedWithAnEmptySecret(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc := NewService(q, nil)

	if w := callHistory(svc, "", "Bearer ", "agent-1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("history with empty secret = %d, want 401", w.Code)
	}
	r := httptest.NewRequest("POST", "/api/v1/agents/agent-1/commands", strings.NewReader(`{"type":"scan_now"}`))
	r.SetPathValue("id", "agent-1")
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	svc.EnqueueHandler("")(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enqueue with empty secret = %d, want 401", w.Code)
	}
	if _, ok := pending(q, "agent-1"); ok {
		t.Fatal("a command was enqueued through an unauthenticated route")
	}
}

func TestHistoryHandlerEmptyAndValidation(t *testing.T) {
	svc := NewService(openQ(t, "", 0, newClock()), nil)

	// An agent without commands is a normal answer, not an error: the queue does not
	// know which agents exist.
	w := callHistory(svc, "s3cret", "Bearer s3cret", "agent-new")
	if w.Code != http.StatusOK {
		t.Fatalf("unknown agent = %d, want 200", w.Code)
	}
	var raw struct {
		Commands json.RawMessage `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw.Commands) != "[]" {
		t.Fatalf("commands = %s, want [] (never null)", raw.Commands)
	}

	// Auth is checked before the id.
	r := httptest.NewRequest("GET", "/api/v1/agents//commands", nil)
	w = httptest.NewRecorder()
	svc.HistoryHandler("s3cret")(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer + no id = %d, want 401", w.Code)
	}
	r = httptest.NewRequest("GET", "/api/v1/agents//commands", nil)
	r.Header.Set("Authorization", "Bearer s3cret")
	w = httptest.NewRecorder()
	svc.HistoryHandler("s3cret")(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no id = %d, want 400", w.Code)
	}
}

// The agent client (agent/internal/command) decodes {id,type} from GET /v1/commands
// and posts {"id"} to /v1/commands/ack. The new lifecycle must not leak into that
// wire format.
func TestAgentWireContractIsUnchanged(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc := NewService(q, nil)
	c := mustEnqueue(t, q, "agent-1")

	// Poll: exactly {id,type,created_at}, and again on redelivery.
	for i := range 2 {
		w := agentPoll(svc, "agent-1")
		if w.Code != http.StatusOK {
			t.Fatalf("poll #%d = %d, want 200", i+1, w.Code)
		}
		if k := strings.Join(keysOf(t, w.Body.Bytes()), ","); k != "created_at,id,type" {
			t.Fatalf("poll #%d body keys = %s, want created_at,id,type (no lifecycle fields)", i+1, k)
		}
		var agentView struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &agentView); err != nil || agentView.ID != c.ID || agentView.Type != CmdScanNow {
			t.Fatalf("poll #%d agent view = %+v err=%v, want %s/%s", i+1, agentView, err, c.ID, CmdScanNow)
		}
	}
	if st := only(t, q, "agent-1").State; st != StateDelivered {
		t.Fatalf("after polls state = %s, want DELIVERED", st)
	}

	// Ack: {"id": "..."} -> 204, and the command is done.
	if w := agentAck(svc, "agent-1", `{"id":"`+c.ID+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("ack = %d, want 204", w.Code)
	}
	if st := only(t, q, "agent-1").State; st != StateAcked {
		t.Fatalf("after ack state = %s, want ACKED", st)
	}
	if w := agentPoll(svc, "agent-1"); w.Code != http.StatusNoContent {
		t.Fatalf("poll after ack = %d, want 204", w.Code)
	}
	// Acking something unknown stays a quiet 204 (the client treats any 2xx as done).
	if w := agentAck(svc, "agent-1", `{"id":"stale"}`); w.Code != http.StatusNoContent {
		t.Fatalf("stale ack = %d, want 204", w.Code)
	}
	if w := agentAck(svc, "agent-1", `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("ack without id = %d, want 400", w.Code)
	}
	if w := agentAck(svc, "", `{"id":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("ack without a client cert = %d, want 403", w.Code)
	}
}

// What the operator gets back when enqueueing is also unchanged.
func TestEnqueueResponseShapeIsUnchanged(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc := NewService(q, nil)

	r := httptest.NewRequest("POST", "/api/v1/agents/agent-1/commands", strings.NewReader(`{"type":"scan_now"}`))
	r.SetPathValue("id", "agent-1")
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	svc.EnqueueHandler("s3cret")(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("enqueue = %d, want 202", w.Code)
	}
	if k := strings.Join(keysOf(t, w.Body.Bytes()), ","); k != "created_at,id,type" {
		t.Fatalf("202 body keys = %s, want created_at,id,type", k)
	}

	w = httptest.NewRecorder()
	svc.SessionEnqueueHandler()(w, gatedReq("POST", "/agents/scan?id=agent-2"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("session enqueue = %d, want 202", w.Code)
	}
	if k := strings.Join(keysOf(t, w.Body.Bytes()), ","); k != "created_at,id,type" {
		t.Fatalf("session 202 body keys = %s, want created_at,id,type", k)
	}
}

// End to end through the handlers, across a control-plane restart.
func TestOperatorCanFollowACommandAcrossARestart(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	svc1 := NewService(openQ(t, path, 0, clk), nil)

	r := httptest.NewRequest("POST", "/api/v1/agents/agent-1/commands", strings.NewReader(`{"type":"scan_now"}`))
	r.SetPathValue("id", "agent-1")
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	svc1.EnqueueHandler("s3cret")(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("enqueue = %d, want 202", w.Code)
	}
	var enq Command
	if err := json.Unmarshal(w.Body.Bytes(), &enq); err != nil || enq.ID == "" {
		t.Fatalf("enqueue body: %v %s", err, w.Body)
	}

	// The control-plane is redeployed before the agent polls.
	clk.Advance(time.Minute)
	svc2 := NewService(openQ(t, path, 0, clk), nil)
	if w := agentPoll(svc2, "agent-1"); w.Code != http.StatusOK {
		t.Fatalf("poll after restart = %d, want 200 (the request must survive the deploy)", w.Code)
	}
	if w := agentAck(svc2, "agent-1", `{"id":"`+enq.ID+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("ack = %d", w.Code)
	}

	w = callHistory(svc2, "s3cret", "Bearer s3cret", "agent-1")
	var hist struct {
		Commands []Record `json:"commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &hist); err != nil || len(hist.Commands) != 1 {
		t.Fatalf("history: %v %s", err, w.Body)
	}
	if rec := hist.Commands[0]; rec.ID != enq.ID || rec.State != StateAcked || rec.DeliveredAt.IsZero() || rec.AckedAt.IsZero() {
		t.Fatalf("history record = %+v, want ACKED with delivery and ack times", rec)
	}
}

// 202 means "durably queued": when the write fails the operator must be told, and
// nothing may be left half-queued.
func TestEnqueueHandlersAnswer500WhenThePersistFails(t *testing.T) {
	path := brokenDiskPath(t)
	q := openQ(t, path, 0, newClock())
	svc := NewService(q, nil)
	breakDisk(t, path)

	r := httptest.NewRequest("POST", "/api/v1/agents/agent-1/commands", strings.NewReader(`{"type":"scan_now"}`))
	r.SetPathValue("id", "agent-1")
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	svc.EnqueueHandler("s3cret")(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("bearer enqueue = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), path) {
		t.Fatalf("the 500 body must not leak the server path: %s", w.Body)
	}

	w = httptest.NewRecorder()
	svc.SessionEnqueueHandler()(w, gatedReq("POST", "/agents/scan?id=agent-1"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("session enqueue = %d, want 500", w.Code)
	}
	if _, ok := pending(q, "agent-1"); ok {
		t.Fatal("a command whose persist failed is still queued")
	}
	if h := q.History("agent-1"); len(h) != 0 {
		t.Fatalf("failed enqueues left history behind: %+v", h)
	}
}

// --- fix round 1 ---

// sessionScan POSTs /agents/scan?id=<id> the way nginx delivers it (gate marker set).
func sessionScan(svc *Service, id string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	svc.SessionEnqueueHandler()(w, gatedReq("POST", "/agents/scan?id="+url.QueryEscape(id)))
	return w
}

// bearerEnqueue POSTs /api/v1/agents/{id}/commands with the admin bearer.
func bearerEnqueue(svc *Service, id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/agents/x/commands", strings.NewReader(`{"type":"scan_now"}`))
	r.SetPathValue("id", id)
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	svc.EnqueueHandler("s3cret")(w, r)
	return w
}

// The queue used to accept any string as an agent id and to grow without bound, and
// the Agents UI route sits behind a gate that today only checks that a cookie exists.
// Every state change rewrites (and fsyncs) the whole file under the lock that every
// agent poll takes, and boot loads all of it, so an unbounded file is an outage.
func TestEnqueueRejectsBadIDsAndCapsAgents(t *testing.T) {
	const max = 40
	agent := func(i int) string { return fmt.Sprintf("agent-%03d", i) }

	t.Run("bad ids are refused and nothing is written", func(t *testing.T) {
		path := statePath(t)
		q := openQCfg(t, Config{Path: path, MaxAgents: max}, newClock())
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		for name, id := range map[string]string{
			"129 bytes":           strings.Repeat("a", 129),
			"130 bytes, 65 runes": strings.Repeat("é", 65),
			"empty":               "",
			"less-than":           "agent<1",
			"greater-than":        "agent>1",
			"comma":               "agent,O=evil",
			"equals":              "agent=1",
			"plus":                "agent+1",
			"double quote":        `agent"1`,
			"backslash":           `agent\1`,
			"semicolon":           "agent;1",
			"NUL":                 "agent\x00",
			"newline":             "agent\n1",
			"tab":                 "agent\t1",
			"DEL":                 "agent\x7f",
			"invalid UTF-8":       "agent\xff",
		} {
			c, err := q.Enqueue(id, CmdScanNow)
			if !errors.Is(err, ErrInvalidAgentID) {
				t.Errorf("%s: Enqueue(%q) err = %v, want ErrInvalidAgentID", name, id, err)
			}
			if c.ID != "" {
				t.Errorf("%s: a refused id produced a command: %+v", name, c)
			}
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("refused ids changed the state file:\nbefore %s\nafter  %s", before, after)
		}

		// The boundary itself is fine: the limit is 128 BYTES, as at enrollment.
		for _, id := range []string{strings.Repeat("a", 128), strings.Repeat("é", 64), "a", "srv-01.example_net", "Ünï-çode"} {
			if _, err := q.Enqueue(id, CmdScanNow); err != nil {
				t.Errorf("valid id %q refused: %v", id, err)
			}
		}
	})

	t.Run("distinct agents are capped", func(t *testing.T) {
		path := statePath(t)
		q := openQCfg(t, Config{Path: path, TTL: time.Hour, MaxAgents: max}, newClock())

		refused := 0
		for i := range max + 50 {
			_, err := q.Enqueue(agent(i), CmdScanNow)
			if i < max {
				if err != nil {
					t.Fatalf("agent %d, below the cap, was refused: %v", i, err)
				}
				continue
			}
			if !errors.Is(err, ErrQueueFull) {
				t.Fatalf("agent %d, over the cap: err = %v, want ErrQueueFull", i, err)
			}
			refused++
		}
		if refused != 50 {
			t.Fatalf("%d extra agents refused, want 50", refused)
		}
		if got := len(readState(t, path).Agents); got != max {
			t.Fatalf("the state file holds %d agents, want exactly %d", got, max)
		}
		if h := q.History(agent(max)); len(h) != 0 {
			t.Fatalf("a refused newcomer left history behind: %+v", h)
		}

		// Agents already queued keep working at the cap: only NEW ids are refused.
		if _, err := q.Enqueue(agent(0), CmdScanNow); err != nil {
			t.Fatalf("an agent already in the queue was refused at the cap: %v", err)
		}
		// And nothing live was evicted to make room.
		for i := range max {
			if _, ok := pending(q, agent(i)); !ok {
				t.Fatalf("agent %s lost its live command", agent(i))
			}
		}
	})

	t.Run("idle agents with nothing live are reclaimed, live ones never", func(t *testing.T) {
		path := statePath(t)
		clk := newClock()
		q := openQCfg(t, Config{Path: path, TTL: time.Hour, MaxAgents: max}, clk)
		for i := range max {
			c := mustEnqueue(t, q, agent(i))
			if i < max/2 { // the first half is done at t0: delivered and acked
				q.Poll(agent(i))
				if !q.Ack(agent(i), c.ID) {
					t.Fatalf("setup: ack of %s failed", agent(i))
				}
			}
		}

		// t0+30m: the queue is full, nothing has been idle for longer than the TTL, and
		// the other half is live.
		clk.Advance(30 * time.Minute)
		if _, err := q.Enqueue("newcomer-00", CmdScanNow); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("at the cap with nothing idle: err = %v, want ErrQueueFull", err)
		}

		// t0+90m: the acked half has been idle for 90m (> TTL); the other half expired
		// at t0+60m, only 30m ago, so it is kept and its history stays readable.
		clk.Advance(60 * time.Minute)
		if _, err := q.Enqueue("newcomer-00", CmdScanNow); err != nil {
			t.Fatalf("idle agents should have been reclaimed to make room: %v", err)
		}
		disk := readState(t, path).Agents
		if want := max - max/2 + 1; len(disk) != want {
			t.Fatalf("state file holds %d agents after the reclaim, want %d", len(disk), want)
		}
		for i := range max / 2 {
			if _, kept := disk[agent(i)]; kept {
				t.Errorf("idle acked agent %s was not reclaimed", agent(i))
			}
		}
		for i := max / 2; i < max; i++ {
			if h := q.History(agent(i)); len(h) != 1 || h[0].State != StateExpired {
				t.Fatalf("agent %s = %+v, want its EXPIRED command still readable", agent(i), h)
			}
		}

		// The freed slots are real, and then the queue is full again: the expired half
		// is not idle for long enough yet and the newcomers are live.
		for i := 1; i < max/2; i++ {
			if _, err := q.Enqueue(fmt.Sprintf("newcomer-%02d", i), CmdScanNow); err != nil {
				t.Fatalf("newcomer %d should fit in the reclaimed room: %v", i, err)
			}
		}
		if _, err := q.Enqueue("newcomer-overflow", CmdScanNow); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("err = %v, want ErrQueueFull once the reclaimed room is used up", err)
		}

		// t0+135m: the expired half has now been idle for 75m (> TTL) and goes; the
		// newcomers (45m old, within the TTL) are live and are NEVER evicted.
		clk.Advance(45 * time.Minute)
		if _, err := q.Enqueue("newcomer-late", CmdScanNow); err != nil {
			t.Fatalf("the expired half should have been reclaimed: %v", err)
		}
		for i := 0; i < max/2; i++ {
			id := fmt.Sprintf("newcomer-%02d", i)
			if _, ok := pending(q, id); !ok {
				t.Fatalf("%s lost its live command to a reclaim", id)
			}
		}
		for i := max / 2; i < max; i++ {
			if h := q.History(agent(i)); len(h) != 0 {
				t.Fatalf("agent %s should have been reclaimed: %+v", agent(i), h)
			}
		}
	})

	t.Run("a failed save restores the agents a reclaim dropped", func(t *testing.T) {
		path := brokenDiskPath(t)
		clk := newClock()
		q := openQCfg(t, Config{Path: path, TTL: time.Hour, MaxAgents: 3}, clk)
		for _, a := range []string{"a1", "a2", "a3"} {
			c := mustEnqueue(t, q, a)
			q.Poll(a)
			q.Ack(a, c.ID)
		}
		clk.Advance(2 * time.Hour) // all three idle for longer than the TTL
		snapshot := func() string {
			return mustJSON(t, [][]Record{q.History("a1"), q.History("a2"), q.History("a3")})
		}
		before := snapshot()

		breakDisk(t, path)
		_, err := q.Enqueue("newcomer", CmdScanNow)
		if err == nil || errors.Is(err, ErrQueueFull) || errors.Is(err, ErrInvalidAgentID) {
			t.Fatalf("err = %v, want a persistence error", err)
		}
		if after := snapshot(); after != before {
			t.Fatalf("the failed request cost the queue its idle agents:\nbefore %s\nafter  %s", before, after)
		}
		if h := q.History("newcomer"); len(h) != 0 {
			t.Fatalf("the failed newcomer left history behind: %+v", h)
		}

		// The disk comes back: the same request now goes through, reclaim included.
		if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Enqueue("newcomer", CmdScanNow); err != nil {
			t.Fatalf("after the disk recovered: %v", err)
		}
		if disk := readState(t, path).Agents; len(disk) != 1 || len(disk["newcomer"]) != 1 {
			t.Fatalf("state file = %+v, want only the newcomer", disk)
		}
	})

	t.Run("session route: malformed ids are 400, before any enrollment lookup", func(t *testing.T) {
		path := statePath(t)
		q := openQ(t, path, 0, newClock())
		lookups := 0
		svc := NewService(q, func(string) bool { lookups++; return true })

		for name, id := range map[string]string{
			"129 chars":   strings.Repeat("a", 129),
			"comma":       "a,b",
			"angle":       "<b>",
			"unprintable": "a\x01b",
		} {
			if w := sessionScan(svc, id); w.Code != http.StatusBadRequest {
				t.Errorf("%s: session scan = %d, want 400", name, w.Code)
			}
		}
		if lookups != 0 {
			t.Errorf("the enrollment lookup ran %d times for malformed ids", lookups)
		}
		// With no lookup configured it is 400 as well, and nothing is written.
		long := strings.Repeat("a", 129)
		if w := sessionScan(NewService(q, nil), long); w.Code != http.StatusBadRequest {
			t.Errorf("129 chars without a lookup = %d, want 400", w.Code)
		}
		if h := q.History(long); len(h) != 0 {
			t.Errorf("a refused id left history behind: %+v", h)
		}
		if disk := readState(t, path).Agents; len(disk) != 0 {
			t.Errorf("refused ids reached the state file: %+v", disk)
		}
	})

	t.Run("session route: unknown agents are 404 when the lookup is set", func(t *testing.T) {
		path := statePath(t)
		q := openQ(t, path, 0, newClock())
		var asked []string
		enrolled := map[string]bool{"agent-1": true}
		svc := NewService(q, func(id string) bool { asked = append(asked, id); return enrolled[id] })

		if w := sessionScan(svc, "ghost-9"); w.Code != http.StatusNotFound {
			t.Fatalf("unknown agent = %d, want 404", w.Code)
		}
		if h := q.History("ghost-9"); len(h) != 0 {
			t.Fatalf("an unknown agent got a queue entry: %+v", h)
		}
		if _, ok := readState(t, path).Agents["ghost-9"]; ok {
			t.Fatal("an unknown agent reached the state file")
		}
		if w := sessionScan(svc, "agent-1"); w.Code != http.StatusAccepted {
			t.Fatalf("enrolled agent = %d, want 202", w.Code)
		}
		if w := sessionScan(svc, " agent-1 "); w.Code != http.StatusAccepted {
			t.Fatalf("enrolled agent with padding = %d, want 202 (the id is trimmed)", w.Code)
		}
		for _, id := range asked {
			if id != strings.TrimSpace(id) {
				t.Errorf("the lookup got an untrimmed id %q", id)
			}
		}

		// No lookup (in-memory token store) = no check.
		if w := sessionScan(NewService(q, nil), "ghost-9"); w.Code != http.StatusAccepted {
			t.Fatalf("without a lookup = %d, want 202", w.Code)
		}
		// The bearer route is the administrator's and does not consult it.
		if w := bearerEnqueue(svc, "ghost-10"); w.Code != http.StatusAccepted {
			t.Fatalf("bearer enqueue for an unlisted agent = %d, want 202", w.Code)
		}
	})

	t.Run("a full queue answers 503 on both routes", func(t *testing.T) {
		q := openQCfg(t, Config{MaxAgents: 2}, newClock())
		svc := NewService(q, nil)
		for _, id := range []string{"agent-1", "agent-2"} {
			if w := sessionScan(svc, id); w.Code != http.StatusAccepted {
				t.Fatalf("%s = %d, want 202", id, w.Code)
			}
		}
		if w := sessionScan(svc, "agent-3"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("session scan over the cap = %d, want 503", w.Code)
		}
		if w := bearerEnqueue(svc, "agent-3"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("bearer enqueue over the cap = %d, want 503", w.Code)
		}
		if w := sessionScan(svc, "agent-1"); w.Code != http.StatusAccepted {
			t.Fatalf("an agent already queued = %d, want 202 even at the cap", w.Code)
		}
	})

	t.Run("bearer route: malformed ids are 400", func(t *testing.T) {
		q := openQ(t, "", 0, newClock())
		svc := NewService(q, nil)
		for name, id := range map[string]string{"129 chars": strings.Repeat("a", 129), "comma": "a,O=b", "NUL": "a\x00"} {
			if w := bearerEnqueue(svc, id); w.Code != http.StatusBadRequest {
				t.Errorf("%s: bearer enqueue = %d, want 400", name, w.Code)
			}
		}
	})
}

// --- revocation on the agent channel ---

// agentReq builds a poll/ack request the way nginx forwards it: the certificate DN
// and, when non-empty, the certificate serial (X-Client-Cert-Serial).
func agentReq(method, target, cn, serial, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("X-Client-Cert-DN", "CN="+cn+",O=suricatoos")
	if serial != "" {
		r.Header.Set("X-Client-Cert-Serial", serial)
	}
	return r
}

// revocationSvc returns a service whose CA has revoked exactly the given serials
// (compared verbatim, as the fake CA sees them), plus the lines it logs.
func revocationSvc(q *Queue, revoked ...string) (*Service, *[]string, *[]string) {
	set := map[string]bool{}
	for _, s := range revoked {
		set[s] = true
	}
	var asked, logs []string
	svc := NewService(q, nil).WithRevocationCheck(func(serial string) bool {
		asked = append(asked, serial)
		return set[serial]
	})
	svc.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	return svc, &asked, &logs
}

// A revoked certificate neither receives its agent's command nor acks it: 403, and
// the command stays PENDING (it then expires; it is never handed to the revoked cert).
func TestPollAndAckRefuseARevokedCertificate(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc, _, logs := revocationSvc(q, "0A1B2C")
	c := mustEnqueue(t, q, "agent-1")

	w := httptest.NewRecorder()
	svc.PollHandler()(w, agentReq("GET", "/commands", "agent-1", "0A1B2C", ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("poll with a revoked cert = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), c.ID) {
		t.Fatalf("the 403 handed the command out: %s", w.Body)
	}
	if st := only(t, q, "agent-1").State; st != StatePending {
		t.Fatalf("after a refused poll state = %s, want PENDING (not delivered)", st)
	}

	w = httptest.NewRecorder()
	svc.AckHandler()(w, agentReq("POST", "/commands/ack", "agent-1", "0A1B2C", `{"id":"`+c.ID+`"}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ack with a revoked cert = %d, want 403", w.Code)
	}
	if st := only(t, q, "agent-1").State; st != StatePending {
		t.Fatalf("after a refused ack state = %s, want PENDING (not acked)", st)
	}

	found := 0
	for _, l := range *logs {
		if strings.Contains(l, "agent-1") && strings.Contains(l, "0A1B2C") {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("want one log line per refusal naming the agent and the serial, got %q", *logs)
	}
}

// A certificate that was not revoked works exactly as before, and the CA is asked
// about the serial nginx forwarded.
func TestPollAndAckOfANonRevokedCertificateAreUnchanged(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc, asked, logs := revocationSvc(q, "DEAD")
	c := mustEnqueue(t, q, "agent-1")

	w := httptest.NewRecorder()
	svc.PollHandler()(w, agentReq("GET", "/commands", "agent-1", "0A1B2C", ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), c.ID) {
		t.Fatalf("poll = %d %s, want 200 with the command", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	svc.AckHandler()(w, agentReq("POST", "/commands/ack", "agent-1", "0A1B2C", `{"id":"`+c.ID+`"}`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("ack = %d, want 204", w.Code)
	}
	if st := only(t, q, "agent-1").State; st != StateAcked {
		t.Fatalf("state = %s, want ACKED", st)
	}
	w = httptest.NewRecorder()
	svc.PollHandler()(w, agentReq("GET", "/commands", "agent-1", "0A1B2C", ""))
	if w.Code != http.StatusNoContent {
		t.Fatalf("empty poll = %d, want 204", w.Code)
	}
	if strings.Join(*asked, ",") != "0A1B2C,0A1B2C,0A1B2C" {
		t.Fatalf("the CA was asked about %q, want the forwarded serial once per request", *asked)
	}
	if len(*logs) != 0 {
		t.Fatalf("a healthy agent produced log lines: %q", *logs)
	}
}

// An nginx that does not forward the serial yet (deploy transition): accepted, and
// logged once per agent — not once per poll, agents poll every minute.
func TestPollAndAckWithoutTheSerialAreAcceptedAndLoggedOncePerAgent(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	svc, asked, logs := revocationSvc(q, "0A1B2C")
	c := mustEnqueue(t, q, "agent-1")

	for i := range 3 {
		w := httptest.NewRecorder()
		svc.PollHandler()(w, agentReq("GET", "/commands", "agent-1", "", ""))
		if w.Code != http.StatusOK {
			t.Fatalf("poll #%d without a serial = %d, want 200", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	svc.AckHandler()(w, agentReq("POST", "/commands/ack", "agent-1", "", `{"id":"`+c.ID+`"}`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("ack without a serial = %d, want 204", w.Code)
	}
	w = httptest.NewRecorder()
	svc.PollHandler()(w, agentReq("GET", "/commands", "agent-2", "", ""))
	if w.Code != http.StatusNoContent {
		t.Fatalf("other agent's poll without a serial = %d, want 204", w.Code)
	}

	if len(*asked) != 0 {
		t.Fatalf("the CA was asked about %q with no serial forwarded", *asked)
	}
	if len(*logs) != 2 || !strings.Contains((*logs)[0], "agent-1") || !strings.Contains((*logs)[1], "agent-2") {
		t.Fatalf("want exactly one line per agent (agent-1, agent-2), got %q", *logs)
	}
}

// The queue defers to the enrollment rule for what an agent id may look like, so it
// can only ever hold ids a real agent could have; the one addition is UTF-8 validity,
// because the ids here come from URLs (not from JSON, which sanitizes them) and an
// invalid byte would not survive the round trip through the state file.
func TestAgentIDRuleIsTheEnrollmentRule(t *testing.T) {
	for _, id := range []string{
		"", "a", "agent-1", "srv-01.example_net", "Ünï-çode",
		strings.Repeat("a", 128), strings.Repeat("a", 129), strings.Repeat("é", 64), strings.Repeat("é", 65),
		"a,b", "a=b", "a+b", `a"b`, `a\b`, "a;b", "a<b", "a>b",
		"a\x00b", "a\x1fb", "a\x7fb", "a\nb", "a\tb", "a b", "a\xffb",
	} {
		want := enroll.ValidateAgentID(id) == nil && utf8.ValidString(id)
		if got := validAgentID(id); got != want {
			t.Errorf("validAgentID(%q) = %v, want %v (enrollment says %v)", id, got, want, enroll.ValidateAgentID(id))
		}
	}
}
