package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
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
	svc := NewService(q)

	c1 := q.Enqueue("agent-1", CmdScanNow)
	clk.Advance(time.Minute)
	c2 := q.Enqueue("agent-1", CmdScanNow) // supersedes c1
	q.Poll("agent-1")
	clk.Advance(time.Minute)
	q.Ack("agent-1", c2.ID)
	clk.Advance(time.Minute)
	c3 := q.Enqueue("agent-1", CmdScanNow)
	q.Enqueue("agent-2", CmdScanNow) // another agent: must not leak into agent-1's history

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
	q.Enqueue("agent-1", CmdScanNow)
	svc := NewService(q)

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
	svc := NewService(q)

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
	if _, ok := q.Pending("agent-1"); ok {
		t.Fatal("a command was enqueued through an unauthenticated route")
	}
}

func TestHistoryHandlerEmptyAndValidation(t *testing.T) {
	svc := NewService(openQ(t, "", 0, newClock()))

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
	svc := NewService(q)
	c := q.Enqueue("agent-1", CmdScanNow)

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
	svc := NewService(q)

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
	svc1 := NewService(openQ(t, path, 0, clk))

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
	svc2 := NewService(openQ(t, path, 0, clk))
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
	svc := NewService(q)
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
	if _, ok := q.Pending("agent-1"); ok {
		t.Fatal("a command whose persist failed is still queued")
	}
	if h := q.History("agent-1"); len(h) != 0 {
		t.Fatalf("failed enqueues left history behind: %+v", h)
	}
}
