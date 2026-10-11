package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
)

// gatedReq builds a request the way nginx delivers it from a session-gated location:
// carrying the sessiongate marker header.
func gatedReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set(sessiongate.Header, sessiongate.Value)
	return r
}

func TestQueueEnqueuePendingAck(t *testing.T) {
	q := NewQueue()
	if _, ok := pending(q, "a"); ok {
		t.Fatal("empty queue should have no pending command")
	}
	c := mustEnqueue(t, q, "a")
	if c.ID == "" || c.Type != CmdScanNow {
		t.Fatalf("bad command: %+v", c)
	}
	got, ok := pending(q, "a")
	if !ok || got.ID != c.ID {
		t.Fatalf("Pending = %+v ok=%v, want %s", got, ok, c.ID)
	}
	// a stale ack (wrong id) is a no-op
	if q.Ack("a", "wrong") {
		t.Fatal("ack with wrong id must not remove")
	}
	if _, ok := pending(q, "a"); !ok {
		t.Fatal("command should still be pending after a wrong-id ack")
	}
	// correct ack removes it
	if !q.Ack("a", c.ID) {
		t.Fatal("ack with the right id must remove")
	}
	if _, ok := pending(q, "a"); ok {
		t.Fatal("command should be gone after ack")
	}
}

func TestEnqueueSupersedes(t *testing.T) {
	q := NewQueue()
	c1 := mustEnqueue(t, q, "a")
	c2 := mustEnqueue(t, q, "a")
	got, _ := pending(q, "a")
	if got.ID != c2.ID || got.ID == c1.ID {
		t.Fatalf("a fresh enqueue must supersede the previous: got %s, want %s", got.ID, c2.ID)
	}
}

func TestAgentCN(t *testing.T) {
	for dn, want := range map[string]string{
		"CN=ubuntu2404-prod,O=suricatoos":  "ubuntu2404-prod",
		"O=suricatoos,CN=agent-7":          "agent-7",
		"/O=suricatoos/CN=legacy-host":     "legacy-host",
		"emailAddress=x,CN=a.b-c_1,O=acme": "a.b-c_1",
		"O=suricatoos":                     "", // no CN
		"":                                 "",
	} {
		r := httptest.NewRequest("GET", "/commands", nil)
		if dn != "" {
			r.Header.Set("X-Client-Cert-DN", dn)
		}
		if got := agentCN(r); got != want {
			t.Errorf("agentCN(%q) = %q, want %q", dn, got, want)
		}
	}
}

func TestPollHandler(t *testing.T) {
	q := NewQueue()
	svc := NewService(q, nil)

	// no client cert -> 403
	r := httptest.NewRequest("GET", "/commands", nil)
	w := httptest.NewRecorder()
	svc.PollHandler()(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-cert poll = %d, want 403", w.Code)
	}

	// cert but no pending -> 204
	r = httptest.NewRequest("GET", "/commands", nil)
	r.Header.Set("X-Client-Cert-DN", "CN=agent-1,O=suricatoos")
	w = httptest.NewRecorder()
	svc.PollHandler()(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("empty poll = %d, want 204", w.Code)
	}

	// enqueue then poll -> 200 + the command
	enq := mustEnqueue(t, q, "agent-1")
	r = httptest.NewRequest("GET", "/commands", nil)
	r.Header.Set("X-Client-Cert-DN", "CN=agent-1,O=suricatoos")
	w = httptest.NewRecorder()
	svc.PollHandler()(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("poll = %d, want 200", w.Code)
	}
	var got Command
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil || got.ID != enq.ID || got.Type != CmdScanNow {
		t.Fatalf("poll body = %+v err=%v", got, err)
	}

	// another agent's cert must not see agent-1's command
	r = httptest.NewRequest("GET", "/commands", nil)
	r.Header.Set("X-Client-Cert-DN", "CN=agent-2,O=suricatoos")
	w = httptest.NewRecorder()
	svc.PollHandler()(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("other-agent poll = %d, want 204 (isolation)", w.Code)
	}
}

func TestEnqueueHandlerAuthAndType(t *testing.T) {
	q := NewQueue()
	svc := NewService(q, nil)
	h := svc.EnqueueHandler("s3cret")

	req := func(auth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/agents/agent-1/commands", strings.NewReader(body))
		r.SetPathValue("id", "agent-1")
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}

	if w := req("", `{"type":"scan_now"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth = %d, want 401", w.Code)
	}
	if w := req("Bearer wrong", `{"type":"scan_now"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong auth = %d, want 401", w.Code)
	}
	if w := req("Bearer s3cret", `{"type":"reboot"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown type = %d, want 400", w.Code)
	}
	w := req("Bearer s3cret", `{"type":"scan_now"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("valid enqueue = %d, want 202", w.Code)
	}
	if _, ok := pending(q, "agent-1"); !ok {
		t.Fatal("enqueue should leave a pending command for agent-1")
	}
	// empty body defaults to scan_now
	q2 := NewQueue()
	h2 := NewService(q2, nil).EnqueueHandler("s3cret")
	r := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	r.SetPathValue("id", "agent-9")
	r.Header.Set("Authorization", "Bearer s3cret")
	w2 := httptest.NewRecorder()
	h2(w2, r)
	if got, ok := pending(q2, "agent-9"); !ok || got.Type != CmdScanNow {
		t.Fatalf("empty body should default to scan_now: %+v ok=%v", got, ok)
	}
}

func TestSessionEnqueueHandler(t *testing.T) {
	q := NewQueue()
	h := NewService(q, nil).SessionEnqueueHandler()

	// no id -> 400
	w := httptest.NewRecorder()
	h(w, gatedReq("POST", "/agents/scan"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no id = %d, want 400", w.Code)
	}
	// valid id -> 202 + queued on the shared queue (no bearer; nginx gates)
	w = httptest.NewRecorder()
	h(w, gatedReq("POST", "/agents/scan?id=agent-7"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("valid = %d, want 202", w.Code)
	}
	if got, ok := pending(q, "agent-7"); !ok || got.Type != CmdScanNow {
		t.Fatalf("expected pending scan_now for agent-7: %+v ok=%v", got, ok)
	}
}

// Without the marker nginx sets only on session-gated locations, the handler must
// refuse and enqueue nothing (defense in depth: a location that lacks the gate must
// not be able to trigger scans).
func TestSessionEnqueueHandlerRequiresGate(t *testing.T) {
	q := NewQueue()
	h := NewService(q, nil).SessionEnqueueHandler()

	for _, gate := range []string{"", "1", "GSAD-SESSION"} {
		r := httptest.NewRequest("POST", "/agents/scan?id=agent-7", nil)
		if gate != "" {
			r.Header.Set(sessiongate.Header, gate)
		}
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("marker %q = %d, want 403", gate, w.Code)
		}
		if _, ok := pending(q, "agent-7"); ok {
			t.Fatalf("marker %q: a command was enqueued despite the 403", gate)
		}
	}

	// Positive control: the marker is the only difference.
	w := httptest.NewRecorder()
	h(w, gatedReq("POST", "/agents/scan?id=agent-7"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("with marker = %d, want 202", w.Code)
	}
}
