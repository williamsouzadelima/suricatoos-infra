package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQueueEnqueuePendingAck(t *testing.T) {
	q := NewQueue()
	if _, ok := q.Pending("a"); ok {
		t.Fatal("empty queue should have no pending command")
	}
	c := q.Enqueue("a", CmdScanNow)
	if c.ID == "" || c.Type != CmdScanNow {
		t.Fatalf("bad command: %+v", c)
	}
	got, ok := q.Pending("a")
	if !ok || got.ID != c.ID {
		t.Fatalf("Pending = %+v ok=%v, want %s", got, ok, c.ID)
	}
	// a stale ack (wrong id) is a no-op
	if q.Ack("a", "wrong") {
		t.Fatal("ack with wrong id must not remove")
	}
	if _, ok := q.Pending("a"); !ok {
		t.Fatal("command should still be pending after a wrong-id ack")
	}
	// correct ack removes it
	if !q.Ack("a", c.ID) {
		t.Fatal("ack with the right id must remove")
	}
	if _, ok := q.Pending("a"); ok {
		t.Fatal("command should be gone after ack")
	}
}

func TestEnqueueSupersedes(t *testing.T) {
	q := NewQueue()
	c1 := q.Enqueue("a", CmdScanNow)
	c2 := q.Enqueue("a", CmdScanNow)
	got, _ := q.Pending("a")
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
	svc := NewService(q)

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
	enq := q.Enqueue("agent-1", CmdScanNow)
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
	svc := NewService(q)
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
	if _, ok := q.Pending("agent-1"); !ok {
		t.Fatal("enqueue should leave a pending command for agent-1")
	}
	// empty body defaults to scan_now
	q2 := NewQueue()
	h2 := NewService(q2).EnqueueHandler("s3cret")
	r := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	r.SetPathValue("id", "agent-9")
	r.Header.Set("Authorization", "Bearer s3cret")
	w2 := httptest.NewRecorder()
	h2(w2, r)
	if got, ok := q2.Pending("agent-9"); !ok || got.Type != CmdScanNow {
		t.Fatalf("empty body should default to scan_now: %+v ok=%v", got, ok)
	}
}
