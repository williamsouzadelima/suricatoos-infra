package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClock is a controllable time source so TTL and timestamp assertions are exact.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
	return &testClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// openQ opens a queue on path ("" = in-memory) driven by clk. Calling it again on
// the same path simulates a control-plane restart.
func openQ(t *testing.T, path string, ttl time.Duration, clk *testClock) *Queue {
	t.Helper()
	q, err := Open(Config{Path: path, TTL: ttl})
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	q.now = clk.Now
	return q
}

// statePath returns a state-file path inside a fresh temp dir.
func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "commands.json")
}

// brokenDiskPath returns a state-file path whose directory the test can delete
// (breakDisk) to make every later save fail, on any OS.
func brokenDiskPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "commands.json")
}

func breakDisk(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}

// readState parses the on-disk state file.
func readState(t *testing.T, path string) fileFormat {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler %s: %v", path, err)
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("estado em disco não é JSON válido: %v\n%s", err, b)
	}
	return f
}

// only returns agent's single history entry, failing unless there is exactly one.
func only(t *testing.T, q *Queue, agent string) Record {
	t.Helper()
	h := q.History(agent)
	if len(h) != 1 {
		t.Fatalf("History(%q) has %d entries, want 1: %+v", agent, len(h), h)
	}
	return h[0]
}

// logSink collects what the queue logs, for single-goroutine tests.
type logSink struct{ lines []string }

func (l *logSink) logf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func TestLifecyclePendingDeliveredAcked(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", 0, clk)
	created := clk.Now()
	c := q.Enqueue("a", CmdScanNow)

	rec := only(t, q, "a")
	if rec.ID != c.ID || rec.Type != CmdScanNow || rec.State != StatePending || !rec.CreatedAt.Equal(created) {
		t.Fatalf("fresh record = %+v, want PENDING %s created %s", rec, c.ID, created)
	}
	if !rec.DeliveredAt.IsZero() || !rec.AckedAt.IsZero() {
		t.Fatalf("fresh record must carry no delivery/ack time: %+v", rec)
	}

	// Pending is a peek: looking must not count as delivering.
	if _, ok := q.Pending("a"); !ok {
		t.Fatal("Pending lost the command")
	}
	if got := only(t, q, "a").State; got != StatePending {
		t.Fatalf("Pending changed the state to %s", got)
	}

	// The agent polls: PENDING -> DELIVERED.
	clk.Advance(time.Minute)
	delivered := clk.Now()
	got, ok := q.Poll("a")
	if !ok || got.ID != c.ID || got.Type != CmdScanNow || !got.CreatedAt.Equal(created) {
		t.Fatalf("Poll = %+v ok=%v, want the enqueued command %s", got, ok, c.ID)
	}
	rec = only(t, q, "a")
	if rec.State != StateDelivered || !rec.DeliveredAt.Equal(delivered) {
		t.Fatalf("after Poll record = %+v, want DELIVERED at %s", rec, delivered)
	}

	// The agent acks: DELIVERED -> ACKED.
	clk.Advance(time.Minute)
	if !q.Ack("a", c.ID) {
		t.Fatal("Ack with the right id must succeed")
	}
	rec = only(t, q, "a")
	if rec.State != StateAcked || !rec.AckedAt.Equal(clk.Now()) || !rec.DeliveredAt.Equal(delivered) {
		t.Fatalf("after Ack record = %+v, want ACKED at %s (delivered %s kept)", rec, clk.Now(), delivered)
	}
	if !rec.UpdatedAt.Equal(clk.Now()) {
		t.Fatalf("UpdatedAt = %s, want the ack time %s", rec.UpdatedAt, clk.Now())
	}

	// Nothing left to hand out.
	if _, ok := q.Poll("a"); ok {
		t.Fatal("an acked command must not be delivered again")
	}
	if _, ok := q.Pending("a"); ok {
		t.Fatal("an acked command is no longer pending")
	}
}

func TestDeliveredIsRedeliveredUntilAcked(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", 0, clk)
	c := q.Enqueue("a", CmdScanNow)

	first := clk.Now()
	if _, ok := q.Poll("a"); !ok {
		t.Fatal("first poll must deliver")
	}
	// The agent crashed before acking: the next poll hands the same command out
	// again (this is how the in-memory queue always behaved).
	clk.Advance(5 * time.Minute)
	got, ok := q.Poll("a")
	if !ok || got.ID != c.ID {
		t.Fatalf("second poll = %+v ok=%v, want %s again", got, ok, c.ID)
	}
	if rec := only(t, q, "a"); rec.State != StateDelivered || !rec.DeliveredAt.Equal(first) {
		t.Fatalf("record = %+v, want DELIVERED with the FIRST delivery time %s", rec, first)
	}
}

func TestAckIsNoopForStaleUnknownAndRepeated(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", 0, clk)
	c := q.Enqueue("a", CmdScanNow)
	q.Poll("a")

	if q.Ack("a", "not-the-id") {
		t.Fatal("ack with a wrong id must be a no-op")
	}
	if q.Ack("nobody", c.ID) {
		t.Fatal("ack for an agent that has no command must be a no-op")
	}
	if q.Ack("other-agent", c.ID) {
		t.Fatal("an agent must not be able to ack another agent's command")
	}
	if got := only(t, q, "a").State; got != StateDelivered {
		t.Fatalf("no-op acks changed the state to %s", got)
	}

	if !q.Ack("a", c.ID) {
		t.Fatal("the right ack must succeed")
	}
	acked := only(t, q, "a")
	clk.Advance(time.Hour)
	if q.Ack("a", c.ID) {
		t.Fatal("a repeated ack must be a no-op")
	}
	if again := only(t, q, "a"); again.State != StateAcked || !again.AckedAt.Equal(acked.AckedAt) {
		t.Fatalf("a repeated ack rewrote the record: %+v -> %+v", acked, again)
	}
}

func TestNewRequestSupersedesTheLiveCommand(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", 0, clk)
	c1 := q.Enqueue("a", CmdScanNow)
	q.Poll("a") // c1 is DELIVERED and still unacked

	clk.Advance(time.Minute)
	c2 := q.Enqueue("a", CmdScanNow)

	h := q.History("a")
	if len(h) != 2 || h[0].ID != c2.ID || h[1].ID != c1.ID {
		t.Fatalf("history = %+v, want [c2, c1]", h)
	}
	if h[0].State != StatePending {
		t.Fatalf("new command state = %s, want PENDING", h[0].State)
	}
	if h[1].State != StateSuperseded || !h[1].UpdatedAt.Equal(clk.Now()) {
		t.Fatalf("old command = %+v, want SUPERSEDED at %s", h[1], clk.Now())
	}
	if h[1].DeliveredAt.IsZero() {
		t.Fatal("superseding must keep the old command's delivery time")
	}

	// Only the new command is deliverable.
	if got, ok := q.Pending("a"); !ok || got.ID != c2.ID {
		t.Fatalf("Pending = %+v ok=%v, want %s", got, ok, c2.ID)
	}
	if got, ok := q.Poll("a"); !ok || got.ID != c2.ID {
		t.Fatalf("Poll = %+v ok=%v, want %s", got, ok, c2.ID)
	}
	// A late ack of the superseded command must neither resurrect it nor ack the new one.
	if q.Ack("a", c1.ID) {
		t.Fatal("a stale ack of a superseded command must be a no-op")
	}
	h = q.History("a")
	if h[0].State != StateDelivered || h[1].State != StateSuperseded {
		t.Fatalf("states after the stale ack = %s/%s, want DELIVERED/SUPERSEDED", h[0].State, h[1].State)
	}
}

func TestSupersedingNeverDeliveredCommand(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	c1 := q.Enqueue("a", CmdScanNow)
	c2 := q.Enqueue("a", CmdScanNow)
	h := q.History("a")
	if len(h) != 2 || h[1].ID != c1.ID || h[1].State != StateSuperseded || !h[1].DeliveredAt.IsZero() {
		t.Fatalf("history = %+v, want c1 SUPERSEDED without a delivery time", h)
	}
	if h[0].ID != c2.ID || h[0].State != StatePending {
		t.Fatalf("history[0] = %+v, want c2 PENDING", h[0])
	}
}

func TestExpiredCommandIsNotDelivered(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", time.Hour, clk)
	created := clk.Now()
	c := q.Enqueue("a", CmdScanNow)

	// Exactly at the TTL it is not yet "older than" it.
	clk.Advance(time.Hour)
	if _, ok := q.Pending("a"); !ok {
		t.Fatal("a command exactly at the TTL must still be live")
	}

	clk.Advance(time.Nanosecond)
	if got, ok := q.Poll("a"); ok {
		t.Fatalf("an expired command was delivered: %+v", got)
	}
	if _, ok := q.Pending("a"); ok {
		t.Fatal("an expired command must not be pending")
	}
	rec := only(t, q, "a")
	if rec.State != StateExpired || !rec.UpdatedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("record = %+v, want EXPIRED stamped at its deadline %s", rec, created.Add(time.Hour))
	}
	if q.Ack("a", c.ID) {
		t.Fatal("an expired command can no longer be acked")
	}
	if got := only(t, q, "a").State; got != StateExpired {
		t.Fatalf("late ack revived the command: %s", got)
	}
}

func TestDeliveredCommandAlsoExpires(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", time.Hour, clk)
	q.Enqueue("a", CmdScanNow)

	clk.Advance(10 * time.Minute)
	delivered := clk.Now()
	if _, ok := q.Poll("a"); !ok {
		t.Fatal("poll within the TTL must deliver")
	}
	clk.Advance(51 * time.Minute) // 61 minutes after creation
	if got, ok := q.Poll("a"); ok {
		t.Fatalf("a DELIVERED command past the TTL was handed out again: %+v", got)
	}
	rec := only(t, q, "a")
	if rec.State != StateExpired || !rec.DeliveredAt.Equal(delivered) {
		t.Fatalf("record = %+v, want EXPIRED keeping its delivery time %s", rec, delivered)
	}
}

// Expiry is lazy, so whichever call touches the agent first after the deadline must
// notice it and record it, not just Poll.
func TestEveryEntryPointNoticesExpiry(t *testing.T) {
	for name, touch := range map[string]func(t *testing.T, q *Queue, id string){
		"Poll": func(t *testing.T, q *Queue, id string) {
			if got, ok := q.Poll("a"); ok {
				t.Fatalf("Poll delivered an expired command: %+v", got)
			}
		},
		"Pending": func(t *testing.T, q *Queue, id string) {
			if got, ok := q.Pending("a"); ok {
				t.Fatalf("Pending reported an expired command: %+v", got)
			}
		},
		"Ack": func(t *testing.T, q *Queue, id string) {
			if q.Ack("a", id) {
				t.Fatal("Ack accepted an expired command")
			}
		},
		"History": func(t *testing.T, q *Queue, id string) {
			if h := q.History("a"); len(h) != 1 || h[0].State != StateExpired {
				t.Fatalf("History = %+v, want the command as EXPIRED", h)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := statePath(t)
			clk := newClock()
			q := openQ(t, path, time.Hour, clk)
			c := q.Enqueue("a", CmdScanNow)
			clk.Advance(2 * time.Hour)

			touch(t, q, c.ID) // the FIRST call since the deadline

			if got := only(t, q, "a").State; got != StateExpired {
				t.Fatalf("state = %s, want EXPIRED", got)
			}
			if disk := readState(t, path).Agents["a"]; len(disk) != 1 || disk[0].State != StateExpired {
				t.Fatalf("the expiry was not written to disk: %+v", disk)
			}
		})
	}
}

func TestExpiredCommandIsNotReportedAsSuperseded(t *testing.T) {
	clk := newClock()
	q := openQ(t, "", time.Hour, clk)
	c1 := q.Enqueue("a", CmdScanNow)
	clk.Advance(2 * time.Hour)
	c2 := q.Enqueue("a", CmdScanNow)

	h := q.History("a")
	if len(h) != 2 || h[1].ID != c1.ID || h[1].State != StateExpired {
		t.Fatalf("history = %+v, want c1 EXPIRED (it died of age, not of replacement)", h)
	}
	if h[0].ID != c2.ID || h[0].State != StatePending {
		t.Fatalf("history[0] = %+v, want c2 PENDING", h[0])
	}
}

func TestDefaultTTLIsTwentyFourHours(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after time.Duration
		live  bool
	}{
		{"23h59m", 24*time.Hour - time.Minute, true},
		{"24h01m", 24*time.Hour + time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			q := openQ(t, "", 0, clk) // TTL 0 -> default
			q.Enqueue("a", CmdScanNow)
			clk.Advance(tc.after)
			if _, ok := q.Poll("a"); ok != tc.live {
				t.Fatalf("Poll after %s delivered=%v, want %v", tc.after, ok, tc.live)
			}
		})
	}
}

func TestHistoryIsCappedAndNewestFirst(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q := openQ(t, path, 0, clk)

	n := HistoryLimit + 5
	ids := make([]string, n)
	for i := range n {
		clk.Advance(time.Second)
		ids[i] = q.Enqueue("a", CmdScanNow).ID
	}
	other := q.Enqueue("b", CmdScanNow)

	h := q.History("a")
	if len(h) != HistoryLimit {
		t.Fatalf("history has %d entries, want the cap %d", len(h), HistoryLimit)
	}
	for i, rec := range h {
		if want := ids[n-1-i]; rec.ID != want {
			t.Fatalf("history[%d] = %s, want %s (newest first)", i, rec.ID, want)
		}
		if i > 0 && !rec.CreatedAt.Before(h[i-1].CreatedAt) {
			t.Fatalf("history is not strictly newest-first at %d", i)
		}
		wantState := StateSuperseded
		if i == 0 {
			wantState = StatePending
		}
		if rec.State != wantState {
			t.Fatalf("history[%d].State = %s, want %s", i, rec.State, wantState)
		}
	}
	// The cap is per agent.
	if hb := q.History("b"); len(hb) != 1 || hb[0].ID != other.ID {
		t.Fatalf("another agent's history was disturbed: %+v", hb)
	}
	// The file is capped too, not just the view.
	if got := len(readState(t, path).Agents["a"]); got != HistoryLimit {
		t.Fatalf("state file keeps %d records for the agent, want %d", got, HistoryLimit)
	}
}

func TestHistoryOfUnknownAgentIsEmptyNotNil(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	h := q.History("nobody")
	if h == nil || len(h) != 0 {
		t.Fatalf("History(unknown) = %#v, want an empty non-nil slice (JSON [] not null)", h)
	}
}

func TestHistoryReturnsACopy(t *testing.T) {
	q := openQ(t, "", 0, newClock())
	c := q.Enqueue("a", CmdScanNow)
	h := q.History("a")
	h[0].ID = "tampered"
	h[0].State = StateAcked
	if rec := only(t, q, "a"); rec.ID != c.ID || rec.State != StatePending {
		t.Fatalf("mutating a returned history changed the queue: %+v", rec)
	}
}

func TestInMemoryQueueWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for name, q := range map[string]*Queue{"NewQueue": NewQueue(), "Open(empty)": openQ(t, "", 0, newClock())} {
		c, err := q.EnqueueDurable("a", CmdScanNow)
		if err != nil {
			t.Fatalf("%s: an in-memory queue has nothing to persist, EnqueueDurable failed: %v", name, err)
		}
		q.Poll("a")
		q.Ack("a", c.ID)
		q.History("a")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("an in-memory queue wrote files: %v", entries)
	}
}

// --- durability ---

func TestDurableEnqueueSurvivesRestart(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q1 := openQ(t, path, 0, clk)
	c, err := q1.EnqueueDurable("agent-1", CmdScanNow)
	if err != nil {
		t.Fatal(err)
	}

	q2 := openQ(t, path, 0, clk) // control-plane restart
	got, ok := q2.Pending("agent-1")
	if !ok || got.ID != c.ID || got.Type != c.Type || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("after restart Pending = %+v ok=%v, want %+v", got, ok, c)
	}
	// ...and the agent still receives it.
	if polled, ok := q2.Poll("agent-1"); !ok || polled.ID != c.ID {
		t.Fatalf("after restart Poll = %+v ok=%v, want %s", polled, ok, c.ID)
	}
}

func TestDurableLifecycleSurvivesRestart(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q1 := openQ(t, path, 0, clk)
	c := q1.Enqueue("a", CmdScanNow)
	clk.Advance(time.Minute)
	delivered := clk.Now()
	q1.Poll("a")

	q2 := openQ(t, path, 0, clk)
	rec := only(t, q2, "a")
	if rec.State != StateDelivered || !rec.DeliveredAt.Equal(delivered) {
		t.Fatalf("after restart record = %+v, want DELIVERED at %s", rec, delivered)
	}
	if got, ok := q2.Poll("a"); !ok || got.ID != c.ID {
		t.Fatalf("a DELIVERED-but-unacked command must be redelivered after a restart: %+v ok=%v", got, ok)
	}

	clk.Advance(time.Minute)
	if !q2.Ack("a", c.ID) {
		t.Fatal("ack after restart must work")
	}
	q3 := openQ(t, path, 0, clk)
	rec = only(t, q3, "a")
	if rec.State != StateAcked || !rec.AckedAt.Equal(clk.Now()) || !rec.DeliveredAt.Equal(delivered) {
		t.Fatalf("after second restart record = %+v, want ACKED at %s", rec, clk.Now())
	}
	if _, ok := q3.Pending("a"); ok {
		t.Fatal("an acked command came back after a restart")
	}
}

func TestDurableSupersededAndExpiredAreRecordedOnDisk(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q := openQ(t, path, time.Hour, clk)
	c1 := q.Enqueue("a", CmdScanNow)
	c2 := q.Enqueue("a", CmdScanNow) // supersedes c1
	c3 := q.Enqueue("b", CmdScanNow)

	disk := readState(t, path).Agents
	if len(disk["a"]) != 2 || disk["a"][0].ID != c1.ID || disk["a"][0].State != StateSuperseded ||
		disk["a"][1].ID != c2.ID || disk["a"][1].State != StatePending {
		t.Fatalf("disk history for a = %+v, want [c1 SUPERSEDED, c2 PENDING]", disk["a"])
	}

	clk.Advance(2 * time.Hour)
	if _, ok := q.Poll("b"); ok {
		t.Fatal("expired command delivered")
	}
	disk = readState(t, path).Agents
	if len(disk["b"]) != 1 || disk["b"][0].ID != c3.ID || disk["b"][0].State != StateExpired {
		t.Fatalf("the expiry was not written to disk: %+v", disk["b"])
	}
}

func TestDurableFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	path := statePath(t)
	q := openQ(t, path, 0, newClock())
	q.Enqueue("a", CmdScanNow)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode = %o, want 600", perm)
	}
}

func TestSaveIsAtomicAndLeavesNoTempFile(t *testing.T) {
	path := statePath(t)
	q := openQ(t, path, 0, newClock())
	c := q.Enqueue("a", CmdScanNow)
	q.Poll("a")
	q.Ack("a", c.ID)
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind after saves (err=%v)", err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("state directory = %v, want only the state file", entries)
	}
}

func TestStaleTempFileFromACrashIsIgnored(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q1 := openQ(t, path, 0, clk)
	c := q1.Enqueue("a", CmdScanNow)

	// A crash between writing the temp file and renaming it leaves garbage next to
	// the real state; the real state must win and the next save must still work.
	if err := os.WriteFile(path+".tmp", []byte(`{"version":1,"agen`), 0o644); err != nil {
		t.Fatal(err)
	}
	q2 := openQ(t, path, 0, clk)
	if got, ok := q2.Pending("a"); !ok || got.ID != c.ID {
		t.Fatalf("stale temp file broke the load: %+v ok=%v", got, ok)
	}
	q2.Enqueue("a", CmdScanNow)
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("stale temp file survived the next save (err=%v)", err)
	}
	if len(readState(t, path).Agents["a"]) != 2 {
		t.Fatal("the next save did not land")
	}
}

func TestOpenRefusesACorruptStateFile(t *testing.T) {
	valid := `{"version":1,"agents":{"a":[{"id":"x","type":"scan_now","created_at":"2026-10-11T12:00:00Z","state":"PENDING","updated_at":"2026-10-11T12:00:00Z"}]}}`

	// Positive control: the fixture itself loads, so the failures below are caused
	// by the damage and not by a typo in the fixture.
	okPath := statePath(t)
	if err := os.WriteFile(okPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Path: okPath})
	if err != nil {
		t.Fatalf("the valid fixture must load: %v", err)
	}
	if got, ok := q.Pending("a"); !ok || got.ID != "x" {
		t.Fatalf("fixture not loaded: %+v ok=%v", got, ok)
	}

	for _, tc := range []struct{ name, content string }{
		{"not json", "this is not json"},
		{"truncated mid-write", valid[:len(valid)/2]},
		{"empty file", ""},
		{"wrong shape", `[1,2,3]`},
		{"json null", `null`},
		{"missing version", strings.Replace(valid, `"version":1,`, "", 1)},
		{"unsupported version", strings.Replace(valid, `"version":1`, `"version":99`, 1)},
		{"unknown state", strings.Replace(valid, "PENDING", "LOST", 1)},
		{"record without id", strings.Replace(valid, `"id":"x"`, `"id":""`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := statePath(t)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			q, err := Open(Config{Path: path})
			if err == nil {
				t.Fatalf("Open accepted a corrupt state file (queue=%v)", q)
			}
			if q != nil {
				t.Fatal("Open must not return a queue together with an error")
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("the error must name the file so the operator can find it: %v", err)
			}
			// Never destroy the evidence: the damaged file is left untouched.
			if b, _ := os.ReadFile(path); string(b) != tc.content {
				t.Fatalf("Open rewrote a corrupt file: %q", b)
			}
		})
	}
}

func TestOpenCreatesTheFileAndFailsFastOnABadPath(t *testing.T) {
	path := statePath(t)
	openQ(t, path, 0, newClock())
	// Creating the file at boot proves the path is writable BEFORE the first request.
	if f := readState(t, path); f.Version != fileVersion || len(f.Agents) != 0 {
		t.Fatalf("fresh state file = %+v, want an empty v%d state", f, fileVersion)
	}

	bad := filepath.Join(t.TempDir(), "no-such-dir", "commands.json")
	q, err := Open(Config{Path: bad})
	if err == nil {
		t.Fatalf("Open on an unwritable path must fail at boot (queue=%v)", q)
	}
	if !strings.Contains(err.Error(), bad) {
		t.Fatalf("the error must name the path: %v", err)
	}
}

func TestEnqueueDurableRollsBackWhenTheSaveFails(t *testing.T) {
	path := brokenDiskPath(t)
	clk := newClock()
	q := openQ(t, path, 0, clk)
	c1, err := q.EnqueueDurable("a", CmdScanNow)
	if err != nil {
		t.Fatal(err)
	}
	q.Poll("a")
	before := q.History("a")

	breakDisk(t, path)
	clk.Advance(time.Minute)
	c2, err := q.EnqueueDurable("a", CmdScanNow)
	if err == nil {
		t.Fatalf("EnqueueDurable reported success although nothing was persisted (%+v)", c2)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("the error must name the file: %v", err)
	}

	// Memory and disk must agree: the failed request left no trace.
	after := q.History("a")
	if b, a := mustJSON(t, before), mustJSON(t, after); b != a {
		t.Fatalf("a failed enqueue changed the queue:\nbefore %s\nafter  %s", b, a)
	}
	if got, ok := q.Pending("a"); !ok || got.ID != c1.ID {
		t.Fatalf("the previous command must stay live, got %+v ok=%v", got, ok)
	}
	// A failed enqueue for a brand-new agent must not leave an empty entry either.
	if _, err := q.EnqueueDurable("fresh", CmdScanNow); err == nil {
		t.Fatal("expected a save failure for the new agent as well")
	}
	if h := q.History("fresh"); len(h) != 0 {
		t.Fatalf("failed enqueue left history behind: %+v", h)
	}

	// The disk comes back: the queue carries on, and the file holds the rolled-back
	// history plus the new command — nothing of the failed requests.
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	c3, err := q.EnqueueDurable("a", CmdScanNow)
	if err != nil {
		t.Fatalf("EnqueueDurable after the disk recovered: %v", err)
	}
	disk := readState(t, path).Agents
	if _, ghost := disk["fresh"]; ghost {
		t.Fatalf("a rolled-back agent leaked into the state file: %+v", disk["fresh"])
	}
	if len(disk["a"]) != 2 || disk["a"][0].ID != c1.ID || disk["a"][0].State != StateSuperseded ||
		disk["a"][1].ID != c3.ID || disk["a"][1].State != StatePending {
		t.Fatalf("state file for a = %+v, want [c1 SUPERSEDED, c3 PENDING] (c2 never existed)", disk["a"])
	}
}

func TestAFailedSaveLeavesNoTempFile(t *testing.T) {
	path := statePath(t)
	q := openQ(t, path, 0, newClock())
	// Replace the state file by a directory so the final rename cannot succeed, after
	// the temp file has been written.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := q.EnqueueDurable("a", CmdScanNow); err == nil {
		t.Fatal("the save should have failed")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind after a failed save (err=%v)", err)
	}
}

func TestLegacyEnqueueKeepsTheCommandInMemoryWhenTheSaveFails(t *testing.T) {
	path := brokenDiskPath(t)
	q := openQ(t, path, 0, newClock())
	sink := &logSink{}
	q.logf = sink.logf

	breakDisk(t, path)
	c := q.Enqueue("a", CmdScanNow) // the infallible form: best effort
	if c.ID == "" {
		t.Fatal("Enqueue returned an empty command")
	}
	if got, ok := q.Poll("a"); !ok || got.ID != c.ID {
		t.Fatalf("the command must still be deliverable from memory: %+v ok=%v", got, ok)
	}
	if len(sink.lines) == 0 || !strings.Contains(sink.lines[0], path) {
		t.Fatalf("the failed save must be logged with the path, got %q", sink.lines)
	}
}

func TestPollAndAckSurviveASaveFailureAndLogIt(t *testing.T) {
	path := brokenDiskPath(t)
	q := openQ(t, path, 0, newClock())
	c := q.Enqueue("a", CmdScanNow)
	sink := &logSink{}
	q.logf = sink.logf

	breakDisk(t, path)
	// scan_now is idempotent, so delivering although the DELIVERED mark could not
	// be persisted is safe (worst case after a restart: it is handed out again).
	if got, ok := q.Poll("a"); !ok || got.ID != c.ID {
		t.Fatalf("Poll must still deliver: %+v ok=%v", got, ok)
	}
	if got := only(t, q, "a").State; got != StateDelivered {
		t.Fatalf("in-memory state = %s, want DELIVERED", got)
	}
	if !q.Ack("a", c.ID) {
		t.Fatal("Ack must still work")
	}
	if got := only(t, q, "a").State; got != StateAcked {
		t.Fatalf("in-memory state = %s, want ACKED", got)
	}
	if len(sink.lines) != 2 {
		t.Fatalf("each failed save must be logged (poll + ack), got %d lines: %q", len(sink.lines), sink.lines)
	}
}

func TestConcurrentUseKeepsMemoryAndFileConsistent(t *testing.T) {
	path := statePath(t)
	clk := newClock()
	q := openQ(t, path, time.Hour, clk)
	agents := []string{"a", "b", "c"}

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 30 {
				agent := agents[(w+i)%len(agents)]
				switch i % 4 {
				case 0:
					if _, err := q.EnqueueDurable(agent, CmdScanNow); err != nil {
						t.Errorf("EnqueueDurable: %v", err)
					}
				case 1:
					q.Poll(agent)
				case 2:
					if c, ok := q.Pending(agent); ok {
						q.Ack(agent, c.ID)
					}
				default:
					_ = q.History(agent)
				}
			}
		}()
	}
	wg.Wait()

	// Invariant: at most one live command per agent, and it is the newest.
	for _, agent := range agents {
		live := 0
		for i, rec := range q.History(agent) {
			if rec.State == StatePending || rec.State == StateDelivered {
				live++
				if i != 0 {
					t.Errorf("agent %s: live command %s is not the newest record", agent, rec.ID)
				}
			}
		}
		if live > 1 {
			t.Errorf("agent %s has %d live commands, want at most 1", agent, live)
		}
	}
	// What a restart would load is exactly what memory holds.
	reopened := openQ(t, path, time.Hour, clk)
	for _, agent := range agents {
		if mem, disk := mustJSON(t, q.History(agent)), mustJSON(t, reopened.History(agent)); mem != disk {
			t.Errorf("agent %s: memory and disk diverged\nmemory %s\ndisk   %s", agent, mem, disk)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
