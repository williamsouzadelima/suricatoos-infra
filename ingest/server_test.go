package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url+"/v1/inventory", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestIngestAcceptsValidInventory(t *testing.T) {
	sink := &MemSink{}
	srv := httptest.NewServer(NewServer(sink).Handler())
	defer srv.Close()
	body := `{"schema_version":"1.0.0","agent":{"agent_id":"a1","hostname":"h"},"os":{"family":"linux","distro":"debian","release":"12"},"packages":[{"name":"x"}],"cycle_hash":"abc"}`
	resp := post(t, srv.URL, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d, want 202", resp.StatusCode)
	}
	if sink.Count() != 1 {
		t.Fatalf("count=%d, want 1", sink.Count())
	}
	last, _ := sink.Last()
	if last.Agent.AgentID != "a1" || last.OS.Family != "linux" {
		t.Fatalf("recebido errado: %+v", last)
	}
}

func TestIngestRejectsBadInput(t *testing.T) {
	sink := &MemSink{}
	srv := httptest.NewServer(NewServer(sink).Handler())
	defer srv.Close()
	cases := map[string]string{
		"json lixo":     `{`,
		"schema errada": `{"schema_version":"9.9.9","agent":{"agent_id":"a"},"os":{"family":"linux"}}`,
		"sem agent_id":  `{"schema_version":"1.0.0","agent":{},"os":{"family":"linux"}}`,
		"sem os.family": `{"schema_version":"1.0.0","agent":{"agent_id":"a"},"os":{}}`,
	}
	for name, body := range cases {
		resp := post(t, srv.URL, body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", name, resp.StatusCode)
		}
		resp.Body.Close()
	}
	if sink.Count() != 0 {
		t.Fatalf("nada inválido deveria ter sido aceito; count=%d", sink.Count())
	}
}

func getAgents(t *testing.T, url string, uiHeader bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url+"/agents", nil)
	if uiHeader {
		req.Header.Set("X-Suricatoos-UI", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAgentsRequiresUIHeader(t *testing.T) {
	srv := httptest.NewServer(NewServer(&MemSink{}).Handler())
	defer srv.Close()
	resp := getAgents(t, srv.URL, false) // no X-Suricatoos-UI → must be refused
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-header /agents = %d, want 403", resp.StatusCode)
	}
}

func TestAgentsMergesPostureAndStatus(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	s := NewServer(&MemSink{})
	s.now = func() time.Time { return now }
	s.onlineWindow = 35 * time.Minute
	s.queryAgents = func(context.Context) ([]byte, error) {
		return []byte(`[{"host":"fresh","severity":9.8},{"host":"stale","severity":0.0},{"host":"never","severity":5}]`), nil
	}
	s.lastSeen["fresh"] = now.Add(-10 * time.Minute) // within window → online
	s.lastSeen["stale"] = now.Add(-90 * time.Minute) // outside window → offline

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp := getAgents(t, srv.URL, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	byHost := map[string]map[string]any{}
	for _, a := range list {
		byHost[a["host"].(string)] = a
	}
	if got := byHost["fresh"]["status"]; got != "online" || byHost["fresh"]["online"] != true {
		t.Errorf("fresh status=%v online=%v, want online/true", got, byHost["fresh"]["online"])
	}
	if got := byHost["stale"]["status"]; got != "offline" || byHost["stale"]["online"] != false {
		t.Errorf("stale status=%v online=%v, want offline/false", got, byHost["stale"]["online"])
	}
	if got := byHost["never"]["status"]; got != "unknown" {
		t.Errorf("never status=%v, want unknown (no check-in seen)", got)
	}
	// posture from the query survives the merge
	if byHost["fresh"]["severity"].(float64) != 9.8 {
		t.Errorf("severity lost in merge: %v", byHost["fresh"]["severity"])
	}
}

func TestAgentsMarkSeenFromInventoryPost(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	s := NewServer(&MemSink{})
	s.now = func() time.Time { return now }
	s.queryAgents = func(context.Context) ([]byte, error) {
		return []byte(`[{"host":"a1"}]`), nil
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// before any report: unknown
	r1 := getAgents(t, srv.URL, true)
	var l1 []map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&l1)
	r1.Body.Close()
	if l1[0]["status"] != "unknown" {
		t.Fatalf("pre-report status=%v, want unknown", l1[0]["status"])
	}

	// a report from a1 marks it seen → online
	post(t, srv.URL, `{"schema_version":"1.0.0","agent":{"agent_id":"a1","hostname":"h"},"os":{"family":"linux"},"cycle_hash":"x"}`).Body.Close()
	r2 := getAgents(t, srv.URL, true)
	var l2 []map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&l2)
	r2.Body.Close()
	if l2[0]["status"] != "online" {
		t.Fatalf("post-report status=%v, want online", l2[0]["status"])
	}
}

func TestLastSeenPersistRoundTrip(t *testing.T) {
	path := t.TempDir() + "/lastseen.json"
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	t.Setenv("AGENT_LASTSEEN_FILE", path)

	s1 := NewServer(&MemSink{})
	s1.now = func() time.Time { return now }
	s1.markSeen("a1")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lastSeen file not written: %v", err)
	}
	// a fresh server (simulating a restart) restores the check-in
	s2 := NewServer(&MemSink{})
	if got, ok := s2.seen("a1"); !ok || !got.Equal(now) {
		t.Fatalf("restored lastSeen = %v ok=%v, want %v", got, ok, now)
	}
}
