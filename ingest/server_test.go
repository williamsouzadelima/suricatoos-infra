package ingest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
