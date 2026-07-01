package command

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPollNoCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/commands" {
			t.Errorf("path = %q, want /v1/commands", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := Poll(context.Background(), srv.Client(), srv.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatalf("expected no command, got %+v", c)
	}
}

func TestPollScanNow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Command{ID: "abc123", Type: ScanNow})
	}))
	defer srv.Close()

	c, err := Poll(context.Background(), srv.Client(), srv.URL+"/v1/")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.ID != "abc123" || c.Type != ScanNow {
		t.Fatalf("Poll = %+v, want scan_now/abc123", c)
	}
}

func TestPollServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Poll(context.Background(), srv.Client(), srv.URL+"/v1"); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestAck(t *testing.T) {
	var gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/commands/ack" {
			t.Errorf("ack req = %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			ID string `json:"id"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		gotID = body.ID
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := Ack(context.Background(), srv.Client(), srv.URL+"/v1", "cmd-9"); err != nil {
		t.Fatal(err)
	}
	if gotID != "cmd-9" {
		t.Fatalf("acked id = %q, want cmd-9", gotID)
	}
}

func TestAckError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer srv.Close()
	if err := Ack(context.Background(), srv.Client(), srv.URL+"/v1", "x"); err == nil {
		t.Fatal("expected error on 400")
	}
}

func TestPollEmptyIDIsNoCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"","type":""}`)
	}))
	defer srv.Close()
	c, err := Poll(context.Background(), srv.Client(), srv.URL+"/v1")
	if err != nil || c != nil {
		t.Fatalf("empty id should be no command: c=%+v err=%v", c, err)
	}
}

func TestPollTrimsTrailingSlash(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, _ = Poll(context.Background(), srv.Client(), srv.URL+"/v1//")
	if strings.Contains(path, "//") {
		t.Errorf("double slash in path: %q", path)
	}
}
