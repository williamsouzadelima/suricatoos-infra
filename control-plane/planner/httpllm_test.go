package planner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPLLM_RequestShapeAndParse(t *testing.T) {
	var gotBody map[string]any
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"ok\"}"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	defer srv.Close()

	resp, err := NewHTTPLLM().Chat(context.Background(), ChatRequest{
		BaseURL: srv.URL, APIKey: "k", Model: "m",
		Messages: []ChatMessage{{Role: "system", Content: "s"}, {Role: "user", Content: "u"}},
		Schema:   planSchema,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if resp.Content != `{"summary":"ok"}` {
		t.Fatalf("content = %q", resp.Content)
	}
	if resp.Usage.PromptTokens != 10 || resp.Usage.CompletionTokens != 5 {
		t.Fatalf("usage = %+v", resp.Usage)
	}
	if gotAuth != "Bearer k" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
	// Claude 5: NO temperature.
	if _, ok := gotBody["temperature"]; ok {
		t.Fatal("NÃO pode enviar temperature (regra Claude 5)")
	}
	if _, ok := gotBody["response_format"]; !ok {
		t.Fatal("deveria pedir response_format (structured output)")
	}
	// No assistant prefill: only the two messages we passed.
	if msgs, _ := gotBody["messages"].([]any); len(msgs) != 2 {
		t.Fatalf("messages = %v (sem prefill = exatamente os enviados)", gotBody["messages"])
	}
}

func TestHTTPLLM_Non2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key"}`))
	}))
	defer srv.Close()
	if _, err := NewHTTPLLM().Chat(context.Background(), ChatRequest{BaseURL: srv.URL, APIKey: "k", Model: "m"}); err == nil {
		t.Fatal("401 do provedor deveria dar erro")
	}
}

func TestHTTPLLM_EmptyChoicesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[],"usage":{}}`))
	}))
	defer srv.Close()
	if _, err := NewHTTPLLM().Chat(context.Background(), ChatRequest{BaseURL: srv.URL, APIKey: "k", Model: "m"}); err == nil {
		t.Fatal("resposta sem choices deveria dar erro")
	}
}
