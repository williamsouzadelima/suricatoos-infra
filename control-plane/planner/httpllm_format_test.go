package planner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// rfType is the response_format type a request asked for ("none" when absent).
func rfType(body map[string]any) string {
	rf, ok := body["response_format"].(map[string]any)
	if !ok {
		return "none"
	}
	t, _ := rf["type"].(string)
	return t
}

type answer struct {
	status int
	body   string
}

// formatServer answers according to the response_format type of each request and
// records every request body, in order.
func formatServer(t *testing.T, answers map[string]answer) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		seen = append(seen, body)
		mu.Unlock()
		a, ok := answers[rfType(body)]
		if !ok {
			t.Errorf("tipo de response_format inesperado: %q", rfType(body))
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), seen...)
	}
}

const okChat = `{"choices":[{"message":{"content":"{\"summary\":\"ok\"}"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`

func chatReq(base string) ChatRequest {
	return ChatRequest{
		BaseURL: base, APIKey: "k", Model: "m",
		Messages: []ChatMessage{{Role: "system", Content: "sistema"}, {Role: "user", Content: "usuário"}},
		Schema:   planSchema,
	}
}

func types(seen []map[string]any) string {
	var out []string
	for _, b := range seen {
		out = append(out, rfType(b))
	}
	return strings.Join(out, ",")
}

// systemContent returns the system message content a request carried.
func systemContent(t *testing.T, body map[string]any) string {
	t.Helper()
	msgs, _ := body["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if mm["role"] == "system" {
			s, _ := mm["content"].(string)
			return s
		}
	}
	t.Fatalf("sem mensagem de sistema: %v", body["messages"])
	return ""
}

// assertClaude5 checks every attempt: NO temperature, NO prefill (exactly the
// system + user messages, never an assistant turn).
func assertClaude5(t *testing.T, seen []map[string]any) {
	t.Helper()
	for i, b := range seen {
		if _, ok := b["temperature"]; ok {
			t.Fatalf("tentativa %d enviou temperature (regra Claude 5)", i+1)
		}
		msgs, _ := b["messages"].([]any)
		if len(msgs) != 2 {
			t.Fatalf("tentativa %d: %d mensagens (sem prefill = exatamente system+user)", i+1, len(msgs))
		}
		for _, m := range msgs {
			if mm, _ := m.(map[string]any); mm["role"] == "assistant" {
				t.Fatalf("tentativa %d enviou prefill de assistant", i+1)
			}
		}
	}
}

func TestHTTPLLM_FallsBackToJSONObjectOn400(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {400, `{"error":{"message":"This model does not support response_format of type json_schema","code":400}}`},
		"json_object": {200, okChat},
	})
	resp, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if resp.Content != `{"summary":"ok"}` {
		t.Fatalf("content = %q", resp.Content)
	}
	s := seen()
	if got := types(s); got != "json_schema,json_object" {
		t.Fatalf("tentativas = %s", got)
	}
	assertClaude5(t, s)
	// Without json_schema in response_format, the schema goes in the system prompt
	// (otherwise the model cannot know the fields parseDraft requires) ...
	if sys := systemContent(t, s[1]); !strings.Contains(sys, string(planSchema)) || !strings.HasPrefix(sys, "sistema") {
		t.Fatalf("a tentativa json_object deveria levar o schema no prompt de sistema: %q", sys)
	}
	// ... while the json_schema attempt keeps the prompt untouched.
	if sys := systemContent(t, s[0]); sys != "sistema" {
		t.Fatalf("a tentativa json_schema não deveria mexer no prompt: %q", sys)
	}
}

func TestHTTPLLM_FallsBackToNoResponseFormat(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {400, `{"error":{"message":"Structured outputs are not supported by this provider"}}`},
		"json_object": {400, `{"error":{"message":"Response format json_object is not supported"}}`},
		"none":        {200, okChat},
	})
	resp, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if resp.Content != `{"summary":"ok"}` {
		t.Fatalf("content = %q", resp.Content)
	}
	s := seen()
	if got := types(s); got != "json_schema,json_object,none" {
		t.Fatalf("tentativas = %s", got)
	}
	assertClaude5(t, s)
	if _, ok := s[2]["response_format"]; ok {
		t.Fatal("a 3ª tentativa não deveria mandar response_format")
	}
	if sys := systemContent(t, s[2]); !strings.Contains(sys, string(planSchema)) {
		t.Fatalf("a tentativa sem response_format deveria levar o schema no prompt: %q", sys)
	}
}

func TestHTTPLLM_No400FallbackWhenNotAboutFormat(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {400, `{"error":{"message":"model not found: m"}}`},
	})
	_, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("esperava StatusError 400, veio %v", err)
	}
	if n := len(seen()); n != 1 {
		t.Fatalf("400 que não cita o formato não re-tenta: %d tentativa(s)", n)
	}
}

func TestHTTPLLM_OnlyA400TriggersTheFormatFallback(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {422, `{"error":{"message":"response_format json_schema invalid"}}`},
	})
	if _, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL)); err == nil {
		t.Fatal("422 deveria dar erro")
	}
	if n := len(seen()); n != 1 {
		t.Fatalf("só um 400 dispara o fallback de formato: %d tentativa(s)", n)
	}
}

func TestHTTPLLM_GivesUpAfterTheThreeFormats(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {400, `{"error":"json_schema unsupported"}`},
		"json_object": {400, `{"error":"response_format unsupported"}`},
		"none":        {400, `{"error":"structured output required"}`},
	})
	_, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("esperava StatusError 400 ao fim, veio %v", err)
	}
	if got := types(seen()); got != "json_schema,json_object,none" {
		t.Fatalf("no máximo 3 tentativas (uma por formato): %s", got)
	}
}

func TestHTTPLLM_StatusErrorCarriesCode(t *testing.T) {
	srv, seen := formatServer(t, map[string]answer{
		"json_schema": {429, `{"error":{"message":"rate limited (response_format irrelevant)"}}`},
	})
	_, err := NewHTTPLLM().Chat(context.Background(), chatReq(srv.URL))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusTooManyRequests {
		t.Fatalf("esperava StatusError 429, veio %v", err)
	}
	if n := len(seen()); n != 1 {
		t.Fatalf("429 não é assunto de formato: %d tentativa(s)", n)
	}
}

func TestHTTPLLM_ErrorNeverEchoesTheKey(t *testing.T) {
	const key = "sk-or-v1-SEGREDO-0000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"chave inválida: ` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `"}`))
	}))
	defer srv.Close()
	req := chatReq(srv.URL)
	req.APIKey = key
	_, err := NewHTTPLLM().Chat(context.Background(), req)
	if err == nil {
		t.Fatal("401 deveria dar erro")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("o erro ecoou a chave: %v", err)
	}
}
