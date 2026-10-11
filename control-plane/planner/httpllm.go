package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxLLMResponse = 1 << 20

// snippetMax caps, in characters, how much of a provider's error body a
// StatusError keeps: the planner's final error (and its log line) may carry it.
const snippetMax = 160

// keyLike matches API-key-shaped tokens a provider may echo back (sk-…), besides
// the exact key of the request, which redactKey already removes.
var keyLike = regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`)

// The response formats Chat tries, in this order.
const (
	formatJSONSchema = "json_schema"
	formatJSONObject = "json_object"
	formatNone       = ""
)

var responseFormats = []string{formatJSONSchema, formatJSONObject, formatNone}

// schemaInstruction carries the schema in the system prompt when response_format
// cannot (json_object or no response_format): without it the model could not know
// the fields a valid draft requires. It extends the SYSTEM message — never an
// assistant turn (no prefill).
const schemaInstruction = "\n\nFormato obrigatório da resposta: um único objeto JSON, sem markdown e sem texto fora dele, que valide neste JSON Schema:\n"

// StatusError is a non-2xx answer from the provider (after the response-format
// fallback): the Planner moves on to the next provider and lists Code (with the
// Snippet) in its final error.
type StatusError struct {
	Code    int
	Snippet string // short, sanitized start of the provider's body (see snippet); never the key

	formatRelated bool // a 400 that cites the response format: Chat tries the next format
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("provedor respondeu %d: %s", e.Code, e.Snippet)
}

// HTTPLLM is the real OpenAI-compatible chat client — it serves OpenRouter,
// UnoRouter and any compatible gateway with one code path. It obeys the Claude 5
// rules: it sends NO temperature and NO assistant prefill, and requests structured
// output via response_format json_schema (with the fallbacks in Chat). It never
// follows a redirect (newLLMClient). It makes an EXTERNAL call, so it only runs
// when the operator explicitly triggers a draft with consent (the Planner gates
// consent/free rule/budget before this is reached).
type HTTPLLM struct {
	hc *http.Client
}

// NewHTTPLLM builds a client with a conservative timeout that follows no redirect.
func NewHTTPLLM() *HTTPLLM {
	return &HTTPLLM{hc: newLLMClient(nil)}
}

// newLLMClient is the planner's outbound client: bounded per attempt and following
// NO redirect — a 307/308 would re-send the request body, the prompt, to wherever
// Location points. The 3xx itself comes back as the provider's non-2xx answer
// (StatusError), so the Planner moves on to the next provider. rt == nil uses the
// default transport.
func newLLMClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: rt,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Chat posts one structured-output completion to BaseURL+"/chat/completions". It
// asks for response_format json_schema first. Many free models do not support it:
// when the provider answers 400 citing the response format, Chat retries ONCE with
// {"type":"json_object"} and, on another such 400, once more without
// response_format (the schema then travels in the system prompt). Whatever format
// answered, the caller still validates the content (parseDraft): no fallback
// loosens what a valid draft is.
func (c *HTTPLLM) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	var err error
	for _, format := range responseFormats {
		var resp ChatResponse
		resp, err = c.chatOnce(ctx, req, format)
		if err == nil {
			return resp, nil
		}
		var se *StatusError
		if !errors.As(err, &se) || !se.formatRelated {
			return ChatResponse{}, err
		}
	}
	return ChatResponse{}, err
}

// chatOnce is one attempt with one response format.
func (c *HTTPLLM) chatOnce(ctx context.Context, req ChatRequest, format string) (ChatResponse, error) {
	payload := map[string]any{
		"model":    req.Model,
		"messages": messagesFor(req, format),
		// Deliberately NO "temperature" and NO trailing assistant message (prefill).
	}
	switch format {
	case formatJSONSchema:
		payload["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "remediation_plan",
				"strict": true,
				"schema": req.Schema,
			},
		}
	case formatJSONObject:
		payload["response_format"] = map[string]any{"type": "json_object"}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ChatResponse{}, err
	}
	url := strings.TrimRight(req.BaseURL, "/") + "/chat/completions"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return ChatResponse{}, err
	}
	hreq.Header.Set("Authorization", "Bearer "+req.APIKey)
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(hreq)
	if err != nil {
		return ChatResponse{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponse))
	if resp.StatusCode/100 != 2 {
		return ChatResponse{}, &StatusError{
			Code:          resp.StatusCode,
			Snippet:       snippet(raw, req.APIKey),
			formatRelated: resp.StatusCode == http.StatusBadRequest && citesResponseFormat(raw),
		}
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return ChatResponse{}, fmt.Errorf("resposta do provedor inválida: %w", err)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return ChatResponse{}, fmt.Errorf("provedor não retornou conteúdo")
	}
	return ChatResponse{
		Content: out.Choices[0].Message.Content,
		Usage:   Usage{PromptTokens: out.Usage.PromptTokens, CompletionTokens: out.Usage.CompletionTokens},
	}, nil
}

// messagesFor returns the messages for one attempt: unchanged for json_schema;
// for the fallback formats, a copy whose system message also carries the schema.
func messagesFor(req ChatRequest, format string) []ChatMessage {
	if format == formatJSONSchema || len(req.Schema) == 0 {
		return req.Messages
	}
	msgs := make([]ChatMessage, len(req.Messages))
	copy(msgs, req.Messages)
	for i := range msgs {
		if msgs[i].Role == "system" {
			msgs[i].Content += schemaInstruction + string(req.Schema)
			return msgs
		}
	}
	sys := ChatMessage{Role: "system", Content: strings.TrimPrefix(schemaInstruction, "\n\n") + string(req.Schema)}
	return append([]ChatMessage{sys}, msgs...)
}

// citesResponseFormat reports whether a provider's error body is about the response
// format (response_format / json_schema / json_object / structured outputs),
// accepting a space or hyphen in place of the underscore.
func citesResponseFormat(body []byte) bool {
	s := strings.NewReplacer(" ", "_", "-", "_").Replace(strings.ToLower(string(body)))
	for _, k := range []string{"response_format", "json_schema", "json_object", "structured"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// redactKey removes the API key from text a provider sent back (some echo it in
// error messages), so it never reaches an error, a log or a response. Very short
// values (test placeholders) are left alone: replacing them would mangle the text.
func redactKey(s, key string) string {
	if len(key) < 8 {
		return s
	}
	return strings.ReplaceAll(s, key, "[chave]")
}

// snippet is the short, sanitized start of a provider's error body: the request's
// key — and anything shaped like a key — redacted, invalid UTF-8 dropped, control
// characters and runs of whitespace folded into single spaces (one printable
// line), at most snippetMax characters.
func snippet(body []byte, key string) string {
	s := strings.ToValidUTF8(redactKey(string(body), key), "")
	s = keyLike.ReplaceAllString(s, "[chave]")
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
	if utf8.RuneCountInString(s) > snippetMax {
		s = string([]rune(s)[:snippetMax])
	}
	return s
}
