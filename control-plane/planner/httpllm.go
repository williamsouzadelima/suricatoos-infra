package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxLLMResponse = 1 << 20

// HTTPLLM is the real OpenAI-compatible chat client — it serves OpenRouter,
// UnoRouter and any compatible gateway with one code path. It obeys the Claude 5
// rules: it sends NO temperature and NO assistant prefill, and requests structured
// output via response_format json_schema. It makes an EXTERNAL call, so it only
// runs when the operator explicitly triggers a draft with consent (the Planner
// gates consent/budget before this is reached).
type HTTPLLM struct {
	hc *http.Client
}

// NewHTTPLLM builds a client with a conservative timeout.
func NewHTTPLLM() *HTTPLLM {
	return &HTTPLLM{hc: &http.Client{Timeout: 60 * time.Second}}
}

// Chat posts one structured-output completion to BaseURL+"/chat/completions".
func (c *HTTPLLM) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	payload := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "remediation_plan",
				"strict": true,
				"schema": req.Schema,
			},
		},
		// Deliberately NO "temperature" and NO trailing assistant message (prefill).
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
		return ChatResponse{}, fmt.Errorf("provedor respondeu %d: %s", resp.StatusCode, snippet(raw))
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

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
