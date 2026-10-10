package planner

import (
	"context"
	"encoding/json"
)

// ChatMessage is one role-tagged message. No assistant "prefill" is ever used
// (Claude 5 rule): the caller sends only system+user and lets the model answer.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Usage is the token accounting the provider returns, used for the budget.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// ChatRequest is one structured-output completion against a resolved provider. The
// real client (a later slice) must send NO temperature (Claude 5 rule) and request
// structured output via Schema.
type ChatRequest struct {
	BaseURL  string
	APIKey   string
	Model    string
	Messages []ChatMessage
	Schema   json.RawMessage
}

// ChatResponse is the model's raw structured content plus usage.
type ChatResponse struct {
	Content string
	Usage   Usage
}

// LLM is the injected seam the Planner drives. The core slice ships only this
// interface + a fake for tests; the real OpenAI-compatible HTTP client is a
// separate, separately-reviewed slice so this core writes/calls nothing external.
type LLM interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

// Provider is the resolved endpoint the Planner sends to.
type Provider struct {
	Name    string
	BaseURL string
	APIKey  string
	Model   string
}

// ProviderResolver yields an ENABLED, governed provider (the real impl wraps the
// aiproviders registry; a fake is used in tests). It errors if none is usable.
type ProviderResolver interface {
	Resolve(ctx context.Context) (Provider, error)
}
