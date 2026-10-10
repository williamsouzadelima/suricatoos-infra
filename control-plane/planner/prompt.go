package planner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// systemPrompt fixes the model's role and the hard governance rules. It never asks
// the model for a severity or a decision.
const systemPrompt = "Você é um assistente que redige RASCUNHOS de plano de remediação para um analista de " +
	"segurança revisar. Regras invioláveis: (1) NÃO invente achados, CVEs ou severidade — eles já foram " +
	"determinados por fonte autoritativa e vêm no input; apenas explique e proponha passos. (2) NÃO decida, " +
	"aprove ou aplique nada — o humano revisa e aprova cada ação. (3) Responda SOMENTE no JSON do schema " +
	"pedido, em português, de forma objetiva e acionável. Os identificadores são pseudônimos (host-1, ip-1, …); " +
	"use-os como estão."

// planSchema is the JSON schema for the model's structured output (Claude 5 /
// OpenAI-compatible structured output). It has NO severity/cve field on purpose.
var planSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["summary", "steps", "rationale", "prioritization", "caveats"],
  "properties": {
    "summary": {"type": "string"},
    "steps": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["action"],
        "properties": {"action": {"type": "string"}, "detail": {"type": "string"}}
      }
    },
    "rationale": {"type": "string"},
    "prioritization": {"type": "string"},
    "caveats": {"type": "string"}
  }
}`)

// buildMessages renders the chat messages from an ALREADY-pseudonymized request.
// It builds the user content from an allowlist of fields — the raw PlanRequest is
// never serialized wholesale — so only attested technical facts + pseudonyms go out.
func buildMessages(preq PlanRequest) []ChatMessage {
	var b strings.Builder
	line := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	line("tipo", preq.Type)
	line("titulo", preq.Title)
	line("severidade (atestada, nao alterar)", preq.Severity)
	if len(preq.CVEs) > 0 {
		line("cves (atestados)", strings.Join(preq.CVEs, ", "))
	}
	line("regra_cis", preq.RuleRef)
	line("kb", preq.KB)
	line("evidencia", preq.Evidence)
	line("so", preq.OS)
	line("host", preq.Host)      // já pseudonimizado
	line("agente", preq.AgentID) // já pseudonimizado
	b.WriteString("\nRedija o rascunho do plano para corrigir/endurecer este item.")

	return []ChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: b.String()},
	}
}
