package planner

import (
	"testing"
	"time"
)

func TestBudget_AllowThenExceed(t *testing.T) {
	b := newBudget(0.01, 0.005, nil) // teto US$0,01; US$0,005 / 1k tokens
	if !b.allow() {
		t.Fatal("deveria permitir no início")
	}
	b.add(Usage{PromptTokens: 2000, CompletionTokens: 2000}) // 4k tokens → US$0,02 > teto
	if b.allow() {
		t.Fatal("deveria recusar após estourar o teto")
	}
}

func TestBudget_ZeroCapIsUnlimited(t *testing.T) {
	b := newBudget(0, 0.005, nil)
	b.add(Usage{PromptTokens: 1 << 20})
	if !b.allow() {
		t.Fatal("teto <= 0 = sem limite")
	}
}

func TestBudget_MonthlyReset(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	b := newBudget(0.01, 0.005, func() time.Time { return now })
	b.add(Usage{PromptTokens: 5000, CompletionTokens: 0}) // estoura
	if b.allow() {
		t.Fatal("deveria recusar dentro do mês")
	}
	now = now.AddDate(0, 1, 0) // vira o mês
	if !b.allow() {
		t.Fatal("deveria resetar no novo mês")
	}
}
