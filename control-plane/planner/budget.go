package planner

import (
	"sync"
	"time"
)

// budget is a simple monthly spend ceiling. It is an in-memory estimate (cost is
// derived from the provider's reported token usage × a configured rate) meant to
// REFUSE runaway usage, not to be an exact accounting. It resets at month change.
type budget struct {
	mu          sync.Mutex
	capUSD      float64
	per1kTokens float64
	spentUSD    float64
	month       string
	now         func() time.Time
}

func newBudget(capUSD, per1kTokens float64, now func() time.Time) *budget {
	if now == nil {
		now = time.Now
	}
	return &budget{capUSD: capUSD, per1kTokens: per1kTokens, now: now, month: monthKey(now())}
}

func monthKey(t time.Time) string { return t.Format("2006-01") }

func (b *budget) rollIfNeeded() {
	m := monthKey(b.now())
	if m != b.month {
		b.month = m
		b.spentUSD = 0
	}
}

// allow reports whether another call is within the monthly ceiling. A zero or
// negative cap means "unlimited" (the operator opted out of the budget gate).
func (b *budget) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollIfNeeded()
	if b.capUSD <= 0 {
		return true
	}
	return b.spentUSD < b.capUSD
}

// add charges the estimated cost of a call against the current month.
func (b *budget) add(u Usage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollIfNeeded()
	tokens := float64(u.PromptTokens + u.CompletionTokens)
	b.spentUSD += (tokens / 1000.0) * b.per1kTokens
}
