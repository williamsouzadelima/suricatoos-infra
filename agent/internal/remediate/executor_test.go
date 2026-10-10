package remediate

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeHandler records calls and returns a scripted result/error — NO OS writes.
type fakeHandler struct {
	typ    Type
	calls  int
	result *Result
	err    error
}

func (f *fakeHandler) Type() Type { return f.typ }
func (f *fakeHandler) Apply(_ context.Context, _ *Job) (*Result, error) {
	f.calls++
	return f.result, f.err
}

func baseJob() *Job {
	return &Job{JobID: "j-1", AgentID: "win-a", Tenant: "acme", Type: TypePackagePatch}
}

func TestExecutorAppliesAndIsIdempotent(t *testing.T) {
	fh := &fakeHandler{typ: TypePackagePatch, result: &Result{After: "patched"}}
	e := NewExecutor(t.TempDir(), fh)

	out, res, err := e.Apply(context.Background(), baseJob())
	if err != nil || out != OutcomeApplied {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if res.Status != StatusApplied || res.After != "patched" {
		t.Fatalf("result inesperado: %+v", res)
	}
	if fh.calls != 1 {
		t.Fatalf("handler chamado %d vezes (esperado 1)", fh.calls)
	}

	// Re-apply the same job → skipped, handler NOT called again (idempotency).
	out2, res2, _ := e.Apply(context.Background(), baseJob())
	if out2 != OutcomeSkipped || res2 != nil {
		t.Fatalf("reaplicação devia ser skipped: out=%v res=%v", out2, res2)
	}
	if fh.calls != 1 {
		t.Fatalf("handler NÃO devia rodar de novo (calls=%d)", fh.calls)
	}

	// A fresh Executor over the same stateDir reads the persisted journal → skip.
	e2 := NewExecutor(e.stateDir, fh)
	if out, _, _ := e2.Apply(context.Background(), baseJob()); out != OutcomeSkipped {
		t.Fatalf("journal persistido devia dar skipped, deu %v", out)
	}
	if fh.calls != 1 {
		t.Fatalf("handler rodou após reload do journal (calls=%d)", fh.calls)
	}
}

func TestExecutorDefersBeforeWindow(t *testing.T) {
	fh := &fakeHandler{typ: TypePackagePatch, result: &Result{}}
	e := NewExecutor(t.TempDir(), fh)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }

	j := baseJob()
	j.NotBefore = now.Add(time.Hour) // window opens later
	out, res, _ := e.Apply(context.Background(), j)
	if out != OutcomeDeferred || res != nil {
		t.Fatalf("antes da janela devia diferir: out=%v res=%v", out, res)
	}
	if fh.calls != 0 {
		t.Fatalf("handler NÃO devia rodar antes da janela (calls=%d)", fh.calls)
	}
}

func TestExecutorRefusesAfterWindow(t *testing.T) {
	fh := &fakeHandler{typ: TypePackagePatch, result: &Result{}}
	e := NewExecutor(t.TempDir(), fh)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }

	j := baseJob()
	j.NotAfter = now.Add(-time.Hour) // window already closed
	out, res, _ := e.Apply(context.Background(), j)
	if out != OutcomeFailed || res == nil || res.Status != StatusFailed {
		t.Fatalf("após a janela devia falhar: out=%v res=%v", out, res)
	}
	if fh.calls != 0 {
		t.Fatalf("handler NÃO devia rodar após a janela (calls=%d)", fh.calls)
	}
}

func TestExecutorUnknownType(t *testing.T) {
	// Only a package_patch handler is registered; a config_hardening job has none.
	fh := &fakeHandler{typ: TypePackagePatch, result: &Result{}}
	e := NewExecutor(t.TempDir(), fh)
	j := baseJob()
	j.Type = TypeConfigHardening
	out, res, _ := e.Apply(context.Background(), j)
	if out != OutcomeFailed || res == nil || res.Status != StatusFailed {
		t.Fatalf("tipo sem handler devia falhar: out=%v res=%v", out, res)
	}
	if fh.calls != 0 {
		t.Fatalf("handler de outro tipo NÃO devia rodar (calls=%d)", fh.calls)
	}
}

func TestExecutorHandlerErrorReportsFailedAndRetriable(t *testing.T) {
	fh := &fakeHandler{typ: TypePackagePatch, err: errors.New("winget saiu 1")}
	e := NewExecutor(t.TempDir(), fh)

	out, res, _ := e.Apply(context.Background(), baseJob())
	if out != OutcomeFailed || res.Status != StatusFailed || res.Detail == "" {
		t.Fatalf("erro do handler devia virar FAILED com detalhe: out=%v res=%+v", out, res)
	}

	// FAILED is retriable: a second attempt runs the handler again (not skipped).
	fh.err = nil
	fh.result = &Result{After: "ok"}
	out2, res2, _ := e.Apply(context.Background(), baseJob())
	if out2 != OutcomeApplied || res2.Status != StatusApplied {
		t.Fatalf("retry após falha devia aplicar: out=%v res=%+v", out2, res2)
	}
	if fh.calls != 2 {
		t.Fatalf("handler devia rodar 2x (falha+retry), rodou %d", fh.calls)
	}
}
