package remediate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeApplier struct {
	outcome Outcome
	res     *Result
	err     error
	called  bool
}

func (f *fakeApplier) Apply(context.Context, *Job) (Outcome, *Result, error) {
	f.called = true
	return f.outcome, f.res, f.err
}

type fakeSource struct {
	job       *Job
	pollErr   error
	ackErr    error
	reportErr error
	acked     []string
	reported  map[string]*Result
}

func (f *fakeSource) poll(context.Context) (*Job, error) { return f.job, f.pollErr }

func (f *fakeSource) ack(_ context.Context, id string) error {
	f.acked = append(f.acked, id)
	return f.ackErr
}

func (f *fakeSource) report(_ context.Context, id string, res *Result) error {
	if f.reported == nil {
		f.reported = map[string]*Result{}
	}
	f.reported[id] = res
	return f.reportErr
}

func runnerWith(src jobSource, exec applier) *Runner {
	return &Runner{src: src, exec: exec, now: func() time.Time { return time.Unix(0, 0) }}
}

func job1() *Job { return &Job{JobID: "j1", Type: TypePackagePatch} }

func TestRunner_NoJobIsNoOp(t *testing.T) {
	src := &fakeSource{job: nil}
	exec := &fakeApplier{}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if exec.called || len(src.acked) != 0 || len(src.reported) != 0 {
		t.Fatal("sem job não deveria aplicar/ackar/reportar")
	}
}

func TestRunner_PollErrorNeverActs(t *testing.T) {
	// Cobre o fail-closed: PollJob devolve erro quando a verificação falha; o Runner
	// não pode aplicar nem ackar um job não verificado.
	src := &fakeSource{pollErr: errors.New("falhou verificação")}
	exec := &fakeApplier{}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err == nil {
		t.Fatal("erro de poll deveria propagar")
	}
	if exec.called || len(src.acked) != 0 {
		t.Fatal("job não verificado NUNCA pode ser aplicado ou ackado")
	}
}

func TestRunner_AppliedAcksAndReports(t *testing.T) {
	src := &fakeSource{job: job1()}
	exec := &fakeApplier{outcome: OutcomeApplied, res: &Result{Status: StatusApplied, After: "ok"}}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(src.acked) != 1 || src.acked[0] != "j1" {
		t.Fatalf("deveria ackar j1: %v", src.acked)
	}
	if r := src.reported["j1"]; r == nil || r.Status != StatusApplied {
		t.Fatalf("deveria reportar APPLIED: %+v", r)
	}
}

func TestRunner_FailedReportsFailed(t *testing.T) {
	src := &fakeSource{job: job1()}
	exec := &fakeApplier{outcome: OutcomeFailed, res: &Result{Status: StatusFailed, Detail: "boom"}}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if r := src.reported["j1"]; r == nil || r.Status != StatusFailed {
		t.Fatalf("deveria reportar FAILED: %+v", r)
	}
}

func TestRunner_DeferredDoesNotAckOrReport(t *testing.T) {
	src := &fakeSource{job: job1()}
	exec := &fakeApplier{outcome: OutcomeDeferred}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(src.acked) != 0 || len(src.reported) != 0 {
		t.Fatal("job diferido (fora da janela) NÃO pode ser ackado nem reportado")
	}
}

func TestRunner_SkippedReReportsApplied(t *testing.T) {
	// Idempotência: job já aplicado (ack/report perdido) re-reporta APPLIED em vez de
	// redelivery infinito.
	src := &fakeSource{job: job1()}
	exec := &fakeApplier{outcome: OutcomeSkipped}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	r := src.reported["j1"]
	if r == nil || r.Status != StatusApplied {
		t.Fatalf("Skipped deveria re-reportar APPLIED: %+v", r)
	}
}

func TestRunner_ReportErrorPropagates(t *testing.T) {
	src := &fakeSource{job: job1(), reportErr: errors.New("502")}
	exec := &fakeApplier{outcome: OutcomeApplied, res: &Result{Status: StatusApplied}}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err == nil {
		t.Fatal("erro de report deveria propagar (retry no próximo tick)")
	}
}

func TestRunner_AckFailureStillReports(t *testing.T) {
	// Ack é higiene; o report (que o servidor aceita a partir de DELIVERED) ainda
	// precisa avançar o job mesmo se o ack falhar.
	src := &fakeSource{job: job1(), ackErr: errors.New("ack 500")}
	exec := &fakeApplier{outcome: OutcomeApplied, res: &Result{Status: StatusApplied}}
	if err := runnerWith(src, exec).RunOnce(context.Background()); err != nil {
		t.Fatalf("ack falho não deveria impedir report: %v", err)
	}
	if src.reported["j1"] == nil {
		t.Fatal("deveria reportar mesmo com ack falho")
	}
}
