package scanlaunch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// reconciler is the SINGLE serialized owner of gvmd interaction. Because only
// this goroutine launches, polls, fetches and stops, the classic count-then-start
// and find-then-create TOCTOU races are structurally impossible: the HTTP handlers
// only persist PENDING jobs (and stop-requests), never touch gvmd.
type reconciler struct {
	reg         *Registry
	cfg         Config
	run         bridgeRunner
	findingsDir string
	now         func() time.Time
}

func newReconciler(reg *Registry, cfg Config, run bridgeRunner) *reconciler {
	return &reconciler{reg: reg, cfg: cfg, run: run, findingsDir: cfg.FindingsDir, now: time.Now}
}

// Run drives the state machine on a fixed tick until ctx is done.
func (rc *reconciler) Run(ctx context.Context) {
	t := time.NewTicker(rc.cfg.TickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc.tick(ctx)
		}
	}
}

// tick advances every non-terminal job once. Stops are handled first (so a DELETE
// takes effect promptly), then RUNNING jobs are polled, then PENDING jobs are
// launched up to the free concurrency budget.
func (rc *reconciler) tick(ctx context.Context) {
	jobs := rc.reg.List() // sorted by SubmittedAt

	for _, j := range jobs {
		if j.State.terminal() {
			continue
		}
		if j.StopRequested {
			rc.stop(ctx, j)
		}
	}

	active := rc.reg.CountActive()
	for _, j := range jobs {
		if j.State != StateRunning || j.StopRequested {
			continue
		}
		rc.poll(ctx, j)
	}

	slots := rc.cfg.MaxConcurrent - active
	for _, j := range jobs {
		if slots <= 0 {
			break
		}
		if j.State != StatePending || j.StopRequested {
			continue
		}
		if rc.launch(ctx, j) {
			slots--
		}
	}

	// Evict old terminal jobs so the registry (map + persisted file) stays bounded.
	if n := rc.reg.ReapTerminal(rc.cfg.Retention, rc.findingsDir); n > 0 {
		log.Printf("scanlaunch: reaper removeu %d job(s) terminal(is) > retenção", n)
	}
}

// launch transitions PENDING → RUNNING via scan_bridge.py launch. Returns true
// if a gvmd task is now running (a slot was consumed).
func (rc *reconciler) launch(ctx context.Context, j *Job) bool {
	res, err := rc.run(ctx, "launch", j)
	if err != nil {
		log.Printf("scanlaunch: launch %s (scan_history=%d) falhou: %v", j.RequestID, j.ScanHistoryID, err)
		rc.reg.Update(j.RequestID, func(job *Job) {
			job.State = StateFailed
			job.Error = truncErr(err.Error())
			job.CompletedAt = rc.now().UTC()
		})
		return false
	}
	log.Printf("scanlaunch: launch %s → task=%s (%s) status=%s", j.RequestID, res.TaskID, j.taskName(), res.Status)
	rc.reg.Update(j.RequestID, func(job *Job) {
		job.State = StateRunning
		job.GVMTargetID = res.TargetID
		job.GVMTaskID = res.TaskID
		job.GVMReportID = res.ReportID
		job.StartedAt = rc.now().UTC()
		job.Error = ""
		job.FetchFailures = 0 // a relaunch (job reopened after FAILED) gets a fresh retry budget
	})
	return true
}

// poll updates a RUNNING job from gvmd; on Done it fetches + caches findings.
//
// Status is checked BEFORE the SCAN_MAX_DURATION cap on purpose: a scan that gvmd
// reports Done must be fetched regardless of how long it ran (a finished report
// past the cap — e.g. an ingest restart during a long scan — must not be discarded
// as EXPIRED). The cap only auto-stops a scan that is genuinely still running —
// or one whose status gvmd cannot give at all once past the cap (below): without
// a status nobody can tell it is Done, and the job must not hold a slot forever.
func (rc *reconciler) poll(ctx context.Context, j *Job) {
	res, err := rc.run(ctx, "status", j)
	if err != nil {
		if rc.pastMaxDuration(j) {
			log.Printf("scanlaunch: %s sem status do gvmd além de SCAN_MAX_DURATION — parando: %v", j.RequestID, err)
			rc.bestEffortStop(ctx, j)
			rc.reg.Update(j.RequestID, func(job *Job) {
				job.State = StateExpired
				job.Error = truncErr(fmt.Sprintf("sem status do gvmd além do limite de duração (SCAN_MAX_DURATION=%s): %v",
					rc.cfg.MaxDuration, err))
				job.CompletedAt = rc.now().UTC()
			})
			return
		}
		log.Printf("scanlaunch: status %s falhou: %v", j.RequestID, err)
		return // transient; retry next tick
	}
	switch res.Status {
	case "Done":
		rc.complete(ctx, j, res)
	case "Stopped":
		rc.reg.Update(j.RequestID, func(job *Job) { job.State = StateStopped; job.CompletedAt = rc.now().UTC() })
	case "Interrupted", "Failed":
		rc.reg.Update(j.RequestID, func(job *Job) {
			job.State = StateFailed
			job.Error = "scan " + res.Status
			job.CompletedAt = rc.now().UTC()
		})
	default: // still New/Requested/Queued/Running/Processing
		// Auto-stop only a scan that is confirmed still running past the cap.
		if rc.pastMaxDuration(j) {
			log.Printf("scanlaunch: %s excedeu SCAN_MAX_DURATION — parando", j.RequestID)
			rc.bestEffortStop(ctx, j)
			rc.reg.Update(j.RequestID, func(job *Job) {
				job.State = StateExpired
				job.Error = fmt.Sprintf("scan ainda em execução além do limite de duração (SCAN_MAX_DURATION=%s) — parado",
					rc.cfg.MaxDuration)
				job.CompletedAt = rc.now().UTC()
			})
			return
		}
		rc.reg.Update(j.RequestID, func(job *Job) {
			job.Progress = res.Progress
			if res.ReportID != "" {
				job.GVMReportID = res.ReportID
			}
		})
	}
}

// pastMaxDuration reports whether a launched job has run longer than SCAN_MAX_DURATION.
func (rc *reconciler) pastMaxDuration(j *Job) bool {
	return !j.StartedAt.IsZero() && rc.now().Sub(j.StartedAt) > rc.cfg.MaxDuration
}

// bestEffortStop asks gvmd to stop the job's task; a failure is only logged (the
// task may then keep running in gvmd, outside the concurrency budget).
func (rc *reconciler) bestEffortStop(ctx context.Context, j *Job) {
	if _, err := rc.run(ctx, "stop", j); err != nil {
		log.Printf("scanlaunch: stop %s falhou (a task pode seguir rodando no gvmd): %v", j.RequestID, err)
	}
}

// complete fetches the finished report once, caches the findings, and marks
// COMPLETED — but only when the report shows the scan measured something. A Done
// task without a report, or whose report holds zero hosts (the alive test found
// nobody), is FAILED with the reason, never a "COMPLETED, 0 findings" that reads as
// a clean bill of health (D8); no findings are cached for it. A bridge older than
// hosts_scanned (field absent) keeps the old behavior.
func (rc *reconciler) complete(ctx context.Context, j *Job, statusRes *bridgeResult) {
	res, err := rc.run(ctx, "fetch", j)
	if err != nil {
		// Stay RUNNING; retry fetch next tick (scan is Done, safe to retry) — bounded.
		rc.retryDone(j, statusRes, fmt.Errorf("fetch: %w", err))
		return
	}
	switch {
	case res.ReportMissing:
		rc.failDone(j, statusRes, "task Done sem relatório")
		return
	case res.HostsScanned != nil && *res.HostsScanned == 0:
		rc.failDone(j, statusRes, "scan não mediu nenhum host vivo (verifique alive test/alcance)")
		return
	}
	if err := rc.writeFindings(j.RequestID, res.Findings); err != nil {
		rc.retryDone(j, statusRes, fmt.Errorf("cache findings: %w", err))
		return
	}
	log.Printf("scanlaunch: %s COMPLETED — %d finding(s)", j.RequestID, len(res.Findings))
	rc.reg.Update(j.RequestID, func(job *Job) {
		job.State = StateCompleted
		job.Progress = 100
		if statusRes.ReportID != "" {
			job.GVMReportID = statusRes.ReportID
		}
		job.CompletedAt = rc.now().UTC()
	})
}

// failDone marks a job whose gvmd task is Done as FAILED with reason, keeping the
// report id so the operator can inspect it in the GSA.
func (rc *reconciler) failDone(j *Job, statusRes *bridgeResult, reason string) {
	log.Printf("scanlaunch: %s FAILED — %s", j.RequestID, reason)
	rc.reg.Update(j.RequestID, func(job *Job) {
		job.State = StateFailed
		job.Error = reason
		if statusRes.ReportID != "" {
			job.GVMReportID = statusRes.ReportID
		}
		job.CompletedAt = rc.now().UTC()
	})
}

// retryDone counts a failed attempt (fetch or cache write) to turn a Done task into
// COMPLETED. Below the limit the job stays RUNNING and the next tick retries; at the
// limit it becomes FAILED with the last error instead of holding a concurrency slot
// forever. The count is persisted in the Job, so an ingest restart does not reset it.
func (rc *reconciler) retryDone(j *Job, statusRes *bridgeResult, err error) {
	limit := rc.fetchRetryLimit()
	job, ok := rc.reg.Update(j.RequestID, func(job *Job) {
		job.FetchFailures++
		if job.FetchFailures >= limit {
			job.State = StateFailed
			job.Error = truncErr(fmt.Sprintf("task Done, mas o relatório não foi obtido após %d tentativa(s): %v",
				job.FetchFailures, err))
			if statusRes.ReportID != "" {
				job.GVMReportID = statusRes.ReportID
			}
			job.CompletedAt = rc.now().UTC()
		}
	})
	if !ok {
		return
	}
	if job.State == StateFailed {
		log.Printf("scanlaunch: %s FAILED — %s", j.RequestID, job.Error)
		return
	}
	log.Printf("scanlaunch: %s tentativa %d/%d falhou (re-tenta no próximo tick): %v", j.RequestID, job.FetchFailures, limit, err)
}

func (rc *reconciler) fetchRetryLimit() int {
	if rc.cfg.FetchRetryLimit > 0 {
		return rc.cfg.FetchRetryLimit
	}
	return DefaultFetchRetryLimit
}

// stop kills a job: RUNNING → best-effort gvmd stop; PENDING → just mark stopped.
func (rc *reconciler) stop(ctx context.Context, j *Job) {
	if j.State == StateRunning {
		if _, err := rc.run(ctx, "stop", j); err != nil {
			log.Printf("scanlaunch: stop %s falhou: %v", j.RequestID, err)
		}
	}
	rc.reg.Update(j.RequestID, func(job *Job) {
		job.State = StateStopped
		job.CompletedAt = rc.now().UTC()
	})
}

func (rc *reconciler) writeFindings(requestID string, f []Finding) error {
	if rc.findingsDir == "" {
		return nil
	}
	if err := os.MkdirAll(rc.findingsDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	path := filepath.Join(rc.findingsDir, requestID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readFindings loads the cached findings for a COMPLETED job (nil if absent).
func readFindings(dir, requestID string) []Finding {
	if dir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, requestID+".json"))
	if err != nil {
		return nil
	}
	var f []Finding
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f
}

func truncErr(s string) string {
	const max = 500
	if len(s) > max {
		return s[:max]
	}
	return s
}
