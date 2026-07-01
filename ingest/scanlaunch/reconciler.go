package scanlaunch

import (
	"context"
	"encoding/json"
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
	log.Printf("scanlaunch: launch %s → task=%s status=%s", j.RequestID, res.TaskID, res.Status)
	rc.reg.Update(j.RequestID, func(job *Job) {
		job.State = StateRunning
		job.GVMTargetID = res.TargetID
		job.GVMTaskID = res.TaskID
		job.GVMReportID = res.ReportID
		job.StartedAt = rc.now().UTC()
		job.Error = ""
	})
	return true
}

// poll updates a RUNNING job from gvmd; on Done it fetches + caches findings.
func (rc *reconciler) poll(ctx context.Context, j *Job) {
	if !j.StartedAt.IsZero() && rc.now().Sub(j.StartedAt) > rc.cfg.MaxDuration {
		log.Printf("scanlaunch: %s excedeu SCAN_MAX_DURATION — parando", j.RequestID)
		rc.run(ctx, "stop", j) // best effort
		rc.reg.Update(j.RequestID, func(job *Job) {
			job.State = StateExpired
			job.CompletedAt = rc.now().UTC()
		})
		return
	}
	res, err := rc.run(ctx, "status", j)
	if err != nil {
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
	default: // New/Requested/Queued/Running/Processing
		rc.reg.Update(j.RequestID, func(job *Job) {
			job.Progress = res.Progress
			if res.ReportID != "" {
				job.GVMReportID = res.ReportID
			}
		})
	}
}

// complete fetches the finished report once, caches the findings, and marks COMPLETED.
func (rc *reconciler) complete(ctx context.Context, j *Job, statusRes *bridgeResult) {
	res, err := rc.run(ctx, "fetch", j)
	if err != nil {
		log.Printf("scanlaunch: fetch %s falhou: %v", j.RequestID, err)
		return // stay RUNNING; retry fetch next tick (scan is Done, safe to retry)
	}
	if err := rc.writeFindings(j.RequestID, res.Findings); err != nil {
		log.Printf("scanlaunch: cache findings %s falhou: %v", j.RequestID, err)
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
