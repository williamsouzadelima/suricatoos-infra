package remediate

import (
	"context"
	"errors"
	"fmt"
)

// errEnginePending is what a production handler returns until the real OS engines
// are implemented and validated in the LAB-gated slice. It is deliberately a hard
// error so that, before that slice lands, a job reports FAILED with a clear reason
// and the agent writes NOTHING to the OS.
var errEnginePending = errors.New("motor de execução real pendente: implementar e validar em LAB (docs/runbooks/remediation-lab-canary.md)")

// patchEngine is the OS-touching seam for ONE package engine (wua|winget). The
// real implementations (PowerShell/COM for WUA, winget.exe) are a later, LAB-gated
// slice; this slice wires a pending stub. Tests inject fakes so the handler logic
// is exercised on every CI platform without touching the OS.
type patchEngine interface {
	// satisfied reports whether the target update is already present, letting the
	// handler no-op idempotently. The string describes the prior state (for audit).
	satisfied(ctx context.Context, p *PackagePatchPayload) (done bool, before string, err error)
	// apply installs/upgrades the target, returning the resulting state and whether
	// a reboot is still pending.
	apply(ctx context.Context, p *PackagePatchPayload) (after string, rebootPending bool, err error)
}

// PackagePatchHandler applies a package_patch job by dispatching to the engine
// named by the payload's Source. There is exactly ONE Handler per job Type, so
// both engines live behind this single handler. It captures prior state into
// Result.Before and never writes when the target is already satisfied.
type PackagePatchHandler struct {
	engines map[string]patchEngine
}

// newPackagePatchHandler wires a handler to a set of engines keyed by source. Used
// by the production constructor and by tests (which pass fakes).
func newPackagePatchHandler(engines map[string]patchEngine) *PackagePatchHandler {
	return &PackagePatchHandler{engines: engines}
}

// NewPackagePatchHandler returns the production handler. Its engines are PENDING
// (real WUA/winget execution is the LAB-gated slice), so until that lands every
// job reports FAILED with a clear reason and NOTHING is written to the OS.
func NewPackagePatchHandler() *PackagePatchHandler {
	return newPackagePatchHandler(map[string]patchEngine{
		"wua":    pendingPatchEngine{},
		"winget": pendingPatchEngine{},
	})
}

// Type implements Handler.
func (*PackagePatchHandler) Type() Type { return TypePackagePatch }

// Apply implements Handler. It parses and dispatches the payload; the executor
// has already verified authenticity and enforced the window/idempotency gates.
func (h *PackagePatchHandler) Apply(ctx context.Context, j *Job) (*Result, error) {
	p, err := ParsePackagePatch(j.Payload)
	if err != nil {
		return nil, err
	}
	eng, ok := h.engines[p.Source]
	if !ok {
		return nil, fmt.Errorf("sem motor de patch para source %q", p.Source)
	}
	done, before, err := eng.satisfied(ctx, p)
	if err != nil {
		return &Result{Before: before}, fmt.Errorf("checagem de estado (%s): %w", p.Source, err)
	}
	if done {
		return &Result{
			Before: before,
			After:  before,
			Detail: fmt.Sprintf("já em conformidade (no-op idempotente): %s", patchID(p)),
		}, nil
	}
	after, reboot, err := eng.apply(ctx, p)
	if err != nil {
		return &Result{Before: before}, fmt.Errorf("aplicar %s via %s: %w", patchID(p), p.Source, err)
	}
	return &Result{
		Before:        before,
		After:         after,
		RebootPending: reboot,
		Detail:        fmt.Sprintf("patch aplicado via %s: %s", p.Source, patchID(p)),
	}, nil
}

// patchID is the human-facing identifier of the update (KB when known, else the id).
func patchID(p *PackagePatchPayload) string {
	if p.KB != "" {
		return p.KB
	}
	return p.ID
}

// pendingPatchEngine is the inert default until the real OS engines land (LAB).
type pendingPatchEngine struct{}

func (pendingPatchEngine) satisfied(context.Context, *PackagePatchPayload) (bool, string, error) {
	return false, "", errEnginePending
}

func (pendingPatchEngine) apply(context.Context, *PackagePatchPayload) (string, bool, error) {
	return "", false, errEnginePending
}
