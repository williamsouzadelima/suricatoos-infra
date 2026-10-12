package verifier

import (
	"errors"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// Gate is the scope gate of line 9 for ONE tenant, with the shape of scopegate.(*Scope).CheckTarget (F2.4a): it
// checks hosts and excludeHosts — every host an IP/CIDR literal inside the tenant's scope, outside the degenerate
// space and containing no IP of the node or of the hub; every exclusion a literal — and returns the CANONICAL lists it
// checked, which are what the executor forwards to gvmd, never the raw input. Any error is a refusal (scope_denied).
// The connector (F2.6) builds it from scopegate: the tenant's scope, FLEET_SELF_DENY_IPS read with
// scopegate.ParseSelfDeny (strict) and added with WithSelfDeny, and the hub's IPs with WithSelfDeny.
type Gate interface {
	CheckTarget(hosts, excludeHosts []string) (canonHosts, canonExclude []string, err error)
}

// Scope is what line 9 needs from the node; the connector (F2.6) wires it to scopegate and to the gvmd reads. The
// reads are of the tenant's objects only: an object of another tenant is ErrNotFound, exactly like one that does not
// exist, so line 9 never tells them apart.
type Scope interface {
	// Gate returns the gate of a tenant that line 6 admitted. An error is a local failure: unavailable.
	Gate(st tenant.Standing) (Gate, error)
	// Target reads in gvmd the hosts and exclude_hosts of a target of the tenant.
	Target(tenantName, targetID string) (TargetHosts, error)
	// Task reads in gvmd a task of the tenant: its target and its schedule.
	Task(tenantName, taskID string) (TaskInfo, error)
	// ScheduleTasks reads in gvmd the tasks of the tenant linked to a schedule.
	ScheduleTasks(tenantName, scheduleID string) ([]string, error)
}

// TargetHosts are the entries of a target as gvmd holds them (literal or not: the gate decides).
type TargetHosts struct {
	Hosts, ExcludeHosts []string
}

// TaskInfo is what line 9 needs of a task: its target ("" for a task without one, which scans nothing) and its
// schedule ("" = none).
type TaskInfo struct {
	TargetID, ScheduleID string
}

// ErrNotFound: the object does not exist for the tenant. Line 9 cannot prove the scope of what it cannot read, so the
// command is refused (scope_denied, final) — never accepted on the hope that the execution will not find it either.
// Any OTHER error of a read is a read failure: unavailable.
var ErrNotFound = errors.New("verifier: objeto não encontrado no gvmd para o tenant")

// deniedError is a refusal of line 9.
type deniedError struct{ detail string }

func (e *deniedError) Error() string { return "verifier: scope_denied: " + e.detail }

// unavailableError is a local failure of line 9, with the fixed detail of its ack.
type unavailableError struct {
	detail string
	err    error
}

func (e *unavailableError) Error() string { return "verifier: " + e.detail + ": " + errText(e.err) }
func (e *unavailableError) Unwrap() error { return e.err }

// scoped are the canonical lists line 9 checked (target.create, target.modify, sensor_job.enqueue).
type scoped struct{ hosts, exclude []string }

// scope is line 9 (ADR-0011, the table and "Escopo, regra completa"): the hosts of target.create and the resulting
// ones of target.modify (read in gvmd when the payload brings none); the targets of sensor_job.enqueue; the hosts of
// the target of task.start/resume; of task.create's target and of task.modify's new target; and those of the targets
// of the tasks a command links to a schedule or whose schedule it changes (schedule.create with task_ids, task.modify
// with a non-empty schedule_id, task.clone of a task with a schedule, schedule.modify). The canonical lists replace,
// in the payload, the hosts the executor forwards.
func (c *check) scope(st tenant.Standing, payload any) (scoped, error) {
	typ := c.cmd.Type
	if !needsScope(typ, payload) {
		return scoped{}, nil
	}
	gate, err := c.v.scope.Gate(st)
	if err != nil {
		return scoped{}, &unavailableError{detail: detailScopeGate, err: err}
	}
	g := &gvmScope{scope: c.v.scope, gate: gate, tenant: c.cmd.Tenant}
	switch p := payload.(type) {
	case *contract.PayloadTargetCreate:
		h, x, err := gate.CheckTarget(p.Hosts, p.ExcludeHosts)
		if err != nil {
			return scoped{}, &deniedError{detail: detailScopeDenied}
		}
		p.Hosts = h
		if p.ExcludeHosts != nil {
			p.ExcludeHosts = x
		}
		return scoped{h, x}, nil
	case *contract.PayloadTargetModify:
		hosts := p.Hosts
		if hosts == nil { // the current hosts, read in gvmd: the target.modify keeps them
			th, err := g.target(p.TargetID)
			if err != nil {
				return scoped{}, err
			}
			hosts = th.Hosts
		}
		h, x, err := gate.CheckTarget(hosts, p.ExcludeHosts)
		if err != nil {
			return scoped{}, &deniedError{detail: detailScopeDenied}
		}
		if p.Hosts != nil {
			p.Hosts = h
		}
		if p.ExcludeHosts != nil {
			p.ExcludeHosts = x
		}
		return scoped{h, x}, nil
	case *contract.PayloadSensorJobEnqueue:
		h, _, err := gate.CheckTarget(p.Targets, nil)
		if err != nil {
			return scoped{}, &deniedError{detail: detailScopeDenied}
		}
		p.Targets = h
		return scoped{hosts: h}, nil
	case *contract.PayloadTaskRef: // task.start, task.resume
		return scoped{}, g.task(p.TaskID)
	case *contract.PayloadTaskCreate:
		return scoped{}, g.targetHosts(p.TargetID)
	case *contract.PayloadTaskModify:
		if p.TargetID != nil { // the new target: with or without a schedule, it is what the task will scan
			return scoped{}, g.targetHosts(*p.TargetID)
		}
		return scoped{}, g.task(p.TaskID) // a non-empty schedule_id (needsScope)
	case *contract.PayloadTaskClone:
		info, err := g.taskInfo(p.TaskID)
		if err != nil {
			return scoped{}, err
		}
		if info.ScheduleID == "" || info.TargetID == "" { // no schedule, or a task without a target: nothing is scanned
			return scoped{}, nil
		}
		return scoped{}, g.targetHosts(info.TargetID)
	case *contract.PayloadScheduleCreate:
		for _, id := range p.TaskIDs {
			if err := g.task(id); err != nil {
				return scoped{}, err
			}
		}
		return scoped{}, nil
	case *contract.PayloadScheduleModify:
		ids, err := c.v.scope.ScheduleTasks(c.cmd.Tenant, p.ScheduleID)
		if err := readErr(err); err != nil {
			return scoped{}, err
		}
		for _, id := range ids {
			if err := g.task(id); err != nil {
				return scoped{}, err
			}
		}
		return scoped{}, nil
	}
	return scoped{}, &unavailableError{detail: detailScopeRead, err: errors.New("payload sem regra de escopo")} // unreachable
}

// needsScope reports whether a command goes through the scope gate at all.
func needsScope(typ contract.CommandType, payload any) bool {
	switch typ {
	case contract.TypeTargetCreate, contract.TypeTargetModify, contract.TypeSensorJobEnqueue, contract.TypeTaskStart,
		contract.TypeTaskResume, contract.TypeTaskCreate, contract.TypeTaskClone, contract.TypeScheduleModify:
		return true
	case contract.TypeTaskModify:
		p, _ := payload.(*contract.PayloadTaskModify)
		return p != nil && (p.TargetID != nil || (p.ScheduleID != nil && *p.ScheduleID != ""))
	case contract.TypeScheduleCreate:
		p, _ := payload.(*contract.PayloadScheduleCreate)
		return p != nil && len(p.TaskIDs) > 0
	}
	return false
}

// readErr maps an error of a gvmd read: ErrNotFound is a refusal, anything else a local failure.
func readErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return &deniedError{detail: detailScopeNotFound}
	}
	return &unavailableError{detail: detailScopeRead, err: err}
}

// gvmScope checks, for one command, the hosts of targets read in gvmd.
type gvmScope struct {
	scope  Scope
	gate   Gate
	tenant string
}

func (g *gvmScope) target(id string) (TargetHosts, error) {
	th, err := g.scope.Target(g.tenant, id)
	return th, readErr(err)
}

func (g *gvmScope) taskInfo(id string) (TaskInfo, error) {
	info, err := g.scope.Task(g.tenant, id)
	return info, readErr(err)
}

// targetHosts checks the hosts of a target through the gate.
func (g *gvmScope) targetHosts(id string) error {
	th, err := g.target(id)
	if err != nil {
		return err
	}
	if _, _, err := g.gate.CheckTarget(th.Hosts, th.ExcludeHosts); err != nil {
		return &deniedError{detail: detailScopeDenied}
	}
	return nil
}

// task checks the hosts of a task's target; a task without a target scans nothing.
func (g *gvmScope) task(id string) error {
	info, err := g.taskInfo(id)
	if err != nil {
		return err
	}
	if info.TargetID == "" {
		return nil
	}
	return g.targetHosts(info.TargetID)
}
