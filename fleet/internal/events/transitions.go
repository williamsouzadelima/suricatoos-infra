package events

import (
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/state"
)

// Observe takes in one cycle of the state (state.Config.Observe; see the package documentation for the rules of each
// transition): it compares the new snapshot of every tracked kind — and the feeds of the node — with the baseline,
// and records, in one tx of the log, the change of the baseline with the events of the transitions. Only once that
// tx is on disk does the memory move; an error means nothing moved (it is logged too), so the next cycle compares
// again with the same baseline and finds the same transitions — none is lost, none goes twice. A kind absent from
// the observation (its collection failed) keeps its baseline; a kind or the feeds without a baseline yet only get one,
// without events.
func (o *Outbox) Observe(obs state.Observation) error {
	o.observing.Lock()
	defer o.observing.Unlock()
	d := &delta{}
	var ps []pending
	memo := map[contract.StateKind]string{}

	if ob, ok := obs.Kinds[contract.KindNode]; ok && !ob.Partial && o.memo[contract.KindNode] != ob.Snapshot.SHA256 {
		fd, fe, err := o.diffFeeds(ob)
		if err != nil {
			o.log.Error("eventos: retrato do node ilegível; os feeds ficam como estavam", "erro", err.Error())
		} else {
			d.Feeds, ps, memo[contract.KindNode] = fd, append(ps, fe...), ob.Snapshot.SHA256
		}
	}
	for _, kind := range o.kinds {
		ob, ok := obs.Kinds[kind]
		key := memoKey(ob)
		if !ok || o.memo[kind] == key {
			continue
		}
		kd, ke, err := o.diffKind(kind, ob)
		if err != nil {
			o.log.Error("eventos: retrato ilegível; o kind fica como estava", "kind", string(kind), "erro", err.Error())
			continue
		}
		if kd != nil {
			if d.Kinds == nil {
				d.Kinds = map[contract.StateKind]*kindDelta{}
			}
			d.Kinds[kind] = kd
		}
		ps, memo[kind] = append(ps, ke...), key
	}
	if d.empty() && len(ps) == 0 {
		maps.Copy(o.memo, memo)
		return nil
	}

	evs := make([]built, 0, len(ps))
	for _, p := range ps {
		id := o.newID()
		_, enc, err := build(id, p)
		if err != nil { // unreachable: every value comes from a snapshot the state checked
			o.log.Error("eventos: transição fora do schema não vira evento", "tipo", string(p.typ), "erro", err.Error())
			continue
		}
		evs = append(evs, built{id: id, enc: enc})
	}
	o.mu.Lock()
	err := o.commitLocked(d, evs)
	o.mu.Unlock()
	if err != nil {
		o.log.Warn("eventos: a observação do ciclo não foi gravada; a próxima coleta compara com a mesma linha de base",
			"erro", err.Error())
		return err
	}
	maps.Copy(o.memo, memo)
	return nil
}

// memoKey identifies what a kind's observation holds: the bytes of its snapshot and the tenants it attributed to. An
// observation with the same key as the last one taken in has nothing new.
func memoKey(ob state.Observed) string {
	return ob.Snapshot.SHA256 + "|" + strings.Join(ob.Tenants, ",")
}

// object is one object of a tracked kind as the transitions read it: its tenant, id and baseline value, and the item
// itself, for the data of its event.
type object struct {
	tenant, id, value string
	item              any
}

// objectsOf decodes the snapshot of a tracked kind (contract.DecodeStrict) into its objects.
func objectsOf(kind contract.StateKind, data []byte) ([]object, error) {
	var out []object
	switch kind {
	case contract.KindTasks:
		var d contract.DataTasks
		if err := contract.DecodeStrict(data, &d); err != nil {
			return nil, err
		}
		for i := range d.Items {
			it := &d.Items[i]
			out = append(out, object{tenant: it.Tenant, id: it.TaskID, value: it.Status, item: it})
		}
	case contract.KindReports:
		var d contract.DataReports
		if err := contract.DecodeStrict(data, &d); err != nil {
			return nil, err
		}
		for i := range d.Items {
			it := &d.Items[i]
			v := ""
			if completed(it) {
				v = valueCompleted
			}
			out = append(out, object{tenant: it.Tenant, id: it.ReportID, value: v, item: it})
		}
	case contract.KindAgents:
		var d contract.DataAgents
		if err := contract.DecodeStrict(data, &d); err != nil {
			return nil, err
		}
		for i := range d.Items {
			it := &d.Items[i]
			v := valueOffline
			if it.Online {
				v = valueOnline
			}
			out = append(out, object{tenant: it.Tenant, id: it.AgentID, value: v, item: it})
		}
	case contract.KindRemediation:
		var d contract.DataRemediation
		if err := contract.DecodeStrict(data, &d); err != nil {
			return nil, err
		}
		for i := range d.Items {
			it := &d.Items[i]
			out = append(out, object{tenant: it.Tenant, id: it.JobID, item: it})
		}
	default:
		return nil, errors.New("kind sem transições")
	}
	return out, nil
}

// completed reports whether a report has reached Done with its scan start and end — what report.completed carries.
func completed(r *contract.ReportItem) bool {
	return r.ScanStatus == "Done" && r.ScanStart != nil && r.ScanEnd != nil
}

// diffKind compares a kind's observation with its baseline and returns the change (nil when there is none) and the
// events of its transitions. By tenant:
//
//   - a tenant attributable now and before: its objects are compared one by one — a new object, or one whose value
//     changed, goes to the baseline and may fire its kind's event (transition); one that vanished leaves the
//     baseline, without event;
//   - a tenant that became attributable (enabled again, registered, given a gvmd user of its own): its objects only
//     enter the baseline — appearing in the list because of the tenant is not a transition of theirs;
//   - a tenant no longer attributable (disabled, removed): its objects leave the baseline without event.
//
// An object listed twice (same tenant and id) is ambiguous: it is left as it was. Without a baseline for the kind, the
// observation only becomes one.
func (o *Outbox) diffKind(kind contract.StateKind, ob state.Observed) (*kindDelta, []pending, error) {
	objs, err := objectsOf(kind, ob.Snapshot.Data)
	if err != nil {
		return nil, nil, err
	}
	var tenants []string // attributable now, sorted (the state sends them sorted; a name outside the rules is left out)
	attributable := map[string]bool{}
	for _, t := range ob.Tenants {
		if state.ValidTenant(t) && !attributable[t] {
			attributable[t] = true
			tenants = append(tenants, t)
		}
	}
	slices.Sort(tenants)
	now := map[string]map[string]object{}
	ambiguous := map[[2]string]bool{}
	for _, obj := range objs {
		if !attributable[obj.tenant] || !validID(kind, obj.id) || !validValue(kind, obj.value) {
			continue // never listed by the state; left out rather than trusted
		}
		m := now[obj.tenant]
		if m == nil {
			m = map[string]object{}
			now[obj.tenant] = m
		}
		if _, dup := m[obj.id]; dup {
			ambiguous[[2]string{obj.tenant, obj.id}] = true
		}
		m[obj.id] = obj
	}
	for k := range ambiguous {
		delete(now[k[0]], k[1])
	}

	kd := &kindDelta{}
	set := func(t string, obj object) { kd.Set = append(kd.Set, entry{Tenant: t, ID: obj.id, Value: obj.value}) }
	old, had := o.base.kinds[kind]
	if !had { // no baseline for the kind yet: the observation only becomes one
		for _, t := range tenants {
			kd.Add = append(kd.Add, t)
			for _, id := range slices.Sorted(maps.Keys(now[t])) {
				set(t, now[t][id])
			}
		}
		return kd, nil, nil
	}
	var ps []pending
	for _, t := range slices.Sorted(maps.Keys(old)) {
		if !attributable[t] {
			kd.Drop = append(kd.Drop, t)
		}
	}
	at := ob.Snapshot.CollectedAt
	for _, t := range tenants {
		prev, kept := old[t]
		cur := now[t]
		if !kept {
			kd.Add = append(kd.Add, t)
			for _, id := range slices.Sorted(maps.Keys(cur)) {
				set(t, cur[id])
			}
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(prev)) {
			if _, ok := cur[id]; !ok && !ambiguous[[2]string{t, id}] {
				kd.Del = append(kd.Del, entry{Tenant: t, ID: id})
			}
		}
		for _, id := range slices.Sorted(maps.Keys(cur)) {
			obj := cur[id]
			pv, seen := prev[id]
			if seen && pv == obj.value {
				continue
			}
			set(t, obj)
			if p, ok := transition(t, obj, pv, seen, at); ok {
				ps = append(ps, p)
			}
		}
	}
	if len(kd.Drop) == 0 && len(kd.Add) == 0 && len(kd.Del) == 0 && len(kd.Set) == 0 {
		return nil, nil, nil
	}
	return kd, ps, nil
}

// transition is the event of an object that is new (seen false) or whose value changed from prev, if its kind has one:
//
//   - tasks: task.status_changed, from the previous status ("" for a new task) to the current one, with the task's
//     last report and progress when the state has them;
//   - reports: report.completed when the report reached Done with its scan start and end (also a report seen for the
//     first time already done), with the summary of counts;
//   - agents: agent.online or agent.offline on a change of the online flag; a new agent online is agent.online, a new
//     agent offline has no event;
//   - remediation: remediation.pending_approval for a new job in PENDING_APPROVAL (a job never changes value: the
//     baseline only holds that it exists).
func transition(tenant string, obj object, prev string, seen bool, at time.Time) (pending, bool) {
	p := pending{tenant: tenant, at: at}
	switch it := obj.item.(type) {
	case *contract.TaskItem:
		from := ""
		if seen {
			from = prev
		}
		p.typ = contract.EventTaskStatusChanged
		p.data = contract.DataTaskStatusChanged{TaskID: it.TaskID, From: from, To: it.Status,
			ReportID: clonePtr(it.LastReportID), Progress: clonePtr(it.Progress)}
	case *contract.ReportItem:
		if obj.value != valueCompleted {
			return pending{}, false
		}
		p.typ = contract.EventReportCompleted
		p.data = contract.DataReportCompleted{ReportID: it.ReportID, TaskID: it.TaskID, ScanStart: *it.ScanStart,
			ScanEnd: *it.ScanEnd, Counts: it.Counts, HostsCount: it.HostsCount}
	case *contract.AgentItem:
		switch {
		case it.Online:
			p.typ = contract.EventAgentOnline
		case seen:
			p.typ = contract.EventAgentOffline
		default:
			return pending{}, false
		}
		p.data = contract.DataAgentPresence{AgentID: it.AgentID, LastSeen: clonePtr(it.LastSeen)}
	case *contract.RemediationItem:
		if seen || it.State != contract.RemediationPendingApproval {
			return pending{}, false
		}
		p.typ = contract.EventRemediationPendingApproval
		p.data = contract.DataRemediationPending{JobID: it.JobID, AgentID: it.AgentID, Type: it.Type,
			CreatedAt: it.CreatedAt, ExpiresAt: clonePtr(it.ExpiresAt)}
	default:
		return pending{}, false
	}
	return p, true
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// diffFeeds compares the feeds of the node's observation with their baseline and returns the new baseline (nil when
// nothing changed) and the events: feed.updated when a feed's version is not the one last seen (without
// previous_version for a feed never seen), feed.stale when its age passes the threshold (FLEET_FEED_STALE_HOURS) — once
// per passage: the flag stays while the age is above it. A feed absent from the observation, or listed twice
// (ambiguous), keeps its baseline. Without a baseline for the feeds, the observation only becomes one.
func (o *Outbox) diffFeeds(ob state.Observed) (*feedsDelta, []pending, error) {
	var node contract.DataNode
	if err := contract.DecodeStrict(ob.Snapshot.Data, &node); err != nil {
		return nil, nil, err
	}
	byType := map[contract.FeedType][]contract.FeedStatus{}
	for _, f := range node.Feeds {
		byType[f.Feed] = append(byType[f.Feed], f)
	}
	first := o.base.feeds == nil
	marks := maps.Clone(o.base.feeds)
	if first {
		marks = map[contract.FeedType]feedMark{}
	}
	var ps []pending
	at := ob.Snapshot.CollectedAt
	for _, ft := range feedTypes {
		fs := byType[ft]
		if len(fs) != 1 {
			continue
		}
		f := fs[0]
		if !state.ValidVersion(f.Version) || !(f.AgeHours >= 0) || math.IsInf(f.AgeHours, 0) {
			continue // never in a node the state built; left out rather than trusted
		}
		stale := f.AgeHours > float64(o.staleAfter)
		m, had := marks[ft]
		marks[ft] = feedMark{Version: f.Version, Stale: stale}
		if first {
			continue
		}
		if !had || m.Version != f.Version {
			d := contract.DataFeedUpdated{Feed: ft, Version: f.Version}
			if had {
				d.PreviousVersion = clonePtr(&m.Version)
			}
			ps = append(ps, pending{typ: contract.EventFeedUpdated, at: at, data: d})
		}
		if stale && !(had && m.Stale) {
			ps = append(ps, pending{typ: contract.EventFeedStale, at: at, data: contract.DataFeedStale{Feed: ft,
				Version: f.Version, AgeHours: f.AgeHours, StaleAfterHours: int64(o.staleAfter)}})
		}
	}
	if !first && maps.Equal(marks, o.base.feeds) {
		return nil, nil, nil
	}
	return &feedsDelta{Marks: marks}, ps, nil
}
