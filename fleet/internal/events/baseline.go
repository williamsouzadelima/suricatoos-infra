package events

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/state"
)

// trackedKinds are the state kinds whose objects have transitions, in the order their events take.
var trackedKinds = []contract.StateKind{contract.KindTasks, contract.KindReports, contract.KindAgents,
	contract.KindRemediation}

// kindsOf returns the tracked kinds that exist on a node kind (state.KindsOf: agents and remediation only on the
// central node), in trackedKinds' order.
func kindsOf(k contract.NodeKind) []contract.StateKind {
	all := state.KindsOf(k)
	var out []contract.StateKind
	for _, kind := range trackedKinds {
		if slices.Contains(all, kind) {
			out = append(out, kind)
		}
	}
	return out
}

// The value the baseline keeps of each object — the minimum its transitions need.
const (
	// reports: "completed" once the report reached Done with its scan start and end (report.completed went, or the
	// report was taken in without an event); "" before that
	valueCompleted = "completed"
	// agents: the online flag of the ingest
	valueOnline  = "online"
	valueOffline = "offline"
	// tasks keep their gvmd status; remediation jobs only their existence (value "")
)

// validID reports whether id is an object id of kind.
func validID(kind contract.StateKind, id string) bool {
	switch kind {
	case contract.KindTasks, contract.KindReports:
		return state.ValidUUID(id)
	case contract.KindAgents:
		return state.ValidAgentID(id)
	case contract.KindRemediation:
		return state.ValidJobID(id)
	}
	return false
}

// validValue reports whether v is a value the baseline keeps for an object of kind.
func validValue(kind contract.StateKind, v string) bool {
	switch kind {
	case contract.KindTasks:
		return state.ValidGVMStatus(v)
	case contract.KindReports:
		return v == "" || v == valueCompleted
	case contract.KindAgents:
		return v == valueOnline || v == valueOffline
	case contract.KindRemediation:
		return v == ""
	}
	return false
}

// baseline is what the transitions compare the next observation with: per tracked kind, the tenants it attributed
// objects to and, for each, the value of each object; and the version and stale flag of each feed. A kind (or the
// feeds) without an entry has no baseline yet: its next observation only records one, without events.
type baseline struct {
	kinds map[contract.StateKind]map[string]map[string]string // kind → tenant → object id → value
	feeds map[contract.FeedType]feedMark                      // nil: the feeds have no baseline yet
}

func newBaseline() *baseline {
	return &baseline{kinds: map[contract.StateKind]map[string]map[string]string{}}
}

// feedMark is what the baseline keeps of a feed: its version and whether feed.stale already went in the current
// passage over the threshold.
type feedMark struct {
	Version string `json:"version"`
	Stale   bool   `json:"stale"`
}

// delta is a change of the baseline, as one record of the log carries it. A kind present in Kinds has a baseline
// after it, even when its kindDelta is empty (the first observation of a kind with nothing in it); Feeds, when present,
// replaces the feeds' baseline whole.
type delta struct {
	Kinds map[contract.StateKind]*kindDelta `json:"kinds,omitzero"`
	Feeds *feedsDelta                       `json:"feeds,omitzero"`
}

// kindDelta is the change of one kind, applied in this order: Drop (tenants that left, with their objects), Add
// (tenants that came, empty), Del (objects that vanished), Set (objects that are new or changed).
type kindDelta struct {
	Drop []string `json:"drop,omitzero"`
	Add  []string `json:"add,omitzero"`
	Del  []entry  `json:"del,omitzero"`
	Set  []entry  `json:"set,omitzero"`
}

// entry is one object of a kindDelta.
type entry struct {
	Tenant string `json:"tenant"`
	ID     string `json:"id"`
	Value  string `json:"value,omitzero"`
}

// feedsDelta is the feeds' whole baseline.
type feedsDelta struct {
	Marks map[contract.FeedType]feedMark `json:"marks"`
}

func (d *delta) empty() bool { return d == nil || (len(d.Kinds) == 0 && d.Feeds == nil) }

// check reports whether d applies to b, for a node whose tracked kinds are kinds: every kind tracked, every tenant,
// id and value valid; a dropped tenant or deleted object that exists, an added tenant that does not; every set object
// inside a tenant that exists once the adds are in, with no object twice. Only a checked delta is applied, and
// applying it cannot fail.
func (b *baseline) check(d *delta, kinds []contract.StateKind) error {
	for kind, kd := range d.Kinds {
		if !slices.Contains(kinds, kind) {
			return fmt.Errorf("kind %.32q sem transições neste nó", kind)
		}
		if kd == nil {
			return fmt.Errorf("%s: mudança vazia", kind)
		}
		if err := checkKind(kind, b.kinds[kind], kd); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
	}
	if d.Feeds != nil {
		if d.Feeds.Marks == nil {
			return errors.New("feeds sem marcas")
		}
		for feed, m := range d.Feeds.Marks {
			if !oneOf(feed, feedTypes...) || !state.ValidVersion(m.Version) {
				return fmt.Errorf("feed %.32q fora do schema", feed)
			}
		}
	}
	return nil
}

func checkKind(kind contract.StateKind, cur map[string]map[string]string, kd *kindDelta) error {
	dropped := map[string]bool{}
	for _, t := range kd.Drop {
		if _, ok := cur[t]; !ok || dropped[t] {
			return fmt.Errorf("tenant %.64q tirado sem estar na base", t)
		}
		dropped[t] = true
	}
	added := map[string]bool{}
	for _, t := range kd.Add {
		if _, ok := cur[t]; ok || added[t] || !state.ValidTenant(t) {
			return fmt.Errorf("tenant %.64q posto que já está na base ou inválido", t)
		}
		added[t] = true
	}
	deleted := map[[2]string]bool{}
	for _, e := range kd.Del {
		k := [2]string{e.Tenant, e.ID}
		if _, ok := cur[e.Tenant][e.ID]; !ok || dropped[e.Tenant] || deleted[k] || e.Value != "" {
			return fmt.Errorf("objeto %.64q tirado sem estar na base", e.ID)
		}
		deleted[k] = true
	}
	set := map[[2]string]bool{}
	for _, e := range kd.Set {
		k := [2]string{e.Tenant, e.ID}
		_, kept := cur[e.Tenant]
		inside := added[e.Tenant] || (kept && !dropped[e.Tenant])
		if !inside || set[k] || deleted[k] || !validID(kind, e.ID) || !validValue(kind, e.Value) {
			return fmt.Errorf("objeto %.64q posto fora de um tenant da base ou inválido", e.ID)
		}
		set[k] = true
	}
	return nil
}

// apply applies a delta that check accepted.
func (b *baseline) apply(d *delta) {
	for kind, kd := range d.Kinds {
		cur := b.kinds[kind]
		if cur == nil {
			cur = map[string]map[string]string{}
			b.kinds[kind] = cur
		}
		for _, t := range kd.Drop {
			delete(cur, t)
		}
		for _, t := range kd.Add {
			cur[t] = map[string]string{}
		}
		for _, e := range kd.Del {
			delete(cur[e.Tenant], e.ID)
		}
		for _, e := range kd.Set {
			cur[e.Tenant][e.ID] = e.Value
		}
	}
	if d.Feeds != nil {
		b.feeds = maps.Clone(d.Feeds.Marks)
	}
}

// full is the delta that builds b from an empty baseline: what a rewrite of the log writes. Tenants and objects go in
// order, so the same baseline always gives the same bytes.
func (b *baseline) full() *delta {
	d := &delta{}
	if len(b.kinds) > 0 {
		d.Kinds = map[contract.StateKind]*kindDelta{}
	}
	for kind, tenants := range b.kinds {
		kd := &kindDelta{}
		for _, t := range slices.Sorted(maps.Keys(tenants)) {
			kd.Add = append(kd.Add, t)
			for _, id := range slices.Sorted(maps.Keys(tenants[t])) {
				kd.Set = append(kd.Set, entry{Tenant: t, ID: id, Value: tenants[t][id]})
			}
		}
		d.Kinds[kind] = kd
	}
	if b.feeds != nil {
		d.Feeds = &feedsDelta{Marks: maps.Clone(b.feeds)}
	}
	return d
}

// prune forgets the kinds that have no transitions on this node (a FLEET_STATE_DIR that changed node kind).
func (b *baseline) prune(kinds []contract.StateKind) {
	for kind := range b.kinds {
		if !slices.Contains(kinds, kind) {
			delete(b.kinds, kind)
		}
	}
}
