package state

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sync"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// SentFileName is the file inside FLEET_STATE_DIR that remembers, per kind, the last content_sha256 the hub
// accepted, so that a restart does not send again what the hub already has.
const SentFileName = "state-sent.json"

const (
	sentFileVersion  = 1
	maxSentFileBytes = 64 << 10 // the file is ~1 KiB
)

// allKinds is fleet-state.schema.json#/$defs/state_kind, in the schema's order.
var allKinds = []contract.StateKind{contract.KindNode, contract.KindTasks, contract.KindTargets,
	contract.KindSchedules, contract.KindReports, contract.KindAgents, contract.KindTokens, contract.KindSensors,
	contract.KindScanRequests, contract.KindRemediation, contract.KindScope, contract.KindAuditTail}

// centralOnly are the kinds that exist only on the central node (the schema's state_kind description).
var centralOnly = map[contract.StateKind]bool{contract.KindAgents: true, contract.KindTokens: true,
	contract.KindSensors: true, contract.KindScanRequests: true, contract.KindRemediation: true}

// KindsOf returns the state kinds of a node kind, in the schema's order: every kind on the central node; on
// standalone and sensor all but agents, tokens, sensors, scan_requests and remediation. nil for an invalid kind.
func KindsOf(k contract.NodeKind) []contract.StateKind {
	switch k {
	case contract.NodeCentral:
		return slices.Clone(allKinds)
	case contract.NodeStandalone, contract.NodeSensor:
		var out []contract.StateKind
		for _, kind := range allKinds {
			if !centralOnly[kind] {
				out = append(out, kind)
			}
		}
		return out
	}
	return nil
}

// Recovery is what Open found in FLEET_STATE_DIR/state-sent.json.
type Recovery struct {
	// Lost says why a file that existed could not be used (unreadable, too big, not the expected JSON, a kind or a
	// hash that is not one). It was ignored: every kind counts as never sent and goes again — the safe direction,
	// since a snapshot the hub already has costs one PUT, while a snapshot taken for sent would leave the hub stale
	// until a heartbeat noticed. nil when the file was read, or did not exist.
	Lost error
}

// sentFile is the content of state-sent.json.
type sentFile struct {
	Version int               `json:"version"`
	Sent    map[string]string `json:"sent"`
}

// tracker is the "send only when it changes" bookkeeping (ADR-0011 "Estado"): the current snapshot of each kind,
// the last error of its collection and the last content_sha256 the hub accepted. The truth is the memory; the file
// is a cache of the accepted hashes for the next start, rewritten whole (fsutil.WriteAtomic) whenever they change.
// A tracker is safe for concurrent use.
type tracker struct {
	path  string
	kinds []contract.StateKind
	write func(path string, data []byte) error // fsutil.WriteAtomic; a field only so that a test can fail it

	mu      sync.Mutex
	current map[contract.StateKind]Snapshot
	errs    map[contract.StateKind]error
	sent    map[contract.StateKind]string
	dirty   bool // the file is behind the memory: the last write failed
}

// openTracker reads stateDir/state-sent.json for a node with the given kinds. A file that cannot be used is no
// error (Recovery.Lost, everything is sent again); only an empty stateDir is. It also removes the temporaries an
// interrupted write of this file left behind (only those: the directory holds the other state files too).
func openTracker(stateDir string, kinds []contract.StateKind) (*tracker, Recovery, error) {
	if stateDir == "" {
		return nil, Recovery{}, errors.New("state: FLEET_STATE_DIR vazio")
	}
	t := &tracker{
		path:    filepath.Join(stateDir, SentFileName),
		kinds:   slices.Clone(kinds),
		write:   fsutil.WriteAtomic,
		current: map[contract.StateKind]Snapshot{},
		errs:    map[contract.StateKind]error{},
		sent:    map[contract.StateKind]string{},
	}
	_, _ = fsutil.RemoveOrphanTemps(t.path) // best effort: a leftover only takes space
	var rec Recovery
	sent, err := t.read()
	if err != nil {
		rec.Lost = err
		return t, rec, nil
	}
	for kind, hash := range sent {
		if slices.Contains(t.kinds, kind) {
			t.sent[kind] = hash
		}
	}
	return t, rec, nil
}

// read loads the accepted hashes of the file; a file that does not exist is an empty map.
func (t *tracker) read() (map[contract.StateKind]string, error) {
	data, err := fsutil.ReadBounded(t.path, maxSentFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: ler %s: %w", t.path, err)
	}
	var f sentFile
	if err := contract.DecodeStrict(data, &f); err != nil {
		return nil, fmt.Errorf("state: %s: %w", t.path, err)
	}
	if f.Version != sentFileVersion {
		return nil, fmt.Errorf("state: %s: versão %d desconhecida", t.path, f.Version)
	}
	out := make(map[contract.StateKind]string, len(f.Sent))
	for k, hash := range f.Sent {
		kind := contract.StateKind(k)
		if !slices.Contains(allKinds, kind) || !ruleSHA256.ok(hash) {
			return nil, fmt.Errorf("state: %s: entrada %.64q inválida", t.path, k)
		}
		out[kind] = hash
	}
	return out, nil
}

// update records a successful collection: the kind's current snapshot, and no error.
func (t *tracker) update(s Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current[s.Kind] = s
	delete(t.errs, s.Kind)
}

// fail records a failed collection: the kind keeps its last snapshot, if any, and exposes the error.
func (t *tracker) fail(kind contract.StateKind, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errs[kind] = err
}

// pending lists, in the schema's order, the kinds that have a current snapshot the hub has not accepted: its hash
// differs from the last accepted one, or there is none (never sent, or a resync forgot it).
func (t *tracker) pending() []contract.StateKind {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []contract.StateKind
	for _, kind := range t.kinds {
		if s, ok := t.current[kind]; ok && t.sent[kind] != s.SHA256 {
			out = append(out, kind)
		}
	}
	return out
}

// snapshot returns the kind's current snapshot, with its own copy of the bytes.
func (t *tracker) snapshot(kind contract.StateKind) (Snapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.current[kind]
	if ok {
		s.Data = bytes.Clone(s.Data)
	}
	return s, ok
}

// beginSend comes BEFORE every PUT of kind: it makes the file stop saying that the hub has a snapshot of kind —
// it drops the kind's accepted hash and rewrites the file —, so that a hub that accepts the PUT while the process
// then dies (or its mark is lost) can never leave behind a file that suppresses a needed resend (the A→B→A case:
// the file says A, B goes and is accepted, the mark of B is lost, the state goes back to A — without this, A would
// not be pending after a restart while the hub holds B). Only after it returned nil may the PUT go; an error — a
// write that failed or was not confirmed (fsutil.ErrNotDurable) — means not now: the kind stays pending and a later
// beginSend rewrites the file before saying yes. It writes only when there is something to drop or the file is
// behind the memory: one atomic write per change sent, then markSent restores the entry with the new hash.
func (t *tracker) beginSend(kind contract.StateKind) error {
	if !slices.Contains(t.kinds, kind) {
		return fmt.Errorf("state: kind %.64q não existe neste nó", kind)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, had := t.sent[kind]; !had && !t.dirty {
		return nil
	}
	delete(t.sent, kind)
	return t.persistLocked()
}

// markSent records that the hub accepted (2xx) the snapshot of kind whose content_sha256 is hash. The memory moves
// at once — the hub has it, whatever the disk says —; then the file is rewritten. A write that fails (ErrNotDurable
// included) is returned and leaves the file behind: the next write (flush, every cycle) redoes it whole, and until
// then a restart would only send the kind again.
func (t *tracker) markSent(kind contract.StateKind, hash string) error {
	if !slices.Contains(t.kinds, kind) {
		return fmt.Errorf("state: kind %.64q não existe neste nó", kind)
	}
	if !ruleSHA256.ok(hash) {
		return errors.New("state: content_sha256 inválido")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sent[kind] == hash && !t.dirty {
		return nil
	}
	t.sent[kind] = hash
	return t.persistLocked()
}

// resync forgets what the hub accepted of the kinds asked for (heartbeat resync, state.resync), so each goes
// again with its current snapshot — or with the first one, when it has none yet. It returns, deduplicated and in
// the schema's order, the kinds of this node among those asked for; any other is ignored (ADR "Catálogo":
// "kind inexistente no nó é ignorado"). The memory moves at once; an error means only that the file is behind.
func (t *tracker) resync(kinds []contract.StateKind) ([]contract.StateKind, error) {
	var out []contract.StateKind
	for _, kind := range t.kinds {
		if slices.Contains(kinds, kind) {
			out = append(out, kind)
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for _, kind := range out {
		if _, ok := t.sent[kind]; ok {
			delete(t.sent, kind)
			changed = true
		}
	}
	if !changed && !t.dirty {
		return out, nil
	}
	return out, t.persistLocked()
}

// flush rewrites the file if a previous write failed.
func (t *tracker) flush() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty {
		return nil
	}
	return t.persistLocked()
}

func (t *tracker) persistLocked() error {
	f := sentFile{Version: sentFileVersion, Sent: make(map[string]string, len(t.sent))}
	for kind, hash := range t.sent {
		f.Sent[string(kind)] = hash
	}
	data, err := contract.MarshalCompact(f)
	if err == nil {
		err = t.write(t.path, data)
	}
	if err != nil {
		t.dirty = true
		return fmt.Errorf("state: gravar %s: %w", t.path, err)
	}
	t.dirty = false
	return nil
}

// hashes returns the content_sha256 of every kind's current snapshot (the heartbeat's state_hashes).
func (t *tracker) hashes() map[contract.StateKind]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[contract.StateKind]string, len(t.current))
	for kind, s := range t.current {
		out[kind] = s.SHA256
	}
	return out
}

// errors returns the kinds whose last collection failed, with the error.
func (t *tracker) errors() map[contract.StateKind]error {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[contract.StateKind]error, len(t.errs))
	for kind, err := range t.errs {
		out[kind] = err
	}
	return out
}
