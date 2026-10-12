// Package policy reads the LOCAL policy of the fleet connector: FLEET_STATE_DIR/policy.json (ADR-0011, "Catálogo
// de comandos v1" → "Regras transversais" → "Política local"). The file is edited only by the node's operator;
// the connector never writes it and no command can change it.
//
//	{"allow": ["state.resync", ...], "sensitive_per_hour": 30, "total_per_hour": 120}
//
// Without the file the policy is contract.DefaultPolicy(node_kind). With the file, it is exactly what the file
// says, and a file that is present but cannot be used is an ERROR — never a silent fall back to the default: a
// typo in an edit that tightens the policy must not leave the looser one (or the default) in force.
//
// There is no cache. Load reads the file every time it is called (a few hundred bytes) and the caller asks once
// per command, so an edit takes effect on the next command and nothing can go stale; the returned SHA256 is
// what the caller compares with the previous one to notice a change (the policy_changed audit event is the
// caller's: slice F2.4c).
package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// FileName is the policy file inside FLEET_STATE_DIR.
const FileName = "policy.json"

// The bounds of the numeric members, copied from the schema (fleet-state.schema.json
// #/$defs/data_node/properties/policy); a test compares them with the schema file.
const (
	MinPerHour          = 0
	MaxSensitivePerHour = 1000
	MaxTotalPerHour     = 3600
)

// maxFileBytes bounds the read: the largest valid policy (22 types, any whitespace a person types) is a few KiB.
const maxFileBytes = 64 << 10

// ErrInvalid is wrapped by every error about the CONTENT of a policy file (syntax, shape, catalog, bounds). A
// file that cannot be read at all is a plain I/O error.
var ErrInvalid = errors.New("política local inválida")

// Snapshot is the policy in force at one read.
type Snapshot struct {
	Policy contract.Policy
	// SHA256 is contract.PolicySHA256(Policy): the data_node.policy_sha256 the hub recomputes.
	SHA256 string
	// FromFile is false when there is no policy.json and Policy is the default of the node kind.
	FromFile bool
}

// Load returns the policy in force for a node of the given kind, reading stateDir/policy.json:
//
//   - no such file: the default policy of kind (FromFile false);
//   - a valid file: its policy (FromFile true);
//   - a file that is present but unreadable, too big, not a regular file or invalid: an error and an EMPTY
//     Snapshot. The connector does not start with it, and at reload the caller answers unavailable.
//
// A type in allow that the node kind does not support is valid in the file: line 7 answers unsupported before
// it looks at allow.
func Load(stateDir string, kind contract.NodeKind) (Snapshot, error) {
	if stateDir == "" {
		return Snapshot{}, errors.New("policy: FLEET_STATE_DIR vazio")
	}
	if !slices.Contains([]contract.NodeKind{contract.NodeCentral, contract.NodeStandalone, contract.NodeSensor}, kind) {
		return Snapshot{}, fmt.Errorf("policy: node_kind %.64q inválido", kind)
	}
	path := filepath.Join(stateDir, FileName)
	data, err := fsutil.ReadBounded(path, maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		p := contract.DefaultPolicy(kind)
		return Snapshot{Policy: p, SHA256: contract.PolicySHA256(p)}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("policy: ler %s: %w", path, err)
	}
	p, err := parse(data)
	if err != nil {
		return Snapshot{}, fmt.Errorf("policy: %s: %w", path, err)
	}
	return Snapshot{Policy: p, SHA256: contract.PolicySHA256(p), FromFile: true}, nil
}

// parse decodes and validates the bytes of a policy.json: strict JSON (ADR "Codificação JSON": no duplicate
// member, no unknown member, case-exact names, no null, integers only) and then the constraints of the schema.
// Every error wraps ErrInvalid.
func parse(data []byte) (contract.Policy, error) {
	var p contract.Policy
	if err := contract.DecodeStrict(data, &p); err != nil {
		return contract.Policy{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := validate(p); err != nil {
		return contract.Policy{}, err
	}
	return p, nil
}

// validate applies the constraints of fleet-state.schema.json#/$defs/data_node/properties/policy that the
// strict decode does not: every item of allow is a command_type of the v1 catalog and none repeats, and the two
// budgets are inside the schema's bounds.
func validate(p contract.Policy) error {
	seen := make(map[contract.CommandType]bool, len(p.Allow))
	for i, t := range p.Allow {
		if _, ok := contract.LookupType(t); !ok {
			return fmt.Errorf("%w: allow[%d] %.64q não é um tipo do catálogo v1", ErrInvalid, i, t)
		}
		if seen[t] {
			return fmt.Errorf("%w: allow repete %s", ErrInvalid, t) // t is a catalog type here: safe to print
		}
		seen[t] = true
	}
	if p.SensitivePerHour < MinPerHour || p.SensitivePerHour > MaxSensitivePerHour {
		return fmt.Errorf("%w: sensitive_per_hour %d fora de %d–%d", ErrInvalid, p.SensitivePerHour, MinPerHour, MaxSensitivePerHour)
	}
	if p.TotalPerHour < MinPerHour || p.TotalPerHour > MaxTotalPerHour {
		return fmt.Errorf("%w: total_per_hour %d fora de %d–%d", ErrInvalid, p.TotalPerHour, MinPerHour, MaxTotalPerHour)
	}
	return nil
}

// Missing returns the first type that a command of type typ needs in allow and does not find there, and true;
// it returns "" and false when nothing is missing, i.e. the policy allows the command. A command needs its own
// type; schedule.create that carries task_ids also needs task.modify, because linking a task to the new
// schedule is a task modification (ADR "Catálogo": schedule.create).
func Missing(p contract.Policy, typ contract.CommandType, linksTasks bool) (contract.CommandType, bool) {
	if !slices.Contains(p.Allow, typ) {
		return typ, true
	}
	if typ == contract.TypeScheduleCreate && linksTasks && !slices.Contains(p.Allow, contract.TypeTaskModify) {
		return contract.TypeTaskModify, true
	}
	return "", false
}

// Allows reports whether the policy allows a command of type typ (see Missing).
func Allows(p contract.Policy, typ contract.CommandType, linksTasks bool) bool {
	_, missing := Missing(p, typ, linksTasks)
	return !missing
}
