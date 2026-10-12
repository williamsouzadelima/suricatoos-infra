package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fleetops"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// Runner runs one fleet_ops.py request (*fleetops.Runner has it).
type Runner interface {
	Run(ctx context.Context, request any, user, password string) (fleetops.Result, error)
}

var (
	_ Runner = (*fleetops.Runner)(nil)
	_ GVM    = (*Bridge)(nil)
)

// maxPasswordFileBytes bounds the read of FLEET_GMP_PASSWORD_FILE (a password is a few bytes).
const maxPasswordFileBytes = 4 << 10

// Bridge is the GVM of the state over gmp-bridge/fleet_ops.py (slice F2.3): each read is one exec of its state.*
// op — {"op", "command_id": "", "owners", "payload": {}} for the lists, {"op", "command_id": "", "payload"} for
// state.node —, run as the node's CURRENT gvmd user (ADR-0011 D6: the user with Super over the tenants' users).
// The password is read from FLEET_GMP_PASSWORD_FILE at every call, so a rotation counts at the next read, and it
// goes only to the Runner (the child's environment). The answer is decoded strictly into the contract's type: a
// member the contract does not have — a comment, a hostname list, a finding — fails the read; it is never dropped
// in silence, and never reaches the state.
type Bridge struct {
	Runner       Runner
	User         string // FLEET_GMP_USER
	PasswordFile string // FLEET_GMP_PASSWORD_FILE
}

type stateListRequest struct {
	Op        string            `json:"op"`
	CommandID string            `json:"command_id"`
	Owners    map[string]string `json:"owners"`
	Payload   struct{}          `json:"payload"`
}

type stateNodeRequest struct {
	Op        string      `json:"op"`
	CommandID string      `json:"command_id"`
	Payload   NodeRequest `json:"payload"`
}

// Node is fleet_ops' state.node.
func (b *Bridge) Node(ctx context.Context, req NodeRequest) (contract.DataNode, error) {
	var out contract.DataNode
	return out, b.call(ctx, stateNodeRequest{Op: "state.node", Payload: req}, &out)
}

// Tasks is fleet_ops' state.tasks.
func (b *Bridge) Tasks(ctx context.Context, owners map[string]string) (contract.DataTasks, error) {
	var out contract.DataTasks
	return out, b.list(ctx, "state.tasks", owners, &out)
}

// Targets is fleet_ops' state.targets.
func (b *Bridge) Targets(ctx context.Context, owners map[string]string) (contract.DataTargets, error) {
	var out contract.DataTargets
	return out, b.list(ctx, "state.targets", owners, &out)
}

// Schedules is fleet_ops' state.schedules.
func (b *Bridge) Schedules(ctx context.Context, owners map[string]string) (contract.DataSchedules, error) {
	var out contract.DataSchedules
	return out, b.list(ctx, "state.schedules", owners, &out)
}

// Reports is fleet_ops' state.reports.
func (b *Bridge) Reports(ctx context.Context, owners map[string]string) (contract.DataReports, error) {
	var out contract.DataReports
	return out, b.list(ctx, "state.reports", owners, &out)
}

func (b *Bridge) list(ctx context.Context, op string, owners map[string]string, out any) error {
	if owners == nil {
		owners = map[string]string{} // fleet_ops wants an object, never null
	}
	return b.call(ctx, stateListRequest{Op: op, Owners: owners}, out)
}

func (b *Bridge) call(ctx context.Context, req any, out any) error {
	op := opOf(req)
	if b.Runner == nil || b.User == "" {
		return fmt.Errorf("state: %s: fleet_ops sem executor ou sem FLEET_GMP_USER", op)
	}
	password, err := readPassword(b.PasswordFile)
	if err != nil {
		return fmt.Errorf("state: %s: %w", op, err)
	}
	res, err := b.Runner.Run(ctx, req, b.User, password)
	if err != nil {
		return fmt.Errorf("state: %s: %w", op, err)
	}
	if res.Artifact != nil {
		return fmt.Errorf("state: %s: resposta com artifact", op)
	}
	if err := contract.DecodeStrict(res.Output, out); err != nil {
		return fmt.Errorf("state: %s: resposta fora do contrato: %w", op, err)
	}
	return nil
}

func opOf(req any) string {
	switch r := req.(type) {
	case stateListRequest:
		return r.Op
	case stateNodeRequest:
		return r.Op
	}
	return "?"
}

// readPassword reads FLEET_GMP_PASSWORD_FILE now. The line break at the end (`echo senha > arquivo`) is not part of
// the password; spaces anywhere are. No path, no file or nothing but line breaks is an error — fleet_ops needs both
// user and password —, and no error carries anything read from the file.
func readPassword(path string) (string, error) {
	if path == "" {
		return "", errors.New("FLEET_GMP_PASSWORD_FILE não configurado")
	}
	data, err := fsutil.ReadBounded(path, maxPasswordFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("FLEET_GMP_PASSWORD_FILE %s ausente", path)
	}
	if err != nil {
		return "", fmt.Errorf("ler FLEET_GMP_PASSWORD_FILE %s: %w", path, err)
	}
	pw := strings.TrimRight(string(data), "\r\n")
	if pw == "" {
		return "", fmt.Errorf("FLEET_GMP_PASSWORD_FILE %s vazio", path)
	}
	return pw, nil
}
