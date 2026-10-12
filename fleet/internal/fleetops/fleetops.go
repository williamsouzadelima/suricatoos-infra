// Package fleetops runs gmp-bridge/fleet_ops.py (ADR-0011, slice F2.3) — the GVM half of the fleet catalog, the
// inspect.* reads of the scope gate and the state.* reads — from the Go connector. The protocol is fleet_ops.py's
// own (its module docstring is normative here):
//
//   - ONE exec per call: the interpreter and the script (Runner.Command) and nothing else in argv;
//   - stdin: ONE compact JSON object, the request (contract.MarshalCompact: UTF-8, no BOM, no HTML escaping), at most
//     MaxRequestBytes — fleet_ops' own cap;
//   - stdout: ONE JSON object — {"ok": true, "output": {...}} (report.export adds "artifact") or {"ok": false,
//     "error": {"code", "message"}} — read under a cap (Runner.MaxOutput) and decoded strictly (contract.DecodeStrict:
//     one value, no duplicate or unknown member, case-exact names), with the shape checked: ok carries output and no
//     error, a failure carries error and nothing else;
//   - exit 0 for every handled outcome, 1 for an unexpected failure (still one JSON error on stdout).
//
// # Credentials
//
// The gvmd user and password go ONLY in the child's environment (GMP_USERNAME, GMP_PASSWORD), never in argv, a
// log or an error. The environment is minimal and explicit — those two and GVMD_SOCKET when set — and never the
// connector's own: the ingest container, for one, exports GMP_USERNAME=admin. (On Windows os/exec adds SYSTEMROOT,
// without which no process starts there.) The child's stderr is discarded, unread: nothing it writes can reach a
// log. The message of a structured error is fleet_ops' own (it redacts the password first); Run redacts it once more,
// replaces control characters and cuts it to MaxMessageRunes, so an Error never carries the password whatever the
// child wrote.
//
// # Failures
//
// Every failure is an *Error whose Code is a contract.ErrorCode: the child's own code when it answered with a valid
// error; timeout when Runner.Timeout ran out (the process is killed); interrupted when the caller's context ended
// first; unavailable when the process could not be started; internal_error for everything else — output over the
// cap (the process is killed at once), output outside the protocol, an error code outside the contract, a request
// the connector should never build (too big, no user or password, a NUL).
package fleetops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const (
	// DefaultTimeout is the ADR's per-call ceiling for reads and operations (120 s); fleet_ops' own gvmd socket
	// timeout (110 s) sits below it, so a slow gvmd is reported by the child as timeout before it is killed.
	// report.summary and report.export (5 and 15 min) set their own Timeout.
	DefaultTimeout = 120 * time.Second
	// DefaultMaxOutput bounds what is read from stdout. The largest answer fleet_ops can legitimately give is a
	// state list at its item caps: 2 000 schedules with an 8 192-character iCalendar and 256 task ids each (~86 MB
	// in the worst encoding), or 5 000 targets with 256 hosts each (~64 MB). The cap sits above that, so a valid
	// answer is never refused — the state cuts it to its 16 MiB itself — and a runaway child cannot grow the
	// connector's memory without bound.
	DefaultMaxOutput = 128 << 20
	// MaxRequestBytes is fleet_ops' MAX_REQUEST_BYTES: a bigger request is refused here, before any exec.
	MaxRequestBytes = 1 << 20
	// MaxMessageRunes is the schema's cap on error.message (fleet-result.schema.json#/$defs/error).
	MaxMessageRunes = 512

	// waitDelay bounds how long Wait waits for the I/O of a child that was killed.
	waitDelay = 2 * time.Second
)

// Runner execs fleet_ops.py. Its fields are configuration only; it holds no credential and is safe for concurrent
// use (each call is its own process).
type Runner struct {
	// Command is the argv that runs fleet_ops.py, e.g. ["/usr/bin/python3", "-I", "/opt/gmp-bridge/fleet_ops.py"].
	// Nothing is ever appended to it.
	Command []string
	// Socket is GVMD_SOCKET for the child; empty leaves fleet_ops' default (/run/gvmd/gvmd.sock).
	Socket string
	// Timeout is the ceiling of one call, the process killed when it runs out; zero means DefaultTimeout.
	Timeout time.Duration
	// MaxOutput is the cap on stdout in bytes; zero means DefaultMaxOutput.
	MaxOutput int64
}

// Result is a successful answer: the raw "output" object (fleet-result output_<op>, a fleet-state data_<kind> or
// an inspect.* view), byte for byte as the child wrote it, and the "artifact" object of report.export (nil for every
// other op).
type Result struct {
	Output   json.RawMessage
	Artifact json.RawMessage
}

// Error is a failed call. Message is short, bounded, free of control characters and never carries the password.
type Error struct {
	Code    contract.ErrorCode
	Message string
}

func (e *Error) Error() string { return "fleet_ops: " + string(e.Code) + ": " + e.Message }

// errorCodes are fleet-result.schema.json#/$defs/error_code (a test compares them with the schema file).
var errorCodes = map[contract.ErrorCode]bool{
	contract.ErrorNotFound: true, contract.ErrorConflict: true, contract.ErrorGVM: true, contract.ErrorTimeout: true,
	contract.ErrorInterrupted: true, contract.ErrorUnavailable: true, contract.ErrorArtifactTooLarge: true,
	contract.ErrorArtifactUploadFailed: true, contract.ErrorSecretLost: true, contract.ErrorInternal: true,
}

type response struct {
	OK       bool            `json:"ok"`
	Output   json.RawMessage `json:"output,omitzero"`
	Error    *responseError  `json:"error,omitzero"`
	Artifact json.RawMessage `json:"artifact,omitzero"`
}

type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func fail(code contract.ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Run sends request (any value contract.MarshalCompact serializes into a JSON object: one struct per request
// shape, as fleet_ops refuses an unknown key) to a new fleet_ops process authenticated as user/password, and
// returns its answer. See the package documentation for the protocol and the failures.
func (r *Runner) Run(ctx context.Context, request any, user, password string) (Result, error) {
	if len(r.Command) == 0 || r.Command[0] == "" {
		return Result{}, fail(contract.ErrorInternal, "Command do fleet_ops vazio")
	}
	if user == "" || password == "" {
		return Result{}, fail(contract.ErrorInternal, "usuário e senha gvmd são obrigatórios")
	}
	if strings.ContainsRune(user, 0) || strings.ContainsRune(password, 0) || strings.ContainsRune(r.Socket, 0) {
		return Result{}, fail(contract.ErrorInternal, "credencial ou socket com NUL")
	}
	req, err := contract.MarshalCompact(request)
	if err != nil {
		return Result{}, fail(contract.ErrorInternal, "pedido ao fleet_ops não serializa")
	}
	if len(req) > MaxRequestBytes {
		return Result{}, fail(contract.ErrorInternal, "pedido ao fleet_ops acima do teto de %d bytes", MaxRequestBytes)
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	limit := r.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	run, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(run, r.Command[0], r.Command[1:]...)
	cmd.Env = []string{"GMP_USERNAME=" + user, "GMP_PASSWORD=" + password}
	if r.Socket != "" {
		cmd.Env = append(cmd.Env, "GVMD_SOCKET="+r.Socket)
	}
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stderr = nil // the null device: never read, never logged
	cmd.WaitDelay = waitDelay
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fail(contract.ErrorInternal, "pipe do fleet_ops: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return Result{}, fail(contract.ErrorUnavailable, "não foi possível executar o fleet_ops: %v", err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(out)) > limit {
		cancel() // kills the child: nobody reads the rest
		_ = cmd.Wait()
		return Result{}, fail(contract.ErrorInternal, "saída do fleet_ops acima do teto de %d bytes", limit)
	}
	waitErr := cmd.Wait()

	switch {
	case ctx.Err() != nil:
		return Result{}, fail(contract.ErrorInterrupted, "execução do fleet_ops interrompida")
	case errors.Is(run.Err(), context.DeadlineExceeded):
		return Result{}, fail(contract.ErrorTimeout, "o fleet_ops não respondeu em %s", timeout)
	case readErr != nil && waitErr == nil:
		return Result{}, fail(contract.ErrorInternal, "leitura da saída do fleet_ops falhou")
	}
	return decode(out, waitErr, password)
}

// decode reads the one JSON object of the child's stdout. waitErr is how the process ended.
func decode(out []byte, waitErr error, password string) (Result, error) {
	var resp response
	if err := contract.DecodeStrict(out, &resp); err != nil {
		if waitErr != nil {
			return Result{}, fail(contract.ErrorInternal, "o fleet_ops terminou com erro (%s) sem resposta válida",
				exitText(waitErr))
		}
		return Result{}, fail(contract.ErrorInternal, "resposta do fleet_ops fora do protocolo")
	}
	switch {
	case resp.OK && resp.Output != nil && resp.Error == nil && waitErr == nil:
		return Result{Output: resp.Output, Artifact: resp.Artifact}, nil
	case !resp.OK && resp.Error != nil && resp.Output == nil && resp.Artifact == nil:
		code := contract.ErrorCode(resp.Error.Code)
		if !errorCodes[code] {
			return Result{}, fail(contract.ErrorInternal, "o fleet_ops devolveu um código de erro fora do contrato")
		}
		return Result{}, &Error{Code: code, Message: sanitize(resp.Error.Message, password)}
	}
	return Result{}, fail(contract.ErrorInternal, "resposta do fleet_ops fora do protocolo")
}

// exitText is the bounded description of how the child ended (an exit status or a signal, never its output).
func exitText(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ProcessState.String()
	}
	return "falha de espera"
}

// sanitize makes a message from the child safe to log and to report: the password redacted FIRST (so no cut can
// leave a piece of it), control characters and U+FFFE/U+FFFF replaced by spaces, invalid UTF-8 replaced, trimmed and
// cut to MaxMessageRunes.
func sanitize(msg, password string) string {
	if password != "" {
		msg = strings.ReplaceAll(msg, password, "[redacted]")
	}
	msg = strings.ToValidUTF8(msg, string(utf8.RuneError))
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffe || r == 0xffff {
			return ' '
		}
		return r
	}, msg)
	msg = strings.TrimSpace(msg)
	if utf8.RuneCountInString(msg) > MaxMessageRunes {
		msg = strings.TrimSpace(string([]rune(msg)[:MaxMessageRunes]))
	}
	if msg == "" {
		return "erro sem detalhe"
	}
	return msg
}
