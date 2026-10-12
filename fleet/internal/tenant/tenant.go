// Package tenant is what the fleet connector knows about the tenants of its node: the check of verification line 6
// of ADR-0011 ("tenant conhecido e habilitado no nó; escrita exige também usuário gvmd + segredo do tenant", reason
// tenant_unknown), the scope of each tenant as TEXT, and the gvmd credentials the executor will need.
//
// Two sources, picked by node kind (Open):
//
//   - central: the registry TENANTS_FILE (a JSON array of the control-plane/tenants Record: name, scope, gmp_user,
//     enabled, updated_at) and the secrets file SENSOR_TENANT_SECRETS (a JSON object {tenant: password});
//   - standalone and sensor: the single local tenant FLEET_TENANT, with FLEET_SCAN_SCOPE, FLEET_TENANT_GMP_USER and
//     the password in the file FLEET_TENANT_GMP_PASSWORD_FILE.
//
// The module fleet does not import control-plane, so this package reads the registry on its own. The format is
// guarded by a shared fixture (testdata/tenants.json), read by a test on each side. The reader is strict, like
// the rest of the contract (an unknown member is an error): a field the control-plane starts to honor and the
// fleet ignores could otherwise let a command through that the control-plane would refuse.
//
// Nothing is cached: every call reads the files again (they are small and a command arrives every few seconds
// at most), so a tenant the control-plane just disabled, or a password the operator just rotated, counts on the
// next command. What a file cannot tell is an ERROR, never a verdict: an unreadable, oversized or malformed
// registry, or a malformed secrets file when a write needs it, returns an error and the caller answers
// unavailable (deferred), exactly as for any local dependency that failed. Plain absence is a verdict: no
// registry file means no known tenant, no secrets file or no entry in it means no password.
//
// # Where the password goes
//
// The password never sits in the Source or in a Standing, never appears in an error, a log or a JSON, and
// Resolve only checks that one exists. The single way out of the package is Credentials: it reads the secret
// at that moment and returns it inside a Secret, which prints as "[redacted]" with every fmt verb, as JSON and
// as text. The executor (slice F2.6) calls Secret.Reveal at the one place where it authenticates to gvmd.
package tenant

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Why says why a tenant failed line 6 (Standing.Why). It is for the audit detail; the reason of the rejection is
// tenant_unknown in every case.
type Why string

const (
	// WhyUnknown: not in the registry (central) / not FLEET_TENANT (standalone, sensor).
	WhyUnknown Why = "unknown"
	// WhyDisabled: in the registry, with enabled=false.
	WhyDisabled Why = "disabled"
	// WhyNoGVMUser: a command that runs as the tenant's gvmd user, and the tenant has no gvmd user configured.
	WhyNoGVMUser Why = "no_gvm_user"
	// WhyNoSecret: same, and there is no password for that user.
	WhyNoSecret Why = "no_secret"
)

// Standing is the answer of line 6 for one tenant and one command type.
type Standing struct {
	// OK: the tenant is known and enabled here, and — for a type that runs as the tenant's gvmd user — has a gvmd
	// user and a password.
	OK bool
	// Why is empty when OK.
	Why Why
	// Scope is the tenant's scope as text (CIDRs separated by commas or spaces, as the registry or
	// FLEET_SCAN_SCOPE hold it), set whenever the tenant is known AND enabled — also when OK is false because of
	// the missing gvmd user or password. It is not interpreted here: the scope gate (F2.4a) does that. An unknown
	// or disabled tenant has no scope ("" = deny all).
	Scope string
}

// Credentials are the gvmd user of a tenant and its password.
type Credentials struct {
	User     string
	Password Secret
}

// ErrNoCredentials: the tenant is unknown or disabled, or has no gvmd user, or no password.
var ErrNoCredentials = errors.New("tenant: sem credenciais gvmd (usuário e senha) para o tenant")

// Source is the tenant knowledge of one node.
type Source interface {
	// Resolve answers line 6 for a command of type typ addressed to the tenant name. The password file is read
	// only for the types that run as the tenant's gvmd user (RunsAs). A non-nil error means the node could not
	// read what it needs: the verdict is "unavailable", not tenant_unknown.
	Resolve(name string, typ contract.CommandType) (Standing, error)
	// Credentials returns the gvmd user and password of tenant name, read now. ErrNoCredentials when it has
	// none; any other error is a read failure.
	Credentials(name string) (Credentials, error)
}

// Config is the environment of the node that this package reads (ADR "Configuração do nó"). Open uses the
// fields of its node kind and ignores the others.
type Config struct {
	// central
	TenantsFile string // TENANTS_FILE
	SecretsFile string // SENSOR_TENANT_SECRETS (may be empty: no tenant has a password)

	// standalone and sensor
	Tenant          string // FLEET_TENANT
	Scope           string // FLEET_SCAN_SCOPE
	GVMUser         string // FLEET_TENANT_GMP_USER
	GVMPasswordFile string // FLEET_TENANT_GMP_PASSWORD_FILE
}

var tenantName = regexp.MustCompile(contract.PatternTenant)

// Caps on what is read: a registry of thousands of tenants is a few hundred KiB, and a password file a few bytes.
const (
	maxRegistryBytes     = 4 << 20 // TENANTS_FILE
	maxSecretsBytes      = 1 << 20 // SENSOR_TENANT_SECRETS
	maxPasswordFileBytes = 4 << 10 // FLEET_TENANT_GMP_PASSWORD_FILE
)

// Open builds the Source of a node of the given kind. It fails on a configuration the node cannot run with: a
// central node without TENANTS_FILE, or a standalone/sensor node without a valid FLEET_TENANT (a name the
// schema would accept in a command).
func Open(kind contract.NodeKind, cfg Config) (Source, error) {
	switch kind {
	case contract.NodeCentral:
		if cfg.TenantsFile == "" {
			return nil, errors.New("tenant: TENANTS_FILE é obrigatório no nó central")
		}
		return &central{tenantsFile: cfg.TenantsFile, secretsFile: cfg.SecretsFile}, nil
	case contract.NodeStandalone, contract.NodeSensor:
		if !tenantName.MatchString(cfg.Tenant) {
			return nil, fmt.Errorf("tenant: FLEET_TENANT %.64q inválido (padrão %s)", cfg.Tenant, contract.PatternTenant)
		}
		return &local{tenant: cfg.Tenant, scope: cfg.Scope, gvmUser: cfg.GVMUser, passwordFile: cfg.GVMPasswordFile}, nil
	}
	return nil, fmt.Errorf("tenant: node_kind %.64q inválido", kind)
}

// entry is a tenant as one of the sources found it.
type entry struct {
	found   bool
	enabled bool
	scope   string
	gvmUser string
}

// admit is the rule of line 6, shared by both sources. secret reads the tenant's password ("" = none); it runs
// only when the command type needs it.
func admit(e entry, typ contract.CommandType, secret func() (string, error)) (Standing, error) {
	switch {
	case !e.found:
		return Standing{Why: WhyUnknown}, nil
	case !e.enabled:
		return Standing{Why: WhyDisabled}, nil
	}
	st := Standing{Scope: e.scope}
	if RunsAs(typ) == UserTenant {
		if e.gvmUser == "" {
			st.Why = WhyNoGVMUser
			return st, nil
		}
		pw, err := secret()
		if err != nil {
			return Standing{}, err
		}
		if pw == "" {
			st.Why = WhyNoSecret
			return st, nil
		}
	}
	st.OK = true
	return st, nil
}

// credentials is Credentials for both sources.
func credentials(e entry, secret func() (string, error)) (Credentials, error) {
	if !e.found || !e.enabled || e.gvmUser == "" {
		return Credentials{}, ErrNoCredentials
	}
	pw, err := secret()
	if err != nil {
		return Credentials{}, err
	}
	if pw == "" {
		return Credentials{}, ErrNoCredentials
	}
	return Credentials{User: e.gvmUser, Password: newSecret(pw)}, nil
}
