package tenant

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// local is the source of a standalone or sensor node: one tenant, from the environment. It is never disabled.
type local struct {
	tenant       string // FLEET_TENANT
	scope        string // FLEET_SCAN_SCOPE
	gvmUser      string // FLEET_TENANT_GMP_USER
	passwordFile string // FLEET_TENANT_GMP_PASSWORD_FILE
}

func (l *local) Resolve(name string, typ contract.CommandType) (Standing, error) {
	return admit(l.lookup(name), typ, l.password)
}

func (l *local) Credentials(name string) (Credentials, error) {
	return credentials(l.lookup(name), l.password)
}

func (l *local) lookup(name string) entry {
	if name == "" || name != l.tenant {
		return entry{}
	}
	return entry{found: true, enabled: true, scope: l.scope, gvmUser: l.gvmUser}
}

// password reads the password file now: "" when there is no path or no such file or nothing but line breaks in
// it; an error when the file exists and cannot be read. The line break at the end (`echo senha > arquivo`) is
// not part of the password; spaces anywhere are.
func (l *local) password() (string, error) {
	if l.passwordFile == "" {
		return "", nil
	}
	data, err := fsutil.ReadBounded(l.passwordFile, maxPasswordFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("tenant: ler a senha em %s: %w", l.passwordFile, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}
