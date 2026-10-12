package tenant

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// record is one element of TENANTS_FILE: control-plane/tenants.Record as the control-plane writes it. name and
// enabled are required; the others may be absent (empty = no scope, no gvmd user), which is the safe reading.
// updated_at is accepted and unused.
type record struct {
	Name      string `json:"name"`
	Scope     string `json:"scope,omitzero"`
	GmpUser   string `json:"gmp_user,omitzero"`
	Enabled   bool   `json:"enabled"`
	UpdatedAt string `json:"updated_at,omitzero"`
}

// parseRegistry decodes TENANTS_FILE strictly. A tenant name that appears twice makes the whole file unusable:
// the control-plane (last wins) and the ingest loader (first wins) disagree on such a file, and the fleet does not
// pick a side — the control-plane never writes one (Put upserts by name).
func parseRegistry(data []byte) ([]record, error) {
	var list []record
	if err := contract.DecodeStrict(data, &list); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(list))
	for _, r := range list {
		if r.Name == "" {
			continue // never matches the tenant of an envelope (schema: at least one character)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("tenant %.64q repetido no registro", r.Name)
		}
		seen[r.Name] = true
	}
	return list, nil
}

// central is the source of a central node: the control-plane's registry and the per-tenant secrets file.
type central struct {
	tenantsFile string
	secretsFile string
}

func (c *central) Resolve(name string, typ contract.CommandType) (Standing, error) {
	e, err := c.lookup(name)
	if err != nil {
		return Standing{}, err
	}
	return admit(e, typ, func() (string, error) { return c.password(name) })
}

func (c *central) Credentials(name string) (Credentials, error) {
	e, err := c.lookup(name)
	if err != nil {
		return Credentials{}, err
	}
	return credentials(e, func() (string, error) { return c.password(name) })
}

// lookup reads the registry now. A registry file that does not exist knows no tenant.
func (c *central) lookup(name string) (entry, error) {
	recs, err := c.records()
	if err != nil {
		return entry{}, err
	}
	if name == "" {
		return entry{}, nil
	}
	for _, r := range recs {
		if r.Name == name {
			return entry{found: true, enabled: r.Enabled, scope: r.Scope, gvmUser: r.GmpUser}, nil
		}
	}
	return entry{}, nil
}

// records reads the registry now: nil when the file does not exist.
func (c *central) records() ([]record, error) {
	data, err := fsutil.ReadBounded(c.tenantsFile, maxRegistryBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: ler registro %s: %w", c.tenantsFile, err)
	}
	recs, err := parseRegistry(data)
	if err != nil {
		return nil, fmt.Errorf("tenant: registro %s: %w", c.tenantsFile, err)
	}
	return recs, nil
}

func (c *central) List() ([]Listing, error) {
	recs, err := c.records()
	if err != nil {
		return nil, err
	}
	out := make([]Listing, 0, len(recs))
	for _, r := range recs {
		out = append(out, Listing{Name: r.Name, Enabled: r.Enabled, Scope: r.Scope, GVMUser: r.GmpUser})
	}
	return out, nil
}

func (c *central) WithPassword() (map[string]bool, error) {
	secrets, err := c.secrets()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(secrets))
	for name, pw := range secrets {
		if pw != "" {
			out[name] = true
		}
	}
	return out, nil
}

// password reads the secrets file now and returns the tenant's password, "" if there is none: no path, no file,
// or no entry. A file that exists and cannot be read or parsed is an error, and so is an entry that is not a
// string. The error text carries member names at most, never a value.
func (c *central) password(name string) (string, error) {
	secrets, err := c.secrets()
	if err != nil {
		return "", err
	}
	return secrets[name], nil
}

// secrets reads the whole secrets file now: nil when there is no path or no file (see password for the errors).
func (c *central) secrets() (map[string]string, error) {
	if c.secretsFile == "" {
		return nil, nil
	}
	data, err := fsutil.ReadBounded(c.secretsFile, maxSecretsBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: ler segredos %s: %w", c.secretsFile, err)
	}
	var secrets map[string]string
	if err := contract.DecodeStrict(data, &secrets); err != nil {
		return nil, fmt.Errorf("tenant: segredos %s: %w", c.secretsFile, err)
	}
	return secrets, nil
}

func (c *central) SecretFileWarnings() []string {
	return secretFileWarnings("SENSOR_TENANT_SECRETS", c.secretsFile, fsutil.LooseMode)
}
