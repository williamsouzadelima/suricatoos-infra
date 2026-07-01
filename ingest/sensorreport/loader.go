package sensorreport

import (
	"encoding/json"
	"os"
)

// FileResolver builds a TenantResolver from two host-mounted files:
//   - tenantsPath: the NON-SECRET tenant registry the control-plane writes
//     (control-plane/tenants) — a JSON array of {name, scope, gmp_user, enabled}.
//     ingest reads it read-only (it can't import the control-plane module).
//   - secretsPath: a SECRET JSON object {tenant: gvmd_password} kept out of the
//     registry so passwords never live in the shared, less-guarded tenants file.
//
// Both files are re-read on each Resolve (sensor reports are infrequent, not a hot
// path), so an operator's tenant/scope/password change takes effect without an
// ingest restart.
type FileResolver struct {
	tenantsPath string
	secretsPath string
}

// NewFileResolver returns a resolver over the two files.
func NewFileResolver(tenantsPath, secretsPath string) *FileResolver {
	return &FileResolver{tenantsPath: tenantsPath, secretsPath: secretsPath}
}

// tenantRecord mirrors control-plane/tenants.Record (the fields ingest needs).
type tenantRecord struct {
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	GmpUser string `json:"gmp_user"`
	Enabled bool   `json:"enabled"`
}

// Resolve implements TenantResolver: it returns the tenant's config (scope +
// scoped gvmd user + password), or ok=false when the tenant is unknown, disabled,
// has an empty/invalid scope, or is missing a password secret.
func (f *FileResolver) Resolve(tenant string) (TenantConfig, bool) {
	rec, ok := f.lookup(tenant)
	if !ok || !rec.Enabled || rec.GmpUser == "" {
		return TenantConfig{}, false
	}
	sc, err := NewScope(rec.Scope)
	if err != nil || sc == nil || len(sc.nets) == 0 {
		return TenantConfig{}, false // no/invalid scope → deny (never import unbounded)
	}
	pw, ok := f.password(tenant)
	if !ok || pw == "" {
		return TenantConfig{}, false
	}
	return TenantConfig{GmpUsername: rec.GmpUser, GmpPassword: pw, Scope: sc}, true
}

func (f *FileResolver) lookup(tenant string) (tenantRecord, bool) {
	b, err := os.ReadFile(f.tenantsPath)
	if err != nil {
		return tenantRecord{}, false
	}
	var list []tenantRecord
	if json.Unmarshal(b, &list) != nil {
		return tenantRecord{}, false
	}
	for _, r := range list {
		if r.Name == tenant {
			return r, true
		}
	}
	return tenantRecord{}, false
}

func (f *FileResolver) password(tenant string) (string, bool) {
	if f.secretsPath == "" {
		return "", false
	}
	b, err := os.ReadFile(f.secretsPath)
	if err != nil {
		return "", false
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return "", false
	}
	pw, ok := m[tenant]
	return pw, ok
}
