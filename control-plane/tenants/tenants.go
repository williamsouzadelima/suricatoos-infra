// Package tenants is the authoritative registry of Suricatoos tenants and their
// internal-scan authorization (ADR-0007): each tenant has an allowed scope (CIDRs)
// and a scoped gvmd user that owns its partition of the central gvmd. It is the
// source of truth the sensor-job dispatch (scope-gate) and the sensor-report
// import (host re-validation + tenant gvmd user) consult. Secrets (the gvmd
// password) live elsewhere — this registry holds only non-secret routing config,
// so it can be safely shared (e.g. a read-only file) with the ingest service.
package tenants

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Record is one tenant's routing/authorization config.
type Record struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`    // comma/space-separated authorized CIDRs
	GmpUser   string    `json:"gmp_user"` // scoped gvmd user (role=User), NOT admin
	Enabled   bool      `json:"enabled"`  // false → deny-all (dispatch + import)
	UpdatedAt time.Time `json:"updated_at"`
}

// Registry is a persistent tenant store (atomic temp+rename writes).
type Registry struct {
	mu      sync.RWMutex
	path    string
	tenants map[string]*Record
	now     func() time.Time
}

// NewRegistry loads the registry from path (missing file = empty).
func NewRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, tenants: map[string]*Record{}, now: time.Now}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("ler tenants %s: %w", path, err)
	}
	var list []*Record
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("tenants %s corrompido: %w", path, err)
	}
	for _, t := range list {
		r.tenants[t.Name] = t
	}
	return r, nil
}

// Put upserts a tenant and persists.
func (r *Registry) Put(rec Record) error {
	if rec.Name == "" {
		return fmt.Errorf("tenant sem nome")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.UpdatedAt = r.now().UTC()
	cp := rec
	r.tenants[rec.Name] = &cp
	return r.saveLocked()
}

// Get returns a tenant record.
func (r *Registry) Get(name string) (Record, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tenants[name]
	if !ok {
		return Record{}, false
	}
	return *t, true
}

// List returns all tenants, sorted by name.
func (r *Registry) List() []Record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Record, 0, len(r.tenants))
	for _, t := range r.tenants {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Known reports whether name is an ENABLED tenant (the partition-key check for
// sensor authz — a disabled/unknown tenant is denied).
func (r *Registry) Known(name string) bool {
	t, ok := r.Get(name)
	return ok && t.Enabled
}

// ScopeSpec returns the tenant's authorized CIDR spec, or "" (deny-all) when the
// tenant is unknown or disabled.
func (r *Registry) ScopeSpec(name string) string {
	t, ok := r.Get(name)
	if !ok || !t.Enabled {
		return ""
	}
	return t.Scope
}

// GmpUser returns the tenant's scoped gvmd user ("" when unknown/disabled).
func (r *Registry) GmpUser(name string) string {
	t, ok := r.Get(name)
	if !ok || !t.Enabled {
		return ""
	}
	return t.GmpUser
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*Record, 0, len(r.tenants))
	for _, t := range r.tenants {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
