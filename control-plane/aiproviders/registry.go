package aiproviders

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sentinel errors the service maps to HTTP status codes.
var (
	ErrNotFound   = errors.New("provedor não encontrado")
	ErrGovernance = errors.New("provedor fora da régua (exige UE + ZDR para habilitar)")
	ErrValidation = errors.New("configuração de provedor inválida")
)

// Registry is the persisted set of configured providers. Writes are serialized and
// persisted atomically (temp+rename, 0600); the API key is encrypted with kek.
type Registry struct {
	mu        sync.Mutex
	path      string
	kek       []byte
	providers map[string]*Provider
	now       func() time.Time
	newID     func() string
}

// NewRegistry loads the store from path (missing file = fresh). kek is the host
// key-encryption-key (see LoadOrCreateKEK).
func NewRegistry(path string, kek []byte) (*Registry, error) {
	r := &Registry{
		path:      path,
		kek:       kek,
		providers: map[string]*Provider{},
		now:       time.Now,
		newID:     randID,
	}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("ler ai-providers %s: %w", path, err)
	}
	var list []*Provider
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("ai-providers %s corrompido: %w", path, err)
	}
	for _, p := range list {
		r.providers[p.ID] = p
	}
	return r, nil
}

// UpsertInput is the operator-supplied config. APIKey == "" on an update keeps the
// stored key (metadata-only change); on a create it means "no key yet".
type UpsertInput struct {
	ID       string
	Name     string
	Kind     string
	BaseURL  string
	Model    string
	EURegion bool
	ZDR      bool
	Enabled  bool
	APIKey   string
}

// Upsert creates or updates a provider and persists it. The API key is encrypted
// before storage and never returned. A provider may be ENABLED only if it meets the
// governance bar (EU region + ZDR).
func (r *Registry) Upsert(in UpsertInput, by string) (PublicProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	if in.Name == "" {
		return PublicProvider{}, fmt.Errorf("%w: name obrigatório", ErrValidation)
	}
	if !validKind(in.Kind) {
		return PublicProvider{}, fmt.Errorf("%w: kind %q (esperado openrouter|openai_compatible)", ErrValidation, in.Kind)
	}
	if in.Kind == KindOpenRouter && in.BaseURL == "" {
		in.BaseURL = "https://openrouter.ai/api/v1"
	}
	if err := validateBaseURL(in.BaseURL); err != nil {
		return PublicProvider{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	// Governance (decision #3): enabling a provider that is not EU-region AND ZDR
	// would route attested data to a processor outside the privacy contract. Allow
	// it to be STORED (disabled) but never ENABLED.
	if in.Enabled && (!in.EURegion || !in.ZDR) {
		return PublicProvider{}, ErrGovernance
	}

	var p *Provider
	if in.ID != "" {
		p = r.providers[in.ID]
		if p == nil {
			return PublicProvider{}, ErrNotFound
		}
	} else {
		p = &Provider{ID: r.newID()}
		r.providers[p.ID] = p
	}
	p.Name, p.Kind, p.BaseURL, p.Model = in.Name, in.Kind, in.BaseURL, in.Model
	p.EURegion, p.ZDR, p.Enabled = in.EURegion, in.ZDR, in.Enabled
	p.UpdatedBy, p.UpdatedAt = by, r.now()
	if in.APIKey != "" {
		ct, err := encrypt(r.kek, []byte(in.APIKey))
		if err != nil {
			return PublicProvider{}, fmt.Errorf("cifrar chave: %w", err)
		}
		p.KeyCipher = ct
		p.KeyLast4 = last4(in.APIKey)
	}
	if err := r.saveLocked(); err != nil {
		return PublicProvider{}, err
	}
	return p.Public(), nil
}

// List returns all providers (key-free), ordered by name then id for stability.
func (r *Registry) List() []PublicProvider {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PublicProvider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Public())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one provider (key-free).
func (r *Registry) Get(id string) (PublicProvider, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[id]
	if !ok {
		return PublicProvider{}, false
	}
	return p.Public(), true
}

// Delete removes a provider, returning whether it existed.
func (r *Registry) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[id]; !ok {
		return false
	}
	delete(r.providers, id)
	_ = r.saveLocked()
	return true
}

// DecryptedKey returns the plaintext API key and the (key-free) provider for an
// ENABLED provider. SERVER-SIDE ONLY — it is never reachable through the HTTP API;
// only an in-process consumer (the planner) calls it.
func (r *Registry) DecryptedKey(id string) (string, PublicProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[id]
	if !ok {
		return "", PublicProvider{}, ErrNotFound
	}
	if !p.Enabled {
		return "", p.Public(), errors.New("provedor desabilitado")
	}
	if len(p.KeyCipher) == 0 {
		return "", p.Public(), errors.New("provedor sem chave configurada")
	}
	key, err := decrypt(r.kek, p.KeyCipher)
	if err != nil {
		return "", p.Public(), fmt.Errorf("decifrar chave: %w", err)
	}
	return string(key), p.Public(), nil
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*Provider, 0, len(r.providers))
	for _, p := range r.providers {
		list = append(list, p)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(list); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validateBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("base_url deve ser uma URL https:// absoluta")
	}
	return nil
}
