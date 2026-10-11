package aiproviders

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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

// Sentinel errors the service maps to HTTP status codes (ErrFreeOnly: free.go).
var (
	ErrNotFound   = errors.New("provedor não encontrado")
	ErrGovernance = errors.New("provedor fora da régua: habilitar exige UE + ZDR, ou modelo gratuito com ciência da política de dados (data_policy_ack)")
	ErrValidation = errors.New("configuração de provedor inválida")
	// ErrNotOfficialEndpoint: the models listing only queries the routers' official
	// endpoints (models.go). Mapped to HTTP 422.
	ErrNotOfficialEndpoint = errors.New("a lista de modelos só consulta o endpoint oficial do OpenRouter/UnoRouter")
)

// Registry is the persisted set of configured providers. Writes are serialized and
// persisted atomically (temp+rename, 0600); the API key is encrypted with kek.
type Registry struct {
	mu        sync.Mutex
	path      string
	kek       []byte
	freeOnly  bool // AI_FREE_MODELS_ONLY: only free models of openrouter/unorouter
	providers map[string]*Provider
	now       func() time.Time
	newID     func() string
}

// Option configures a Registry.
type Option func(*Registry)

// WithFreeModelsOnly turns the free-models-only rule on or off (free.go). The
// control-plane turns it on by default (AI_FREE_MODELS_ONLY); a Registry built
// without this option keeps the rule off.
func WithFreeModelsOnly(on bool) Option {
	return func(r *Registry) { r.freeOnly = on }
}

// NewRegistry loads the store from path (missing file = fresh). kek is the host
// key-encryption-key (see LoadOrCreateKEK).
func NewRegistry(path string, kek []byte, opts ...Option) (*Registry, error) {
	r := &Registry{
		path:      path,
		kek:       kek,
		providers: map[string]*Provider{},
		now:       time.Now,
		newID:     randID,
	}
	for _, o := range opts {
		o(r)
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
// DataPolicyAck is the operator's acknowledgment of a free model's data policy;
// who/when are recorded by the server (Upsert's by + clock), never supplied here.
type UpsertInput struct {
	ID            string
	Name          string
	Kind          string
	BaseURL       string
	Model         string
	EURegion      bool
	ZDR           bool
	Enabled       bool
	DataPolicyAck bool
	APIKey        string
}

// Upsert creates or updates a provider and persists it. The API key is encrypted
// before storage and never returned. With the free-models-only rule on, only the
// openrouter/unorouter kinds and only free models are accepted (ErrFreeOnly). A
// provider may be ENABLED only if it meets the governance bar: (EU region && ZDR)
// || (free model && data-policy acknowledgment).
func (r *Registry) Upsert(in UpsertInput, by string) (PublicProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	in.Model = strings.TrimSpace(in.Model)
	if in.Name == "" {
		return PublicProvider{}, fmt.Errorf("%w: name obrigatório", ErrValidation)
	}
	if !validKind(in.Kind) {
		return PublicProvider{}, fmt.Errorf("%w: kind %q (esperado openrouter|unorouter|openai_compatible)", ErrValidation, in.Kind)
	}
	free := IsFreeModel(in.Kind, in.Model)
	if r.freeOnly {
		// Zero-cost contract: neither a generic gateway nor a paid model may even be
		// stored while the rule is on (a stored one could be enabled later).
		if !freeOnlyKind(in.Kind) {
			return PublicProvider{}, fmt.Errorf("%w: tipo %q não permitido — use openrouter ou unorouter", ErrFreeOnly, in.Kind)
		}
		// The endpoint is FIXED by the kind: any base_url in the request is ignored
		// and the router's official API is stored. Otherwise anyone who can save a
		// provider could repoint one that already holds a key at a host they control
		// and have the server send that write-only key there.
		in.BaseURL = OfficialBaseURL(in.Kind)
		if !free {
			if in.Model == "" {
				return PublicProvider{}, fmt.Errorf("%w: informe um modelo gratuito (%s)", ErrFreeOnly, FreeRule)
			}
			return PublicProvider{}, fmt.Errorf("%w: modelo %q não é gratuito (%s)", ErrFreeOnly, in.Model, FreeRule)
		}
	}
	if in.BaseURL == "" {
		in.BaseURL = defaultBaseURL(in.Kind) // preset for named routers; "" for openai_compatible
	}
	if err := validateBaseURL(in.BaseURL); err != nil {
		return PublicProvider{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	// Governance (decision #3): enabling a provider outside the privacy contract
	// would route attested data to a processor that may retain it. Allow it to be
	// STORED (disabled) but never ENABLED unless it is EU-region AND ZDR, or it is a
	// FREE model whose data policy (may log/train on prompts) the operator has
	// explicitly acknowledged. The planner only ever sends pseudonymized data.
	if in.Enabled && !((in.EURegion && in.ZDR) || (free && in.DataPolicyAck)) {
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
	now := r.now()
	p.Name, p.Kind, p.BaseURL, p.Model = in.Name, in.Kind, in.BaseURL, in.Model
	p.EURegion, p.ZDR, p.Enabled = in.EURegion, in.ZDR, in.Enabled
	p.UpdatedBy, p.UpdatedAt = by, now
	switch {
	case !in.DataPolicyAck:
		p.DataPolicyAck, p.DataPolicyAckBy, p.DataPolicyAckAt = false, "", time.Time{}
	case !p.DataPolicyAck:
		// A new acknowledgment: record who gave it and when. While it stays given,
		// later edits do not rewrite who acknowledged.
		p.DataPolicyAck, p.DataPolicyAckBy, p.DataPolicyAckAt = true, by, now
	}
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

// FreeModelsOnly reports whether the free-models-only rule is on.
func (r *Registry) FreeModelsOnly() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.freeOnly
}

// catalogSource is what the free-models listing needs to query a provider's catalog.
type catalogSource struct {
	kind    string
	baseURL string
	key     string // plaintext; "" when none is stored. NEVER returned or logged.
	sig     string // changes whenever kind, endpoint or key changes (cache validity)
}

// modelsSource returns the catalog endpoint and the decrypted key of provider id.
// Unlike DecryptedKey it does NOT require the provider to be enabled: the operator
// lists the models to PICK one before enabling. SERVER-SIDE ONLY — the key goes
// only to the router's OFFICIAL /models, never into a response.
//
// The listing is reachable from a session, so it queries ONLY a router's official
// endpoint, whatever the rule: a provider stored with another base_url (a generic
// gateway, a custom endpoint saved with the rule off, or one stored before the
// rule) is refused (ErrNotOfficialEndpoint) without any request. Otherwise saving
// a provider with a chosen base_url and listing its models would send the stored
// key — or a server-side request — to any host.
func (r *Registry) modelsSource(id string) (catalogSource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[id]
	if !ok {
		return catalogSource{}, ErrNotFound
	}
	official := OfficialBaseURL(p.Kind)
	if official == "" {
		return catalogSource{}, fmt.Errorf("%w (tipo %q)", ErrNotOfficialEndpoint, p.Kind)
	}
	if !IsOfficialEndpoint(p.Kind, p.BaseURL) {
		hint := ""
		if r.freeOnly {
			hint = " — salve o provedor de novo para fixá-la (com só modelos gratuitos a base vem do tipo)"
		}
		return catalogSource{}, fmt.Errorf("%w: base_url %q não é %s%s", ErrNotOfficialEndpoint, p.BaseURL, official, hint)
	}
	src := catalogSource{kind: p.Kind, baseURL: official}
	keySig := "sem-chave"
	if len(p.KeyCipher) > 0 {
		key, err := decrypt(r.kek, p.KeyCipher)
		if err != nil {
			return catalogSource{}, fmt.Errorf("decifrar chave: %w", err)
		}
		src.key = string(key)
		sum := sha256.Sum256(p.KeyCipher) // fingerprint of the CIPHERTEXT (random nonce), not of the key
		keySig = hex.EncodeToString(sum[:8])
	}
	src.sig = p.Kind + "\x00" + p.BaseURL + "\x00" + keySig
	return src, nil
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
