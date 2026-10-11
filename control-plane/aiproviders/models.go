package aiproviders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// modelsTimeout bounds one catalog query to the provider.
	modelsTimeout = 10 * time.Second
	// modelsMaxBody caps the catalog body read from the provider.
	modelsMaxBody = 8 << 20
	// modelsCacheTTL is how long a provider's free-model list is served from memory.
	modelsCacheTTL = 10 * time.Minute
	// msgPasteKey answers (409) a listing that needs a key when none is stored.
	msgPasteKey = "cole a chave para listar os modelos"
)

// ModelInfo is one FREE model of a provider's live catalog, for the UI's selector.
type ModelInfo struct {
	ID            string `json:"id"`
	ContextLength int    `json:"context_length,omitempty"` // omitted when the provider does not say
	// JSONSchema: the provider lists "structured_outputs" among the model's
	// supported_parameters (response_format json_schema). JSONSchemaKnown is false
	// when the provider does not inform supported_parameters at all — JSONSchema is
	// then false meaning "unknown", not "unsupported".
	JSONSchema      bool `json:"json_schema"`
	JSONSchemaKnown bool `json:"json_schema_known"`
}

// Policy is the AI-config policy the UI adapts to (e.g. hiding the generic
// OpenAI-compatible kind and offering the presets).
type Policy struct {
	FreeModelsOnly bool     `json:"free_models_only"`
	FreeRule       string   `json:"free_rule"`
	Presets        []string `json:"presets"`
}

type modelsCacheEntry struct {
	sig    string
	at     time.Time
	models []ModelInfo
}

// upstreamError is a provider-side failure of a catalog query. msg is short and
// safe to return (502); cause is detail for the server log only. Neither carries
// the key: it travels only in the Authorization header of the outbound request.
type upstreamError struct {
	msg   string
	cause error
}

func (e *upstreamError) Error() string { return e.msg }

// newModelsClient builds the outbound client for catalog queries: bounded by
// modelsTimeout and following NO redirect (a 3xx is answered as a provider error,
// so a redirect can never take the server-side request elsewhere). rt == nil uses
// the default transport.
func newModelsClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: rt,
		Timeout:   modelsTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// doModels lists the FREE models of provider {id} from its live catalog
// (<base_url>/models), queried server-side with the stored key when there is one.
func (s *Service) doModels(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	src, err := s.reg.modelsSource(id)
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "erro interno", http.StatusInternalServerError)
		return
	}
	// Only OpenRouter's catalog is public; UnoRouter (and a generic gateway)
	// refuses /models without a key, so do not even call it.
	if src.key == "" && src.kind != KindOpenRouter {
		writeJSON(w, http.StatusConflict, map[string]any{"error": msgPasteKey})
		return
	}
	if models, ok := s.cachedModels(id, src.sig); ok {
		writeJSON(w, http.StatusOK, map[string]any{"models": models})
		return
	}
	models, err := s.fetchModels(r.Context(), src)
	if err != nil {
		var ue *upstreamError
		if errors.As(err, &ue) && ue.cause != nil {
			log.Printf("ai-providers: catálogo de modelos de %q: %s (%v)", id, ue.msg, ue.cause)
		} else {
			log.Printf("ai-providers: catálogo de modelos de %q: %v", id, err)
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	s.storeModels(id, src.sig, models) // only successes are cached
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// fetchModels queries the catalog and returns its free models, json_schema-capable
// first, then by id.
func (s *Service) fetchModels(ctx context.Context, src catalogSource) ([]ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(src.baseURL, "/")+"/models", nil)
	if err != nil {
		return nil, &upstreamError{msg: "endpoint do provedor inválido", cause: err}
	}
	req.Header.Set("Accept", "application/json")
	if src.key != "" {
		req.Header.Set("Authorization", "Bearer "+src.key)
	}
	resp, err := s.modelsHC.Do(req)
	if err != nil {
		return nil, &upstreamError{msg: "falha ao consultar o provedor (rede ou tempo esgotado)", cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// The body is NOT relayed: a provider may echo the key in its error text.
		return nil, &upstreamError{msg: fmt.Sprintf("o provedor respondeu HTTP %d ao listar os modelos", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.modelsMax+1))
	if err != nil {
		return nil, &upstreamError{msg: "falha ao ler a resposta do provedor", cause: err}
	}
	if int64(len(body)) > s.modelsMax {
		return nil, &upstreamError{msg: "resposta do provedor grande demais"}
	}
	var catalog struct {
		Data []struct {
			ID                  string   `json:"id"`
			ContextLength       any      `json:"context_length"`
			SupportedParameters []string `json:"supported_parameters"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, &upstreamError{msg: "resposta do provedor inválida", cause: err}
	}

	models := make([]ModelInfo, 0, len(catalog.Data))
	seen := map[string]bool{}
	for _, m := range catalog.Data {
		if !IsFreeModel(src.kind, m.ID) || seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		mi := ModelInfo{ID: m.ID, JSONSchemaKnown: m.SupportedParameters != nil}
		if n, ok := m.ContextLength.(float64); ok && n >= 1 && n <= 1<<40 {
			mi.ContextLength = int(n)
		}
		for _, p := range m.SupportedParameters {
			if p == "structured_outputs" {
				mi.JSONSchema = true
				break
			}
		}
		models = append(models, mi)
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].JSONSchema != models[j].JSONSchema {
			return models[i].JSONSchema
		}
		return models[i].ID < models[j].ID
	})
	return models, nil
}

// cachedModels returns the cached list of provider id while it is fresh and was
// fetched for the same kind/endpoint/key (sig).
func (s *Service) cachedModels(id, sig string) ([]ModelInfo, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	e, ok := s.cache[id]
	if !ok || e.sig != sig || s.now().Sub(e.at) >= modelsCacheTTL {
		return nil, false
	}
	return e.models, true
}

func (s *Service) storeModels(id, sig string, models []ModelInfo) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache[id] = modelsCacheEntry{sig: sig, at: s.now(), models: models}
}

func (s *Service) dropModels(id string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	delete(s.cache, id)
}

// doPolicy reports the free-models policy.
func (s *Service) doPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Policy{
		FreeModelsOnly: s.reg.FreeModelsOnly(),
		FreeRule:       FreeRule,
		Presets:        PresetIDs(),
	})
}
