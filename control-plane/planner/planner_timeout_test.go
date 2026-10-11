package planner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlan_DefaultOverallTimeout(t *testing.T) {
	if got := New(&fakeLLM{}, fakeResolver{}, Config{}).Timeout(); got != 5*time.Minute {
		t.Fatalf("tempo total padrão = %s, want 5m", got)
	}
	if got := New(&fakeLLM{}, fakeResolver{}, Config{Timeout: 90 * time.Second}).Timeout(); got != 90*time.Second {
		t.Fatalf("tempo total configurado = %s, want 1m30s", got)
	}
}

// blockUntilDone answers only when ctx ends, the way a hung provider looks to the
// real HTTP client (a *url.Error wrapping the context's error).
func blockUntilDone(ctx context.Context) (ChatResponse, error) {
	<-ctx.Done()
	return ChatResponse{}, &url.Error{Op: "Post", URL: officialOR + "/chat/completions", Err: ctx.Err()}
}

func TestPlan_OverallTimeoutStopsRemainingAttempts(t *testing.T) {
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {fn: blockUntilDone},
		freeB.Model: okScript(),
	}}
	cfg := freeCfg()
	cfg.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, cfg).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("esperava ErrTimeout, veio %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("o tempo total deveria cortar a tentativa (~100ms), levou %s", el)
	}
	if llm.called() != freeA.Model {
		t.Fatalf("com o tempo total esgotado nenhuma outra tentativa pode começar: %s", llm.called())
	}
}

func TestPlan_OverallTimeoutAlsoStopsAfterASlowFailure(t *testing.T) {
	// The provider ignores the deadline and only fails — with a RETRYABLE 503 —
	// after it has passed: the next provider must still not be tried.
	slow503 := func(context.Context) (ChatResponse, error) {
		time.Sleep(150 * time.Millisecond)
		return ChatResponse{}, &StatusError{Code: http.StatusServiceUnavailable}
	}
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {fn: slow503},
		freeB.Model: okScript(),
	}}
	cfg := freeCfg()
	cfg.Timeout = 50 * time.Millisecond
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, cfg).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("esperava ErrTimeout, veio %v", err)
	}
	if llm.called() != freeA.Model {
		t.Fatalf("após o tempo total nenhuma outra tentativa pode começar: %s", llm.called())
	}
}

func TestPlan_OverallTimeoutCancelsTheHTTPAttempt(t *testing.T) {
	var healthyHits int32
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body first: only then does net/http watch the connection and
		// cancel r.Context() when the client hangs up.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer hung.Close()
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&healthyHits, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer healthy.Close()
	llm := routedLLM(hostRouter{hostOf(officialOR): hung, hostOf(officialUno): healthy})

	cfg := freeCfg()
	cfg.Timeout = 150 * time.Millisecond
	start := time.Now()
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, cfg).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("esperava ErrTimeout, veio %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("o pedido HTTP deveria ser cancelado no tempo total (~150ms), levou %s", el)
	}
	if n := atomic.LoadInt32(&healthyHits); n != 0 {
		t.Fatalf("após o tempo total o próximo provedor não pode ser chamado: %d", n)
	}
}

func TestPlan_ExpiredDeadlineMakesNoAttempt(t *testing.T) {
	// The caller's deadline has already passed: no attempt starts, and the error
	// is the timeout (not "no provider enabled").
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	llm := &scriptLLM{byModel: map[string]scripted{freeA.Model: okScript()}}
	_, err := New(llm, fakeResolver{provs: []Provider{freeA}}, freeCfg()).Plan(ctx, sampleReq())
	if !errors.Is(err, ErrTimeout) || llm.called() != "" {
		t.Fatalf("prazo já vencido: esperava ErrTimeout sem tentativa; err=%v chamadas=%q", err, llm.called())
	}
}

// slowLLM drafts after delay — or gives up when ctx ends — like a slow free model.
type slowLLM struct {
	delay time.Duration
	calls int32
}

func (s *slowLLM) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	atomic.AddInt32(&s.calls, 1)
	select {
	case <-time.After(s.delay):
		return ChatResponse{Content: okContent}, nil
	case <-ctx.Done():
		return ChatResponse{}, &url.Error{Op: "Post", URL: req.BaseURL + "/chat/completions", Err: ctx.Err()}
	}
}

// planServer serves the planner route on a server whose WriteTimeout is
// writeTimeout (0 = none), like the control-plane's (30 s there).
func planServer(t *testing.T, p *Planner, writeTimeout time.Duration) *httptest.Server {
	t.Helper()
	m := http.NewServeMux()
	NewService(p, "s3cret").Register(m)
	srv := httptest.NewUnstartedServer(m)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// Control for the next test: the server-wide WriteTimeout DOES kill a handler that
// is slower than it and does not extend its own write deadline.
func TestServer_WriteTimeoutKillsASlowPlainHandler(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.WriteTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("esperava a conexão derrubada pelo WriteTimeout, veio %d", resp.StatusCode)
	}
}

// A draft slower than the server-wide WriteTimeout still reaches the operator: the
// plan route sets its own write deadline from the planner's overall timeout.
// Scaled down from production (WriteTimeout 30 s vs. a slow free model).
func TestService_SlowDraftOutlivesServerWriteTimeout(t *testing.T) {
	llm := &slowLLM{delay: 200 * time.Millisecond}
	p := New(llm, fakeResolver{prov: freeA}, Config{ConsentGranted: true, FreeModelsOnly: true, Timeout: 5 * time.Second})
	srv := planServer(t, p, 50*time.Millisecond)
	resp, body := post(t, srv, "s3cret", reqBody)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"draft":true`) {
		t.Fatalf("rascunho lento = %d %s, want 200 com o rascunho", resp.StatusCode, body)
	}
	if n := atomic.LoadInt32(&llm.calls); n != 1 {
		t.Fatalf("chamadas ao modelo = %d", n)
	}
}

func TestService_PlannerTimeoutIs504(t *testing.T) {
	llm := &slowLLM{delay: 10 * time.Second}
	p := New(llm, fakeResolver{prov: freeA}, Config{ConsentGranted: true, FreeModelsOnly: true, Timeout: 100 * time.Millisecond})
	srv := planServer(t, p, 0)
	start := time.Now()
	resp, body := post(t, srv, "s3cret", reqBody)
	if resp.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, "AI_PLANNER_TIMEOUT") {
		t.Fatalf("tempo total esgotado = %d %s, want 504", resp.StatusCode, body)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("o pedido deveria acabar no tempo total (~100ms), levou %s", el)
	}
}
