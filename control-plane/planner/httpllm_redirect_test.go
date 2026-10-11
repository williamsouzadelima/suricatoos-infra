package planner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// The planner's HTTP client never follows a redirect: a 307/308 would re-send the
// request body — the prompt — to wherever Location points (a 302 would still make
// a request there). The redirect is the provider's non-2xx answer: the next
// provider is tried.
func TestPlan_RedirectIsNeverFollowed(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		target := newCountingServer(t) // where Location points: must never be reached
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.srv.URL+"/chat/completions", code)
		}))
		second := newCountingServer(t)
		llm := NewHTTPLLM() // the production client, only routed to the test servers
		llm.hc.Transport = hostRouter{hostOf(officialOR): redirector, hostOf(officialUno): second.srv}

		plan, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
		if err != nil || plan.Provider != freeB.Name {
			t.Fatalf("%d: o redirect deveria contar como falha do 1º provedor e o 2º atender: plan=%+v err=%v", code, plan, err)
		}
		if n := target.count(); n != 0 {
			t.Fatalf("%d: o cliente seguiu o redirect e mandou o pedido a outro host (%d chamada(s))", code, n)
		}
		if n := second.count(); n != 1 {
			t.Fatalf("%d: o 2º provedor deveria ser chamado 1 vez, foi %d", code, n)
		}

		// Alone, the redirecting provider fails with its own status.
		_, err = New(llm, fakeResolver{provs: []Provider{freeA}}, freeCfg()).Plan(context.Background(), sampleReq())
		if err == nil || errors.Is(err, ErrTimeout) || !strings.Contains(err.Error(), freeA.Name+": provedor respondeu "+strconv.Itoa(code)) {
			t.Fatalf("%d: sozinho, o provedor que redireciona deveria falhar com o próprio status: %v", code, err)
		}
		if n := target.count(); n != 0 {
			t.Fatalf("%d: o destino do redirect não pode ser alcançado: %d chamada(s)", code, n)
		}
		redirector.Close()
	}
}
