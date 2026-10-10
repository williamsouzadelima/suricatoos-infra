package planner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serviceServer(t *testing.T, consent bool) *httptest.Server {
	t.Helper()
	llm := &fakeLLM{resp: ChatResponse{Content: okContent}}
	p := New(llm, fakeResolver{prov: Provider{Name: "p", BaseURL: "b", APIKey: "k", Model: "m"}}, Config{ConsentGranted: consent})
	m := http.NewServeMux()
	NewService(p, "s3cret").Register(m)
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, bearer, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/remediation/plan", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

const reqBody = `{"finding_id":"f1","type":"package_patch","title":"t","severity":"7.5 High","host":"h"}`

func TestService_RequiresBearer(t *testing.T) {
	srv := serviceServer(t, true)
	if resp, _ := post(t, srv, "", reqBody); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sem bearer = %d, want 401", resp.StatusCode)
	}
	if resp, _ := post(t, srv, "wrong", reqBody); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer errado = %d, want 401", resp.StatusCode)
	}
}

func TestService_ConsentOffForbidden(t *testing.T) {
	srv := serviceServer(t, false)
	resp, _ := post(t, srv, "s3cret", reqBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("consentimento off = %d, want 403", resp.StatusCode)
	}
}

func TestService_HappyPathReturnsDraft(t *testing.T) {
	srv := serviceServer(t, true)
	resp, body := post(t, srv, "s3cret", reqBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plan = %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"draft":true`) || !strings.Contains(body, `"severity":"7.5 High"`) {
		t.Fatalf("resposta deveria ter rascunho com severidade atestada: %s", body)
	}
}
