package sensorreport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/ingest/scanlaunch"
)

func notRevoked(string) bool { return false }

// resolver for tenant "acme" with scope 10.20.0.0/16.
func acmeResolver() TenantResolver {
	sc, _ := NewScope("10.20.0.0/16")
	return func(tenant string) (TenantConfig, bool) {
		if tenant == "acme" {
			return TenantConfig{GmpUsername: "tenant-acme", GmpPassword: "pw", Scope: sc}, true
		}
		return TenantConfig{}, false
	}
}

func reportReq(body any, dnO string) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest("POST", "/v1/sensor-report", &buf)
	req.Header.Set("X-Client-Cert-Verify", "SUCCESS")
	req.Header.Set("X-Client-Cert-DN", "CN=sensor-"+dnO+"-1,OU=scanner-sensor,O="+dnO)
	req.Header.Set("X-Client-Cert-Serial", "0A1B")
	return req
}

func mkReport(tenant string, findings ...scanlaunch.Finding) SensorReport {
	return SensorReport{SchemaVersion: SchemaVersion, CorrelationID: "c1", SensorID: "s1", Tenant: tenant, Findings: findings}
}

func serve(s *Service, req *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestNoCert403(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked)
	req := httptest.NewRequest("POST", "/v1/sensor-report", bytes.NewReader([]byte("{}")))
	if w := serve(s, req); w.Code != http.StatusForbidden {
		t.Fatalf("sem cert deveria 403, got %d", w.Code)
	}
}

func TestRevoked403(t *testing.T) {
	s := New(Config{}, acmeResolver(), func(string) bool { return true })
	if w := serve(s, reportReq(mkReport("acme"), "acme")); w.Code != http.StatusForbidden {
		t.Fatalf("serial revogado deveria 403, got %d", w.Code)
	}
}

func TestCRLNotWiredFailClosed(t *testing.T) {
	s := New(Config{}, acmeResolver(), nil)
	if w := serve(s, reportReq(mkReport("acme"), "acme")); w.Code != http.StatusForbidden {
		t.Fatalf("CRL não conectada deveria 403 (fail-closed), got %d", w.Code)
	}
}

func TestTenantBodyMismatch403(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked)
	// cert O=acme but body claims tenant globex.
	if w := serve(s, reportReq(mkReport("globex"), "acme")); w.Code != http.StatusForbidden {
		t.Fatalf("tenant do body ≠ cert O deveria 403, got %d", w.Code)
	}
}

func TestUnknownTenant403(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked)
	// cert O=globex, resolver only knows acme.
	if w := serve(s, reportReq(mkReport("globex"), "globex")); w.Code != http.StatusForbidden {
		t.Fatalf("tenant desconhecido deveria 403, got %d", w.Code)
	}
}

func TestScopeQuarantineAndTenantFromCert(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked)
	var got *bridgeReport
	s.imp = func(_ context.Context, tc TenantConfig, rep bridgeReport) error {
		if tc.GmpUsername != "tenant-acme" {
			t.Errorf("import deveria usar o usuário gvmd do tenant, got %s", tc.GmpUsername)
		}
		got = &rep
		return nil
	}
	// One in-scope host, one out-of-scope (co-tenant/arbitrary).
	body := mkReport("", // body tenant vazio: o O do cert é a autoridade
		scanlaunch.Finding{Host: "10.20.5.5", Port: "443/tcp", OID: "o1"},
		scanlaunch.Finding{Host: "8.8.8.8", Port: "80/tcp", OID: "o2"},
	)
	w := serve(s, reportReq(body, "acme"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("deveria 202, got %d", w.Code)
	}
	var resp map[string]int
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["imported"] != 1 || resp["quarantined"] != 1 {
		t.Fatalf("esperado imported=1 quarantined=1, got %+v", resp)
	}
	if got == nil || got.Tenant != "acme" {
		t.Fatalf("report importado deveria ter tenant=acme (do cert), got %+v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].Host != "10.20.5.5" {
		t.Fatalf("só o achado em escopo deveria ser importado, got %+v", got.Findings)
	}
}

func TestAllOutOfScope202Zero(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked)
	called := false
	s.imp = func(context.Context, TenantConfig, bridgeReport) error { called = true; return nil }
	body := mkReport("acme", scanlaunch.Finding{Host: "1.2.3.4", Port: "80/tcp", OID: "o1"})
	w := serve(s, reportReq(body, "acme"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("deveria 202, got %d", w.Code)
	}
	if called {
		t.Fatal("com tudo fora de escopo o bridge NÃO deveria ser chamado")
	}
}

func TestForwarderPushesToScore(t *testing.T) {
	var got scorePayload
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sc-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer score.Close()

	s := New(Config{}, acmeResolver(), notRevoked).
		WithForwarder(NewForwarder(score.URL, "sc-secret"))
	var imported *bridgeReport
	s.imp = func(_ context.Context, _ TenantConfig, rep bridgeReport) error { imported = &rep; return nil }

	body := mkReport("", scanlaunch.Finding{Host: "10.20.5.5", Port: "443/tcp", OID: "o1"},
		scanlaunch.Finding{Host: "8.8.8.8", Port: "80/tcp", OID: "o2"}) // 8.8.8.8 fora de escopo
	w := serve(s, reportReq(body, "acme"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("deveria 202, got %d", w.Code)
	}
	if imported == nil {
		t.Fatal("import deveria ter rodado")
	}
	// O Score recebe: tenant do CERT (não do body), só os achados EM ESCOPO.
	if got.Tenant != "acme" || got.Source != "sensor" {
		t.Fatalf("payload p/ o Score errado: %+v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].Host != "10.20.5.5" {
		t.Fatalf("Score deveria receber só o achado em escopo: %+v", got.Findings)
	}
}

func TestForwarderDisabledIsNoop(t *testing.T) {
	s := New(Config{}, acmeResolver(), notRevoked) // sem forwarder
	s.imp = func(context.Context, TenantConfig, bridgeReport) error { return nil }
	body := mkReport("acme", scanlaunch.Finding{Host: "10.20.5.5", Port: "443/tcp", OID: "o1"})
	if w := serve(s, reportReq(body, "acme")); w.Code != http.StatusAccepted {
		t.Fatalf("sem forwarder deveria 202 normal, got %d", w.Code)
	}
}
