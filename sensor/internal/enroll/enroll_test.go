package enroll

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollHappyPath(t *testing.T) {
	var gotReq enrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotReq)
		json.NewEncoder(w).Encode(enrollResponse{Certificate: "CERT-PEM", CACert: "CA-PEM"})
	}))
	defer srv.Close()

	res, err := Enroll(context.Background(), Config{
		EnrollURL: srv.URL, Token: "tok", AgentID: "sensor-acme-1", OS: "linux", Arch: "amd64",
		Client: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPEM != "CERT-PEM" || res.CACertPEM != "CA-PEM" || res.KeyPEM == "" {
		t.Fatalf("resultado incompleto: %+v", res)
	}
	// O CSR enviado deve ter CN == agent_id (o control-plane exige isso).
	if gotReq.AgentID != "sensor-acme-1" || gotReq.Token != "tok" {
		t.Fatalf("request errado: %+v", gotReq)
	}
	block, _ := pem.Decode([]byte(gotReq.CSR))
	if block == nil {
		t.Fatal("CSR não é PEM válido")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("CSR inválido: %v", err)
	}
	if csr.Subject.CommonName != "sensor-acme-1" {
		t.Fatalf("CN do CSR = %q, esperado sensor-acme-1", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("assinatura do CSR inválida: %v", err)
	}
}

func TestEnrollRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token inválido", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := Enroll(context.Background(), Config{
		EnrollURL: srv.URL, Token: "bad", AgentID: "s1", Client: srv.Client(),
	}); err == nil {
		t.Fatal("enroll rejeitado deveria retornar erro")
	}
}

func TestEnrollValidation(t *testing.T) {
	if _, err := Enroll(context.Background(), Config{EnrollURL: "http://x", Token: "", AgentID: "s"}); err == nil {
		t.Fatal("token vazio deveria falhar")
	}
	if _, err := Enroll(context.Background(), Config{EnrollURL: "http://x", Token: "t", AgentID: ""}); err == nil {
		t.Fatal("agent_id vazio deveria falhar")
	}
}
