package enroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

func genCSR(t *testing.T, cn string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newService(t *testing.T, now *time.Time) (*Service, *tokens.Manager) {
	t.Helper()
	authority, err := ca.NewEphemeral(*now)
	if err != nil {
		t.Fatal(err)
	}
	tm := tokens.NewManager(tokens.NewMemStore(), tokens.WithClock(func() time.Time { return *now }))
	svc := NewService(tm, authority, WithClock(func() time.Time { return *now }), WithCertTTL(24*time.Hour))
	return svc, tm
}

func mustMint(t *testing.T, tm *tokens.Manager, req tokens.MintRequest) tokens.Minted {
	t.Helper()
	if req.Scope.Tenant == "" {
		req.Scope.Tenant = "acme"
	}
	m, err := tm.Mint(req)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return m
}

func TestEnrollHappyPathBindsScopeAndConsumes(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, Scope: tokens.Scope{Tenant: "acme", Policy: "default", OS: "linux"}, TTL: time.Hour})
	resp, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "agent-1"), AgentID: "agent-1", OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "agent-1" || len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "acme" {
		t.Fatalf("subject = %+v", cert.Subject)
	}
	if resp.CACert == "" {
		t.Fatal("CA cert ausente na resposta")
	}
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "agent-1"), AgentID: "agent-1", OS: "linux", Arch: "amd64"}); !errors.Is(err, tokens.ErrExhausted) {
		t.Fatalf("segundo enroll deve ser ErrExhausted, got %v", err)
	}
}

func TestEnrollReturnsIngestURL(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	authority, err := ca.NewEphemeral(now)
	if err != nil {
		t.Fatal(err)
	}
	tm := tokens.NewManager(tokens.NewMemStore(), tokens.WithClock(func() time.Time { return now }))
	const ingest = "https://scanner.suricatoos.com/ingest/v1/inventory"
	svc := NewService(tm, authority, WithClock(func() time.Time { return now }), WithIngestURL(ingest))
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, Scope: tokens.Scope{Tenant: "acme", OS: "linux"}, TTL: time.Hour})
	resp, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "agent-x"), AgentID: "agent-x", OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if resp.IngestURL != ingest {
		t.Errorf("ingest_url = %q, want %q", resp.IngestURL, ingest)
	}
}

func TestEnrollForbidsExpiredToken(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Minute})
	now = now.Add(2 * time.Minute)
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a"}); !errors.Is(err, tokens.ErrExpired) {
		t.Fatalf("esperado ErrExpired, got %v", err)
	}
}

func TestEnrollScopeMismatchAndEmptyOSRejected(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.Deployment, MaxUses: 5, Scope: tokens.Scope{Tenant: "acme", OS: "linux"}, TTL: time.Hour})
	// OS divergente -> mismatch
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a", OS: "windows"}); !errors.Is(err, tokens.ErrScopeMismatch) {
		t.Fatalf("os divergente: esperado ErrScopeMismatch, got %v", err)
	}
	// OS VAZIO também é mismatch (correção do bypass) — não pode satisfazer um token pinado
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a", OS: ""}); !errors.Is(err, tokens.ErrScopeMismatch) {
		t.Fatalf("os vazio deve ser ErrScopeMismatch (bypass), got %v", err)
	}
}

func TestEnrollCNMismatchDoesNotConsumeToken(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Hour})
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "outro"), AgentID: "a"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("esperado ErrBadRequest, got %v", err)
	}
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a"}); err != nil {
		t.Fatalf("token não devia ter sido consumido: %v", err)
	}
}

func TestEnrollBadTokenForbidden(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, _ := newService(t, &now)
	if _, err := svc.Enroll(Request{Token: "st_naoexiste.segredo", CSR: genCSR(t, "a"), AgentID: "a"}); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatalf("esperado ErrNotFound, got %v", err)
	}
}

func TestEnrollRejectsBadAgentID(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Hour})
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a,O=evil"), AgentID: "a,O=evil"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("agent_id com vírgula deve ser ErrBadRequest, got %v", err)
	}
}

func TestEnrollDuplicateAgentIDReturns409(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	svc, tm := newService(t, &now)
	t1 := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Hour})
	t2 := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Hour})

	if _, err := svc.Enroll(Request{Token: t1.Token, CSR: genCSR(t, "srv-dup"), AgentID: "srv-dup"}); err != nil {
		t.Fatalf("primeiro enroll deve passar: %v", err)
	}
	if _, err := svc.Enroll(Request{Token: t2.Token, CSR: genCSR(t, "srv-dup"), AgentID: "srv-dup"}); !errors.Is(err, tokens.ErrAgentAlreadyExists) {
		t.Fatalf("segundo enroll com mesmo agent_id deve retornar ErrAgentAlreadyExists, got %v", err)
	}
}

// failingSigner sempre falha ao assinar — usado para provar que uma falha de
// assinatura NÃO consome o token.
type failingSigner struct{ authority *ca.CA }

func (f failingSigner) SignClientCSR(*x509.CertificateRequest, ca.CertProfile, time.Duration, time.Time) ([]byte, error) {
	return nil, errors.New("falha simulada de assinatura")
}
func (f failingSigner) SignClientCSRIssued(*x509.CertificateRequest, ca.CertProfile, time.Duration, time.Time) (ca.IssuedCert, error) {
	return ca.IssuedCert{}, errors.New("falha simulada de assinatura")
}
func (f failingSigner) CertPEM() []byte { return f.authority.CertPEM() }

func TestEnrollSignFailureDoesNotConsumeToken(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	authority, _ := ca.NewEphemeral(now)
	tm := tokens.NewManager(tokens.NewMemStore(), tokens.WithClock(func() time.Time { return now }))
	bad := NewService(tm, failingSigner{authority: authority}, WithClock(func() time.Time { return now }))
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost, TTL: time.Hour})

	if _, err := bad.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a"}); err == nil {
		t.Fatal("esperava erro de assinatura")
	}
	// token NÃO consumido -> ainda válido com um signer bom
	good := NewService(tm, authority, WithClock(func() time.Time { return now }))
	if _, err := good.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "a"), AgentID: "a"}); err != nil {
		t.Fatalf("token não devia ter sido queimado pela falha de assinatura: %v", err)
	}
}

// enrollAgent enrolls agent-1 (tenant acme, policy scanner-sensor) and returns the
// service + manager, so renew tests start from a real enrolled identity.
func enrollAgent(t *testing.T, now *time.Time) (*Service, *tokens.Manager, string) {
	t.Helper()
	svc, tm := newService(t, now)
	mint := mustMint(t, tm, tokens.MintRequest{Type: tokens.SingleHost,
		Scope: tokens.Scope{Tenant: "acme", Policy: "scanner-sensor", OS: "linux"}, TTL: time.Hour})
	if _, err := svc.Enroll(Request{Token: mint.Token, CSR: genCSR(t, "sensor-acme-1"),
		AgentID: "sensor-acme-1", OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	return svc, tm, mint.ID
}

func TestRenewRotatesSameIdentity(t *testing.T) {
	now := time.Now().UTC()
	svc, tm, tokenID := enrollAgent(t, &now)

	dn := "CN=sensor-acme-1,O=acme,OU=scanner-sensor"
	resp, err := svc.Renew("SUCCESS", dn, RenewRequest{CSR: genCSR(t, "sensor-acme-1"), AgentID: "sensor-acme-1"})
	if err != nil {
		t.Fatalf("renew válido deveria funcionar: %v", err)
	}
	if resp.Certificate == "" || resp.CACert == "" {
		t.Fatal("renew deveria retornar cert + ca")
	}
	// O serial renovado foi anexado ao record do token → revogável.
	recs, _ := tm.List()
	var rec tokens.Record
	for _, r := range recs {
		if r.ID == tokenID {
			rec = r
		}
	}
	if len(rec.Enrollments) != 2 {
		t.Fatalf("serial renovado deveria estar na trilha do token (2 enrollments), got %d", len(rec.Enrollments))
	}
	if rec.Enrollments[1].CertSerial == "" || rec.Enrollments[1].CertSerial == rec.Enrollments[0].CertSerial {
		t.Fatal("cert renovado deveria ter um serial NOVO")
	}
}

func TestRenewRequiresVerifiedCert(t *testing.T) {
	now := time.Now().UTC()
	svc, _, _ := enrollAgent(t, &now)
	dn := "CN=sensor-acme-1,O=acme,OU=scanner-sensor"
	if _, err := svc.Renew("", dn, RenewRequest{CSR: genCSR(t, "sensor-acme-1")}); err == nil {
		t.Fatal("renew sem cert verificado deveria falhar")
	}
	if _, err := svc.Renew("FAILED", dn, RenewRequest{CSR: genCSR(t, "sensor-acme-1")}); err == nil {
		t.Fatal("renew com verify=FAILED deveria falhar")
	}
}

func TestRenewCannotChangeIdentity(t *testing.T) {
	now := time.Now().UTC()
	svc, _, _ := enrollAgent(t, &now)
	dn := "CN=sensor-acme-1,O=acme,OU=scanner-sensor"
	// CSR com CN diferente do cert → rejeitado (não pode virar outro agente).
	if _, err := svc.Renew("SUCCESS", dn, RenewRequest{CSR: genCSR(t, "sensor-evil-9"), AgentID: "sensor-acme-1"}); err == nil {
		t.Fatal("CN divergente deveria ser rejeitado")
	}
	// body agent_id divergente → rejeitado.
	if _, err := svc.Renew("SUCCESS", dn, RenewRequest{CSR: genCSR(t, "sensor-acme-1"), AgentID: "outro"}); err == nil {
		t.Fatal("agent_id divergente deveria ser rejeitado")
	}
}

func TestRenewUnknownAgentRejected(t *testing.T) {
	now := time.Now().UTC()
	svc, _ := newService(t, &now) // ninguém enrolado
	dn := "CN=sensor-ghost-1,O=acme,OU=scanner-sensor"
	if _, err := svc.Renew("SUCCESS", dn, RenewRequest{CSR: genCSR(t, "sensor-ghost-1")}); err == nil {
		t.Fatal("renew de agente nunca enrolado deveria falhar (não há record p/ ancorar a revogação)")
	}
}
