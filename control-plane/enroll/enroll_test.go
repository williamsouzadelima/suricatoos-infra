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
