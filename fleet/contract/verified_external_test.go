package contract_test

// An EXTERNAL test package: it sees Verified exactly as the connector and the commandcenter will. The attack it
// pins: a package holding a *Verified copies it, changes node_id or not_after and calls
// CheckAt on the copy. Verified exposes no field, so the copy can only change what the accessors hand out (fresh
// copies), and CheckAt keeps judging the values Verify authenticated.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const (
	extNodeID   = "node-lab-0001"
	extOther    = "node-lab-0002"
	extNotAfter = "2026-10-11T13:00:00Z"
	extPayload  = `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`
	extCmdID    = "1da079c9-a306-4091-aed0-11c470723271"
)

var (
	extInWindow = time.Date(2026, 10, 11, 12, 30, 0, 0, time.UTC)
	extNextDay  = time.Date(2026, 10, 12, 12, 30, 0, 0, time.UTC)
)

// extEnvelope signs a task.start for extNodeID, window [12:00, 13:00], with the PUBLIC golden test key.
func extEnvelope(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte(contract.GoldenTestKeySeedText))
	priv := ed25519.NewKeyFromSeed(seed[:])
	raw, err := contract.Sign(priv, contract.Command{
		SchemaVersion: "1.0.0",
		CommandID:     extCmdID,
		NodeID:        extNodeID,
		Tenant:        "acme",
		Type:          contract.TypeTaskStart,
		IssuedBy:      "op-7f3a",
		IssuedAt:      "2026-10-11T12:00:00Z",
		NotAfter:      extNotAfter,
		Nonce:         "882ba481a508a1d2c95cf92512deb7d2d5d94082b8d84fb5e7e900ee0a34f8dd",
	}, []byte(extPayload))
	if err != nil {
		t.Fatal(err)
	}
	return priv.Public().(ed25519.PublicKey), raw
}

func extReason(err error) contract.RejectReason {
	r, _ := contract.ReasonOf(err)
	return r
}

// TestVerifiedHasNoExportedField: nothing of a Verified can be assigned from outside the package, so no copy of
// one can carry values Verify did not authenticate.
func TestVerifiedHasNoExportedField(t *testing.T) {
	typ := reflect.TypeFor[contract.Verified]()
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("Verified.%s é exportado: uma cópia alterada fora do pacote mudaria o que CheckAt confere", f.Name)
		}
	}
}

// TestVerifiedCopyKeepsAuthenticatedValues: a copy, with every value the accessors hand out changed, is judged by
// CheckAt exactly as the original — on the authenticated node_id and window.
func TestVerifiedCopyKeepsAuthenticatedValues(t *testing.T) {
	pub, raw := extEnvelope(t)
	v, err := contract.Verify(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	cp := *v
	c := cp.Command()
	c.NodeID, c.IssuedAt, c.NotAfter = extOther, "2026-10-12T12:00:00Z", "2026-10-12T13:00:00Z"
	c.Payload[0] = '['
	cp.Canonical()[0] ^= 0xff
	cp.Signature()[0] ^= 0xff
	cp.Command().Payload[1] = '!'

	for name, w := range map[string]*contract.Verified{"original": v, "cópia": &cp} {
		if r := extReason(w.CheckAt(extInWindow, extOther, contract.DefaultClockSkew)); r != contract.ReasonWrongNode {
			t.Errorf("%s: CheckAt para %s = %q, esperado wrong_node", name, extOther, r)
		}
		if r := extReason(w.CheckAt(extNextDay, extNodeID, contract.DefaultClockSkew)); r != contract.ReasonExpired {
			t.Errorf("%s: CheckAt no dia seguinte = %q, esperado expired", name, r)
		}
		if err := w.CheckAt(extInWindow, extNodeID, contract.DefaultClockSkew); err != nil {
			t.Errorf("%s: CheckAt autêntico: %v", name, err)
		}
		got := w.Command()
		if got.NodeID != extNodeID || got.NotAfter != extNotAfter || string(got.Payload) != extPayload {
			t.Errorf("%s: Command() mudou: %+v", name, got)
		}
		if !w.NotAfter().Equal(time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)) ||
			!w.IssuedAt().Equal(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("%s: janela mudou: %v %v", name, w.IssuedAt(), w.NotAfter())
		}
		sum := sha256.Sum256(w.Canonical())
		if hex.EncodeToString(sum[:]) != w.CanonicalSHA256() || !ed25519.Verify(pub, w.Canonical(), w.Signature()) {
			t.Errorf("%s: a forma canônica ou a assinatura entregues não são mais as autenticadas", name)
		}
	}
}

// TestVerifiedNotMadeByVerify: the zero value (all an external package can build) and a nil pointer are refused.
func TestVerifiedNotMadeByVerify(t *testing.T) {
	var zero contract.Verified
	if err := zero.CheckAt(extInWindow, extNodeID, contract.DefaultClockSkew); !errors.Is(err, contract.ErrNotVerified) {
		t.Errorf("Verified zero: %v", err)
	}
	var none *contract.Verified
	if err := none.CheckAt(extInWindow, extNodeID, contract.DefaultClockSkew); !errors.Is(err, contract.ErrNotVerified) {
		t.Errorf("Verified nil: %v", err)
	}
}

// TestRejectErrorEnvelopeFromOutside: an authenticated refusal carries the envelope to ack, read-only as well.
func TestRejectErrorEnvelopeFromOutside(t *testing.T) {
	pub, raw := extEnvelope(t)
	v, err := contract.VerifyAt(pub, raw, extInWindow, extOther, contract.DefaultClockSkew)
	var re *contract.RejectError
	if v != nil || !errors.As(err, &re) || re.Reason != contract.ReasonWrongNode || re.Envelope == nil {
		t.Fatalf("VerifyAt em outro nó: %v %v", v, err)
	}
	if re.Envelope.Command().CommandID != extCmdID {
		t.Errorf("envelope da recusa: %+v", re.Envelope.Command())
	}
	cp := *re.Envelope
	if r := extReason(cp.CheckAt(extInWindow, extOther, contract.DefaultClockSkew)); r != contract.ReasonWrongNode {
		t.Errorf("cópia do envelope da recusa: %q", r)
	}
}
