package contract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
)

// FuzzVerifyAt (seeds = every golden vector, run as a normal test in CI): VerifyAt never panics; every refusal
// carries a reject_reason of the contract and never a *Verified, and its RejectError carries the authenticated
// envelope exactly when the envelope authenticated (lines 3-4); and no
// mutation of a signed envelope that changes the signed bytes or the payload is ever authenticated — whatever
// it authenticates is a canonical form the golden test key really signed, with its own payload. Mutations that
// keep those bytes (insignificant whitespace, member order) may pass: they change nothing that is signed.
func FuzzVerifyAt(f *testing.F) {
	gf := loadGolden(f)
	pub := GoldenTestPublicKey()
	signed := map[string]bool{}
	for _, v := range gf.Vectors {
		f.Add([]byte(v.CommandJSON), v.VerifyAt, v.OwnNodeID)
		if m := signatureMember.FindStringSubmatch(v.CommandJSON); m != nil {
			if sig, err := base64.StdEncoding.DecodeString(m[1]); err == nil && ed25519.Verify(pub, []byte(v.Canonical), sig) {
				signed[v.CanonicalSHA256] = true
			}
		}
	}
	fallback := utc(gAt)
	f.Fuzz(func(t *testing.T, raw []byte, at, own string) {
		now, err := ParseUTCTime(at)
		if err != nil {
			now = fallback
		}
		v, err := VerifyAt(pub, raw, now, own, DefaultClockSkew)
		if err != nil {
			var re *RejectError
			if !errors.As(err, &re) || !re.Reason.Valid() {
				t.Fatalf("erro sem reject_reason do contrato: %v", err)
			}
			if v != nil {
				t.Fatalf("%s: *Verified junto com um erro", re.Reason)
			}
			if (re.Envelope == nil) != (re.Reason.Class() == ClassUnauthenticated) {
				t.Fatalf("%s: envelope autenticado presente = %v", re.Reason, re.Envelope != nil)
			}
			if re.Envelope == nil {
				return
			}
			v = re.Envelope // authenticated refusal (lines 3-4): the same checks below
		}
		cmd := v.Command()
		if !signed[v.CanonicalSHA256()] {
			t.Fatalf("autenticou uma forma canônica que a chave de teste nunca assinou:\n%q", v.Canonical())
		}
		if !bytes.Equal(Canonical(&cmd), v.Canonical()) || payloadDigest(cmd.Payload) != cmd.PayloadSHA256 {
			t.Fatal("Verified incoerente com o envelope")
		}
		if err == nil && (cmd.NodeID != own || now.Before(v.IssuedAt().Add(-DefaultClockSkew)) || now.After(v.NotAfter().Add(DefaultClockSkew))) {
			t.Fatal("aceito fora da janela ou para outro nó")
		}
	})
}

// FuzzValidatePayload (seeds = the payloads of the golden vectors with a catalog type): never panics; a refusal
// is a *Violation or ErrUnknownType; and an accepted payload, re-serialized with MarshalCompact, is accepted
// again with the same value (presence preserved: absent stays absent, "" and [] stay present).
func FuzzValidatePayload(f *testing.F) {
	for _, v := range loadGolden(f).Vectors {
		if c, ok := lenientFields(v.CommandJSON); ok {
			if _, known := LookupType(c.Type); known {
				f.Add(string(c.Type), []byte(c.Payload))
			}
		}
	}
	f.Fuzz(func(t *testing.T, typ string, raw []byte) {
		p, err := DecodePayload(CommandType(typ), raw)
		if err != nil {
			var viol *Violation
			if !errors.As(err, &viol) && !errors.Is(err, ErrUnknownType) {
				t.Fatalf("erro fora do contrato: %v", err)
			}
			return
		}
		b, err := MarshalCompact(p)
		if err != nil {
			t.Fatal(err)
		}
		p2, err := DecodePayload(CommandType(typ), b)
		if err != nil {
			t.Fatalf("payload válido re-serializado foi recusado: %v\n%s", err, b)
		}
		if !reflect.DeepEqual(p, p2) {
			t.Fatalf("ida e volta mudou o payload:\n%#v\n%#v", p, p2)
		}
	})
}
