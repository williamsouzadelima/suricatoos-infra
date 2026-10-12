package contract

import (
	"bytes"
	"strings"
	"testing"
)

// TestSignADRExample: Sign reproduces the ADR-0011 envelope byte for byte (member order, compact payload,
// payload_sha256 over the exact bytes, deterministic Ed25519 signature).
func TestSignADRExample(t *testing.T) {
	c := adrCommand()
	c.PayloadSHA256 = "" // Sign computes it
	got, err := Sign(goldenPriv, c, []byte(adrPayload))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != adrEnvelope {
		t.Fatalf("Sign divergiu do exemplo do ADR:\n got %s\nwant %s", got, adrEnvelope)
	}
}

// TestSignLiteralCharacters: a payload built with MarshalCompact carries '<', '>', '&' and U+2028 literally,
// and the hash covers exactly those bytes.
func TestSignLiteralCharacters(t *testing.T) {
	comment := "linha 1\xe2\x80\xa8linha 2"
	p, err := MarshalCompact(PayloadTaskCreate{
		Name: "Rede <LAB> & DMZ", Comment: &comment,
		TargetID: "9a7e3c21-5b0d-4f8e-a1c6-2e4d7b9f0a35", ScanConfigID: "daba56c8-73ec-11df-a475-002264764cea",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := adrCommand()
	c.Type = TypeTaskCreate
	raw, err := Sign(goldenPriv, c, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("Rede <LAB> & DMZ")) || !bytes.Contains(raw, []byte("linha 1\xe2\x80\xa8linha 2")) {
		t.Fatalf("caracteres devem ir literais: %s", raw)
	}
	v, err := Verify(goldenPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Command().PayloadSHA256 != sha256hex(p) {
		t.Fatal("payload_sha256 sobre os bytes exatos")
	}
}

// TestSignRefuses: the hub side is fail-closed — Sign never emits an envelope a node would refuse at lines 0
// or 3, nor a non-compact payload.
func TestSignRefuses(t *testing.T) {
	ok := adrCommand()
	cases := []struct {
		name    string
		mut     func(*Command)
		payload string
		priv    []byte
	}{
		{"payload não compacto", nil, `{"task_id": "2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`, nil},
		{"payload com newline final", nil, adrPayload + "\n", nil},
		{"payload não é objeto", nil, `["x"]`, nil},
		{"payload com chave duplicada", nil, `{"a":1,"a":1}`, nil},
		{"payload com inteiro 70.0", nil, `{"min_qod":70.0}`, nil},
		{"payload inválido", nil, `{"task_id":`, nil},
		{"payload acima de 48 KiB", nil, `{"x":"` + strings.Repeat("a", MaxPayloadBytes) + `"}`, nil},
		{"nonce maiúsculo", func(c *Command) { c.Nonce = strings.ToUpper(c.Nonce) }, adrPayload, nil},
		{"tempo com fração", func(c *Command) { c.IssuedAt = "2026-10-11T12:00:00.5Z" }, adrPayload, nil},
		{"schema_version sem suporte", func(c *Command) { c.SchemaVersion = "1.1.0" }, adrPayload, nil},
		{"janela vazia", func(c *Command) { c.NotAfter = c.IssuedAt }, adrPayload, nil},
		{"janela acima de 24 h", func(c *Command) { c.NotAfter = "2026-10-12T12:00:01Z" }, adrPayload, nil},
		{"chave privada de tamanho errado", nil, adrPayload, goldenPriv[:32]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := ok
			if c.mut != nil {
				c.mut(&cmd)
			}
			priv := goldenPriv
			if c.priv != nil {
				priv = c.priv
			}
			if raw, err := Sign(priv, cmd, []byte(c.payload)); err == nil {
				t.Fatalf("Sign deveria recusar, emitiu %s", raw)
			}
		})
	}
}

// TestSignOverwritesComputedFields: payload_sha256, payload and signature always come from Sign itself.
func TestSignOverwritesComputedFields(t *testing.T) {
	c := adrCommand()
	c.PayloadSHA256 = strings.Repeat("0", 64)
	c.Payload = []byte(`{"x":1}`)
	c.Signature = "lixo"
	got, err := Sign(goldenPriv, c, []byte(adrPayload))
	if err != nil || string(got) != adrEnvelope {
		t.Fatalf("got %s, %v", got, err)
	}
}
