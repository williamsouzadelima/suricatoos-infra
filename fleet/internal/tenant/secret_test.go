package tenant

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const fakePassword = "hunter2-acme-fictícia"

// leaks reports whether s carries the password in the clear or as hex.
func leaks(s string) bool {
	return strings.Contains(s, fakePassword) || strings.Contains(strings.ToLower(s), hex.EncodeToString([]byte(fakePassword)))
}

// TestSecretNaoApareceEmNenhumaSaida first proves the detector can see the password (a plain struct with the
// same string leaks through every path), and only then asserts that Secret and Credentials do not.
func TestSecretNaoApareceEmNenhumaSaida(t *testing.T) {
	type plain struct {
		User     string
		Password string
	}
	control := plain{User: "tenant-acme", Password: fakePassword}
	secret := newSecret(fakePassword)
	creds := Credentials{User: "tenant-acme", Password: secret}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10v", "%-30s", "%.3v"}
	for _, verb := range verbs {
		// controle positivo: o detector enxerga a senha onde ela vaza de verdade
		if verb == "%v" || verb == "%+v" || verb == "%#v" || verb == "%s" || verb == "%q" || verb == "%x" || verb == "%X" {
			if !leaks(fmt.Sprintf(verb, control)) {
				t.Fatalf("controle: o detector não viu a senha em %s de uma struct comum", verb)
			}
		}
		for name, v := range map[string]any{
			"Secret":      secret,
			"*Secret":     &secret,
			"Credentials": creds,
			"*Cred":       &creds,
			"slice":       []any{secret, creds},
			"map":         map[string]any{"k": secret, "c": creds},
		} {
			if out := fmt.Sprintf(verb, v); leaks(out) {
				t.Errorf("%s com %s vazou a senha: %s", name, verb, out)
			}
		}
	}

	// dentro de uma struct de OUTRO pacote, em campo não exportado, o fmt ignora os métodos e imprime a
	// representação crua: o Secret guarda a senha atrás de um ponteiro para que isso mostre só um endereço
	holder := struct{ hidden Credentials }{creds}
	holderControl := struct{ hidden plain }{control}
	if !leaks(fmt.Sprintf("%+v", holderControl)) {
		t.Fatal("controle: campo não exportado de struct comum deveria vazar")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, holder); leaks(out) {
			t.Errorf("campo não exportado com %s vazou a senha: %s", verb, out)
		}
	}

	// erro e texto
	if out := fmt.Errorf("falha com %v e %w", creds, fmt.Errorf("%s", secret)).Error(); leaks(out) {
		t.Errorf("erro vazou a senha: %s", out)
	}
	if out := secret.String() + secret.GoString(); leaks(out) {
		t.Errorf("String/GoString vazou a senha: %s", out)
	}
	if text, err := secret.MarshalText(); err != nil || leaks(string(text)) {
		t.Errorf("MarshalText: %q %v", text, err)
	}
}

func TestSecretNaoApareceEmJSONNemEmLog(t *testing.T) {
	type plain struct {
		Password string `json:"password"`
	}
	secret := newSecret(fakePassword)
	creds := Credentials{User: "tenant-acme", Password: secret}

	// controle: o detector vê a senha num JSON comum
	if b, _ := json.Marshal(plain{Password: fakePassword}); !leaks(string(b)) {
		t.Fatal("controle: o detector não viu a senha no JSON de uma struct comum")
	}
	for name, v := range map[string]any{"Secret": secret, "Credentials": creds, "map": map[string]any{"s": secret}} {
		b, err := json.Marshal(v)
		if err != nil || leaks(string(b)) {
			t.Errorf("%s: JSON vazou a senha ou falhou: %s %v", name, b, err)
		}
	}
	if b, err := json.MarshalIndent(creds, "", "  "); err != nil || leaks(string(b)) {
		t.Errorf("MarshalIndent: %s %v", b, err)
	}

	// log/slog, os dois handlers
	for _, mk := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var control, real bytes.Buffer
		slog.New(mk(&control)).Info("tenant", "senha", fakePassword)
		if !leaks(control.String()) {
			t.Fatal("controle: o detector não viu a senha no log de um string comum")
		}
		slog.New(mk(&real)).Info("tenant", "senha", secret, "credenciais", creds, slog.Any("grupo", creds))
		if leaks(real.String()) {
			t.Errorf("log vazou a senha: %s", real.String())
		}
	}
}

func TestSecretRevealEAUnicaSaida(t *testing.T) {
	if got := newSecret(fakePassword).Reveal(); got != fakePassword {
		t.Fatalf("Reveal = %q", got)
	}
	if got := (Secret{}).Reveal(); got != "" {
		t.Fatalf("o valor zero não tem senha: %q", got)
	}
	// duas cópias do Secret enxergam a mesma senha (é um valor, não um recurso)
	a := newSecret("x")
	b := a
	if b.Reveal() != "x" {
		t.Fatal("cópia perdeu a senha")
	}
}
