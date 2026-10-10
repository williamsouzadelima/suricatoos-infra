package remediate

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// fakePatchEngine records whether apply was called and returns scripted results,
// so the handler logic is exercised without touching the OS.
type fakePatchEngine struct {
	already     bool
	before      string
	after       string
	reboot      bool
	satErr      error
	applyErr    error
	applyCalled bool
}

func (f *fakePatchEngine) satisfied(context.Context, *PackagePatchPayload) (bool, string, error) {
	return f.already, f.before, f.satErr
}

func (f *fakePatchEngine) apply(context.Context, *PackagePatchPayload) (string, bool, error) {
	f.applyCalled = true
	return f.after, f.reboot, f.applyErr
}

func patchJob(payload string) *Job {
	return &Job{JobID: "j-pkg", Type: TypePackagePatch, Payload: json.RawMessage(payload)}
}

func TestPackagePatch_AppliesWhenMissing(t *testing.T) {
	eng := &fakePatchEngine{before: "KB5041580 ausente", after: "KB5041580 instalada", reboot: true}
	h := newPackagePatchHandler(map[string]patchEngine{"wua": eng})
	res, err := h.Apply(context.Background(), patchJob(`{"source":"wua","id":"u1","kb":"KB5041580"}`))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !eng.applyCalled {
		t.Fatal("apply não foi chamado para update ausente")
	}
	if res.Before != "KB5041580 ausente" || res.After != "KB5041580 instalada" {
		t.Fatalf("before/after = %q/%q", res.Before, res.After)
	}
	if !res.RebootPending {
		t.Fatal("reboot_pending deveria propagar do motor")
	}
}

func TestPackagePatch_NoOpWhenSatisfied(t *testing.T) {
	eng := &fakePatchEngine{already: true, before: "KB5041580 instalada"}
	h := newPackagePatchHandler(map[string]patchEngine{"wua": eng})
	res, err := h.Apply(context.Background(), patchJob(`{"source":"wua","id":"u1","kb":"KB5041580"}`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if eng.applyCalled {
		t.Fatal("apply NÃO deveria ser chamado quando já satisfeito (idempotência)")
	}
	if res.After != "KB5041580 instalada" {
		t.Fatalf("after = %q, want estado corrente", res.After)
	}
}

func TestPackagePatch_EngineErrorFails(t *testing.T) {
	eng := &fakePatchEngine{before: "KB1 ausente", applyErr: errors.New("instalação falhou")}
	h := newPackagePatchHandler(map[string]patchEngine{"wua": eng})
	res, err := h.Apply(context.Background(), patchJob(`{"source":"wua","id":"u1","kb":"KB1"}`))
	if err == nil {
		t.Fatal("erro do motor deveria propagar (FAILED)")
	}
	if res == nil || res.Before != "KB1 ausente" {
		t.Fatalf("estado anterior deveria ser capturado mesmo no erro: %+v", res)
	}
}

func TestPackagePatch_WingetAbsentDegrades(t *testing.T) {
	// Server Core: winget indisponível → o precheck (satisfied) erra; o handler
	// retorna erro claro (FAILED), nunca panic nem dependência dura.
	eng := &fakePatchEngine{satErr: errors.New("winget indisponível")}
	h := newPackagePatchHandler(map[string]patchEngine{"winget": eng})
	if _, err := h.Apply(context.Background(), patchJob(`{"source":"winget","id":"Vendor.App","version":"1.2.3"}`)); err == nil {
		t.Fatal("winget ausente deveria falhar com erro claro")
	}
}

func TestPackagePatch_InvalidPayloadFailsAtParse(t *testing.T) {
	h := NewPackagePatchHandler()
	if _, err := h.Apply(context.Background(), patchJob(`{"source":"nope","id":"x"}`)); err == nil {
		t.Fatal("source inválido deveria falhar no parse, antes de qualquer motor")
	}
}

func TestPackagePatch_ProductionHandlerInertUntilLAB(t *testing.T) {
	h := NewPackagePatchHandler()
	if h.Type() != TypePackagePatch {
		t.Fatalf("Type = %v, want %v", h.Type(), TypePackagePatch)
	}
	// O handler de produção nasce com motores PENDING → qualquer job falha e NADA
	// é escrito no SO até a fatia de LAB trocar o motor real.
	if _, err := h.Apply(context.Background(), patchJob(`{"source":"wua","id":"u1","kb":"KB1"}`)); err == nil {
		t.Fatal("handler de produção deve nascer inerte (motor pendente)")
	}
}
