package remediate

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// fakeSettingEngine records the write and returns a scripted current value.
type fakeSettingEngine struct {
	current     string
	readErr     error
	writeErr    error
	writeCalled bool
}

func (f *fakeSettingEngine) read(context.Context, *ConfigHardeningPayload) (string, error) {
	return f.current, f.readErr
}

func (f *fakeSettingEngine) write(context.Context, *ConfigHardeningPayload) error {
	f.writeCalled = true
	return f.writeErr
}

func cfgJob(payload string) *Job {
	return &Job{JobID: "j-cfg", Type: TypeConfigHardening, Payload: json.RawMessage(payload)}
}

func TestConfigHardening_WritesWhenDrifted(t *testing.T) {
	eng := &fakeSettingEngine{current: "0"}
	h := newConfigHardeningHandler(map[string]settingEngine{"registry": eng})
	res, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"2.3.1.1","source":"registry","key":"HKLM\\SOFTWARE\\X\\Enabled","value":"1"}`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !eng.writeCalled {
		t.Fatal("write deveria ser chamado quando há drift")
	}
	if res.Before != "0" || res.After != "1" {
		t.Fatalf("before/after = %q/%q, want 0/1", res.Before, res.After)
	}
}

func TestConfigHardening_NoOpWhenCompliant(t *testing.T) {
	eng := &fakeSettingEngine{current: "1"}
	h := newConfigHardeningHandler(map[string]settingEngine{"registry": eng})
	res, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"2.3.1.1","source":"registry","key":"HKLM\\SOFTWARE\\X\\Enabled","value":"1"}`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if eng.writeCalled {
		t.Fatal("write NÃO deveria ser chamado quando já conforme (idempotência)")
	}
	if res.After != "1" {
		t.Fatalf("after = %q, want 1", res.After)
	}
}

func TestConfigHardening_RefusesPolicyManaged(t *testing.T) {
	eng := &fakeSettingEngine{current: "0"}
	h := newConfigHardeningHandler(map[string]settingEngine{"registry": eng})
	_, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"18.9","source":"registry","key":"HKLM\\SOFTWARE\\Policies\\Microsoft\\X","value":"1"}`))
	if err == nil {
		t.Fatal(`chave sob \SOFTWARE\Policies\ deveria ser recusada (gerida por GPO)`)
	}
	if eng.writeCalled {
		t.Fatal("NÃO pode escrever numa chave gerida por política")
	}
}

func TestConfigHardening_ReadErrorFails(t *testing.T) {
	eng := &fakeSettingEngine{readErr: errors.New("acesso negado")}
	h := newConfigHardeningHandler(map[string]settingEngine{"registry": eng})
	if _, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"r","source":"registry","key":"HKLM\\SOFTWARE\\X","value":"1"}`)); err == nil {
		t.Fatal("erro de leitura deveria falhar (FAILED)")
	}
}

func TestConfigHardening_DispatchesBySource(t *testing.T) {
	reg := &fakeSettingEngine{current: "x"}
	aud := &fakeSettingEngine{current: "y"}
	h := newConfigHardeningHandler(map[string]settingEngine{"registry": reg, "auditpol": aud})
	if _, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"r","source":"auditpol","key":"Logon","value":"Success and Failure"}`)); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !aud.writeCalled || reg.writeCalled {
		t.Fatalf("despacho errado: registry.write=%v auditpol.write=%v", reg.writeCalled, aud.writeCalled)
	}
}

func TestConfigHardening_InertUntilLAB(t *testing.T) {
	h := NewConfigHardeningHandler()
	if h.Type() != TypeConfigHardening {
		t.Fatalf("Type = %v, want %v", h.Type(), TypeConfigHardening)
	}
	if _, err := h.Apply(context.Background(), cfgJob(`{"rule_ref":"r","source":"registry","key":"HKLM\\SOFTWARE\\X","value":"1"}`)); err == nil {
		t.Fatal("handler de produção deve nascer inerte (motor pendente)")
	}
}

func TestConfigHardening_PolicyDetector(t *testing.T) {
	cases := map[string]bool{
		`HKLM\SOFTWARE\Policies\Microsoft\Windows\X`: true,
		`HKEY_LOCAL_MACHINE\Software\Policies\Y`:     true,
		`SOFTWARE\Policies\Z`:                        true,
		`HKLM/SOFTWARE/Policies/Slashed`:             true,
		`HKLM\SOFTWARE\Microsoft\Windows\X`:          false,
		`HKLM\SYSTEM\CurrentControlSet\Services\X`:   false,
	}
	for k, want := range cases {
		if got := isPolicyManaged(k); got != want {
			t.Errorf("isPolicyManaged(%q) = %v, want %v", k, got, want)
		}
	}
}
