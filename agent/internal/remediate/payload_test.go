package remediate

import (
	"encoding/json"
	"testing"
)

func TestParsePackagePatch(t *testing.T) {
	ok, err := ParsePackagePatch(json.RawMessage(`{"source":"wua","id":"abc-123","kb":"KB5041580"}`))
	if err != nil || ok.Source != "wua" || ok.ID != "abc-123" || ok.KB != "KB5041580" {
		t.Fatalf("payload válido falhou: %+v err=%v", ok, err)
	}
	bad := []string{
		`{"source":"apt","id":"x"}`, // engine inválido
		`{"source":"wua"}`,          // sem id
		`{"id":"x"}`,                // sem source
		`not json`,                  // json inválido
	}
	for _, b := range bad {
		if _, err := ParsePackagePatch(json.RawMessage(b)); err == nil {
			t.Errorf("devia rejeitar: %s", b)
		}
	}
}

func TestParseConfigHardening(t *testing.T) {
	ok, err := ParseConfigHardening(json.RawMessage(`{"rule_ref":"18.9.1","source":"registry","key":"HKLM\\Software\\X","value":"1"}`))
	if err != nil || ok.RuleRef != "18.9.1" || ok.Source != "registry" || ok.Key == "" {
		t.Fatalf("payload válido falhou: %+v err=%v", ok, err)
	}
	bad := []string{
		`{"source":"registry","key":"x","value":"1"}`, // sem rule_ref
		`{"rule_ref":"1","source":"bogus","key":"x"}`, // source inválido
		`{"rule_ref":"1","source":"registry"}`,        // sem key
		`{]`,                                          // json inválido
	}
	for _, b := range bad {
		if _, err := ParseConfigHardening(json.RawMessage(b)); err == nil {
			t.Errorf("devia rejeitar: %s", b)
		}
	}
}
