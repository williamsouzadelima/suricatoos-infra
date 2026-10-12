package fleetops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Os códigos que o Run aceita do fleet_ops e o teto da mensagem são os do schema
// (fleet-result.schema.json#/$defs/error_code e #/$defs/error/properties/message), lidos do arquivo.
func TestCodigosEMensagemConferemComOSchema(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "fleet-result.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			ErrorCode struct {
				Enum []contract.ErrorCode `json:"enum"`
			} `json:"error_code"`
			Error struct {
				Properties struct {
					Message struct {
						MinLength int `json:"minLength"`
						MaxLength int `json:"maxLength"`
					} `json:"message"`
				} `json:"properties"`
			} `json:"error"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	got := make([]contract.ErrorCode, 0, len(errorCodes))
	for c := range errorCodes {
		got = append(got, c)
	}
	slices.Sort(got)
	want := slices.Clone(schema.Defs.ErrorCode.Enum)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("códigos aceitos %v, schema %v", got, want)
	}
	if m := schema.Defs.Error.Properties.Message; m.MinLength != 1 || m.MaxLength != MaxMessageRunes {
		t.Errorf("message do schema %+v, Go teto %d", m, MaxMessageRunes)
	}
}
