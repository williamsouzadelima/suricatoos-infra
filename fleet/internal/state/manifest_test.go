package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// r5Manifest é o report-formats/manifest.json da fatia R5 (PR #153) como ela o publica.
const r5Manifest = `{
  "version": "20261012g",
  "report_formats": [
    {"format": "suricatoos-pdf", "lang": "en", "variant": "technical", "uuid": "c6482c1b-57bb-406b-a501-c97eed86ad05", "name": "Suricatoos PDF — Technical (EN)"},
    {"format": "suricatoos-pdf", "lang": "pt_BR", "variant": "technical", "uuid": "e43a4f20-d845-4916-83f0-851ac6dc5e57", "name": "Suricatoos PDF — Técnico (PT-BR)"},
    {"format": "suricatoos-pdf", "lang": "es", "variant": "technical", "uuid": "91afce49-21fd-4ea0-ba16-7ba2bc51a03a", "name": "Suricatoos PDF — Técnico (ES)"},
    {"format": "suricatoos-pdf", "lang": "en", "variant": "client", "uuid": "97ce15ea-69b9-4b0e-8799-ca0938b11bd6", "name": "Suricatoos PDF — Client (EN)"},
    {"format": "suricatoos-pdf", "lang": "pt_BR", "variant": "client", "uuid": "6b746183-2d7d-4a90-89f7-b082a4775cb9", "name": "Suricatoos PDF — Cliente (PT-BR)"},
    {"format": "suricatoos-pdf", "lang": "es", "variant": "client", "uuid": "9ebc0c90-4f1c-49cb-a62f-598d59b473a6", "name": "Suricatoos PDF — Cliente (ES)"},
    {"format": "suricatoos-pdf", "lang": "en", "variant": "executive", "uuid": "15195ce6-6093-4c4e-8f71-84205ea5a37b", "name": "Suricatoos PDF — Executive (EN)"},
    {"format": "suricatoos-pdf", "lang": "pt_BR", "variant": "executive", "uuid": "94e96b4b-2584-46b0-afcb-5852ab8c24c9", "name": "Suricatoos PDF — Executivo (PT-BR)"},
    {"format": "suricatoos-pdf", "lang": "es", "variant": "executive", "uuid": "330072bd-3941-40fd-8114-38ab9cbbf396", "name": "Suricatoos PDF — Ejecutivo (ES)"}
  ]
}
`

func TestManifestoDaR5(t *testing.T) {
	m, err := ParseManifest([]byte(r5Manifest))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []contract.ReportLang{contract.LangEN, contract.LangPTBR, contract.LangES} {
		for _, v := range []contract.ReportVariant{tech, cli, exe} {
			if !m.allows(contract.FormatSuricatoosPDF, l, v) {
				t.Errorf("suricatoos-pdf %s %s fora", l, v)
			}
		}
	}
	// os gvm-* não estão no manifesto: valem pela tabela do ADR, só en + technical
	if !m.allows(contract.FormatGVMXML, contract.LangEN, tech) || m.allows(contract.FormatGVMXML, contract.LangES, tech) ||
		m.allows(contract.FormatGVMCSVResults, contract.LangEN, cli) {
		t.Error("gvm-* fora da regra do ADR")
	}
}

func TestSemManifestoSoTechnical(t *testing.T) {
	var m *Manifest
	if !m.allows(contract.FormatSuricatoosPDF, contract.LangPTBR, tech) || m.allows(contract.FormatSuricatoosPDF, contract.LangEN, cli) ||
		m.allows(contract.FormatSuricatoosPDF, contract.LangEN, exe) || !m.allows(contract.FormatGVMPDF, contract.LangEN, tech) {
		t.Fatal("sem manifesto: só technical")
	}
}

func TestManifestoQueSoTemTechnicalNaoAnunciaOResto(t *testing.T) {
	m, err := ParseManifest([]byte(`{"version":"x","report_formats":[{"format":"suricatoos-pdf","lang":"es","variant":"technical","uuid":"` +
		uuidN(1) + `","name":"n"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !m.allows(contract.FormatSuricatoosPDF, contract.LangES, tech) || m.allows(contract.FormatSuricatoosPDF, contract.LangEN, tech) {
		t.Fatal("o manifesto é a lista: en technical não está nele")
	}
}

func TestManifestoInvalidoEErro(t *testing.T) {
	entry := func(format, lang, variant, uuid string) string {
		return `{"format":"` + format + `","lang":"` + lang + `","variant":"` + variant + `","uuid":"` + uuid + `","name":"n"}`
	}
	doc := func(entries ...string) string {
		return `{"version":"x","report_formats":[` + strings.Join(entries, ",") + `]}`
	}
	cases := map[string]string{
		"não é JSON":          `{`,
		"sem version":         `{"report_formats":[]}`,
		"version vazia":       `{"version":"","report_formats":[]}`,
		"membro desconhecido": `{"version":"x","report_formats":[],"extra":1}`,
		"formato fora do enum": doc(entry("pdf", "en", "technical", uuidN(1))),
		"idioma fora do enum":  doc(entry("suricatoos-pdf", "fr", "technical", uuidN(1))),
		"edição fora do enum":  doc(entry("suricatoos-pdf", "en", "full", uuidN(1))),
		"uuid inválido":        doc(entry("suricatoos-pdf", "en", "technical", "X")),
		"combinação repetida":  doc(entry("suricatoos-pdf", "en", "technical", uuidN(1)), entry("suricatoos-pdf", "en", "technical", uuidN(2))),
		"uuid repetido":        doc(entry("suricatoos-pdf", "en", "technical", uuidN(1)), entry("suricatoos-pdf", "es", "technical", uuidN(1))),
		"gvm-* fora de en technical": doc(entry("gvm-xml", "es", "technical", uuidN(1))),
	}
	for name, content := range cases {
		if _, err := ParseManifest([]byte(content)); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
}

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(r5Manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil || !m.allows(contract.FormatSuricatoosPDF, contract.LangES, exe) {
		t.Fatalf("LoadManifest = %v, %v", m, err)
	}
	if _, err := LoadManifest(filepath.Join(dir, "nao-existe.json")); err == nil {
		t.Fatal("manifesto configurado e ausente é erro")
	}
}
