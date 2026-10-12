package state

import (
	"fmt"
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// The enums of report.export in the schema's order: the order capabilities.report_formats is sent in.
var (
	formatOrder = []contract.ReportFormat{contract.FormatSuricatoosPDF, contract.FormatGVMXML,
		contract.FormatGVMCSVResults, contract.FormatGVMPDF}
	langOrder    = []contract.ReportLang{contract.LangEN, contract.LangPTBR, contract.LangES}
	variantOrder = []contract.ReportVariant{contract.VariantTechnical, contract.VariantClient,
		contract.VariantExecutive}
)

const maxManifestBytes = 1 << 20

// Manifest is report-formats/manifest.json (slice R5): the (format, lang, variant) → report-format UUID of the
// editions the node's image ships. A nil *Manifest is the node before R5: only the technical edition of
// suricatoos-pdf, in its three languages (ADR-0011 "report.export": "até a R5 entrar, anuncia só technical").
type Manifest struct {
	version string
	entries map[formatKey]string
}

type formatKey struct {
	format  contract.ReportFormat
	lang    contract.ReportLang
	variant contract.ReportVariant
}

type manifestFile struct {
	Version       string          `json:"version"`
	ReportFormats []manifestEntry `json:"report_formats"`
}

type manifestEntry struct {
	Format  contract.ReportFormat  `json:"format"`
	Lang    contract.ReportLang    `json:"lang"`
	Variant contract.ReportVariant `json:"variant"`
	UUID    string                 `json:"uuid"`
	Name    string                 `json:"name"`
}

// isGVMFormat: the gvm-* formats are gvmd's own (python-gvm ReportFormatType); they exist only in en + technical.
func isGVMFormat(f contract.ReportFormat) bool {
	return f != contract.FormatSuricatoosPDF && slices.Contains(formatOrder, f)
}

// ParseManifest reads a manifest strictly (contract.DecodeStrict: no unknown or repeated member): a version, and
// entries whose format, lang and variant are the schema's, with a UUID each, no combination and no UUID twice, and
// no gvm-* outside en + technical.
func ParseManifest(data []byte) (*Manifest, error) {
	var f manifestFile
	if err := contract.DecodeStrict(data, &f); err != nil {
		return nil, fmt.Errorf("state: manifesto de report formats: %w", err)
	}
	if !ruleVersion.ok(f.Version) {
		return nil, fmt.Errorf("state: manifesto de report formats sem version válida")
	}
	m := &Manifest{version: f.Version, entries: make(map[formatKey]string, len(f.ReportFormats))}
	uuids := map[string]bool{}
	for i, e := range f.ReportFormats {
		k := formatKey{e.Format, e.Lang, e.Variant}
		switch {
		case !slices.Contains(formatOrder, e.Format) || !slices.Contains(langOrder, e.Lang) ||
			!slices.Contains(variantOrder, e.Variant):
			return nil, fmt.Errorf("state: manifesto: entrada %d fora dos enums de report.export", i)
		case isGVMFormat(e.Format) && (e.Lang != contract.LangEN || e.Variant != contract.VariantTechnical):
			return nil, fmt.Errorf("state: manifesto: entrada %d: gvm-* só existe em en + technical", i)
		case !ruleUUID.ok(e.UUID) || !ruleName.ok(e.Name):
			return nil, fmt.Errorf("state: manifesto: entrada %d com uuid ou name inválido", i)
		case m.entries[k] != "" || uuids[e.UUID]:
			return nil, fmt.Errorf("state: manifesto: entrada %d repete combinação ou uuid", i)
		}
		m.entries[k] = e.UUID
		uuids[e.UUID] = true
	}
	return m, nil
}

// LoadManifest reads the manifest at path (the image ships it; slice F2.6 says where). A configured manifest that
// is missing or unreadable is an error: the connector does not guess its editions.
func LoadManifest(path string) (*Manifest, error) {
	data, err := fsutil.ReadBounded(path, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("state: ler o manifesto de report formats: %w", err)
	}
	return ParseManifest(data)
}

// allows reports whether the node may advertise a combination: gvm-* only as en + technical (ADR-0011 table);
// suricatoos-pdf as the manifest lists it — or, without one, only the technical edition.
func (m *Manifest) allows(f contract.ReportFormat, l contract.ReportLang, v contract.ReportVariant) bool {
	if !slices.Contains(langOrder, l) || !slices.Contains(variantOrder, v) {
		return false
	}
	switch {
	case isGVMFormat(f):
		return l == contract.LangEN && v == contract.VariantTechnical
	case f != contract.FormatSuricatoosPDF:
		return false
	case m == nil:
		return v == contract.VariantTechnical
	}
	_, ok := m.entries[formatKey{f, l, v}]
	return ok
}

// filter turns what gvmd reported — fleet_ops' groups of the mapped combinations whose report-format object is
// present, active and trusted — into capabilities.report_formats: only the combinations the node may advertise
// (allows), anything outside the schema's enums dropped, repeated groups merged, in the enums' order. The node never
// advertises more than gvmd has, nor more than its image ships.
func (m *Manifest) filter(groups []contract.ReportFormatCapability) []contract.ReportFormatCapability {
	type fl struct {
		f contract.ReportFormat
		l contract.ReportLang
	}
	seen := map[fl]map[contract.ReportVariant]bool{}
	for _, g := range groups {
		for _, v := range g.Variants {
			if m.allows(g.Format, g.Lang, v) {
				k := fl{g.Format, g.Lang}
				if seen[k] == nil {
					seen[k] = map[contract.ReportVariant]bool{}
				}
				seen[k][v] = true
			}
		}
	}
	out := []contract.ReportFormatCapability{}
	for _, f := range formatOrder {
		for _, l := range langOrder {
			vs := seen[fl{f, l}]
			if len(vs) == 0 {
				continue
			}
			variants := []contract.ReportVariant{}
			for _, v := range variantOrder {
				if vs[v] {
					variants = append(variants, v)
				}
			}
			out = append(out, contract.ReportFormatCapability{Format: f, Lang: l, Variants: variants})
		}
	}
	return out
}
