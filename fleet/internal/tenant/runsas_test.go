package tenant

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var adrPath = filepath.Join("..", "..", "..", "docs", "adr", "0011-gestao-remota-da-frota.md")

var backticked = regexp.MustCompile("`([^`]+)`")

// adrCatalogRows returns the body rows of the ADR table "Catálogo de comandos v1" (7 columns), as trimmed cells.
// It is its own reader of the document, independent of the code under test and of the contract package.
func adrCatalogRows(t *testing.T) [][]string {
	t.Helper()
	b, err := os.ReadFile(adrPath)
	if err != nil {
		t.Fatalf("ADR-0011 ilegível: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "## Catálogo de comandos v1") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatal(`ADR-0011 sem a seção "## Catálogo de comandos v1"`)
	}
	var rows [][]string
	started := false
	for _, l := range lines[start:] {
		if !strings.HasPrefix(l, "|") {
			if started {
				break
			}
			continue
		}
		started = true
		cells := strings.Split(strings.Trim(strings.ReplaceAll(l, `\|`, "\x00"), "|"), "|")
		if len(cells) != 7 {
			t.Fatalf("linha da tabela com %d colunas: %q", len(cells), l)
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(cells[i], "\x00", "|"))
		}
		rows = append(rows, cells)
	}
	if len(rows) < 3 || rows[0][0] != "Tipo" || rows[0][5] != "Usuário gvmd" {
		t.Fatalf("cabeçalho inesperado na tabela do catálogo: %v", rows[0])
	}
	return rows[2:] // header and separator
}

// TestRunsAsConfereComAColunaDoADR: for every type of the ADR table, the code's "which gvmd user" is the
// column "Usuário gvmd" of the document ("atual", "atual (leitura)" → current; "tenant" → tenant; "—" → none),
// and the table covers the whole v1 catalog, nothing more and nothing less.
func TestRunsAsConfereComAColunaDoADR(t *testing.T) {
	rows := adrCatalogRows(t)
	if len(rows) != len(contract.Catalog()) {
		t.Fatalf("o ADR tem %d tipos, o catálogo Go %d", len(rows), len(contract.Catalog()))
	}
	seen := map[contract.CommandType]bool{}
	counts := map[GVMUser]int{}
	for _, r := range rows {
		m := backticked.FindStringSubmatch(r[0])
		if m == nil {
			t.Fatalf("linha sem tipo: %v", r)
		}
		typ := contract.CommandType(m[1])
		if _, ok := contract.LookupType(typ); !ok {
			t.Errorf("%s do ADR não está no catálogo Go", typ)
		}
		var want GVMUser
		switch col := r[5]; {
		case strings.HasPrefix(col, "atual"):
			want = UserCurrent
		case col == "tenant":
			want = UserTenant
		case col == "—":
			want = UserNone
		default:
			t.Fatalf("%s: coluna Usuário gvmd com valor desconhecido: %q", typ, col)
		}
		if got := RunsAs(typ); got != want {
			t.Errorf("%s: RunsAs = %v, o ADR diz %q (%v)", typ, got, r[5], want)
		}
		if _, ok := runsAs[typ]; !ok {
			t.Errorf("%s não tem linha na tabela do código (um tipo ausente passaria por \"—\" sem ninguém decidir)", typ)
		}
		seen[typ] = true
		counts[want]++
	}
	for _, e := range contract.Catalog() {
		if !seen[e.Type] {
			t.Errorf("%s está no catálogo Go e não na tabela do ADR", e.Type)
		}
	}
	// o ADR e o código concordam em quantos de cada; se o ADR trocar de tipo, a conta muda junto
	if counts[UserTenant] == 0 || counts[UserCurrent] == 0 || counts[UserNone] == 0 {
		t.Errorf("a tabela deveria usar as três classes: %v", counts)
	}
}

func TestRunsAsTipoForaDoCatalogoNaoExigeEscrita(t *testing.T) {
	// a linha 6 só exige usuário e segredo de quem escreve; um tipo desconhecido é do veredito unsupported (linha 7)
	for _, typ := range []contract.CommandType{"", "tenant.scope_set", "task.explode"} {
		if got := RunsAs(typ); got != UserNone {
			t.Errorf("RunsAs(%q) = %v", typ, got)
		}
	}
}
