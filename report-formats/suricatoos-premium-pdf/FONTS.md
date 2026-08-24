# Fontes do relatório — IBM Plex (Type1)

`plex-min.tar.gz` é uma subárvore TDS com as faces IBM Plex que o relatório usa,
em **Type1**, prontas para o `pdflatex`.

## Por que o tarball existe

O container `gvmd` não tem IBM Plex, e não dá para instalar nada nele: o formato
de relatório é entregue **pelo feed**, como um objeto de dados — é isso que faz o
gvmd marcá-lo `predefined=1, trust=1` e exibi-lo sozinho no dropdown da GSA, sem
assinatura GPG e sem mexer no frontend. Então a fonte viaja junto com o bundle.

Sem ela o `pdflatex` **não falha**: ele cai em Latin Modern calado, e o relatório
sai com a tipografia errada sem nenhum aviso no log.

O caminho óbvio — LuaLaTeX + `fontspec` + OTF — **não funciona neste container**:
o `lualatex` está lá, mas sem `luaotfload` (`module 'luaotfload-main' not found`),
então qualquer OpenType morre na carga. Daí Type1 + pdflatex.

O `generate` extrai o tarball no diretório temporário da execução e aponta
`TEXMFHOME` para ele.

## Conteúdo

Seis faces, que são exatamente as que o design usa:

| face | uso |
|---|---|
| `plxSans` | corpo de texto |
| `plxSans-Bold` | título da capa, números dos KPIs |
| `plxSans-SmBld` | títulos de seção e de card (`\suriSB`) |
| `plxSans-Italic` | ênfase em notas |
| `plxMono` | dados técnicos, rótulos, rodapés |
| `plxMono-Bold` | dados em destaque |

Mais os `.tfm`/`.vf` de T1 e TS1, os `.enc`, os `.fd` e um `plex.map` filtrado só
para essas faces. **Pedir qualquer outro peso** (Light, Thin, Medium, Text,
Condensed) gera `Font shape ... undefined` — eles não estão no subset.

## Proveniência e licença

- Fonte: pacote **`plex`** do CTAN (`https://mirrors.ctan.org/install/fonts/plex.tds.zip`),
  empacotamento LaTeX por Bob Tennent sobre as fontes IBM Plex.
- Licença: **SIL Open Font License 1.1** — redistribuição permitida, inclusive
  embutida em PDF. O texto da licença viaja dentro do próprio tarball, em
  `doc/fonts/plex/LICENSE.txt`.
- Copyright © 2017 IBM Corp., com Reserved Font Name "Plex".

## Como regerar

Baixe `plex.tds.zip` do CTAN, extraia, e monte a subárvore com as seis faces
acima: os `.pfb` de `fonts/type1/ibm/plex/`, os `.tfm`/`.vf` de T1 e TS1 dessas
faces, todos os `.enc` de `fonts/enc/dvips/plex/`, todos os `.fd` e os `.sty` de
`tex/latex/plex/` (menos os de Serif, que o relatório não usa), e as linhas
correspondentes de `fonts/map/dvips/plex/plex.map`. Empacote com
`tar czf plex-min.tar.gz -C <subárvore> .`.

Depois **prove** que ficou completo: compile o relatório e confirme que o log não
tem nenhum `Font shape ... undefined` e que o `pdffonts` do PDF lista só faces
`plx*` — nenhuma Computer Modern.
