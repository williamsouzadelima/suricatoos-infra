#!/usr/bin/env python3
r"""Converte o catálogo de tradução dos NVTs de JSON para o XML que o relatório lê.

    python3 tools/build-nvt-catalog.py catalogo-pt_BR.json pt_BR > nvt-i18n-pt_BR.xml

Entrada: array de objetos `{oid, name, summary, insight, impact, affected, solution}`.
Saída: `<nvti18n lang="..."><n o="OID"><campo>…</campo>…</n>…</nvti18n>`, que o
`latex.xsl` carrega com `document()` e consulta por OID.

DESESCAPE DA QUEBRA DE LINHA — o ponto que já custou um defeito em produção
-------------------------------------------------------------------------
A coluna `nvts.summary` do banco do gvmd guarda a quebra de linha como os DOIS
caracteres `\` e `n`. O XML do relatório, por outro lado, entrega quebra REAL.
Um catálogo montado a partir do banco carrega o escape, e aí o `\n` sai
**impresso** no PDF — foram 264 linhas assim na primeira tentativa. Este script
desescapa; não remova essa etapa.

Depois de gerar, rode SEMPRE o teste de tortura (tools/build-torture-fixture.py):
é ele que prova que nenhuma das entradas quebra o LaTeX.
"""
import json
import re
import sys
from xml.sax.saxutils import escape

CAMPOS = ("name", "summary", "insight", "impact", "affected", "solution")


def desescapa(v: str) -> str:
    """Quebra de linha na forma que o LaTeX espera, e nada de `\\n` impresso."""
    v = v.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    v = v.replace('\\"', '"').replace("\\t", " ")
    # Três ou mais quebras não fazem nada de útil no LaTeX além de \par duplo.
    return re.sub(r"\n{3,}", "\n\n", v).strip()


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    caminho, lang = sys.argv[1], sys.argv[2]
    cat = json.load(open(caminho, encoding="utf-8"))

    vistos = set()
    linhas = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!-- Catálogo de tradução dos NVTs, indexado pelo OID.",
        "     Origem: textos do Greenbone Community Feed (GPL), traduzidos.",
        "     Gerado por tools/build-nvt-catalog.py — não editar à mão.",
        "     OID ausente aqui faz o relatório cair no texto do fornecedor, e o",
        '     card recebe o chip "ORIGINAL DO FORNECEDOR". -->',
        '<nvti18n lang="%s">' % escape(lang),
    ]
    for x in cat:
        oid = (x.get("oid") or "").strip()
        if not oid:
            print("entrada sem oid, ignorada", file=sys.stderr)
            continue
        if oid in vistos:
            print("OID duplicado, ignorado: %s" % oid, file=sys.stderr)
            continue
        vistos.add(oid)
        partes = ['<n o="%s">' % escape(oid)]
        for c in CAMPOS:
            v = desescapa(x.get(c) or "")
            if v:
                partes.append("<%s>%s</%s>" % (c, escape(v), c))
        partes.append("</n>")
        linhas.append("".join(partes))
    linhas.append("</nvti18n>")

    xml = "\n".join(linhas)
    sys.stdout.write(xml + "\n")
    print("catálogo %s: %d entradas, %d bytes"
          % (lang, len(vistos), len(xml.encode())), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
