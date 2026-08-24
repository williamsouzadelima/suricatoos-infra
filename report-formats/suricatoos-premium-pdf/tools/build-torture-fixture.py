#!/usr/bin/env python3
"""Gera um relatório sintético que exercita TODA entrada do catálogo de tradução.

Por que existe
--------------
O catálogo (`nvt-i18n-<lang>.xml`) injeta centenas de milhares de caracteres de
texto novo no LaTeX. Um relatório real toca ~100 dos ~670 NVTs, então compilar um
relatório de verdade prova pouco: um caractere não escapado em qualquer das outras
entradas só apareceria quando um cliente batesse nela.

Este script monta um XML de relatório com **um achado por OID do catálogo**. Se ele
compila limpo, toda a tradução está provada segura no LaTeX.

Uso
---
    python3 tools/build-torture-fixture.py pt_BR > /tmp/tortura.xml
    xsltproc --stringparam lang pt_BR latex.xsl /tmp/tortura.xml > r.tex
    pdflatex -interaction=batchmode r.tex

Gates (todos obrigatórios):
    grep -cE '^! ' r.log                    -> 0
    grep -cE 'Font shape .* undefined' r.log -> 0
    grep -cE 'Overfull .hbox' r.log          -> 0
    pdffonts r.pdf | grep -c 'Type 3'        -> 0

ATENÇÃO à raiz do XML: o `latex.xsl` trata `<report extension="xml">` como
invólucro e procura um `<report>` interno. A raiz aqui NÃO leva `extension`, senão
o xsltproc devolve saída vazia com exit 0 — falha silenciosa que já custou uma
rodada de depuração.

ESPERADO, não é defeito: o PDF sai com centenas de "texto original do fornecedor".
São os NVTs cujo `insight`/`impact`/`affected` são vazios NA FONTE — o catálogo os
deixa vazios também, e aí o fallback (o placeholder daqui) é o que renderiza.
`summary` e `name` nunca são vazios, então esses dois estão sempre exercitados
pelo texto traduzido de verdade.
"""
import sys
from xml.sax.saxutils import escape
from xml.etree import ElementTree as ET

CAMPOS = ("summary", "insight", "impact", "affected")


def main() -> int:
    lang = sys.argv[1] if len(sys.argv) > 1 else "pt_BR"
    cat = ET.parse("nvt-i18n-%s.xml" % lang).getroot()
    entradas = cat.findall("n")
    if not entradas:
        print("catálogo vazio para %s — nada a exercitar" % lang, file=sys.stderr)
        return 1

    res = []
    for i, n in enumerate(entradas):
        oid = n.get("o")
        nome = (n.findtext("name") or "sem nome").strip()
        # As tags carregam o texto do FORNECEDOR; o catálogo é que substitui na
        # renderização. Aqui vão placeholders: o objeto do teste é o texto
        # traduzido, não o fallback.
        tags = "|".join("%s=texto original do fornecedor para %s" % (c, oid)
                        for c in CAMPOS)
        sol = (n.findtext("solution") or "sem solução").strip()
        sev = ("9.8", "7.5", "5.3", "2.6", "0.0")[i % 5]
        qod = ("98", "80", "70", "30")[i % 4]
        res.append(
            '<result id="tortura-%04d">'
            "<name>%s</name>"
            "<host>10.0.0.%d<hostname>t%d.exemplo</hostname></host>"
            "<port>%d/tcp</port>"
            '<nvt oid="%s"><type>nvt</type><name>%s</name>'
            "<family>Torture</family><cvss_base>%s</cvss_base>"
            "<tags>%s</tags>"
            '<solution type="VendorFix">%s</solution>'
            '<refs><ref type="cve" id="CVE-2024-%04d"/></refs></nvt>'
            "<threat>High</threat><severity>%s</severity>"
            "<qod><value>%s</value><type>remote_banner</type></qod>"
            "<description>saida literal de ferramenta, nao traduzida</description>"
            "</result>"
            % (i, escape(nome), 1 + i % 250, i, 1000 + i % 9000,
               escape(oid), escape(nome), sev, escape(tags), escape(sol),
               1000 + i % 9000, sev, qod)
        )

    n = len(res)
    faixa = n // 5
    print(
        '<report content_type="text/xml" id="tortura-0000-0000-0000-000000000000">'
        "<owner><name>admin</name></owner><name>tortura</name>"
        '<task id="t-0000"><name>catalogo-tortura-%s</name></task>'
        "<scan_start>2026-01-01T00:00:00Z</scan_start>"
        "<scan_end>2026-01-01T01:00:00Z</scan_end>"
        "<timezone>UTC</timezone><timezone_abbrev>UTC</timezone_abbrev>"
        '<filters id="0"><term>apply_overrides=0 levels=chmlgf rows=-1 min_qod=1</term></filters>'
        "<result_count>%d<full>%d</full><filtered>%d</filtered>"
        "<critical><full>%d</full><filtered>%d</filtered></critical>"
        "<high><full>%d</full><filtered>%d</filtered></high>"
        "<medium><full>%d</full><filtered>%d</filtered></medium>"
        "<low><full>%d</full><filtered>%d</filtered></low>"
        "<log><full>%d</full><filtered>%d</filtered></log></result_count>"
        "<hosts><count>250</count></hosts>"
        '<results start="1" max="%d">%s</results>'
        "</report>"
        % (lang, n, n, n, faixa, faixa, faixa, faixa, faixa, faixa,
           faixa, faixa, faixa, faixa, n, "".join(res))
    )
    print("tortura: %d entradas de %s" % (n, lang), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
