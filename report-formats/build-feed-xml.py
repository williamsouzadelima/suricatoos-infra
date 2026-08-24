#!/usr/bin/env python3
"""Build the combined Greenbone feed XML for the Suricatoos Premium PDF report
format from the files in the suricatoos-premium-pdf/ bundle directory.

The report ships in THREE languages — English, Brazilian Portuguese and Spanish
— as three separate ``<report_format>`` objects so the user can pick the report
language straight from the GSA "Download report" dropdown (GSA offers no
per-download parameter for predefined formats, so one format per language is the
only way to expose the choice there).

The three formats share the SAME stylesheet (``latex.xsl``) and logo assets; the
only thing that differs is the ``generate`` script's ``--stringparam lang`` value
(and the object's id/name). We therefore keep a single source bundle and
synthesise the per-language ``generate`` and ``report_format.xml`` here, so there
is nothing duplicated on disk to drift out of sync.

Each object's ``<file>`` children carry the bundle files base64-encoded, mirroring
the stock Greenbone ``pdf-c402cc3e-...`` feed object. Dropping the resulting files
into the report-formats feed source makes gvmd install them as predefined +
trusted (no GPG signing, no GSA change).

Usage:  python3 build-feed-xml.py
"""
import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "suricatoos-premium-pdf")

VERSION = "20260824b"

# (lang code passed to xsltproc, report_format UUID, dropdown name).
# EN keeps the original UUID so the already-deployed object is updated in place
# rather than duplicated.
LANGS = [
    ("en",    "c6482c1b-57bb-406b-a501-c97eed86ad05", "Suricatoos Premium PDF (EN)"),
    ("pt_BR", "e43a4f20-d845-4916-83f0-851ac6dc5e57", "Suricatoos Premium PDF (PT-BR)"),
    ("es",    "91afce49-21fd-4ea0-ba16-7ba2bc51a03a", "Suricatoos Premium PDF (ES)"),
]

SUMMARY = {
    "en":    ("Premium branded PDF vulnerability report with the port and IP exposure map "
              "(English). Version " + VERSION + "."),
    "pt_BR": ("Relatório PDF premium de vulnerabilidades com o mapa de exposição de portas "
              "e IPs (Português-BR). Versão " + VERSION + "."),
    "es":    ("Informe PDF premium de vulnerabilidades con el mapa de exposición de puertos "
              "e IPs (Español). Versión " + VERSION + "."),
}
DESCRIPTION = {
    "en": (
        "A premium, corporate vulnerability assessment report in PDF (English): "
        "branded cover, executive risk summary with a severity dashboard, a "
        "hexagonal PORT EXPOSURE MAP that shows every (transport, port) in the "
        "scope with its severity and the IP addresses mapped to it (plus a "
        "per-host appendix), a hosts and open-ports inventory, a findings summary "
        "table, and detailed findings grouped by vulnerability (CVSS, CVEs, "
        "affected systems, remediation). Version " + VERSION + "."
    ),
    "pt_BR": (
        "Relatório corporativo premium de avaliação de vulnerabilidades em PDF "
        "(Português-BR): capa com a marca, resumo executivo de risco com painel de "
        "severidade, MAPA DE EXPOSIÇÃO DE PORTAS em favo de mel mostrando cada par "
        "(transporte, porta) do escopo com sua severidade e os endereços IP "
        "mapeados (mais um apêndice por host), inventário de hosts e portas "
        "abertas, tabela-resumo de achados e achados detalhados agrupados por "
        "vulnerabilidade (CVSS, CVEs, sistemas afetados, remediação). "
        "Versão " + VERSION + "."
    ),
    "es": (
        "Informe corporativo premium de evaluación de vulnerabilidades en PDF "
        "(Español): portada con la marca, resumen ejecutivo de riesgo con panel de "
        "severidad, MAPA DE EXPOSICIÓN DE PUERTOS en panal que muestra cada par "
        "(transporte, puerto) del alcance con su severidad y las direcciones IP "
        "mapeadas (más un apéndice por host), inventario de hosts y puertos "
        "abiertos, tabla-resumen de hallazgos y hallazgos detallados agrupados por "
        "vulnerabilidad (CVSS, CVEs, sistemas afectados, remediación). "
        "Versión " + VERSION + "."
    ),
}

# Files whose content is IDENTICAL across all three languages (read from disk).
# Everything here travels base64-encoded inside each feed object, so gvmd writes
# it back out next to `generate' at install time; `generate' then copies the
# .sty modules and unpacks plex-min.tar.gz into the per-run temp dir.
#
# The .sty design-system modules are DISCOVERED, not listed: they are written by
# several hands in parallel and `generate' ships whatever `cp ./*.sty' finds, so
# a hardcoded list here would silently drop a module and the report would fail to
# compile in production. Sorted for a stable, reviewable file order.
STATIC_SHARED_FILES = [
    "latex.xsl",
    # IBM Plex as a Type1 TDS subtree. BINARY, and by far the largest member of
    # the bundle: the gvmd container ships no Plex, and without this pdflatex
    # falls back to Latin Modern without saying a word.
    "plex-min.tar.gz",
    # Catalogo de traducao dos NVTs (um por idioma). Sem ele o relatorio em
    # pt-BR sai com metade da prosa em ingles, porque o texto de
    # vulnerabilidade do feed do Greenbone so existe nesse idioma.
    "suricatoos-wordmark-navy.pdf",
    "suricatoos-wordmark-white.pdf",
    "suricatoos-mark-navy.pdf",
    "suricatoos-mark-white.pdf",
]


def shared_files(lang=None):
    """The bundle members of one object, design-system .sty modules included.

    O catalogo de traducao dos NVTs e' POR IDIOMA e pesa ~425 KB: mandar os tres
    em cada objeto triplicaria o peso sem que nenhum dos dois extras chegasse a
    ser lido (o latex.xsl carrega exatamente `nvt-i18n-<lang>.xml`). Entao cada
    objeto leva so' o seu."""
    styles = sorted(n for n in os.listdir(BUNDLE) if n.endswith(".sty"))
    if "suricatoos-tokens.sty" not in styles:
        raise SystemExit(
            "bundle is missing suricatoos-tokens.sty — refusing to build a feed "
            "object that cannot compile"
        )
    missing = [n for n in STATIC_SHARED_FILES
               if not os.path.exists(os.path.join(BUNDLE, n))]
    if missing:
        raise SystemExit("bundle is missing: %s" % ", ".join(missing))
    cat = ["nvt-i18n-%s.xml" % lang] if lang else []
    for n in cat:
        if not os.path.exists(os.path.join(BUNDLE, n)):
            raise SystemExit("bundle is missing: %s" % n)
    return STATIC_SHARED_FILES[:1] + styles + cat + STATIC_SHARED_FILES[1:]


def object_file_names(lang=None):
    """Every <file> the object carries, in the order it is written."""
    return ["generate", "report_format.xml"] + shared_files(lang)


# Canonical generate script, read once and rewritten per language. It carries the
# literal token "--stringparam lang en"; we swap "en" for the target language.
GENERATE_TOKEN = "--stringparam lang en"


def b64_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_file(path: str) -> str:
    with open(path, "rb") as fh:
        return b64_bytes(fh.read())


def generate_for(lang: str) -> bytes:
    # Read as BYTES, like every other bundle member: the bundle now carries a
    # gzip tarball, and one text-mode read anywhere in here would corrupt it, so
    # the whole path stays on bytes with no encode/decode round trip.
    with open(os.path.join(BUNDLE, "generate"), "rb") as fh:
        script = fh.read()
    token = GENERATE_TOKEN.encode("ascii")
    if token not in script:
        raise SystemExit(
            "generate: expected token %r not found — cannot set language"
            % GENERATE_TOKEN
        )
    return script.replace(token, b"--stringparam lang " + lang.encode("ascii"))


def report_format_xml_for(fmt_id: str, name: str, lang: str) -> bytes:
    """A per-language report_format.xml embedded as the object's own descriptor.
    gvmd uses the outer feed element for identity, but we keep this consistent so
    the delivered descriptor never contradicts the object it ships in."""
    files = "\n".join('  <file name="%s"/>' % n for n in object_file_names(lang))
    xml = (
        "<!-- Copyright (C) 2026 Suricatoos -->\n"
        '<report_format id="%s">\n'
        "  <name>%s</name>\n"
        "  <summary>%s</summary>\n"
        "  <description>%s</description>\n"
        "  <extension>pdf</extension>\n"
        "  <content_type>application/pdf</content_type>\n"
        "  <report_type>all</report_type>\n"
        "%s\n"
        "</report_format>\n"
    ) % (fmt_id, name, SUMMARY[lang], DESCRIPTION[lang], files)
    return xml.encode("utf-8")


def build_feed_object(lang: str, fmt_id: str, name: str) -> str:
    # Order mirrors the stock bundle: scripts first, then embedded assets.
    parts = [
        "<!-- Copyright (C) 2026 Suricatoos -->",
        '<report_format id="%s">' % fmt_id,
        "  <name>%s</name>" % name,
        "  <summary>%s</summary>" % SUMMARY[lang],
        "  <description>%s</description>" % DESCRIPTION[lang],
        "  <extension>pdf</extension>",
        "  <content_type>application/pdf</content_type>",
        "  <report_type>all</report_type>",
    ]
    # Synthesised, language-specific files.
    parts.append('  <file name="generate">%s</file>' % b64_bytes(generate_for(lang)))
    parts.append('  <file name="report_format.xml">%s</file>'
                 % b64_bytes(report_format_xml_for(fmt_id, name, lang)))
    # Bundle members, all read in binary. Quase todos sao identicos entre os
    # idiomas; a excecao e' o catalogo de traducao, que e' o do idioma do objeto.
    for n in shared_files(lang):
        parts.append('  <file name="%s">%s</file>' % (n, b64_file(os.path.join(BUNDLE, n))))
    parts.append("</report_format>")
    parts.append("")
    return "\n".join(parts)


def main():
    print("bundle manifest (%s):" % VERSION)
    for n in object_file_names(LANGS[0][0]):
        src = os.path.join(BUNDLE, n)
        size = os.path.getsize(src) if os.path.exists(src) else 0
        print("  %-32s %9s bytes%s" % (n, size or "synth", "" if size else " (synthesised)"))
    for lang, fmt_id, name in LANGS:
        xml = build_feed_object(lang, fmt_id, name)
        out = os.path.join(HERE, "pdf-suricatoos-%s.xml" % fmt_id)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(xml)
        print("wrote %s  (%s, %d bytes)" % (os.path.basename(out), name, os.path.getsize(out)))


if __name__ == "__main__":
    main()
