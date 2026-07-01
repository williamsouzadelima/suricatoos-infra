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

VERSION = "20260701"

# (lang code passed to xsltproc, report_format UUID, dropdown name).
# EN keeps the original UUID so the already-deployed object is updated in place
# rather than duplicated.
LANGS = [
    ("en",    "c6482c1b-57bb-406b-a501-c97eed86ad05", "Suricatoos Premium PDF (EN)"),
    ("pt_BR", "e43a4f20-d845-4916-83f0-851ac6dc5e57", "Suricatoos Premium PDF (PT-BR)"),
    ("es",    "91afce49-21fd-4ea0-ba16-7ba2bc51a03a", "Suricatoos Premium PDF (ES)"),
]

SUMMARY = {
    "en":    "Premium branded PDF vulnerability report (English). Version " + VERSION + ".",
    "pt_BR": "Relatório PDF premium de vulnerabilidades (Português-BR). Versão " + VERSION + ".",
    "es":    "Informe PDF premium de vulnerabilidades (Español). Versión " + VERSION + ".",
}
DESCRIPTION = {
    "en": (
        "A premium, corporate vulnerability assessment report in PDF (English): "
        "branded cover, executive risk summary with a severity dashboard, a hosts "
        "and open-ports inventory, a findings summary table, and detailed findings "
        "grouped by vulnerability (CVSS, CVEs, affected systems, remediation). "
        "Version " + VERSION + "."
    ),
    "pt_BR": (
        "Relatório corporativo premium de avaliação de vulnerabilidades em PDF "
        "(Português-BR): capa com a marca, resumo executivo de risco com painel de "
        "severidade, inventário de hosts e portas abertas, tabela-resumo de achados "
        "e achados detalhados agrupados por vulnerabilidade (CVSS, CVEs, sistemas "
        "afetados, remediação). Versão " + VERSION + "."
    ),
    "es": (
        "Informe corporativo premium de evaluación de vulnerabilidades en PDF "
        "(Español): portada con la marca, resumen ejecutivo de riesgo con panel de "
        "severidad, inventario de hosts y puertos abiertos, tabla-resumen de "
        "hallazgos y hallazgos detallados agrupados por vulnerabilidad (CVSS, CVEs, "
        "sistemas afectados, remediación). Versión " + VERSION + "."
    ),
}

# Files whose content is IDENTICAL across all three languages (read from disk).
SHARED_FILES = [
    "latex.xsl",
    "suricatoos-wordmark-white.pdf",
    "suricatoos-mark-navy.pdf",
    "suricatoos-mark-white.pdf",
]

# Canonical generate script, read once and rewritten per language. It carries the
# literal token "--stringparam lang en"; we swap "en" for the target language.
GENERATE_TOKEN = "--stringparam lang en"


def b64_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_file(path: str) -> str:
    with open(path, "rb") as fh:
        return b64_bytes(fh.read())


def generate_for(lang: str) -> bytes:
    with open(os.path.join(BUNDLE, "generate"), "r", encoding="utf-8") as fh:
        script = fh.read()
    if GENERATE_TOKEN not in script:
        raise SystemExit(
            "generate: expected token %r not found — cannot set language"
            % GENERATE_TOKEN
        )
    return script.replace(GENERATE_TOKEN, "--stringparam lang " + lang).encode("utf-8")


def report_format_xml_for(fmt_id: str, name: str, lang: str) -> bytes:
    """A per-language report_format.xml embedded as the object's own descriptor.
    gvmd uses the outer feed element for identity, but we keep this consistent so
    the delivered descriptor never contradicts the object it ships in."""
    files = "\n".join(
        '  <file name="%s"/>' % n
        for n in ["generate", "latex.xsl", "report_format.xml",
                  "suricatoos-wordmark-white.pdf", "suricatoos-mark-navy.pdf",
                  "suricatoos-mark-white.pdf"]
    )
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
    # Shared files (identical bytes across languages).
    for n in SHARED_FILES:
        parts.append('  <file name="%s">%s</file>' % (n, b64_file(os.path.join(BUNDLE, n))))
    parts.append("</report_format>")
    parts.append("")
    return "\n".join(parts)


def main():
    for lang, fmt_id, name in LANGS:
        xml = build_feed_object(lang, fmt_id, name)
        out = os.path.join(HERE, "pdf-suricatoos-%s.xml" % fmt_id)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(xml)
        print("wrote %s  (%s, %d bytes)" % (os.path.basename(out), name, os.path.getsize(out)))


if __name__ == "__main__":
    main()
