#!/usr/bin/env python3
"""Build the combined Greenbone feed XML for the Suricatoos Premium PDF report
format from the files in the suricatoos-premium-pdf/ bundle directory.

The report ships in THREE editions -- technical, client and executive, the
`variant' of the fleet contract (ADR-0011, report.export and
capabilities.report_formats) -- in THREE languages each -- English, Brazilian
Portuguese and Spanish --, as NINE separate ``<report_format>`` objects, so the
user can pick edition and language straight from the GSA "Download report"
dropdown (GSA offers no per-download parameter for predefined formats, so one
format per combination is the only way to expose the choice there).

The nine formats share the SAME stylesheet (``latex.xsl``) and logo assets; the
only thing that differs is the ``generate`` script's ``--stringparam lang`` and
``--stringparam variant`` values (and the object's id/name). We therefore keep a
single source bundle and synthesise the per-object ``generate`` and
``report_format.xml`` here, so there is nothing duplicated on disk to drift out
of sync.

Each object's ``<file>`` children carry the bundle files base64-encoded, mirroring
the stock Greenbone ``pdf-c402cc3e-...`` feed object. Dropping the resulting files
into the report-formats feed source makes gvmd install them as predefined +
trusted (no GPG signing, no GSA change).

The nine objects are BUILD OUTPUTS, not versioned (.gitignore): every report
change used to regenerate ~21 MB in the history of the public repo. The CI
(feed-sync) and the publish workflow run this script before using them, and the
Dockerfile COPYs them into the feed image.

The VERSION is never edited by hand: it is derived from the content (see
``derive_version``), so the same bundle gives the same VERSION on any machine
and any change to what the objects carry gives another one.

It also writes ``manifest.json``: the nine ``{format, lang, variant, uuid, name}``
combinations, versioned in the repo, which the fleet connector reads to announce
``capabilities.report_formats`` and to map a ``report.export`` to the right
report format id. The CI (ci/check-manifest.py) checks it against the objects.
It carries no VERSION: a versioned file cannot hold a value derived from the
content that is committed together with it (and every bundle change would
conflict on that line). And it writes ``suricatoos-premium-pdf/report_format.xml``,
the reference descriptor of the English technical object (generated and not
versioned like the objects, since it embeds the VERSION; the build never reads it).

Usage:  python3 build-feed-xml.py [--print-version]
"""
import argparse
import base64
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "suricatoos-premium-pdf")
MANIFEST = os.path.join(HERE, "manifest.json")

# ---------------------------------------------------------------------------
# VERSION: derived from the CONTENT, never edited by hand.
#
# It is the sha256 of what the nine feed objects carry -- the bundle members that
# ship, the synthesised generate and descriptor, and the texts written below --,
# rendered with VERSION_TOKEN where the VERSION itself goes (so it cannot depend
# on itself), cut to VERSION_DIGITS hex digits:
#   - the same content gives the same VERSION on any machine and in any directory
#     (no build date, no git history, no path, no mtime);
#   - one byte more or less in any shipped member or text gives another VERSION;
#   - a file of the bundle directory that never ships (FONTS.md, tools/...) does
#     not count: the VERSION names what is delivered, not what sits in the folder;
#   - the order of FORMATS does not count either: the objects are hashed in
#     file-name order (the manifest keeps the FORMATS order: it is its contract).
# The VERSION is informational text -- the summary and description of each object
# --: gvmd re-imports a feed report format when the file's mtime is newer than the
# report format's modification_time (gvmd 26.40.2 and 26.41.0,
# report_format_updated_in_feed), not by comparing versions, and the feed-updater
# only compares the image ID.
# The "sha256-" prefix keeps it from being read as a number: a bare hex string such
# as 1e5 or 000123 is a float or an integer to some YAML and JSON consumers.
VERSION_TOKEN = "@VERSION@"
VERSION_PREFIX = "sha256-"
VERSION_DIGITS = 12

# O `format' do contrato da frota (ADR-0011): o mesmo nos nove objetos.
FORMAT = "suricatoos-pdf"
LANGS = ["en", "pt_BR", "es"]
VARIANTS = ["technical", "client", "executive"]

# (lang code passed to xsltproc, edition, report_format UUID, dropdown name).
# The three technical objects keep their original UUIDs, so the already-deployed
# objects are updated in place rather than duplicated (EN was the first one).
# The six client/executive UUIDs were generated once (uuid4) and are fixed here:
# the fleet connector maps (format, lang, variant) to them through manifest.json.
FORMATS = [
    ("en",    "technical", "c6482c1b-57bb-406b-a501-c97eed86ad05", "Suricatoos PDF — Technical (EN)"),
    ("pt_BR", "technical", "e43a4f20-d845-4916-83f0-851ac6dc5e57", "Suricatoos PDF — Técnico (PT-BR)"),
    ("es",    "technical", "91afce49-21fd-4ea0-ba16-7ba2bc51a03a", "Suricatoos PDF — Técnico (ES)"),
    ("en",    "client",    "97ce15ea-69b9-4b0e-8799-ca0938b11bd6", "Suricatoos PDF — Client (EN)"),
    ("pt_BR", "client",    "6b746183-2d7d-4a90-89f7-b082a4775cb9", "Suricatoos PDF — Cliente (PT-BR)"),
    ("es",    "client",    "9ebc0c90-4f1c-49cb-a62f-598d59b473a6", "Suricatoos PDF — Cliente (ES)"),
    ("en",    "executive", "15195ce6-6093-4c4e-8f71-84205ea5a37b", "Suricatoos PDF — Executive (EN)"),
    ("pt_BR", "executive", "94e96b4b-2584-46b0-afcb-5852ab8c24c9", "Suricatoos PDF — Executivo (PT-BR)"),
    ("es",    "executive", "330072bd-3941-40fd-8114-38ab9cbbf396", "Suricatoos PDF — Ejecutivo (ES)"),
]

# Plain text only: these strings go into the XML verbatim (no & and no <).
# VERSION_TOKEN stands where the VERSION goes; with_version() fills it at render
# time (derive_version() renders with the token itself, to hash everything else).
SUMMARY = {
    ("en", "technical"): (
        "Suricatoos PDF vulnerability report, technical edition: the complete report, with every "
        "finding, the port and IP exposure map and the per-host appendix (English). "
        "Version " + VERSION_TOKEN + "."),
    ("pt_BR", "technical"): (
        "Relatório PDF de vulnerabilidades Suricatoos, edição técnica: o relatório completo, com "
        "todos os achados, o mapa de exposição de portas e IPs e o apêndice por host "
        "(Português-BR). Versão " + VERSION_TOKEN + "."),
    ("es", "technical"): (
        "Informe PDF de vulnerabilidades Suricatoos, edición técnica: el informe completo, con "
        "todos los hallazgos, el mapa de exposición de puertos e IPs y el apéndice por host "
        "(Español). Versión " + VERSION_TOKEN + "."),
    ("en", "client"): (
        "Suricatoos PDF vulnerability report, client edition: the technical report for the "
        "client's IT team, without false positives and with informational (Log) results only as "
        "a count (English). Version " + VERSION_TOKEN + "."),
    ("pt_BR", "client"): (
        "Relatório PDF de vulnerabilidades Suricatoos, edição do cliente: o relatório técnico para "
        "a equipe de TI do cliente, sem falsos positivos e com os resultados informativos (Log) "
        "só como contagem (Português-BR). Versão " + VERSION_TOKEN + "."),
    ("es", "client"): (
        "Informe PDF de vulnerabilidades Suricatoos, edición para el cliente: el informe técnico "
        "para el equipo de TI del cliente, sin falsos positivos y con los resultados informativos "
        "(Log) solo como recuento (Español). Versión " + VERSION_TOKEN + "."),
    ("en", "executive"): (
        "Suricatoos PDF vulnerability report, executive edition: the executive summary, the "
        "priorities and next steps, and the scope, methodology and limitations (English). "
        "Version " + VERSION_TOKEN + "."),
    ("pt_BR", "executive"): (
        "Relatório PDF de vulnerabilidades Suricatoos, edição executiva: o resumo executivo, as "
        "prioridades e próximos passos, e o escopo, a metodologia e as limitações "
        "(Português-BR). Versão " + VERSION_TOKEN + "."),
    ("es", "executive"): (
        "Informe PDF de vulnerabilidades Suricatoos, edición ejecutiva: el resumen ejecutivo, las "
        "prioridades y próximos pasos, y el alcance, la metodología y las limitaciones "
        "(Español). Versión " + VERSION_TOKEN + "."),
}
DESCRIPTION = {
    ("en", "technical"): (
        "Technical edition of the premium, corporate vulnerability assessment report in PDF "
        "(English): branded cover, executive risk summary with a severity dashboard, priorities "
        "and next steps, a hexagonal PORT EXPOSURE MAP that shows every (transport, port) in the "
        "scope with its severity and the IP addresses mapped to it, a hosts and open-ports "
        "inventory, a findings summary table, detailed findings grouped by vulnerability (CVSS, "
        "CVEs, affected systems, remediation), scope, methodology and limitations, and a per-host "
        "appendix. Version " + VERSION_TOKEN + "."),
    ("pt_BR", "technical"): (
        "Edição técnica do relatório corporativo premium de avaliação de vulnerabilidades em PDF "
        "(Português-BR): capa com a marca, resumo executivo de risco com painel de severidade, "
        "prioridades e próximos passos, MAPA DE EXPOSIÇÃO DE PORTAS em favo de mel mostrando cada "
        "par (transporte, porta) do escopo com sua severidade e os endereços IP mapeados, "
        "inventário de hosts e portas abertas, tabela-resumo de achados, achados detalhados "
        "agrupados por vulnerabilidade (CVSS, CVEs, sistemas afetados, remediação), escopo, "
        "metodologia e limitações, e um apêndice por host. Versão " + VERSION_TOKEN + "."),
    ("es", "technical"): (
        "Edición técnica del informe corporativo premium de evaluación de vulnerabilidades en PDF "
        "(Español): portada con la marca, resumen ejecutivo de riesgo con panel de severidad, "
        "prioridades y próximos pasos, MAPA DE EXPOSICIÓN DE PUERTOS en panal que muestra cada par "
        "(transporte, puerto) del alcance con su severidad y las direcciones IP mapeadas, "
        "inventario de hosts y puertos abiertos, tabla-resumen de hallazgos, hallazgos detallados "
        "agrupados por vulnerabilidad (CVSS, CVEs, sistemas afectados, remediación), alcance, "
        "metodología y limitaciones, y un apéndice por host. Versión " + VERSION_TOKEN + "."),
    ("en", "client"): (
        "Client edition of the Suricatoos PDF report, for the client's IT team (English): the "
        "same structure as the technical edition, without any false positive (results marked as "
        "false positive are left out of every list, card, count and total, as if the report had "
        "been exported without them) and with informational (Log) results only as a count; "
        "low-confidence findings stay in the separate block of indicators to validate. "
        "Version " + VERSION_TOKEN + "."),
    ("pt_BR", "client"): (
        "Edição do cliente do relatório PDF Suricatoos, para a equipe de TI do cliente "
        "(Português-BR): a mesma estrutura da edição técnica, sem nenhum falso positivo (os "
        "resultados marcados como falso positivo ficam fora de toda lista, card, contagem e total, "
        "como se o relatório fosse exportado sem eles) e com os resultados informativos (Log) só "
        "como contagem; os achados de baixa confiança continuam no bloco separado de indicadores "
        "a validar. Versão " + VERSION_TOKEN + "."),
    ("es", "client"): (
        "Edición para el cliente del informe PDF Suricatoos, para el equipo de TI del cliente "
        "(Español): la misma estructura de la edición técnica, sin ningún falso positivo (los "
        "resultados marcados como falso positivo quedan fuera de toda lista, tarjeta, recuento y "
        "total, como si el informe se exportara sin ellos) y con los resultados informativos (Log) "
        "solo como recuento; los hallazgos de baja confianza siguen en el bloque separado de "
        "indicadores a validar. Versión " + VERSION_TOKEN + "."),
    ("en", "executive"): (
        "Executive edition of the Suricatoos PDF report (English): the executive summary, the "
        "priorities and next steps, and the scope, methodology and limitations, numbered 1 to 3; "
        "no finding cards, no hosts and ports, no appendix. Version " + VERSION_TOKEN + "."),
    ("pt_BR", "executive"): (
        "Edição executiva do relatório PDF Suricatoos (Português-BR): o resumo executivo, as "
        "prioridades e próximos passos, e o escopo, a metodologia e as limitações, numerados de "
        "1 a 3; sem cards de achado, sem hosts e portas, sem apêndice. Versão " + VERSION_TOKEN + "."),
    ("es", "executive"): (
        "Edición ejecutiva del informe PDF Suricatoos (Español): el resumen ejecutivo, las "
        "prioridades y próximos pasos, y el alcance, la metodología y las limitaciones, numerados "
        "del 1 al 3; sin tarjetas de hallazgo, sin hosts y puertos, sin apéndice. "
        "Versión " + VERSION_TOKEN + "."),
}

# Files whose content is IDENTICAL across all the objects (read from disk).
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


# Canonical generate script, read once and rewritten per object. It carries the
# literal tokens "--stringparam lang en" and "--stringparam variant technical",
# EACH exactly once, on the xsltproc line; we swap the value of each for the
# object's language and edition.
LANG_TOKEN = "--stringparam lang en"
VARIANT_TOKEN = "--stringparam variant technical"


def b64_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_file(path: str) -> str:
    with open(path, "rb") as fh:
        return b64_bytes(fh.read())


def generate_for(lang: str, variant: str) -> bytes:
    # Read as BYTES, like every other bundle member: the bundle now carries a
    # gzip tarball, and one text-mode read anywhere in here would corrupt it, so
    # the whole path stays on bytes with no encode/decode round trip.
    with open(os.path.join(BUNDLE, "generate"), "rb") as fh:
        script = fh.read()
    # A CR here means a CRLF checkout (core.autocrlf on Windows). Embedded in the
    # feed it breaks the shell script inside gvmd AND makes this build differ
    # from the CI's, so refuse instead of shipping it.
    if b"\r" in script:
        raise SystemExit(
            "generate: has CR (CRLF line endings) — check it out with LF "
            "(.gitattributes eol=lf) before building the feed"
        )
    if lang not in LANGS or variant not in VARIANTS:
        raise SystemExit("generate: unknown language/edition %r/%r" % (lang, variant))
    # Each token exactly ONCE: a second copy (in a comment, say) would also be
    # rewritten, and a missing one would leave the object on the canonical value
    # -- the wrong edition in silence.
    for token, value in ((LANG_TOKEN, lang), (VARIANT_TOKEN, variant)):
        raw = token.encode("ascii")
        n = script.count(raw)
        if n != 1:
            raise SystemExit(
                "generate: expected token %r exactly once, found %d — cannot set %s"
                % (token, n, token.split()[1]))
        script = script.replace(raw, raw.rsplit(b" ", 1)[0] + b" " + value.encode("ascii"))
    return script


def with_version(text: str, version: str) -> str:
    """SUMMARY and DESCRIPTION carry VERSION_TOKEN where the VERSION goes."""
    return text.replace(VERSION_TOKEN, version)


def report_format_xml_for(fmt_id: str, name: str, lang: str, variant: str, version: str) -> bytes:
    """A per-object report_format.xml embedded as the object's own descriptor.
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
    ) % (fmt_id, name, with_version(SUMMARY[(lang, variant)], version),
         with_version(DESCRIPTION[(lang, variant)], version), files)
    return xml.encode("utf-8")


def build_feed_object(lang: str, variant: str, fmt_id: str, name: str, version: str) -> str:
    # Order mirrors the stock bundle: scripts first, then embedded assets.
    parts = [
        "<!-- Copyright (C) 2026 Suricatoos -->",
        '<report_format id="%s">' % fmt_id,
        "  <name>%s</name>" % name,
        "  <summary>%s</summary>" % with_version(SUMMARY[(lang, variant)], version),
        "  <description>%s</description>" % with_version(DESCRIPTION[(lang, variant)], version),
        "  <extension>pdf</extension>",
        "  <content_type>application/pdf</content_type>",
        "  <report_type>all</report_type>",
    ]
    # Synthesised, object-specific files.
    parts.append('  <file name="generate">%s</file>' % b64_bytes(generate_for(lang, variant)))
    parts.append('  <file name="report_format.xml">%s</file>'
                 % b64_bytes(report_format_xml_for(fmt_id, name, lang, variant, version)))
    # Bundle members, all read in binary. Quase todos sao identicos entre os
    # objetos; a excecao e' o catalogo de traducao, que e' o do idioma do objeto.
    for n in shared_files(lang):
        parts.append('  <file name="%s">%s</file>' % (n, b64_file(os.path.join(BUNDLE, n))))
    parts.append("</report_format>")
    parts.append("")
    return "\n".join(parts)


def feed_object_name(fmt_id: str) -> str:
    """The file name gvmd requires: it takes the UUID from the end of the name."""
    return "pdf-suricatoos-%s.xml" % fmt_id


def feed_objects(version: str) -> list:
    """The nine feed objects as (file name, text), in the order of FORMATS."""
    return [(feed_object_name(fmt_id), build_feed_object(lang, variant, fmt_id, name, version))
            for lang, variant, fmt_id, name in FORMATS]


def content_digest() -> str:
    """sha256 of everything the nine objects carry but the VERSION itself: the
    objects rendered with VERSION_TOKEN where it goes, each framed by its file
    name and length, in file-name order -- so reordering FORMATS alone, which
    changes nothing the objects carry, does not change the VERSION (and would not
    republish and re-import all nine). Pure function of the bundle members that
    ship and of the texts in this file -- nothing from the machine, the clock or
    git."""
    h = hashlib.sha256()
    for fname, text in sorted(feed_objects(VERSION_TOKEN), key=lambda o: o[0]):
        data = text.encode("utf-8")
        h.update(("%s %d\n" % (fname, len(data))).encode("ascii"))
        h.update(data)
    return h.hexdigest()


def derive_version() -> str:
    """The VERSION of the nine objects: VERSION_PREFIX + the first VERSION_DIGITS
    hex digits of content_digest()."""
    return VERSION_PREFIX + content_digest()[:VERSION_DIGITS]


def manifest() -> dict:
    """As nove combinacoes (format, lang, variant) -> report format, na ordem de
    FORMATS: o que o conector da frota le para anunciar
    capabilities.report_formats e escolher o objeto de um report.export. Sem
    VERSION: arquivo versionado nao pode guardar um valor derivado do conteudo
    que vai no mesmo commit."""
    return {
        "report_formats": [
            {"format": FORMAT, "lang": lang, "variant": variant, "uuid": fmt_id, "name": name}
            for lang, variant, fmt_id, name in FORMATS
        ],
    }


def manifest_bytes() -> bytes:
    return (json.dumps(manifest(), ensure_ascii=False, indent=2) + "\n").encode("utf-8")


# The bundle's own report_format.xml: the reference descriptor of the English
# technical object. The build never READS it (each object embeds its own
# descriptor, synthesised above); it WRITES it, from the same function the EN
# technical object uses, so its summary, description, VERSION and file list
# can no longer go stale by hand. It embeds the VERSION, so it is generated and
# not versioned, like the objects (.gitignore). ci/check-manifest.py checks it.
REFERENCE = os.path.join(BUNDLE, "report_format.xml")
REFERENCE_NOTE = (
    "<!-- Reference descriptor of the English technical object, WRITTEN by\n"
    "     ../build-feed-xml.py: do not edit it by hand. It is the descriptor the\n"
    "     EN technical feed object embeds, so its summary, description, VERSION\n"
    "     and file list follow the build. The nine objects installed (three\n"
    "     editions x three languages) are synthesised by the build, each with its\n"
    "     own copy; the build never reads this file. -->\n")


def reference_descriptor(version: str) -> bytes:
    fmt_id, name = next((f, n) for lang, variant, f, n in FORMATS
                        if (lang, variant) == ("en", "technical"))
    xml = report_format_xml_for(fmt_id, name, "en", "technical", version)
    head = b"<!-- Copyright (C) 2026 Suricatoos -->\n"
    if not xml.startswith(head):
        raise SystemExit("report_format_xml_for: unexpected header, cannot write the reference descriptor")
    return head + REFERENCE_NOTE.encode("utf-8") + xml[len(head):]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--print-version", action="store_true",
                    help="print the VERSION derived from the content and exit (writes nothing)")
    args = ap.parse_args()
    version = derive_version()
    if args.print_version:
        print(version)
        return
    print("VERSION %s  (content digest of the nine objects)" % version)
    print("bundle manifest:")
    for n in object_file_names(LANGS[0]):
        src = os.path.join(BUNDLE, n)
        size = os.path.getsize(src) if os.path.exists(src) else 0
        print("  %-32s %9s bytes%s" % (n, size or "synth", "" if size else " (synthesised)"))
    for (fname, xml), (lang, variant, fmt_id, name) in zip(feed_objects(version), FORMATS):
        out = os.path.join(HERE, fname)
        # newline="\n": the same bytes on every OS (text mode on Windows would
        # write CRLF, and the working copy would stop matching the CI's build).
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(xml)
        digest = hashlib.sha256(xml.encode("utf-8")).hexdigest()[:12]
        print("wrote %s  (%s, %d bytes, sha256 %s)" % (fname, name, os.path.getsize(out), digest))
    with open(MANIFEST, "wb") as fh:
        fh.write(manifest_bytes())
    print("wrote %s  (%d combinations)" % (os.path.basename(MANIFEST), len(FORMATS)))
    with open(REFERENCE, "wb") as fh:
        fh.write(reference_descriptor(version))
    print("wrote suricatoos-premium-pdf/report_format.xml  (reference descriptor, EN technical)")


if __name__ == "__main__":
    main()
