#!/usr/bin/env python3
"""Confere o manifesto dos report formats (report-formats/manifest.json) contra
os objetos de feed que ele descreve -- o que o conector da frota le para
anunciar capabilities.report_formats e escolher o objeto de um report.export
(ADR-0011). Um manifesto que mente manda o export para a edicao ou o idioma
errado sem erro nenhum.

Roda DEPOIS do build-feed-xml.py: os nove objetos e o descritor de referencia
sao gerados, nao versionados. Confere:
  - o manifesto e' o que o build-feed-xml.py escreve (mesmos bytes) e nao traz
    VERSION (arquivo versionado nao guarda valor derivado do conteudo);
  - a VERSION que o build deriva do conteudo tem o formato `sha256-<12 hex>' e e'
    a que cada objeto diz, uma vez no resumo e uma na descricao, e no
    report_format.xml embutido; nenhum objeto deixa o marcador da VERSION
    (VERSION_TOKEN) sem preencher;
  - as combinacoes sao exatamente idioma x edicao (en, pt_BR, es x technical,
    client, executive), uma de cada, com format `suricatoos-pdf', UUIDs
    canonicos (minusculos, v4) e distintos, nomes distintos que dizem o idioma;
  - o nome de cada combinacao e' exatamente "Suricatoos PDF — <edicao>
    (<IDIOMA>)", com o rotulo da EDICAO no idioma dela (EDITION_LABEL:
    Technical/Técnico/Técnico, Client/Cliente/Cliente,
    Executive/Executivo/Ejecutivo): e' pelo nome que se escolhe no GSA;
  - cada combinacao tem o SEU UUID, o fixado aqui: os tres tecnicos sao os de
    sempre (o objeto instalado e' atualizado no lugar; o mapeamento do ADR-0011
    os cita) e os seis das edicoes, os gerados uma vez na fatia R5;
  - para cada combinacao, o pdf-suricatoos-<uuid>.xml existe, o
    <report_format id> e o <name> batem, o `generate' embutido pede
    EXATAMENTE aquele idioma e aquela edicao na linha do xsltproc (os dois
    pares uma vez cada), o report_format.xml embutido tem o mesmo id e nome, e
    o catalogo de NVT embutido e' o do idioma;
  - o objeto leva EXATAMENTE os bytes do bundle: os membros, na ordem do
    build, sao os arquivos de suricatoos-premium-pdf/ lidos daqui (nada a
    mais, nada a menos, nenhum byte trocado) e o `generate' embutido e' o do
    bundle, diferindo so' nos dois valores da linha do xsltproc -- a igualdade
    de conteudo entre o que se publica e o que esta no repo;
  - nao ha pdf-suricatoos-*.xml que o manifesto nao descreva;
  - o descritor de referencia do bundle (suricatoos-premium-pdf/
    report_format.xml) e' o que o build escreve: o do objeto tecnico EN, com a
    VERSION e a lista de arquivos de agora.

Uso: python3 report-formats/ci/check-manifest.py [--dir report-formats/]
Sai 0 se tudo bate, 1 se algo nao bate, 2 em erro de leitura.
"""
import argparse
import base64
import glob
import importlib.util
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
LANGS = ("en", "pt_BR", "es")
VARIANTS = ("technical", "client", "executive")
LANG_LABEL = {"en": "(EN)", "pt_BR": "(PT-BR)", "es": "(ES)"}
# O rotulo da EDICAO no nome do menu do GSA, no idioma do objeto: e' pelo nome
# que o usuario escolhe a edicao no GSA (o conector da frota usa o UUID). Dois
# nomes trocados entre edicoes continuariam distintos e com o idioma certo, e
# so' esta tabela os pega.
EDITION_LABEL = {
    ("en", "technical"): "Technical",
    ("pt_BR", "technical"): "Técnico",
    ("es", "technical"): "Técnico",
    ("en", "client"): "Client",
    ("pt_BR", "client"): "Cliente",
    ("es", "client"): "Cliente",
    ("en", "executive"): "Executive",
    ("pt_BR", "executive"): "Executivo",
    ("es", "executive"): "Ejecutivo",
}
NAME_FORMAT = "Suricatoos PDF — %s %s"   # rotulo da edicao, rotulo do idioma
# Os UUIDs dos nove objetos, FIXOS: os tres tecnicos sao os de antes das
# edicoes (o EN e' o primeiro objeto instalado, e o ADR-0011 os cita), e os seis
# das edicoes do cliente e executiva foram gerados uma vez (uuid4) na fatia R5.
# Um UUID trocado, num objeto ja' instalado, duplica o report format no gvmd ou
# faz um export de uma edicao sair em outra: mudar um deles e' decisao, e muda
# aqui e no build-feed-xml.py juntos.
FIXED_UUIDS = {
    ("en", "technical"): "c6482c1b-57bb-406b-a501-c97eed86ad05",
    ("pt_BR", "technical"): "e43a4f20-d845-4916-83f0-851ac6dc5e57",
    ("es", "technical"): "91afce49-21fd-4ea0-ba16-7ba2bc51a03a",
    ("en", "client"): "97ce15ea-69b9-4b0e-8799-ca0938b11bd6",
    ("pt_BR", "client"): "6b746183-2d7d-4a90-89f7-b082a4775cb9",
    ("es", "client"): "9ebc0c90-4f1c-49cb-a62f-598d59b473a6",
    ("en", "executive"): "15195ce6-6093-4c4e-8f71-84205ea5a37b",
    ("pt_BR", "executive"): "94e96b4b-2584-46b0-afcb-5852ab8c24c9",
    ("es", "executive"): "330072bd-3941-40fd-8114-38ab9cbbf396",
}
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
XSLTPROC = re.compile(rb"(?m)^xsltproc --stringparam lang (\S+) --stringparam variant (\S+) ")
# O formato da VERSION que o build deriva do conteudo (repetido aqui de proposito:
# o checador nao confia no builder para dizer qual e' o formato certo).
VERSION_RE = re.compile(r"sha256-[0-9a-f]{12}")


def load_builder(rf_dir):
    spec = importlib.util.spec_from_file_location(
        "build_feed_xml", os.path.join(rf_dir, "build-feed-xml.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _version_in_text(where, what, tag, text, version):
    """A VERSION do build aparece UMA vez no texto e fecha a frase (`... Version
    <v>.'); nenhuma outra VERSION (a de um build velho) fica no texto."""
    text = text or ""
    if VERSION_RE.findall(text) != [version] or not text.endswith(" " + version + "."):
        return ["%s: o %s do %s nao diz so' a VERSION %s no fim: %r" % (where, tag, what, version, text[-70:])]
    return []


def _members_are_the_bundle(where, root, files, gen, lang, bundle_dir, b):
    """O objeto leva EXATAMENTE os bytes do bundle, lidos daqui e nao do build:
    e' a igualdade de conteudo entre o que se publica e o que esta no repo."""
    fails = []
    order = [f.get("name") for f in root.findall("file")]
    if order != b.object_file_names(lang):
        fails.append("%s: membros %s, o build declara %s" % (where, order, b.object_file_names(lang)))
    # Um .sty do bundle que o objeto nao leva e' relatorio que nao compila em producao.
    for s in sorted(n for n in os.listdir(bundle_dir) if n.endswith(".sty")):
        if s not in files:
            fails.append("%s: o bundle tem %s e o objeto nao o leva" % (where, s))
    for n in order:
        if n in ("generate", "report_format.xml"):
            continue   # sintetizados por objeto; conferidos abaixo e acima
        path = os.path.join(bundle_dir, n)
        if not os.path.exists(path):
            fails.append("%s: o objeto leva %s e o bundle nao o tem" % (where, n))
            continue
        with open(path, "rb") as fh:
            want = fh.read()
        got = base64.b64decode(files.get(n, ""))
        if got != want:
            fails.append("%s: %s embutido (%d bytes) difere do bundle (%d bytes)" % (where, n, len(got), len(want)))
    # O generate e' o do bundle, a menos dos dois valores da linha do xsltproc.
    with open(os.path.join(bundle_dir, "generate"), "rb") as fh:
        canon = fh.read()
    if XSLTPROC.sub(b"xsltproc --stringparam lang en --stringparam variant technical ", gen) != canon:
        fails.append("%s: o generate embutido difere do bundle alem dos dois valores da linha do xsltproc" % where)
    return fails


def check(rf_dir):
    fails = []
    path = os.path.join(rf_dir, "manifest.json")
    with open(path, "rb") as fh:
        raw = fh.read()
    man = json.loads(raw.decode("utf-8"))
    b = load_builder(rf_dir)
    bundle_dir = os.path.join(rf_dir, "suricatoos-premium-pdf")
    version = b.derive_version()
    if raw != b.manifest_bytes():
        fails.append("manifest.json nao e' o que o build-feed-xml.py escreve (regere e commite)")
    if "version" in man:
        fails.append("manifest.json traz `version' (%r): arquivo versionado nao guarda a VERSION, que o "
                     "build deriva do conteudo" % man["version"])
    if not VERSION_RE.fullmatch(version):
        fails.append("VERSION %r fora do formato sha256-<12 hex>" % version)
    entries = man.get("report_formats") or []
    combos = [(e.get("lang"), e.get("variant")) for e in entries]
    want = [(lang, v) for v in VARIANTS for lang in LANGS]
    if sorted(combos) != sorted(want) or len(combos) != len(set(combos)):
        fails.append("combinacoes %s, esperado idioma x edicao, uma de cada" % combos)
    uuids = [e.get("uuid") for e in entries]
    if len(set(uuids)) != len(uuids):
        fails.append("UUID repetido no manifesto")
    names = [e.get("name") for e in entries]
    if len(set(names)) != len(names):
        fails.append("nome repetido no manifesto")
    for e in entries:
        lang, variant, uid, name = e.get("lang"), e.get("variant"), e.get("uuid"), e.get("name")
        where = "%s/%s" % (lang, variant)
        if e.get("format") != "suricatoos-pdf":
            fails.append("%s: format %r, esperado 'suricatoos-pdf'" % (where, e.get("format")))
        if sorted(e) != ["format", "lang", "name", "uuid", "variant"]:
            fails.append("%s: campos %s, esperado format, lang, variant, uuid, name" % (where, sorted(e)))
        if not UUID4.fullmatch(uid or ""):
            fails.append("%s: UUID %r nao e' um v4 canonico minusculo" % (where, uid))
        if uid != FIXED_UUIDS.get((lang, variant)):
            fails.append("%s: UUID %s, o fixado para essa combinacao e' %s"
                         % (where, uid, FIXED_UUIDS.get((lang, variant))))
        if not (name or "").endswith(" " + LANG_LABEL.get(lang, "?")):
            fails.append("%s: o nome %r nao diz o idioma %s" % (where, name, LANG_LABEL.get(lang)))
        want_name = NAME_FORMAT % (EDITION_LABEL.get((lang, variant), "?"), LANG_LABEL.get(lang, "?"))
        if name != want_name:
            fails.append("%s: o nome %r, esperado %r (a edicao e o idioma no menu do GSA)"
                         % (where, name, want_name))
        fpath = os.path.join(rf_dir, "pdf-suricatoos-%s.xml" % uid)
        if not os.path.exists(fpath):
            fails.append("%s: falta %s (os objetos de feed sao gerados, nao versionados: rode "
                         "report-formats/build-feed-xml.py)" % (where, os.path.basename(fpath)))
            continue
        with open(fpath, "rb") as fh:
            data = fh.read()
        root = ET.fromstring(data)
        if root.get("id") != uid or root.findtext("name") != name:
            fails.append("%s: o objeto diz id %s, nome %r" % (where, root.get("id"), root.findtext("name")))
        if b.VERSION_TOKEN.encode("ascii") in data:
            fails.append("%s: o objeto deixou o marcador %s da VERSION sem preencher" % (where, b.VERSION_TOKEN))
        for tag in ("summary", "description"):
            fails.extend(_version_in_text(where, "objeto", tag, root.findtext(tag), version))
        files = {f.get("name"): f.text or "" for f in root.findall("file")}
        gen = base64.b64decode(files.get("generate", ""))
        lines = XSLTPROC.findall(gen)
        if lines != [(lang.encode(), variant.encode())]:
            fails.append("%s: o generate embutido pede %s" % (where, [(a.decode(), v.decode()) for a, v in lines]))
        for tok in (b"--stringparam lang ", b"--stringparam variant "):
            if gen.count(tok) != 1:
                fails.append("%s: o generate embutido tem %r %d vez(es)" % (where, tok.decode(), gen.count(tok)))
        desc_bytes = base64.b64decode(files.get("report_format.xml", ""))
        desc = ET.fromstring(desc_bytes)
        if desc.get("id") != uid or desc.findtext("name") != name:
            fails.append("%s: o report_format.xml embutido diz id %s, nome %r"
                         % (where, desc.get("id"), desc.findtext("name")))
        if b.VERSION_TOKEN.encode("ascii") in desc_bytes:
            fails.append("%s: o report_format.xml embutido deixou o marcador %s da VERSION sem preencher"
                         % (where, b.VERSION_TOKEN))
        for tag in ("summary", "description"):
            fails.extend(_version_in_text(where, "report_format.xml embutido", tag, desc.findtext(tag), version))
        cats = sorted(n for n in files if n.startswith("nvt-i18n-"))
        if cats != ["nvt-i18n-%s.xml" % lang]:
            fails.append("%s: catalogo(s) embutido(s) %s, esperado o do idioma" % (where, cats))
        fails.extend(_members_are_the_bundle(where, root, files, gen, lang, bundle_dir, b))
    ref = os.path.join(bundle_dir, "report_format.xml")
    if not os.path.exists(ref):
        fails.append("falta suricatoos-premium-pdf/report_format.xml (descritor de referencia: gerado, "
                     "nao versionado; rode report-formats/build-feed-xml.py)")
    else:
        with open(ref, "rb") as fh:
            if fh.read() != b.reference_descriptor(version):
                fails.append("suricatoos-premium-pdf/report_format.xml nao e' o descritor de referencia que o "
                             "build-feed-xml.py escreve (arquivo gerado, nao versionado: rode o build)")
    described = {"pdf-suricatoos-%s.xml" % u for u in uuids}
    extra = sorted(os.path.basename(p) for p in glob.glob(os.path.join(rf_dir, "pdf-suricatoos-*.xml"))
                   if os.path.basename(p) not in described)
    if extra:
        fails.append("objeto(s) de feed fora do manifesto: %s" % ", ".join(extra))
    return fails


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", default=os.path.dirname(HERE))
    args = ap.parse_args()
    try:
        fails = check(args.dir)
    except (OSError, ValueError, ET.ParseError) as e:
        print("check-manifest: ERRO de leitura: %s" % e)
        return 2
    if fails:
        print("check-manifest: FALHA")
        for f in fails:
            print("  | %s" % f)
        return 1
    print("check-manifest: OK (9 combinacoes idioma x edicao, manifesto = objetos de feed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
