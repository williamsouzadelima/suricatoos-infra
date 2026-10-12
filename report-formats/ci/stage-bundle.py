#!/usr/bin/env python3
"""Monta, num diretorio gravavel, o bundle de UM objeto de feed (idioma x
edicao) exatamente como o objeto o instala no gvmd: o mesmo `generate`
sintetizado (os pares `--stringparam lang` e `--stringparam variant` trocados
pelo idioma e pela edicao), o mesmo report_format.xml e os mesmos membros
compartilhados (so' o catalogo de NVT do proprio idioma).

Reusa as funcoes do build-feed-xml.py em vez de repetir a regra: se a montagem
do feed mudar, o CI compila a montagem nova sem ninguem lembrar de atualizar
este arquivo.

Uso:
    python3 report-formats/ci/stage-bundle.py <lang> <variant> <destino> [--omit ARQ]...

--omit deixa um membro de fora (controle negativo: bundle sem um .sty).
"""
import argparse
import importlib.util
import os
import sys

sys.dont_write_bytecode = True  # nada de __pycache__ dentro de report-formats/

HERE = os.path.dirname(os.path.abspath(__file__))
BUILDER = os.path.join(os.path.dirname(HERE), "build-feed-xml.py")


def load_builder():
    spec = importlib.util.spec_from_file_location("build_feed_xml", BUILDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("lang")
    ap.add_argument("variant")
    ap.add_argument("dest")
    ap.add_argument("--omit", action="append", default=[], metavar="ARQ")
    args = ap.parse_args()

    b = load_builder()
    objs = {(lang, variant): (fmt_id, name) for lang, variant, fmt_id, name in b.FORMATS}
    if (args.lang, args.variant) not in objs:
        print("stage-bundle: combinacao desconhecida %s/%s (validas: %s)"
              % (args.lang, args.variant, ", ".join("%s/%s" % k for k in objs)), file=sys.stderr)
        return 2
    fmt_id, name = objs[(args.lang, args.variant)]

    # Mesma ordem do objeto de feed: scripts sintetizados, depois os membros.
    members = [
        ("generate", b.generate_for(args.lang, args.variant)),
        ("report_format.xml", b.report_format_xml_for(fmt_id, name, args.lang, args.variant)),
    ]
    for n in b.shared_files(args.lang):
        with open(os.path.join(b.BUNDLE, n), "rb") as fh:
            members.append((n, fh.read()))

    names = [n for n, _ in members]
    unknown = [n for n in args.omit if n not in names]
    if unknown:
        print("stage-bundle: --omit de membro que o bundle nao tem: %s"
              % ", ".join(unknown), file=sys.stderr)
        return 2

    os.makedirs(args.dest, exist_ok=True)
    for n, data in members:
        if n in args.omit:
            continue
        with open(os.path.join(args.dest, n), "wb") as fh:
            fh.write(data)
    kept = [n for n in names if n not in args.omit]
    print("stage-bundle: %s/%s (%s) -> %s (%d arquivos%s)"
          % (args.lang, args.variant, fmt_id, args.dest, len(kept),
             "; omitidos: " + ", ".join(args.omit) if args.omit else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
