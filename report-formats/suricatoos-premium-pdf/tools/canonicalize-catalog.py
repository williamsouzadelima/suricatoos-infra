#!/usr/bin/env python3
r"""Uniformiza o boilerplate do catálogo de tradução: uma fonte, uma redação.

    python3 tools/canonicalize-catalog.py catalogo.json nvts-source.json > canon.json

Por que existe
--------------
O catálogo é traduzido em lotes paralelos. Centenas de NVTs compartilham frases
idênticas ("No known solution was made available…", "Successful exploitation will
allow attacker to execute arbitrary HTML…"), e cada lote as traduz do seu jeito.
Na rodada pt-BR uma única frase saiu com **dez** redações diferentes, em 23
ocorrências; no espanhol, sete. O leitor vê a mesma frase escrita de formas
distintas em cards vizinhos do mesmo relatório.

Isto não é gosto: é o mesmo texto-fonte, então tem que sair igual.

Critério de escolha, nesta ordem
--------------------------------
1. a redação mais FREQUENTE (o consenso dos lotes);
2. desempate: a que tem o mesmo número de quebras de linha da fonte (preserva a
   estrutura de lista/parágrafo que os cards de largura fixa esperam);
3. desempate final: ordem lexicográfica, só para o resultado ser determinístico
   e o script poder rodar de novo sem mudar nada.

Agrupa só fontes com mais de 50 caracteres: abaixo disso a coincidência de texto
costuma ser acidental (um nome de produto, uma versão), não boilerplate.
"""
import json
import sys
from collections import Counter, defaultdict

CAMPOS = ("summary", "insight", "impact", "affected", "solution")
MIN_FONTE = 50


def escolhe(variantes: Counter, fonte: str) -> str:
    """A redação canônica de um grupo, pelo critério documentado acima."""
    n_fonte = fonte.count("\\n") + fonte.count("\n")
    melhor = max(
        variantes.items(),
        key=lambda kv: (
            kv[1],                                        # frequência
            -abs((kv[0].count("\\n") + kv[0].count("\n")) - n_fonte),
            [-ord(c) for c in kv[0][:40]],                # lexicográfico estável
        ),
    )
    return melhor[0]


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    cat = json.load(open(sys.argv[1], encoding="utf-8"))
    src = {x["oid"]: x for x in json.load(open(sys.argv[2], encoding="utf-8"))}

    grupos = defaultdict(Counter)
    for t in cat:
        s = src.get(t["oid"]) or {}
        for c in CAMPOS:
            fonte = (s.get(c) or "").strip()
            trad = (t.get(c) or "").strip()
            if len(fonte) > MIN_FONTE and trad:
                grupos[(c, fonte)][trad] += 1

    canon = {k: escolhe(v, k[1]) for k, v in grupos.items() if len(v) > 1}

    trocas = 0
    for t in cat:
        s = src.get(t["oid"]) or {}
        for c in CAMPOS:
            fonte = (s.get(c) or "").strip()
            alvo = canon.get((c, fonte))
            if alvo and (t.get(c) or "").strip() != alvo:
                t[c] = alvo
                trocas += 1

    json.dump(cat, sys.stdout, ensure_ascii=False, indent=1)
    print("grupos divergentes: %d | campos uniformizados: %d"
          % (len(canon), trocas), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
