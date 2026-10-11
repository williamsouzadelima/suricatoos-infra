#!/usr/bin/env python3
"""Checagem estática da marca de portão de sessão nos configs do nginx.

Regra 1 (ver control-plane/sessiongate): toda location que faz proxy para o
control-plane declara, no PRÓPRIO nível, `proxy_set_header X-Suricatoos-Gate`:
com "gsad-session" só nas locations com portão de sessão (SESSAO abaixo) e
vazio ("") em todas as outras. O nginx não herda proxy_set_header do nível de
cima quando a location define algum, então uma location sem a linha repassaria
o valor que o cliente mandar.

Regra 2: uma location que põe uma marca de confiança no pedido ao upstream
(MARCAS abaixo: X-Suricatoos-Gate "gsad-session" para o control-plane,
X-Suricatoos-UI "1" para o ingest) declara no PRÓPRIO nível um `auth_request`
para uma location `internal` do mesmo arquivo — o portão de sessão forte, em que
o gsad valida cookie E token. Sem ele a location confiaria só no cookie, que
qualquer cliente forja; e um auth_request para uma location que não existe cai
no fallback da SPA, que responde 200: portão aberto.

Regra 3 (espelho da 1 para o ingest): toda location que faz proxy para o ingest
declara, no PRÓPRIO nível, `proxy_set_header X-Suricatoos-UI`: "1" (a marca que
libera GET /agents, a postura da frota) só onde a regra 2 vale, e vazio ("") em
todas as outras — sem a linha, o valor que o cliente mandar chega ao ingest.

Uso: gate_lint.py ARQUIVO.conf [...]   (sai com 1 se alguma location violar)
Só stdlib; não precisa de docker.
"""
import sys

HEADER = "x-suricatoos-gate"
VALUE = "gsad-session"
# Locations com portão de sessão — as únicas que podem setar a marca.
SESSAO = {"/ai-providers/api/", "= /agents/scan", "/agent/provision/"}
# Marca de origem-UI que o ingest exige em GET /agents.
UI_HEADER = "x-suricatoos-ui"
UI_VALUE = "1"
# Marcas de confiança (header em minúsculas → valor) que exigem o portão forte.
MARCAS = {HEADER: VALUE, UI_HEADER: UI_VALUE}


def tokens(text):
    """Tokens do config: palavras, strings entre aspas e os delimitadores { } ;"""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise SyntaxError("aspas sem fechamento")
            yield ("str", "".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    j = text.index("}", j) + 1  # ${var} faz parte da palavra
                    continue
                j += 1
            yield text[i:j]
            i = j


def parse(toks):
    """Árvore de diretivas: lista de (args, filhos-ou-None)."""
    stack, args = [[]], []
    for t in toks:
        if t == ";":
            stack[-1].append((args, None))
            args = []
        elif t == "{":
            node = (args, [])
            stack[-1].append(node)
            stack.append(node[1])
            args = []
        elif t == "}":
            if len(stack) == 1 or args:
                raise SyntaxError("'}' inesperado")
            stack.pop()
        else:
            args.append(t)
    if len(stack) != 1 or args:
        raise SyntaxError("bloco ou diretiva sem fechamento")
    return stack[0]


def word(a):
    return a[1] if isinstance(a, tuple) else a


def walk(nodes):
    for args, kids in nodes:
        yield args, kids
        if kids:
            yield from walk(kids)


def locations(tree):
    """(nome, filhos) de cada bloco location, ex.: ("= /agents/scan", [...])."""
    for args, kids in walk(tree):
        if kids is not None and args and word(args[0]) == "location":
            yield " ".join(word(a) for a in args[1:]), kids


def nivel(kids, nome, n):
    """Diretivas `nome` com n palavras no nível da location (fora de `if`)."""
    return [
        [word(a) for a in d]
        for d, k in kids
        if k is None and len(d) == n and word(d[0]) == nome
    ]


def vai_ao(kids, porta, servico):
    """A location faz proxy para o serviço (porta no proxy_pass ou `set $x servico`)."""
    return any(
        (d[0] == "proxy_pass" and porta in d[-1]) or (d[0] == "set" and d[-1] == servico)
        for d in ([word(a) for a in d] for d, _ in walk(kids) if d)
    )


def internas_de(tree):
    """Nomes ("= /x") das locations com `internal` no próprio nível."""
    return {loc for loc, kids in locations(tree) if nivel(kids, "internal", 1)}


def forte(kids, internas):
    """A regra 2 vale: auth_request no próprio nível, todo alvo uma location interna."""
    alvos = [alvo for _, alvo in nivel(kids, "auth_request", 2)]
    return bool(alvos) and all(f"= {alvo}" in internas for alvo in alvos)


def check_ingest(tree, internas):
    """Regra 3: X-Suricatoos-UI declarado em toda location que vai ao ingest."""
    erros, linhas = [], []
    for loc, kids in locations(tree):
        if not vai_ao(kids, ":9090", "ingest"):
            continue
        valores = [v for _, h, v in nivel(kids, "proxy_set_header", 3) if h.lower() == UI_HEADER]
        if len(valores) != 1 or valores[0] not in ("", UI_VALUE):
            erros.append(
                f"{loc}: vai ao ingest e precisa de exatamente uma linha proxy_set_header "
                f'X-Suricatoos-UI ("" ou "{UI_VALUE}"); achei {valores or "nenhuma"}'
            )
            estado = "ERRO "
        elif valores[0] == UI_VALUE:
            if not forte(kids, internas):
                erros.append(f"{loc}: põe X-Suricatoos-UI {UI_VALUE} sem o portão forte (regra 2)")
            estado = "seta "
        else:
            estado = "limpa"
        linhas.append(f"  {estado}  {loc}")
    return linhas, erros


def check_fortes(tree, internas):
    """Regra 2: marca de confiança só com auth_request para location interna."""
    erros, linhas = [], []
    for loc, kids in locations(tree):
        marcas = [
            f"{h}: {v}"
            for _, h, v in nivel(kids, "proxy_set_header", 3)
            if MARCAS.get(h.lower()) == v
        ]
        if not marcas:
            continue
        alvos = [alvo for _, alvo in nivel(kids, "auth_request", 2)]
        if not alvos:
            erros.append(
                f"{loc}: põe {', '.join(marcas)} sem auth_request no próprio nível "
                "(portão só de cookie é forjável)"
            )
        for alvo in alvos:
            if f"= {alvo}" not in internas:
                erros.append(
                    f"{loc}: auth_request {alvo} não aponta para uma location "
                    f"interna ('location = {alvo}' com internal)"
                )
        linhas.append(f"  forte  {loc} -> auth_request {', '.join(alvos) or '(nenhum)'}")
    return linhas, erros


def check(path):
    with open(path, encoding="utf-8") as fh:
        tree = parse(tokens(fh.read()))
    erros, linhas, vistas = [], [], set()
    for args, kids in walk(tree):
        if kids is None or not args or word(args[0]) != "location":
            continue
        loc = " ".join(word(a) for a in args[1:])
        vai_ao_cp = vai_ao(kids, ":8080", "control-plane")
        # Só as diretivas do nível da location: dentro de `if` não valem p/ todo pedido.
        valores = [
            word(d[2])
            for d, k in kids
            if k is None and len(d) == 3 and word(d[0]) == "proxy_set_header"
            and word(d[1]).lower() == HEADER
        ]
        if VALUE in valores and loc not in SESSAO:
            erros.append(f"{loc}: seta a marca de portão mas não é location de sessão")
        if not vai_ao_cp:
            continue
        esperado = VALUE if loc in SESSAO else ""
        if valores != [esperado]:
            erros.append(
                f"{loc}: vai ao control-plane e precisa de exatamente uma linha "
                f'proxy_set_header X-Suricatoos-Gate "{esperado}"; achei {valores or "nenhuma"}'
            )
        vistas.add(loc)
        linhas.append(f"  {'seta ' if esperado else 'limpa'}  {loc}")
    for loc in sorted(SESSAO - vistas):
        erros.append(f"{loc}: location de sessão não encontrada indo ao control-plane")
    internas = internas_de(tree)
    ingest, erros_ingest = check_ingest(tree, internas)
    fortes, erros_fortes = check_fortes(tree, internas)
    return linhas, ingest, fortes, erros + erros_ingest + erros_fortes


def main(paths):
    falhou = False
    for path in paths:
        try:
            linhas, ingest, fortes, erros = check(path)
        except (OSError, SyntaxError, ValueError) as exc:
            print(f"{path}: não consegui analisar: {exc}")
            falhou = True
            continue
        print(f"{path}: {len(linhas)} locations vão ao control-plane")
        print("\n".join(linhas))
        print(f"{path}: {len(ingest)} locations vão ao ingest")
        print("\n".join(ingest))
        print(f"{path}: {len(fortes)} locations põem marca de confiança")
        print("\n".join(fortes))
        for e in erros:
            print(f"  ERRO {e}")
        falhou = falhou or bool(erros)
    return 1 if falhou else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
