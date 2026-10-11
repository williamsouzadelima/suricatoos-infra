#!/usr/bin/env python3
"""Checagens de VERACIDADE do Suricatoos Premium PDF sobre o .tex gerado.

Os portoes do gates.sh provam que o documento COMPILA (zero erro de TeX, fontes,
links). Isto prova que ele DIZ A VERDADE sobre o XML de entrada: cada checagem
recalcula aqui, a partir do relatorio, o que o leitor deveria ver, e compara
com o que o latex.xsl escreveu. Uma checagem por defeito ja' corrigido (a
fatia de veracidade; as fixtures de report-formats/tests/fixtures/ exercitam um
defeito cada), e todas rodam em TODA fixture -- sample e tortura inclusive --,
porque sao invariantes do documento, nao casos especiais.

  numeracao      o numero de cada linha do Sumario de Achados e' o numero do
                 card que o \\hyperlink dela abre; cada tabela numera 1..n em
                 ordem (grupos primeiro) e os cards de cada bloco seguem a partir
                 de (consolidados + 1);
  secoes         nenhuma tarja "confirmados"/"indicadores" (secoes 4 e 5) sem
                 linha ou card; a tarja de indicadores existe se e somente se ha
                 NVT de baixa confianca;
  consolidado    card consolidado so' com NVT confirmado, com a contagem e a
                 severidade certas; NVT de baixa confianca nunca e' absorvido;
  instancias     severidade = MAXIMA entre as instancias; indicador so' se TODAS
                 as instancias estao abaixo do piso de QoD; QoD exibida = maxima;
                 tabelas e cards em ordem decrescente dessa severidade; o
                 resultado da deteccao do card e' o da instancia que carrega a
                 maxima (a primeira, no empate);
  acao           a acao unica do card consolidado sai do catalogo de traducao;
  vulns-unicas   VULNS UNICAS = NVTs distintos com severidade maxima >= 0.1;
  faixas         as quatro faixas do resumo executivo vem da MESMA fonte; o
                 TOTAL DE ACHADOS e o N de Alto/Critico da narrativa batem com
                 elas; a clausula de remediacao que fecha a frase e' exatamente
                 a esperada, e so' fala de confianca quando Alto/Critico e baixa
                 confianca vem da mesma populacao;
  ancoras        toda ancora casa ^[A-Za-z0-9-]+$; todo link tem alvo; um link e
                 um alvo por grupo consolidado;
  nome           o nome do projeto, quando cortado (capa, contracapa, narrativa,
                 titulo do mapa de portas), e' cortado em fronteira de palavra e
                 o corte declarado bate;
  escopo         a secao 6 (escopo, metodologia e limitacoes), recalculada do
                 XML bloco a bloco: cada \\scopefact com o rotulo e o valor
                 certos -- tarefa, alvo, hosts (e a contagem declarada pelo
                 gvmd quando difere), inicio, fim e duracao do scan, situacao
                 (scan_run_status), versao do feed e do scanner (detalhes
                 scanned_with_* dos hosts, so' quando existem), termo do
                 filtro, piso de QoD, niveis (chave ancorada num token: nada de
                 "levels=" dentro de "compliance_levels="), overrides, export
                 parcial, autenticacao por host, erros de scan --, \\scopena
                 EXATAMENTE onde o dado falta e em nenhum outro lugar; os
                 textos livres (tarefa, alvo, termo, descricao e NVT de um
                 erro) com o teto e o corte declarado; as tabelas de
                 autenticacao e de erros celula a celula ate' o teto
                 $scope-rows-max, com o corte "+ N" declarado so' acima dele e
                 com o N certo; as notas e as limitacoes conforme o estado do
                 scan (nunca iniciou, nao terminou, inventario do agente
                 importado pelo gmp-bridge) e o feed;
  alerta         o resumo executivo abre com o alerta de "nada medido" se e
                 somente se o relatorio nao tem host, e o alerta da' a causa
                 que o dado sustenta: tarefa que nunca iniciou (a mesma regra
                 da secao 6) ou scan que iniciou e nao achou host (alive test).

Os limiares (qod-min, group-min, adv-max, cortes do nome, scope-rows-max e os
tetos de texto da secao 6), as listas de meses e dias e as frases do i18n sao
LIDOS do proprio latex.xsl, para a regua nunca divergir do relatorio; um nome
lido que esteja definido mais de uma vez la' e' erro (exit 2). As regras de
estado do scan (ScanState) e os dois sinais do inventario do agente sao os do
latex.xsl, escritos de novo aqui -- regua independente, como as outras.

Uso:
    check-veracity.py --lang <en|pt_BR|es> --xml <fixture.xml> --tex <report.tex>
                      [--bundle <suricatoos-premium-pdf/>] [--only <checagem>...]

Sai 0 se tudo passa, 1 se alguma checagem reprova, 2 em erro de uso/leitura.
"""
import argparse
import datetime
import math
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
XSL_NS = "{http://www.w3.org/1999/XSL/Transform}"
WS = " \t\r\n"                       # espaco em branco do XPath


# ---------------------------------------------------------------------------
# Leitura do latex.xsl: limiares e textos do i18n
# ---------------------------------------------------------------------------
class StylesheetError(Exception):
    pass


class Stylesheet:
    """Os numeros e as frases que a regua le do latex.xsl. Cada nome lido tem de
    estar definido UMA vez: com duas definicoes (um xsl:param global e uma
    variavel local com o mesmo nome, uma chave de i18n repetida) o valor que
    vale depende do escopo, e a regua passaria a medir contra um palpite."""

    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.defs = {}
        for tag in ("param", "variable"):
            for el in root.iter(XSL_NS + tag):
                if el.get("name"):
                    self.defs.setdefault(el.get("name"), []).append(el.get("select"))
        self.i18n = {}
        for s in root.iter("s"):
            if s.get("k"):
                self.i18n.setdefault(s.get("k"), []).append(
                    {"en": s.get("en"), "pt": s.get("pt"), "es": s.get("es")})

    def num(self, name):
        sels = self.defs.get(name, [])
        if len(sels) != 1:
            raise StylesheetError("%s definido %d vez(es) no latex.xsl, esperado 1"
                                  % (name, len(sels)))
        if not re.fullmatch(r"\d+", sels[0] or ""):
            raise StylesheetError("%s nao e' um inteiro literal no latex.xsl: select=%r"
                                  % (name, sels[0]))
        return int(sels[0])

    def t(self, key, lang):
        nodes = self.i18n.get(key, [])
        if len(nodes) != 1:
            raise StylesheetError("chave de i18n %r definida %d vez(es) no latex.xsl, esperado 1"
                                  % (key, len(nodes)))
        return nodes[0].get(bucket(lang)) or nodes[0]["en"]

    def words(self, name):
        """Uma lista de palavras do latex.xsl (select="'jan fev ...'"): os meses
        e dias da semana que o emit-date imprime."""
        sels = self.defs.get(name, [])
        if len(sels) != 1:
            raise StylesheetError("%s definido %d vez(es) no latex.xsl, esperado 1"
                                  % (name, len(sels)))
        mt = re.fullmatch(r"'([^']*)'", sels[0] or "")
        if not mt:
            raise StylesheetError("%s nao e' uma string literal no latex.xsl: select=%r"
                                  % (name, sels[0]))
        return mt.group(1).split()


def bucket(lang):
    """O $L do latex.xsl: pt | es | en."""
    return "pt" if lang.startswith("pt") else ("es" if lang.startswith("es") else "en")


# ---------------------------------------------------------------------------
# Modelo do relatorio (o "oraculo"): o que o documento deveria dizer
# ---------------------------------------------------------------------------
XPATH_NUMBER = re.compile(r"[ \t\r\n]*-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)[ \t\r\n]*")


def xnum(s):
    """number() do XPath 1.0: so' [-]digitos[.digitos] entre brancos; o resto
    (vazio, expoente, "+", "inf") e' NaN."""
    s = s or ""
    return float(s.strip(WS)) if XPATH_NUMBER.fullmatch(s) else float("nan")


def isnum(x):
    return x == x


def norm_space(s):
    return " ".join(t for t in re.split("[ \t\r\n]+", s or "") if t)


def grp_key(name):
    """As duas primeiras palavras do nome: a chave by-updgrp do latex.xsl."""
    ns = norm_space(name)
    first = ns.split(" ", 1)[0] if ns else ""
    rest = ns.split(" ", 1)[1] if " " in ns else ""
    second = rest.split(" ", 1)[0] if rest else ""
    return first + " " + second


def sev_key_row(sev):
    """Chave de severidade das LINHAS do sumario (gsev/sevk do latex.xsl)."""
    if not isnum(sev):
        return "logsev"
    if sev >= 9.0:
        return "critico"
    if sev >= 7.0:
        return "alto"
    if sev >= 4.0:
        return "medio"
    if sev >= 0.1:
        return "baixo"
    if -1.5 < sev < 0:
        return "neutro"
    return "logsev"


def sev_key_card(sev):
    """Chave dos CARDS (sevkey-detail): falso positivo e' `falsepos'."""
    k = sev_key_row(sev)
    return "falsepos" if k == "neutro" else k


class Result:
    def __init__(self, el, pos):
        self.pos = pos
        nvt = el.find("nvt")
        self.oid = nvt.get("oid") if nvt is not None else ""
        self.name = (nvt.findtext("name") if nvt is not None else "") or ""
        sol = nvt.find("solution") if nvt is not None else None
        self.soltype = sol.get("type") if sol is not None else None
        self.solution = (sol.text or "") if sol is not None else ""
        self.tags = (nvt.findtext("tags") if nvt is not None else "") or ""
        self.sev_raw = el.findtext("severity") or ""
        self.sev = xnum(self.sev_raw)
        q = el.find("qod/value")
        self.has_qod = q is not None
        self.qod_raw = (q.text or "") if q is not None else ""
        self.qod = xnum(self.qod_raw)
        self.desc = el.findtext("description") or ""

    def low(self, floor):
        """Instancia abaixo do piso: tem QoD e ela e' < piso (sem QoD = nao)."""
        return self.has_qod and isnum(self.qod) and self.qod < floor

    def tag(self, name):
        after = self.tags.split(name + "=", 1)
        if len(after) < 2:
            return ""
        return after[1].split("|", 1)[0]


class Nvt:
    def __init__(self, oid, instances, floor):
        self.oid = oid
        self.inst = instances
        self.rep = instances[0]
        self.low = all(r.low(floor) for r in instances)
        sevs = [r.sev for r in instances if isnum(r.sev)]
        self.maxsev = max(sevs) if sevs else float("nan")
        self.maxsev_raw = next((r.sev_raw for r in instances
                                if isnum(self.maxsev) and r.sev == self.maxsev), "")
        # A instancia que representa o NVT no card (pontuacao e evidencia): a
        # primeira com a severidade maxima; sem nenhuma numerica, a primeira.
        self.repr = next((r for r in instances
                          if isnum(self.maxsev) and r.sev == self.maxsev), instances[0])
        qods = [r.qod for r in instances if r.has_qod and isnum(r.qod)]
        self.maxqod = max(qods) if qods else float("nan")
        self.maxqod_raw = next((r.qod_raw for r in instances
                                if r.has_qod and isnum(self.maxqod) and r.qod == self.maxqod), "")
        self.vendorfix = self.rep.soltype == "VendorFix"
        self.group = grp_key(self.rep.name)


class Model:
    def __init__(self, xml_path, sheet):
        root = ET.parse(xml_path).getroot()
        # gvm:report(): o <report> interno quando ha um, senao a raiz.
        inner = root.find("report")
        rep = inner if inner is not None else root
        self.root = root
        self.report = rep
        self.floor = sheet.num("qod-min")
        self.group_min = sheet.num("group-min")
        self.results = [Result(el, i) for i, el in enumerate(rep.findall("results/result"))]
        by = {}
        for r in self.results:
            by.setdefault(r.oid, []).append(r)
        self.nvts = [Nvt(oid, inst, self.floor) for oid, inst in by.items()]
        self.by_anchor = {fnd(n.oid): n for n in self.nvts}
        # Grupos consolidados: so' NVT VendorFix CONFIRMADO conta e entra.
        groups = {}
        for n in self.nvts:
            if n.vendorfix and not n.low:
                groups.setdefault(n.group, []).append(n)
        self.groups = {g: ms for g, ms in groups.items() if len(ms) >= self.group_min}
        self.absorbed = {n.oid for ms in self.groups.values() for n in ms}
        self.hosts = len(rep.findall("host"))

    def project(self):
        t = self.report.find("task")
        if t is None:
            return ""
        for path in ("name", "target/name", "comment"):
            v = t.findtext(path)
            if v is not None and norm_space(v):
                return v
        return ""

    def group_maxsev(self, g):
        sevs = [r.sev for n in self.groups[g] for r in n.inst if isnum(r.sev)]
        return max(sevs) if sevs else float("nan")

    def group_top(self, g):
        """O membro (instancia) mais severo do grupo; empate -> ordem do doc."""
        best = None
        for n in self.groups[g]:
            for r in n.inst:
                if isnum(r.sev) and (best is None or r.sev > best.sev or
                                     (r.sev == best.sev and r.pos < best.pos)):
                    best = r
        if best is None:
            best = min((r for n in self.groups[g] for r in n.inst), key=lambda r: r.pos)
        return best


# ---------------------------------------------------------------------------
# Leitura do .tex
# ---------------------------------------------------------------------------
class TexError(Exception):
    pass


def skip_blank(s, i):
    while i < len(s):
        c = s[i]
        if c in WS:
            i += 1
        elif c == "%":
            j = s.find("\n", i)
            i = len(s) if j < 0 else j + 1
        else:
            break
    return i


def group_at(s, i):
    """Argumento entre chaves em s[i]; devolve (conteudo cru, indice depois)."""
    if i >= len(s) or s[i] != "{":
        raise TexError("esperava '{' na posicao %d" % i)
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "%":
            k = s.find("\n", j)
            j = len(s) if k < 0 else k + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i + 1:j], j + 1
        j += 1
    raise TexError("chave sem par a partir da posicao %d" % i)


def macros(s, name, nargs):
    """[(posicao, [args])] de cada \\name seguido de nargs argumentos."""
    out = []
    for m in re.finditer(r"\\" + re.escape(name) + r"(?![A-Za-z@])", s):
        i, args = m.end(), []
        try:
            for _ in range(nargs):
                i = skip_blank(s, i)
                a, i = group_at(s, i)
                args.append(a)
        except TexError as e:
            raise TexError("\\%s na posicao %d: %s" % (name, m.start(), e))
        out.append((m.start(), args))
    return out


# O inverso do escape_text, numa passada so' (substituicoes em sequencia
# reescreveriam o que a anterior acabou de produzir).
UNESC = re.compile(r"\\(textbackslash\{\}|textasciitilde\{\}|textasciicircum\{\}|[_&%#${}])")
UNESC_MAP = {"textbackslash{}": "\\", "textasciitilde{}": "~", "textasciicircum{}": "^"}


def plain(t, keep_trunc=False):
    """Texto que o leitor ve, a partir do LaTeX que o escape_* emitiu: tira os
    pontos de quebra (%\\n, \\surwb, \\surwbvis, \\surjb) e desfaz o escape."""
    t = re.sub(r"%\n", "", t)
    t = re.sub(r"\\(?:surwbvis|surwb|surjb)\{\}", "", t)
    if not keep_trunc:
        t = re.sub(r"\\suriTruncMark\{\d+\}", "", t)
    return UNESC.sub(lambda m: UNESC_MAP.get(m.group(1), m.group(1)), t)


def trunc_count(t):
    """Quantos caracteres a marca \\suriTruncMark{N} declara cortados (0 sem marca)."""
    mk = re.search(r"\\suriTruncMark\{(\d+)\}", t)
    return int(mk.group(1)) if mk else 0


def flat(t):
    """plain() + sem marcacao de paragrafo/linha/recuo + espaco colapsado. O
    recuo do escape_prose e' \\mbox{} seguido de um ~ (espaco duro) por coluna;
    sai ANTES do unescape, que transforma \\textasciitilde{} do dado em ~."""
    t = re.sub(r"\\mbox\{\}~*", " ", t)
    t = re.sub(r"\\(?:newline|par)(?![A-Za-z])", " ", t)
    return norm_space(plain(t))


class Tex:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            whole = fh.read()
        k = whole.find("\\begin{document}")
        if k < 0:
            raise TexError("sem \\begin{document}")
        self.s = whole[k:]
        s = self.s
        secs = [(p, int(a[0])) for p, a in macros(s, "suriSection", 2)]
        self.sections = {}
        for idx, (p, n) in enumerate(secs):
            end = secs[idx + 1][0] if idx + 1 < len(secs) else len(s)
            self.sections[n] = (p, end)

    def section(self, n):
        p, e = self.sections.get(n, (0, 0))
        return self.s[p:e], p

    def blocks(self, n):
        """Os blocos de uma secao, um por \\suriSummaryHead: [(modo, texto)].
        Sem tarja nenhuma, a secao inteira e' um bloco 'confirmados'."""
        text, _ = self.section(n)
        heads = macros(text, "suriSummaryHead", 1)
        if not heads:
            return [("confirmados", text)]
        out = []
        for i, (p, a) in enumerate(heads):
            end = heads[i + 1][0] if i + 1 < len(heads) else len(text)
            out.append((a[0], text[p:end]))
        return out


ANCHOR_LINK = re.compile(r"\\hyperlink\{([^}]*)\}")
ANCHOR_TARGET = re.compile(r"\\hypertarget\{([^}]*)\}")


def fnd(oid):
    return "fnd-" + oid.replace(".", "-")


def row_group(row, sheet, lang):
    """Nome do grupo de uma linha consolidada do sumario ("<grupo> --- <titulo>"),
    ou None se a linha e' de um NVT. Pelo NOME e nao pela ancora: a regua tem de
    ler tambem a saida antiga, cuja ancora era outra."""
    if (row["anchor"] or "").startswith("fnd-"):
        return None
    suffix = " --- " + sheet.t("grp_title", lang)
    name = plain(row["name"])
    return name[:-len(suffix)] if name.endswith(suffix) else name


def card_group(card, sheet, lang):
    prefix = sheet.t("grp_title", lang) + ": "
    title = plain(card["title"])
    return title[len(prefix):] if title.startswith(prefix) else title


def summary_rows(block):
    """Linhas \\findingrow de um bloco: dicts com num, anchor, name, inst, sev, score."""
    rows = []
    for _, a in macros(block, "findingrow", 5):
        m = ANCHOR_LINK.match(a[1])
        anchor = m.group(1) if m else None
        name = ""
        if m:
            try:
                name, _ = group_at(a[1], m.end())
            except TexError:
                name = ""
        rows.append({"num": a[0].strip(), "anchor": anchor, "name": name,
                     "inst": a[2].strip(), "sev": a[3].strip(), "score": a[4].strip()})
    return rows


def finding_cards(block):
    cards = []
    for _, a in macros(block, "findingcard", 4):
        m = re.match(r"\\hypertarget\{([^}]*)\}\{\}\\#(\d+)$", a[1].strip())
        chips = a[3]
        cs = re.search(r"\\chipsev\{([^}]*)\}\{([^}]*)\}", chips)
        qwarn = re.search(r"\\chipwarn\{QoD ([^\\}]*)\\%", chips)
        qok = re.search(r"\\chip\{QoD ([^\\}]*)\\%\}", chips)
        cards.append({"anchor": m.group(1) if m else None, "num": m.group(2) if m else None,
                      "sev": a[0].strip(), "chipsev": cs.group(1) if cs else None,
                      "score": cs.group(2).strip() if cs else None,
                      "qod_warn": qwarn.group(1).strip() if qwarn else None,
                      "qod": qok.group(1).strip() if qok else None})
    return cards


def card_segments(block):
    """[(card, trecho)]: cada \\findingcard com o texto que vem depois dele ate'
    o proximo card (normal ou consolidado) -- onde moram os blocos do achado."""
    starts = sorted([p for p, _ in macros(block, "findingcard", 4)] +
                    [p for p, _ in macros(block, "consolidatedcard", 7)])
    out = []
    cards = finding_cards(block)
    fpos = [p for p, _ in macros(block, "findingcard", 4)]
    for c, p in zip(cards, fpos):
        nxt = [q for q in starts if q > p]
        out.append((c, block[p:nxt[0] if nxt else len(block)]))
    return out


def consolidated_cards(block):
    cards = []
    for _, a in macros(block, "consolidatedcard", 7):
        m = re.match(r"\\hypertarget\{([^}]*)\}\{\}", a[1])
        title = a[1][m.end():] if m else a[1]
        cs = re.search(r"\\chipsev\{([^}]*)\}\{([^}]*)\}", a[3])
        nadv = re.search(r"\\chip\{(\d+) ", a[3])
        cards.append({"anchor": m.group(1) if m else None, "title": title,
                      "sev": a[0].strip(), "score": cs.group(2).strip() if cs else None,
                      "nadv": int(nadv.group(1)) if nadv else None,
                      "advrows": len(macros(a[5], "advisoryrow", 3)),
                      "advtrunc": len(macros(a[5], "advisorytrunc", 1)),
                      "action": a[6]})
    return cards


# ---------------------------------------------------------------------------
# As checagens. Cada uma devolve a lista de falhas (vazia = passou).
# ---------------------------------------------------------------------------
def check_numeracao(m, tex, sheet, lang):
    """Linha #N do sumario == card #N; e cada lado numera direito por conta
    propria: cada tabela 1..n em ordem, linhas de grupo primeiro; os cards de um
    bloco em sequencia, a partir de (consolidados do bloco + 1). So' a igualdade
    linha == card deixaria passar os dois lados errados do mesmo jeito (sem o
    deslocamento dos grupos nos dois, por exemplo)."""
    fails = []
    rows = {}
    n_grp_rows = 0
    for mode, block in tex.blocks(4):
        nums, seen_nvt = [], False
        for r in summary_rows(block):
            nums.append(r["num"])
            if row_group(r, sheet, lang) is not None:
                n_grp_rows += 1
                if seen_nvt:
                    fails.append("sumario '%s': linha de grupo #%s depois de linha de achado"
                                 % (mode, r["num"]))
            else:
                seen_nvt = True
                if r["anchor"]:
                    rows[r["anchor"]] = (mode, r["num"])
        want = [str(i) for i in range(1, len(nums) + 1)]
        if nums != want:
            fails.append("sumario '%s' numerado %s, esperado 1..%d em ordem"
                         % (mode, " ".join(nums[:15]) + (" ..." if len(nums) > 15 else ""),
                            len(nums)))
    cards = {}
    n_cons = 0
    for mode, block in tex.blocks(5):
        fcs = finding_cards(block)
        ncons = len(consolidated_cards(block))
        n_cons += ncons
        start = ncons + 1 if mode == "confirmados" else 1
        nums = [c["num"] for c in fcs]
        want = [str(i) for i in range(start, start + len(nums))]
        if nums != want:
            fails.append("cards '%s' numerados %s, esperado %d..%d (%d consolidado(s) antes)"
                         % (mode, " ".join(str(x) for x in nums[:15]),
                            start, start + len(nums) - 1, ncons))
        for c in fcs:
            if c["anchor"]:
                cards[c["anchor"]] = (mode, c["num"])
    if n_grp_rows != n_cons:
        fails.append("%d linha(s) de grupo no sumario e %d card(s) consolidado(s)"
                     % (n_grp_rows, n_cons))
    for anchor, (mode, num) in sorted(rows.items()):
        if anchor not in cards:
            fails.append("linha #%s (%s) do sumario aponta %s, sem card" % (num, mode, anchor))
        elif cards[anchor][1] != num:
            fails.append("linha #%s (%s) do sumario abre o card #%s (%s)"
                         % (num, mode, cards[anchor][1], anchor))
    return fails


def check_secoes(m, tex, sheet, lang):
    fails = []
    none_conf = sheet.t("none_confirmed", lang)
    n_low = sum(1 for n in m.nvts if n.low)
    for sec in (4, 5):
        if sec not in tex.sections:
            fails.append("secao %d ausente" % sec)
            continue
        modes = []
        text, _ = tex.section(sec)
        slabs = len(macros(text, "suriSummaryHead", 1))
        for mode, block in tex.blocks(sec):
            modes.append(mode)
            items = (len(macros(block, "findingrow", 5)) if sec == 4 else
                     len(macros(block, "findingcard", 4)) + len(macros(block, "consolidatedcard", 7)))
            # Secao 5 sem tarja nenhuma e relatorio sem achado: nao ha bloco
            # anunciado que pudesse ficar vazio.
            if items == 0 and not slabs and not m.nvts:
                continue
            if items == 0 and not (mode == "confirmados" and none_conf in block):
                fails.append("secao %d: tarja '%s' sem nenhuma %s" %
                             (sec, mode, "linha" if sec == 4 else "card"))
        has_ind = "indicadores" in modes
        if has_ind != (n_low > 0):
            fails.append("secao %d: tarja de indicadores %s, mas o relatorio tem %d NVT(s) de baixa"
                         " confianca" % (sec, "presente" if has_ind else "ausente", n_low))
    return fails


def check_consolidado(m, tex, sheet, lang):
    fails = []
    adv_max = sheet.num("adv-max")
    seen = set()
    for mode, block in tex.blocks(5):
        for c in consolidated_cards(block):
            g = card_group(c, sheet, lang)
            if g not in m.groups:
                fails.append("card consolidado '%s' nao corresponde a grupo de >= %d NVTs"
                             " VendorFix confirmados" % (g, m.group_min))
                continue
            seen.add(g)
            want = len(m.groups[g])
            if c["nadv"] != want:
                fails.append("card '%s': %s advisories no chip, esperado %d (so' confirmados)"
                             % (g, c["nadv"], want))
            if c["advrows"] != min(want, adv_max) or (c["advtrunc"] > 0) != (want > adv_max):
                fails.append("card '%s': %d linhas de advisory (+%d corte), esperado %d"
                             % (g, c["advrows"], c["advtrunc"], min(want, adv_max)))
            if mode != "confirmados":
                fails.append("card consolidado '%s' fora do bloco confirmado" % g)
    for g in sorted(set(m.groups) - seen):
        fails.append("grupo '%s' (%d confirmados) sem card consolidado" % (g, len(m.groups[g])))
    # Quem foi absorvido nao tem card proprio; quem nao foi, tem -- no bloco certo.
    where = {}
    for mode, block in tex.blocks(5):
        for c in finding_cards(block):
            where[c["anchor"]] = mode
    for n in m.nvts:
        a = fnd(n.oid)
        if n.oid in m.absorbed:
            if a in where:
                fails.append("NVT %s absorvido no grupo '%s' e ainda com card proprio" % (n.oid, n.group))
        else:
            want = "indicadores" if n.low else "confirmados"
            if a not in where:
                fails.append("NVT %s (%s) sem card: absorvido indevidamente?" % (n.oid, want))
            elif where[a] != want:
                fails.append("NVT %s no bloco '%s', esperado '%s'" % (n.oid, where[a], want))
    return fails


def check_instancias(m, tex, sheet, lang):
    """Severidade, tabela e QoD de cada NVT pela regra das instancias (maxima;
    indicador so' com TODAS abaixo do piso; QoD exibida = maxima), a ordem das
    tabelas e dos cards pela severidade maxima do ORACULO (Log e falso positivo
    inclusive, que nao imprimem pontuacao), e o resultado da deteccao de cada
    card = o da instancia que carrega a maxima (a primeira, no empate)."""
    fails = []

    def order_key(sev):
        # O xsl:sort numerico decrescente poe NaN no fim.
        return sev if isnum(sev) else float("-inf")

    for mode, block in tex.blocks(4):
        # Duas sequencias ordenadas por tabela: as linhas de grupo (no topo da
        # tabela de confirmados) e as de NVT. Cada uma em ordem decrescente.
        last = {"grp": None, "nvt": None}
        for r in summary_rows(block):
            a = r["anchor"] or ""
            g = row_group(r, sheet, lang)
            if g is None:
                kind = "nvt"
                n = m.by_anchor.get(a)
                if n is None:
                    fails.append("linha %s: OID desconhecido" % a)
                    continue
                want_mode = "indicadores" if n.low else "confirmados"
                want_sev = sev_key_row(n.maxsev)
                want_score = n.maxsev_raw if want_sev not in ("logsev", "neutro") else ""
                if mode != want_mode:
                    fails.append("sumario: %s na tabela '%s', esperado '%s'" % (n.oid, mode, want_mode))
                if (r["sev"], r["score"]) != (want_sev, want_score):
                    fails.append("sumario: %s com %s/%s, esperado %s/%s (maxima das instancias)"
                                 % (n.oid, r["sev"], r["score"] or "-", want_sev, want_score or "-"))
                key = order_key(n.maxsev)
            else:
                kind = "grp"
                if g not in m.groups:
                    fails.append("sumario: linha de grupo '%s' sem grupo de >= %d confirmados"
                                 % (g, m.group_min))
                    continue
                want_sev = sev_key_row(m.group_maxsev(g))
                want_score = "" if want_sev in ("logsev", "neutro") else m.group_top(g).sev_raw
                if (r["sev"], r["score"]) != (want_sev, want_score):
                    fails.append("sumario: grupo '%s' com %s/%s, esperado %s/%s (maxima dos"
                                 " confirmados)" % (g, r["sev"], r["score"] or "-",
                                                    want_sev, want_score or "-"))
                if r["inst"] != str(len(m.groups[g])):
                    fails.append("sumario: grupo '%s' com %s advisories, esperado %d"
                                 % (g, r["inst"], len(m.groups[g])))
                key = order_key(m.group_maxsev(g))
            if last[kind] is not None and key > last[kind]:
                fails.append("sumario '%s' fora de ordem: linha #%s (severidade maxima %s) depois"
                             " de uma de %s" % (mode, r["num"], key, last[kind]))
            last[kind] = key
    for mode, block in tex.blocks(5):
        last = None
        for c, seg in card_segments(block):
            n = m.by_anchor.get(c["anchor"])
            if n is None:
                fails.append("card %s: OID desconhecido" % c["anchor"])
                continue
            want_sev = sev_key_card(n.maxsev)
            want_score = n.maxsev_raw if want_sev not in ("logsev", "falsepos") else ""
            if (c["sev"], c["chipsev"], c["score"]) != (want_sev, want_sev, want_score):
                fails.append("card %s: %s/%s, esperado %s/%s (maxima das instancias)"
                             % (n.oid, c["sev"], c["score"] or "-", want_sev, want_score or "-"))
            if n.low:
                if c["qod_warn"] != n.maxqod_raw or c["qod"] is not None:
                    fails.append("card %s: indicador sem o chip de baixa confianca com QoD %s"
                                 % (n.oid, n.maxqod_raw))
            else:
                if c["qod_warn"] is not None:
                    fails.append("card %s confirmado com chip de BAIXA CONFIANCA (QoD %s)"
                                 % (n.oid, c["qod_warn"]))
                want_q = n.maxqod_raw if isnum(n.maxqod) and n.maxqod >= m.floor else None
                if c["qod"] != want_q:
                    fails.append("card %s: chip QoD %s, esperado %s (maxima das instancias)"
                                 % (n.oid, c["qod"], want_q))
            key = order_key(n.maxsev)
            if last is not None and key > last:
                fails.append("cards '%s' fora de ordem: #%s (severidade maxima %s) depois de um"
                             " de %s" % (mode, c["num"], key, last))
            last = key
            # Evidencia: o termbox do card e' a descricao da instancia
            # representativa; a deteccao vazia (so' branco) nao abre termbox.
            desc = n.repr.desc
            box = re.search(r"\\begin\{termbox\}(.*?)\\end\{termbox\}", seg, re.S)
            if not norm_space(desc):
                if box:
                    fails.append("card %s: termbox sem descricao na instancia representativa"
                                 % n.oid)
                continue
            if not box:
                fails.append("card %s: sem o resultado da deteccao" % n.oid)
                continue
            got, want = flat(box.group(1)), norm_space(desc)
            ok = want.startswith(got) and len(got) > 0 if len(desc) > 1500 else got == want
            if not ok:
                fails.append("card %s: deteccao '%s', esperado a da instancia representativa"
                             " (#%d no XML, severidade %s): '%s'"
                             % (n.oid, got[:60], n.repr.pos + 1, n.repr.sev_raw or "-", want[:60]))
        last = None
        for c in consolidated_cards(block):
            g = card_group(c, sheet, lang)
            if g not in m.groups:
                continue
            want_sev = sev_key_card(m.group_maxsev(g))
            want_score = "" if want_sev in ("logsev", "falsepos") else m.group_top(g).sev_raw
            if (c["sev"], c["score"]) != (want_sev, want_score):
                fails.append("card consolidado '%s': %s/%s, esperado %s/%s"
                             % (g, c["sev"], c["score"], want_sev, want_score))
            key = order_key(m.group_maxsev(g))
            if last is not None and key > last:
                fails.append("cards consolidados fora de ordem: '%s' (%s) depois de um de %s"
                             % (g, key, last))
            last = key
    return fails


def catalog(bundle, lang):
    p = os.path.join(bundle, "nvt-i18n-%s.xml" % lang)
    if not os.path.exists(p):
        return {}
    return {n.get("o"): n for n in ET.parse(p).getroot().findall("n")}


def check_acao(m, tex, sheet, lang, bundle):
    fails = []
    cat = catalog(bundle, lang)
    for mode, block in tex.blocks(5):
        for c in consolidated_cards(block):
            g = card_group(c, sheet, lang)
            if g not in m.groups:
                continue
            top = m.group_top(g)
            orig = top.solution if norm_space(top.solution) else top.tag("solution")
            tr = cat.get(top.oid)
            tr_sol = (tr.findtext("solution") or "") if tr is not None else ""
            want = tr_sol if norm_space(tr_sol) else orig
            got = flat(c["action"])
            if got != norm_space(want):
                fails.append("card '%s': acao unica '%s', esperado '%s' (%s do NVT %s)"
                             % (g, got[:70], norm_space(want)[:70],
                                "catalogo %s" % lang if norm_space(tr_sol) else "texto do fornecedor",
                                top.oid))
    return fails


def check_vulns_unicas(m, tex, sheet, lang):
    k = macros(tex.section(1)[0], "kpirow", 8)
    if not k:
        return ["sem \\kpirow no resumo executivo"]
    got = k[0][1][7].strip()
    want = sum(1 for n in m.nvts if isnum(n.maxsev) and n.maxsev >= 0.1)
    if got != str(want):
        return ["VULNS UNICAS = %s, esperado %d (NVTs com severidade maxima >= 0.1; "
                "%d NVTs no total, Log e falso positivo fora)" % (got, want, len(m.nvts))]
    return []


def check_faixas(m, tex, sheet, lang):
    """As quatro barras do resumo executivo, o TOTAL DE ACHADOS, o numero de
    Alto/Critico da narrativa e a clausula de remediacao que fecha a frase --
    todos da fonte que o latex.xsl tem de usar."""
    fails = []
    rc = m.report.find("result_count")
    names = ("critical", "high", "medium", "low")
    full = [xnum(rc.findtext("%s/full" % b)) if rc is not None else float("nan") for b in names]
    rc_bands = all(isnum(x) for x in full)
    ranges = ((9.0, 99), (7.0, 9.0), (4.0, 7.0), (0.1, 4.0))
    export = [sum(1 for r in m.results if isnum(r.sev) and lo <= r.sev < hi) for lo, hi in ranges]
    want = [int(x) for x in full] if rc_bands else export
    sec1 = tex.section(1)[0]
    bars = re.findall(r"\\sevbar\{(critico|alto|medio|baixo)\}\{([^}]*)\}", sec1)
    got = [int(xnum(v)) if isnum(xnum(v)) else v for _, v in bars]
    src = "result_count/*/full" if rc_bands else "contagem do export (faixa(s) ausente(s) no result_count)"
    if sum(want) == 0:
        if bars:
            fails.append("barras %s, esperado nenhuma (sem achado classificado)" % got)
    elif got != want:
        fails.append("barras critico/alto/medio/baixo = %s, esperado %s (fonte unica: %s)"
                     % (got, want, src))
    # TOTAL DE ACHADOS: o total do SCAN (o texto do result_count) quando e' um
    # inteiro >= o que o export carrega; senao, o que o export carrega.
    total = len(m.results)
    rcn = xnum(rc.text if rc is not None else "")
    total_full = int(rcn) if isnum(rcn) and rcn == int(rcn) and rcn >= total else total
    truncated = total_full > total
    kpi = macros(sec1, "kpirow", 8)
    if not kpi:
        fails.append("sem \\kpirow no resumo executivo")
    elif kpi[0][1][5].strip() != str(total_full):
        fails.append("TOTAL DE ACHADOS = %s, esperado %d (%s)"
                     % (kpi[0][1][5].strip(), total_full,
                        "texto do result_count" if truncated or total_full != total
                        else "results do export"))
    # Narrativa: o N de Alto/Critico e' a soma das MESMAS faixas das barras, e a
    # clausula que fecha a frase depende de N, da baixa confianca (contada no
    # export) e de as duas serem da mesma populacao.
    if m.hosts == 0:
        return fails
    hicrit = want[0] + want[1]
    lowconf = sum(1 for r in m.results if isnum(r.sev) and r.sev >= 7.0 and r.low(m.floor))
    known = (not rc_bands) or (not truncated)
    lede = macros(sec1, "suriLede", 1)
    if not lede:
        return fails + ["sem \\suriLede no resumo executivo"]
    text = lede[0][1][0]
    head = "\\textbf{%d " % hicrit
    k = text.rfind(head)
    if k < 0:
        nums = re.findall(r"\\textbf\{(\d+) ", text)
        return fails + ["narrativa diz %s Alto/Critico, esperado %d (critico + alto das barras)"
                        % (" e ".join(nums) or "nenhum numero", hicrit)]
    try:
        _, end = group_at(text, k + len("\\textbf"))
    except TexError as e:
        return fails + ["narrativa: grupo do numero de Alto/Critico ilegivel (%s)" % e]
    tail = text[end:]
    warrant = sheet.t("exec_warrant", lang)
    if not known:
        want_tail, why = ".", ("faixas do SCAN (%d Alto/Critico) e export parcial: a baixa"
                               " confianca (%d no export) e' de outra populacao, a frase termina"
                               " no numero" % (hicrit, lowconf))
    elif hicrit > 0 and lowconf >= hicrit:
        want_tail, why = sheet.t("exec_all_lowconf", lang), "todos de baixa confianca"
    elif lowconf > 0:
        want_tail = "%s --- %d%s." % (warrant, lowconf, sheet.t("of_which_lowconf", lang))
        why = "%d de baixa confianca" % lowconf
    else:
        want_tail, why = warrant + ".", "nenhum de baixa confianca"
    if tail != want_tail:
        fails.append("clausula de remediacao '%s', esperado '%s' (%s)"
                     % (tail[:90], want_tail[:90], why))
    return fails


def check_ancoras(m, tex, sheet, lang):
    fails = []
    links = ANCHOR_LINK.findall(tex.s)
    targets = ANCHOR_TARGET.findall(tex.s)
    bad = sorted({a for a in links + targets if not re.fullmatch(r"[A-Za-z0-9-]+", a)})
    if bad:
        fails.append("ancora(s) com caractere fora de [A-Za-z0-9-]: %s" % ", ".join(bad[:5]))
    dangling = sorted(set(links) - set(targets))
    if dangling:
        fails.append("link(s) sem alvo: %s" % ", ".join(dangling[:5]))
    dup = sorted({a for a in targets if targets.count(a) > 1})
    if dup:
        fails.append("alvo(s) repetido(s): %s" % ", ".join(dup[:5]))
    glinks = [a for a in links if a.startswith("grp-")]
    gtargets = [a for a in targets if a.startswith("grp-")]
    ng = len(m.groups)
    if not (len(glinks) == len(gtargets) == ng):
        fails.append("grupos consolidados: %d \\hyperlink, %d \\hypertarget, esperado %d de cada"
                     % (len(glinks), len(gtargets), ng))
    return fails


def check_nome(m, tex, sheet, lang):
    """O nome do projeto, onde e' cortado, e' cortado na ULTIMA fronteira de
    palavra do orcamento -- recuando no maximo metade dele e no maximo 199 (a
    escada de inteiros do gvm:cut-at) -- e o corte declarado bate. Um espaco no
    indice 0-based `orcamento' quer dizer que os `orcamento' primeiros
    caracteres sao palavras inteiras. Sem fronteira na janela (token maior que
    ela), o corte e' no orcamento: nao ha onde quebrar."""
    fails = []
    raw = m.project()
    # (onde, orcamento, nome inteiro, texto visivel, caracteres declarados como
    # cortados ou None quando a marca nao traz contagem)
    places = []
    for macro, var in (("suriCover", "cover-name-max"), ("suriBackCover", "backcover-name-max")):
        found = macros(tex.s, macro, 1)
        if not found:
            fails.append("sem \\%s" % macro)
            continue
        body = found[0][1][0]
        k = body.find("projeto=")
        try:
            val, _ = group_at(body, skip_blank(body, k + len("projeto=")))
        except TexError as e:
            fails.append("\\%s: projeto ilegivel (%s)" % (macro, e))
            continue
        places.append(("capa" if macro == "suriCover" else "contracapa", sheet.num(var),
                       raw, plain(val), trunc_count(val)))
    lede = macros(tex.section(1)[0], "suriLede", 1)
    opener = "\\textbf{``"
    if lede:
        t = lede[0][1][0]
        a = t.find(opener)
        b = t.find("''}", a)
        if a >= 0 and b > a:
            val = t[a + len(opener):b]
            places.append(("narrativa", sheet.num("task-name-max"), raw, plain(val),
                           trunc_count(val)))
        else:
            fails.append("narrativa: nome do projeto nao encontrado")
    # Titulo do card do mapa de portas (secao 2): o nome NORMALIZADO, teto de
    # 60 e marca "..." sem contagem (hx-board).
    hexcards = macros(tex.section(2)[0], "hexcard", 3)
    whole = norm_space(raw)
    if hexcards and whole:
        title = plain(hexcards[0][1][0])
        if len(whole) > 60 and title.endswith("..."):
            title = title[:-3]
        places.append(("mapa de portas", 60, whole, title, None))
    for where, budget, name, vis, cut in places:
        fails += cut_fails(where, budget, name, vis, cut)
    return fails


def cut_fails(where, budget, name, vis, cut):
    """O texto visivel `vis' de um campo cortado em `budget' caracteres e' o
    nome inteiro (cabe) ou o seu inicio cortado na ULTIMA fronteira de palavra
    da janela (veja check_nome), com o corte declarado `cut' (None: a marca nao
    traz contagem) batendo com o que sobrou."""
    k = len(vis)
    if cut is None:
        cut = len(name) - k
    if len(name) <= budget:
        if cut or vis != name:
            return ["%s: nome cabe (%d <= %d) e saiu '%s' (+%d)"
                    % (where, len(name), budget, vis[:40], cut)]
        return []
    if not name.startswith(vis) or cut != len(name) - k:
        return ["%s: '%s' (+%d) nao e' o inicio do nome com o corte declarado"
                % (where, vis[:40], cut)]
    back = min(budget // 2, 199)
    spaces = [i for i in range(budget - back, budget + 1) if name[i] in WS]
    want = spaces[-1] if spaces else budget
    if k != want:
        return ["%s: corte em %d caracteres ('...%s|%s...'), esperado %d (%s)"
                % (where, k, vis[-12:], name[k:k + 12], want,
                   "fronteira de palavra" if spaces else "sem fronteira na janela")]
    return []


# ---------------------------------------------------------------------------
# Secao 6: escopo, metodologia e limitacoes
# ---------------------------------------------------------------------------
NA = "\\scopena"     # o valor de todo dado que o relatorio nao traz
# Letras do levels= que tem palavra propria (as outras saem como estao).
LEVEL_KEYS = {"c": "sev_critical", "h": "sev_high", "m": "sev_medium", "l": "sev_low",
              "g": "sev_log", "f": "lvl_falsepos", "d": "lvl_debug"}
SCOPE_BLOCKS = ("scope_measured", "scope_filter", "scope_auth", "scope_errors", "scope_limits")
ISO_DATE = re.compile(r"(-?\d{4,})-(\d\d)-(\d\d)T(\d\d):(\d\d)")
# scan_run_status -> chave da palavra; estado fora da lista sai como esta'.
RUN_KEYS = {"Done": "run_done", "Running": "run_running", "Stop Requested": "run_stopreq",
            "Stopped": "run_stopped", "Interrupted": "run_interrupted",
            "Requested": "run_requested", "Queued": "run_queued", "New": "run_new"}
# Estados compativeis com "nunca iniciou" (vazio = sem o elemento) e os de um
# scan que comecou e nao terminou: as listas de $scan-never-started e
# $scan-unfinished do latex.xsl.
NEVER_STARTED_OK = ("", "New", "Requested", "Queued", "Stop Requested", "Stopped", "Interrupted")
UNFINISHED = ("Running", "Stop Requested", "Stopped", "Interrupted")
# Os dois sinais que o gmp-bridge (bridge.py) grava num relatorio importado do
# inventario do agente: o OID marcador (INVENTORY_MARKER_OID) do resultado que
# ancora um host sem achado, e o comentario da tarefa conteiner do modo agent.
AGENT_MARKER_OID = "1.3.6.1.4.1.55683.1.0.1"
AGENT_COMMENT_PREFIX = "Suricatoos Agent findings for host"
# O veto dos dois sinais: detalhe de host com um destes prefixos e' rastro de
# scan de rede (login do scanner, feed que varreu o host), e o bridge nao grava
# detalhe de host nenhum -- o comentario, editavel, nao vira um scan real em
# inventario.
NETWORK_DETAIL_PREFIXES = ("Auth-", "scanned_with_")


def xp_text(el):
    """string() do XPath de um elemento: todo o texto descendente; '' sem ele."""
    return "".join(el.itertext()) if el is not None else ""


def xp_first_text(el):
    """O 1o no' de texto filho (o host/text() do XPath em contexto de string),
    sem os nos so' de branco que o xsl:strip-space do latex.xsl tira."""
    if el is None:
        return ""
    for piece in [el.text] + [c.tail for c in el]:
        if piece is not None and piece.strip(WS):
            return piece
    return ""


def term_value(term, key):
    """O valor de `key=' no termo do filtro, com a chave ancorada num TOKEN:
    substring-before(substring-after(concat(' ', normalize-space(term), ' '),
    ' key='), ' ') -- "levels=" nao casa dentro de "compliance_levels="."""
    t = " " + norm_space(term) + " "
    k = t.find(" " + key + "=")
    return t[k + len(key) + 2:].split(" ", 1)[0] if k >= 0 else ""


def gvm_num(n, lang):
    """gvm:num: milhar com virgula em en, com ponto em pt/es."""
    s = "{:,}".format(int(n))
    return s if bucket(lang) == "en" else s.replace(",", ".")


def parse_iso(s):
    """O instante que o date:seconds do libexslt le: ISO 8601, fuso Z ou
    +hh:mm; sem fuso vale UTC (medido no libexslt). None se nao for data."""
    try:
        d = datetime.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:
        return None
    return d if d.tzinfo is not None else d.replace(tzinfo=datetime.timezone.utc)


def auth_res(name):
    """gvm:auth-res: 'Success' | 'Failure' de Auth-<protocolo>-<resultado>
    com protocolo nao vazio; '' para qualquer outro nome."""
    n = norm_space(name)
    if not n.startswith("Auth-"):
        return ""
    proto, sep, res = n[5:].partition("-")
    return res if sep and proto and res in ("Success", "Failure") else ""


def detail_named(dets, name):
    """Os <detail> de um host cujo <name> e' exatamente `name' (detail[name=...])."""
    return [d for d in dets if xp_text(d.find("name")) == name]


class ScanState:
    """As tres regras de estado do latex.xsl, que a secao 1 e a secao 6 leem:
    nunca iniciou (sem scan_start, sem host, sem resultado e estado
    compativel), nao terminou (comecou e o estado e' de scan inacabado) e
    inventario do agente (um dos dois sinais do gmp-bridge, e nenhum detalhe
    de host de scan de rede)."""

    def __init__(self, m):
        rep = m.report
        self.status = norm_space(xp_text(rep.find("scan_run_status")))
        self.never_started = (not norm_space(xp_text(rep.find("scan_start")))
                              and not rep.findall("host") and not m.results
                              and self.status in NEVER_STARTED_OK)
        self.unfinished = not self.never_started and self.status in UNFINISHED
        comment = norm_space(xp_text(rep.find("task/comment")))
        # starts-with(name, ...): o 1o <name> do <detail>, sem normalize-space.
        network_trace = any(xp_text(d.find("name")).startswith(NETWORK_DETAIL_PREFIXES)
                            for h in rep.findall("host") for d in h.findall("detail"))
        self.agent_import = ((any(norm_space(r.oid) == AGENT_MARKER_OID for r in m.results)
                              or comment.startswith(AGENT_COMMENT_PREFIX))
                             and not network_trace)


class ScopeOracle:
    """O que a secao 6 deveria dizer, recalculado do XML: por bloco, as linhas
    \\scopefact (rotulo, valor), as linhas de tabela, o corte declarado e as
    notas; e os itens de limitacoes. Valor NA = \\scopena; ("corte", texto,
    teto) = texto livre com o corte declarado do escape_break (regra do
    check_nome); ("ilegivel", s) = data que o oraculo nao le."""

    def __init__(self, m, sheet, lang):
        self.m, self.sheet, self.lang = m, sheet, lang
        self.cap = sheet.num("scope-rows-max")
        st = self.state = ScanState(m)
        rep = m.report
        t = self.t
        hosts = rep.findall("host")
        nh = len(hosts)
        b = {}
        # 1. escopo medido
        start = norm_space(xp_text(rep.find("scan_start")))
        end = norm_space(xp_text(rep.find("scan_end")))
        name_max = sheet.num("task-name-max")
        facts = [(t("scope_task"), self.cut(xp_text(rep.find("task/name")), name_max, NA)),
                 (t("scope_target"), self.cut(xp_text(rep.find("task/target/name")), name_max, NA)),
                 (t("scope_hosts"), self.count(nh, xp_text(rep.find("hosts/count")))),
                 (t("lbl_scan_started"), self.date(start)),
                 (t("lbl_scan_completed"), self.date(end)),
                 (t("scope_duration"),
                  t("scope_agent_na") if st.agent_import else self.duration(start, end)),
                 (t("scope_status"),
                  (t(RUN_KEYS[st.status]) if st.status in RUN_KEYS else st.status) or NA)]
        # Versao do feed: os pares (versao, tipo do feed do mesmo host)
        # distintos; scanner: os valores distintos -- na ordem do documento.
        feeds, scanners = [], []
        for h in hosts:
            dets = h.findall("detail")
            ftype = next((norm_space(xp_text(d.find("value")))
                          for d in detail_named(dets, "scanned_with_feedtype")), "")
            for d in detail_named(dets, "scanned_with_feedversion"):
                v = norm_space(xp_text(d.find("value")))
                if v and (v, ftype) not in feeds:
                    feeds.append((v, ftype))
            for d in detail_named(dets, "scanned_with_scanner"):
                v = norm_space(xp_text(d.find("value")))
                if v and v not in scanners:
                    scanners.append(v)
        if feeds:
            facts.append((t("scope_feed"), "; ".join(
                self.feed_version(v) + (" (%s)" % ft if ft else "") for v, ft in feeds)))
        if scanners:
            facts.append((t("scope_scanner"), "; ".join(scanners)))
        b["scope_measured"] = self.block(
            facts=facts,
            notes=([t("scope_never_started")] if st.never_started else [])
            + ([t("scope_unfinished_note")] if st.unfinished else [])
            + ([t("scope_agent_note")] if st.agent_import else []))
        # 2. filtro do export
        term = xp_text(rep.find("filters/term"))
        mq, lv, ov = (term_value(term, k) for k in ("min_qod", "levels", "apply_overrides"))
        mq_known = mq != "" and isnum(xnum(mq))
        total = len(m.results)
        rcs = norm_space(xp_first_text(rep.find("result_count")))
        rcn = xnum(rcs)
        if rcs and isnum(rcn) and math.floor(rcn) == rcn and rcn >= total:
            partial = "%s --- %d %s %d %s" % (t("word_yes") if rcn > total else t("word_no"),
                                              total, t("of_word"), int(rcn), t("scope_results"))
        else:
            partial = NA
        b["scope_filter"] = self.block(
            facts=[(t("scope_term"), self.cut(norm_space(term), sheet.num("scope-term-max"), NA)),
                   (t("scope_minqod"), mq + "%" if mq_known else NA),
                   (t("scope_levels"), self.levels(lv) if lv else NA),
                   (t("scope_overrides"), {"1": t("word_yes"), "0": t("word_no")}.get(ov, NA)),
                   (t("scope_partial"), partial)],
            notes=([t("scope_minqod_effect_a") + mq + "\\%" + t("scope_minqod_effect_b")]
                   if mq_known else []))
        # 3. autenticacao
        rows, n_ok, n_fail = [], 0, 0
        for h in hosts:
            dets = h.findall("detail")
            res = [auth_res(xp_text(d.find("name"))) for d in dets]
            if "Success" in res:
                n_ok += 1
            elif "Failure" in res:
                n_fail += 1
            hip = norm_space(xp_text(h.find("ip")))
            hname = next((norm_space(xp_text(d.find("value"))) for d in detail_named(dets, "hostname")), "")
            for i, d in enumerate(dets):
                name = xp_text(d.find("name"))
                # not(normalize-space(name) = preceding-sibling::detail/name)
                if not res[i] or norm_space(name) in {xp_text(p.find("name")) for p in dets[:i]
                                                      if p.find("name") is not None}:
                    continue
                proto = norm_space(name)[5:].partition("-")[0]
                rows.append((hip or hname or "---", proto, "ok" if res[i] == "Success" else "falha"))
        if rows:
            b["scope_auth"] = self.block(
                facts=[(t("scope_auth_ok"), "%d %s %d" % (n_ok, t("of_word"), nh)),
                       (t("scope_auth_fail"), str(n_fail)),
                       (t("scope_auth_none"), str(nh - n_ok - n_fail))],
                rows=("authrow", rows), trunc=self.trunc(len(rows), "scope_trunc_auth"),
                notes=[t("scope_auth_partial_note")] if nh - n_ok > 0 else [])
        elif st.agent_import:
            b["scope_auth"] = self.block(facts=[(t("scope_auth_ok"), t("scope_agent_na"))])
        else:
            b["scope_auth"] = self.block(facts=[(t("scope_auth_ok"), NA)],
                                         notes=[t("scope_auth_na_note")])
        # 4. erros de scan
        if rep.find("errors") is None:
            b["scope_errors"] = self.block(facts=[(t("scope_err_count"), NA),
                                                  (t("scope_err_hosts"), NA)])
        else:
            errs = rep.findall("errors/error")
            ehosts = {norm_space(xp_first_text(e.find("host"))) for e in errs} - {""}
            desc_max, nvt_max = sheet.num("scope-desc-max"), sheet.num("scope-nvt-max")
            erows = []
            for e in errs:
                nvt = e.find("nvt")
                nname = norm_space(xp_text(nvt.find("name") if nvt is not None else None))
                oid = norm_space(nvt.get("oid", "") if nvt is not None else "")
                erows.append((norm_space(xp_first_text(e.find("host"))) or "---",
                              norm_space(xp_text(e.find("port"))) or "---",
                              self.cut(norm_space(xp_text(e.find("description"))), desc_max, "---"),
                              self.cut(nname, nvt_max, None) or oid or "---"))
            b["scope_errors"] = self.block(
                facts=[(t("scope_err_count"), self.count(len(errs), xp_text(rep.find("errors/count")))),
                       (t("scope_err_hosts"), str(len(ehosts)))],
                rows=("errorrow", erows) if errs else None,
                trunc=self.trunc(len(errs), "scope_trunc_err"),
                notes=[t("scope_err_note")] if errs else [])
        # 5. limitacoes
        items = ([t("scope_lim_agent")] if st.agent_import
                 else [t("scope_lim_view"), t("scope_lim_alive")])
        items.append(t("scope_lim_qod_a") + str(m.floor) + "\\%" + t("scope_lim_qod_b"))
        if st.unfinished:
            items.append(t("scope_lim_unfinished"))
        if feeds:
            items.append(t("scope_lim_feed"))
        b["scope_limits"] = self.block(items=items)
        self.blocks = [(t(k), b[k]) for k in SCOPE_BLOCKS]

    def t(self, key):
        return self.sheet.t(key, self.lang)

    @staticmethod
    def block(facts=(), rows=None, trunc=(), notes=(), items=None):
        return {"facts": list(facts), "rows": rows, "trunc": list(trunc),
                "notes": list(notes), "items": items}

    @staticmethod
    def cut(text, budget, empty):
        """Texto livre com teto: ("corte", texto, teto); vazio (so' branco) ->
        `empty' (NA num fato, "---" numa celula, None para cair no seguinte)."""
        return ("corte", text, budget) if norm_space(text) else empty

    def count(self, n, declared):
        """scope-count: n e, se o gvmd declara outro inteiro, a ressalva."""
        d = norm_space(declared)
        x = xnum(d)
        if d and isnum(x) and math.floor(x) == x and x != n:
            return "%d (%s %d)" % (n, self.t("scope_gvmd_count"), int(x))
        return str(n)

    def trunc(self, n, key):
        if n <= self.cap:
            return []
        return ["\\suriEllip\\ + " + gvm_num(n - self.cap, self.lang) + self.t(key)]

    def date(self, s):
        """emit-date: "Tue Sep 1, 2026 09:00 UTC" / "ter, 1 set 2026 09:00 UTC"."""
        if not s:
            return NA
        mt = ISO_DATE.match(s)
        if not mt:
            return ("ilegivel", s)
        y, mo, d, hh, mi = mt.groups()
        dow = datetime.date(int(y), int(mo), int(d)).isoweekday() % 7 + 1   # 1 = domingo
        L = bucket(self.lang)
        mon = self.sheet.words("mon-" + L)[int(mo) - 1]
        dw = self.sheet.words("dow-" + L)[dow - 1]
        root = self.m.root
        tz = xp_text(root.find("report/timezone_abbrev") if root.get("extension") == "xml"
                     else root.find("timezone_abbrev"))
        if L == "en":
            return "%s %s %d, %d %s:%s %s" % (dw, mon, int(d), int(y), hh, mi, tz)
        return "%s, %d %s %d %s:%s %s" % (dw, int(d), mon, int(y), hh, mi, tz)

    def duration(self, start, end):
        """scope-duration: fim - inicio, truncado em s / min / h MM min; fim
        antes do inicio ou no mesmo instante (o carimbo do import do sensor)
        nao e' duracao medida."""
        a, z = (parse_iso(start), parse_iso(end)) if start and end else (None, None)
        if a is None or z is None or z <= a:
            return NA
        d = (z - a).total_seconds()
        if d < 60:
            return "%d s" % math.floor(d)
        if d < 3600:
            return "%d min" % math.floor(d / 60)
        return "%d h %02d min" % (math.floor(d / 3600), math.floor((d % 3600) / 60))

    def feed_version(self, v):
        """scope-feed-version: AAAAMMDDhhmm -> "Oct 11, 2026 04:57" (en) ou
        "11 out 2026 04:57" (pt/es); fora do formato, o valor como esta'."""
        mt = re.fullmatch(r"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)", v)
        if not mt:
            return v
        y, mo, d, hh, mi = mt.groups()
        if not (1 <= int(mo) <= 12 and 1 <= int(d) <= 31 and int(hh) <= 23 and int(mi) <= 59):
            return v
        L = bucket(self.lang)
        mon = self.sheet.words("mon-" + L)[int(mo) - 1]
        if L == "en":
            return "%s %d, %s %s:%s" % (mon, int(d), y, hh, mi)
        return "%d %s %s %s:%s" % (int(d), mon, y, hh, mi)

    def levels(self, lv):
        """scope-levels: as letras por extenso, na ordem, sem repetir (ate' 200)."""
        out = []
        for i, ch in enumerate(lv[:200]):
            if ch not in lv[:i]:
                out.append(self.t(LEVEL_KEYS[ch]) if ch in LEVEL_KEYS else ch)
        return ", ".join(out)


def scope_value_fails(where, got, want):
    """[] se o valor `got' (o LaTeX de um fato ou de uma celula) diz `want':
    NA = \\scopena; ("corte", texto, teto) = o texto com o corte declarado do
    escape_break (cut_fails); ("ilegivel", s) = sempre falha; senao, o texto
    que o leitor ve (flat) igual."""
    got = got.strip()
    if isinstance(want, tuple) and want[0] == "corte":
        if got == NA:
            return ["%s = \\scopena, e o XML tem '%s'" % (where, norm_space(want[1])[:40])]
        return cut_fails(where, want[2], want[1], plain(got), trunc_count(got))
    if isinstance(want, tuple):
        return ["%s com data ilegivel no XML (%r)" % (where, want[1])]
    if want == NA:
        return ([] if got == NA else
                ["%s = '%s', esperado \\scopena (o XML nao traz o dado)" % (where, flat(got)[:60])])
    if got == NA:
        return ["%s = \\scopena, e o XML traz '%s'" % (where, want[:60])]
    if flat(got) != norm_space(want):
        return ["%s = '%s', esperado '%s'" % (where, flat(got)[:70], want[:70])]
    return []


def check_escopo(m, tex, sheet, lang):
    """A secao 6 (escopo, metodologia e limitacoes) diz a verdade sobre o XML,
    linha a linha: cada \\scopefact com o rotulo e o valor que o relatorio
    sustenta -- \\scopena EXATAMENTE quando o dado falta, os textos livres com
    o teto e o corte declarado --, as tabelas de autenticacao e de erros com
    as linhas e as celulas certas, na ordem, ate' o teto $scope-rows-max, e o
    corte declarado ("+ N") so' acima dele, com o N certo; as notas e os itens
    de limitacoes conforme o estado do scan (nunca iniciou, nao terminou,
    inventario do agente) e a versao do feed."""
    fails = []
    if 6 not in tex.sections:
        return ["secao 6 ausente"]
    text, _ = tex.section(6)
    want = ScopeOracle(m, sheet, lang)
    labels = macros(text, "blocklabel", 1)
    got_labels = [a[0] for _, a in labels]
    want_labels = [lbl for lbl, _ in want.blocks]
    if got_labels != want_labels:
        return ["blocos %s, esperado %s" % (got_labels, want_labels)]
    intro = macros(text[:labels[0][0]], "suriPara", 1)
    if [a[0] for _, a in intro] != [sheet.t("scope_intro", lang)]:
        fails.append("introducao da secao: %s" % [a[0][:60] for _, a in intro])
    n_na = 0
    for i, (lbl, exp) in enumerate(want.blocks):
        p = labels[i][0]
        blk = text[p:labels[i + 1][0] if i + 1 < len(labels) else len(text)]
        where = "secao 6 / %s" % lbl
        # Fatos: rotulo e valor, na ordem.
        facts = macros(blk, "scopefact", 2)
        if [a[0] for _, a in facts] != [k for k, _ in exp["facts"]]:
            fails.append("%s: rotulos %s, esperado %s"
                         % (where, [a[0] for _, a in facts], [k for k, _ in exp["facts"]]))
        else:
            for (_, a), (k, v) in zip(facts, exp["facts"]):
                n_na += v == NA
                fails += scope_value_fails("%s: '%s'" % (where, k), a[1], v)
        # Tabela (ate' o teto), celula a celula, e o corte declarado.
        for kind, nargs in (("authrow", 3), ("errorrow", 4)):
            got_rows = [a for _, a in macros(blk, kind, nargs)]
            want_rows = exp["rows"][1][:want.cap] if exp["rows"] and exp["rows"][0] == kind else []
            if len(got_rows) != len(want_rows):
                fails.append("%s: %d \\%s, esperado %d (teto %d)"
                             % (where, len(got_rows), kind, len(want_rows), want.cap))
                continue
            for r, (ga, wr) in enumerate(zip(got_rows, want_rows), 1):
                for c, (gx, wx) in enumerate(zip(ga, wr), 1):
                    cell = "%s: \\%s %d, coluna %d" % (where, kind, r, c)
                    if kind == "authrow" and c == 3:
                        if gx.strip() != wx:
                            fails.append("%s: resultado '%s', esperado '%s'" % (cell, gx.strip(), wx))
                    else:
                        fails += scope_value_fails(cell, gx, wx)
        got_trunc = [a[0] for _, a in macros(blk, "scopetrunc", 1)]
        if got_trunc != exp["trunc"]:
            fails.append("%s: corte declarado %s, esperado %s" % (where, got_trunc, exp["trunc"]))
        got_notes = [a[0] for _, a in macros(blk, "blocknote", 1)]
        if got_notes != exp["notes"]:
            fails.append("%s: notas %s, esperado %s"
                         % (where, [x[:50] for x in got_notes], [x[:50] for x in exp["notes"]]))
        if exp["items"] is not None:
            b0, b1 = blk.find("\\begin{suribullets}"), blk.find("\\end{suribullets}")
            items = ([x.strip() for x in re.split(r"\\item(?![A-Za-z@])", blk[b0:b1])[1:]]
                     if 0 <= b0 < b1 else [])
            if items != exp["items"]:
                fails.append("%s: itens %s, esperado %s"
                             % (where, [x[:50] for x in items], [x[:50] for x in exp["items"]]))
    # "Nao informado" so' onde o dado falta: nenhum \scopena fora dos fatos que
    # o oraculo marcou ausentes (numa celula de tabela, numa nota...).
    total_na = len(re.findall(r"\\scopena(?![A-Za-z@])", text))
    if total_na != n_na:
        fails.append("%d \\scopena na secao 6, esperado %d (um por dado ausente)" % (total_na, n_na))
    return fails


def check_alerta(m, tex, sheet, lang):
    """O resumo executivo (secao 1) abre com o alerta de "nada medido" se e
    somente se o relatorio nao tem host, e o alerta da' a causa que o dado
    sustenta, pelas MESMAS regras das notas da secao 6: a tarefa que nunca
    iniciou nao recebe o conselho de corrigir um alive test que nao rodou; o
    scan que iniciou e nao terminou recebe o corpo neutro (nao terminou, nenhum
    host registrado), sem diagnostico; so' o scan que terminou sem achar host
    recebe o conselho do alive test."""
    boxes = macros(tex.section(1)[0], "alertbox", 2)
    if m.hosts > 0:
        return ["alerta de 'nada medido' num relatorio com %d host(s)" % m.hosts] if boxes else []
    if len(boxes) != 1:
        return ["%d alerta(s) no resumo executivo de um relatorio sem host, esperado 1" % len(boxes)]

    def t(k):
        return sheet.t(k, lang)
    st = ScanState(m)
    if st.never_started:
        want = (t("never_title"), t("never_body_a") + "\\textbf{" + t("nohost_body_b") + "}"
                + t("never_body_c"))
        why = "a tarefa nao iniciou"
    elif st.unfinished:
        want = (t("unfin_title"), t("unfin_body_a") + "\\textbf{" + t("nohost_body_b") + "}"
                + t("unfin_body_c"))
        why = "o scan iniciou e nao terminou (%s)" % st.status
    else:
        want = (t("nohost_title"), t("nohost_body_a") + "\\textbf{" + t("nohost_body_b") + "}"
                + t("nohost_body_c"))
        why = "o scan iniciou e nenhum host respondeu"
    got = tuple(x.strip() for x in boxes[0][1])
    if got != want:
        return ["alerta '%s' ('%s...'), esperado '%s' (%s)" % (got[0], got[1][:50], want[0], why)]
    return []


CHECKS = [
    ("numeracao", check_numeracao), ("secoes", check_secoes),
    ("consolidado", check_consolidado), ("instancias", check_instancias),
    ("acao", None), ("vulns-unicas", check_vulns_unicas), ("faixas", check_faixas),
    ("ancoras", check_ancoras), ("nome", check_nome), ("escopo", check_escopo),
    ("alerta", check_alerta),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", required=True)
    ap.add_argument("--xml", required=True)
    ap.add_argument("--tex", required=True)
    ap.add_argument("--bundle", default=os.path.join(os.path.dirname(HERE), "suricatoos-premium-pdf"))
    ap.add_argument("--only", action="append", default=[])
    args = ap.parse_args()
    try:
        sheet = Stylesheet(os.path.join(args.bundle, "latex.xsl"))
        model = Model(args.xml, sheet)
        tex = Tex(args.tex)
    except (OSError, ET.ParseError, TexError, StylesheetError) as e:
        print("check-veracity: ERRO de leitura: %s" % e)
        return 2
    failed = 0
    for name, fn in CHECKS:
        if args.only and name not in args.only:
            continue
        try:
            if name == "acao":
                fails = check_acao(model, tex, sheet, args.lang, args.bundle)
            else:
                fails = fn(model, tex, sheet, args.lang)
        except TexError as e:
            fails = ["o .tex nao pode ser lido: %s" % e]
        except StylesheetError as e:
            print("check-veracity: ERRO no latex.xsl (checagem %s): %s" % (name, e))
            return 2
        if fails:
            failed += 1
            print("  FALHA  %s" % name)
            for f in fails[:12]:
                print("           | %s" % f)
            if len(fails) > 12:
                print("           | ... e mais %d" % (len(fails) - 12))
        else:
            print("  OK     %s" % name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
