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
                 card que o \\hyperlink dela abre;
  secoes         nenhuma tarja "confirmados"/"indicadores" (secoes 4 e 5) sem
                 linha ou card; a tarja de indicadores existe se e somente se ha
                 NVT de baixa confianca;
  consolidado    card consolidado so' com NVT confirmado, com a contagem e a
                 severidade certas; NVT de baixa confianca nunca e' absorvido;
  instancias     severidade = MAXIMA entre as instancias; indicador so' se TODAS
                 as instancias estao abaixo do piso de QoD; QoD exibida = maxima;
                 tabelas em ordem decrescente dessa severidade;
  acao           a acao unica do card consolidado sai do catalogo de traducao;
  vulns-unicas   VULNS UNICAS = NVTs distintos com severidade maxima >= 0.1;
  faixas         as quatro faixas do resumo executivo vem da MESMA fonte; a
                 clausula de remediacao so' fala de confianca quando Alto/Critico
                 e baixa confianca vem da mesma populacao;
  ancoras        toda ancora casa ^[A-Za-z0-9-]+$; todo link tem alvo; um link e
                 um alvo por grupo consolidado;
  nome           o nome do projeto, quando cortado (capa, contracapa, narrativa,
                 titulo do mapa de portas), e' cortado em fronteira de palavra e
                 o corte declarado bate.

Os limiares (qod-min, group-min, adv-max, cortes do nome) sao LIDOS do proprio
latex.xsl, para a regua nunca divergir do relatorio.

Uso:
    check-veracity.py --lang <en|pt_BR|es> --xml <fixture.xml> --tex <report.tex>
                      [--bundle <suricatoos-premium-pdf/>] [--only <checagem>...]

Sai 0 se tudo passa, 1 se alguma checagem reprova, 2 em erro de uso/leitura.
"""
import argparse
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
class Stylesheet:
    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.params = {}
        for tag in ("param", "variable"):
            for el in root.iter(XSL_NS + tag):
                sel = el.get("select")
                if el.get("name") and sel and re.fullmatch(r"\d+", sel):
                    self.params[el.get("name")] = int(sel)
        self.i18n = {}
        for s in root.iter("s"):
            if s.get("k"):
                self.i18n[s.get("k")] = {"en": s.get("en"), "pt": s.get("pt"), "es": s.get("es")}

    def num(self, name):
        if name not in self.params:
            raise SystemExit("check-veracity: %s nao encontrado no latex.xsl" % name)
        return self.params[name]

    def t(self, key, lang):
        bucket = "pt" if lang.startswith("pt") else ("es" if lang.startswith("es") else "en")
        node = self.i18n[key]
        return node.get(bucket) or node["en"]


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
    fails = []
    rows = {}
    for mode, block in tex.blocks(4):
        for r in summary_rows(block):
            if r["anchor"] and r["anchor"].startswith("fnd-"):
                rows[r["anchor"]] = (mode, r["num"])
    cards = {}
    for mode, block in tex.blocks(5):
        for c in finding_cards(block):
            if c["anchor"]:
                cards[c["anchor"]] = (mode, c["num"])
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
    fails = []
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
            else:
                kind = "grp"
                if g not in m.groups:
                    fails.append("sumario: linha de grupo '%s' sem grupo de >= %d confirmados"
                                 % (g, m.group_min))
                else:
                    want_sev = sev_key_row(m.group_maxsev(g))
                    want_score = "" if want_sev in ("logsev", "neutro") else m.group_top(g).sev_raw
                    if (r["sev"], r["score"]) != (want_sev, want_score):
                        fails.append("sumario: grupo '%s' com %s/%s, esperado %s/%s (maxima dos"
                                     " confirmados)" % (g, r["sev"], r["score"] or "-",
                                                        want_sev, want_score or "-"))
                    if r["inst"] != str(len(m.groups[g])):
                        fails.append("sumario: grupo '%s' com %s advisories, esperado %d"
                                     % (g, r["inst"], len(m.groups[g])))
            if r["score"] and isnum(xnum(r["score"])):
                if last[kind] is not None and xnum(r["score"]) > last[kind]:
                    fails.append("sumario '%s' fora de ordem: %s depois de %s"
                                 % (mode, r["score"], last[kind]))
                last[kind] = xnum(r["score"])
    for mode, block in tex.blocks(5):
        for c in finding_cards(block):
            n = m.by_anchor.get(c["anchor"])
            if n is None:
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
        for c in consolidated_cards(block):
            g = card_group(c, sheet, lang)
            if g not in m.groups:
                continue
            want_sev = sev_key_card(m.group_maxsev(g))
            want_score = "" if want_sev in ("logsev", "falsepos") else m.group_top(g).sev_raw
            if (c["sev"], c["score"]) != (want_sev, want_score):
                fails.append("card consolidado '%s': %s/%s, esperado %s/%s"
                             % (g, c["sev"], c["score"], want_sev, want_score))
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
    # Clausula de remediacao: populacoes de Alto/Critico e de baixa confianca.
    if m.hosts == 0:
        return fails
    total = len(m.results)
    rc_text = (rc.text or "").strip(WS) if rc is not None else ""
    truncated = bool(re.fullmatch(r"\d+", rc_text)) and int(rc_text) > total
    hicrit = want[0] + want[1]
    lowconf = sum(1 for r in m.results if isnum(r.sev) and r.sev >= 7.0 and r.low(m.floor))
    known = (not rc_bands) or (not truncated)
    lede = macros(sec1, "suriLede", 1)
    if not lede:
        return fails + ["sem \\suriLede no resumo executivo"]
    text = lede[0][1][0]
    warrant = sheet.t("exec_warrant", lang)
    alllow = sheet.t("exec_all_lowconf", lang)
    ofwhich = sheet.t("of_which_lowconf", lang)
    has = {k: (v in text) for k, v in (("warrant", warrant), ("all", alllow), ("ofwhich", ofwhich))}
    if not known:
        if any(has.values()):
            fails.append("clausula de remediacao fala de confianca com Alto/Critico do SCAN (%d) e"
                         " baixa confianca do EXPORT parcial (%d): populacoes diferentes" % (hicrit, lowconf))
    elif hicrit > 0 and lowconf >= hicrit:
        if not has["all"]:
            fails.append("todos os %d Alto/Critico sao de baixa confianca e a clausula nao diz" % hicrit)
    elif lowconf > 0:
        if not (has["warrant"] and ("--- %d%s" % (lowconf, ofwhich)) in text):
            fails.append("clausula sem '%d de baixa confianca'" % lowconf)
    elif not has["warrant"] or has["ofwhich"] or has["all"]:
        fails.append("clausula de remediacao inesperada (0 de baixa confianca)")
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
        k = len(vis)
        if cut is None:
            cut = len(name) - k
        if len(name) <= budget:
            if cut or vis != name:
                fails.append("%s: nome cabe (%d <= %d) e saiu '%s' (+%d)"
                             % (where, len(name), budget, vis[:40], cut))
            continue
        if not name.startswith(vis) or cut != len(name) - k:
            fails.append("%s: '%s' (+%d) nao e' o inicio do nome com o corte declarado"
                         % (where, vis[:40], cut))
            continue
        back = min(budget // 2, 199)
        spaces = [i for i in range(budget - back, budget + 1) if name[i] in WS]
        want = spaces[-1] if spaces else budget
        if k != want:
            fails.append("%s: corte em %d caracteres ('...%s|%s...'), esperado %d (%s)"
                         % (where, k, vis[-12:], name[k:k + 12], want,
                            "fronteira de palavra" if spaces else "sem fronteira na janela"))
    return fails


CHECKS = [
    ("numeracao", check_numeracao), ("secoes", check_secoes),
    ("consolidado", check_consolidado), ("instancias", check_instancias),
    ("acao", None), ("vulns-unicas", check_vulns_unicas), ("faixas", check_faixas),
    ("ancoras", check_ancoras), ("nome", check_nome),
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
    except (OSError, ET.ParseError, TexError) as e:
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
