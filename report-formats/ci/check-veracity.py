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
  prioridades    a secao 2 (prioridades e proximos passos), recalculada do XML:
                 as acoes -- uma por card de achado confirmado de severidade
                 maxima >= 0.1: o card de um NVT, ou o card consolidado de um
                 grupo, que e' UMA acao com as instancias de todos os membros;
                 sem Log, sem falso positivo e sem indicador -- na ordem
                 documentada (classe de severidade, hosts afetados, EPSS, maior
                 CVSS, nome, OID), linha a linha ate' o teto $prio-rows-max: a
                 acao (primeira frase da solucao -- num grupo, a do membro mais
                 severo --, com o teto $prio-action-max e o corte declarado), o
                 nome (num grupo, o titulo do card), o tipo de solucao
                 traduzido, os hosts distintos (num grupo, a uniao), a
                 severidade, o EPSS e o link para o card certo, com o numero que
                 o card tem; o "+ N" so' acima do teto; a frase "as N primeiras
                 acoes tratam X de Y achados criticos e altos" (e as formas sem
                 nenhum, com um so', com uma acao so' e sem host medido); as
                 notas de EPSS, de indicadores fora do plano e de export
                 parcial;
  escopo         a secao 7 (escopo, metodologia e limitacoes), recalculada do
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
                 da secao 7) ou scan que iniciou e nao achou host (alive test);
  afetados       cada card de achado diz quantas instancias o NVT tem e lista
                 os host:porta distintos delas (teto 40, o resto declarado); o
                 card consolidado, os hosts das instancias dos membros;
  hosts          a secao 4 (hosts e portas abertas): um card por host, as
                 linhas de porta (o inventario <ports> do host, senao as portas
                 dos resultados, mais a linha `geral'), cada uma com o numero
                 de resultados, a chave da maior severidade e o CVSS, e a nota
                 que decompoe a linha `geral' por classe;
  edicao         a capa diz a edicao (o kicker) e o .tex so' usa os blocos da
                 edicao pedida (\\findinglog so' na do cliente, a tabela de
                 prioridades sem coluna de card so' na executiva).

EDICOES (--variant, o `variant' do contrato da frota, ADR-0011):
  technical  o relatorio completo; todas as checagens acima;
  client     o relatorio SEM os resultados falso positivo -- como o gvmd o
             exportaria sem eles: nenhum resultado de severidade -1 (a faixa do
             sev-class), nenhuma porta que so' eles sustentavam, o total do
             scan sem eles -- e o Log so' como contagem: o NVT cuja severidade
             maxima fica abaixo de 0.1 nao tem linha nem card, e cada bloco
             (confirmados, indicadores) diz quantos ha. O oraculo aplica essa
             regra ao XML (client_view) e roda as mesmas checagens, mais a
             `cliente': nenhuma palavra, chave, linha, card, ancora ou porta de
             falso positivo, e as contagens de Log batendo com o XML;
  executive  so' o resumo executivo, as prioridades (sem coluna de card) e o
             escopo, numeradas 1..3: as checagens dessas secoes, mais a
             `executiva' (nenhuma outra secao, card, host, ancora de card ou
             mencao a secao que a edicao nao tem).

Os limiares (qod-min, group-min, adv-max, cortes do nome, scope-rows-max e os
tetos de texto da secao 7, prio-rows-max e prio-action-max da secao 2), as
listas de meses e dias e as frases do i18n sao LIDOS do proprio latex.xsl, para
a regua nunca divergir do relatorio; um nome lido que esteja definido mais de
uma vez la' e' erro (exit 2). As regras de estado do scan (ScanState), os dois
sinais do inventario do agente, a ordem e as regras da secao 2 (PrioOracle) e a
regra da edicao do cliente (client_view) sao as do latex.xsl, escritas de novo
aqui -- regua independente, como as outras.

Uso:
    check-veracity.py --lang <en|pt_BR|es> --xml <fixture.xml> --tex <report.tex>
                      [--variant <technical|client|executive>]
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

# As secoes que as checagens leem, pelo numero que o \suriSection carrega (a
# tabela $sections do latex.xsl; o contrato inteiro, com os titulos, e' o
# SECTIONS do check-navigation.py). A 2 (prioridades) entrou depois do resumo
# executivo, e as seguintes desceram um numero. A edicao executiva so' tem o
# resumo, as prioridades e o escopo, renumerados 1..3: use_variant() troca os
# numeros (None = a secao nao existe nessa edicao).
VARIANTS = ("technical", "client", "executive")
VARIANT = "technical"
SEC_EXEC, SEC_PRIO, SEC_HEXMAP, SEC_HOSTS = 1, 2, 3, 4
SEC_SUMMARY, SEC_DETAIL, SEC_SCOPE, SEC_APPENDIX = 5, 6, 7, 8


def use_variant(variant):
    """Os numeros de secao da edicao: a executiva so' tem 1 (resumo), 2
    (prioridades) e 3 (escopo)."""
    global VARIANT, SEC_HEXMAP, SEC_HOSTS, SEC_SUMMARY, SEC_DETAIL, SEC_SCOPE, SEC_APPENDIX
    VARIANT = variant
    if variant == "executive":
        SEC_HEXMAP = SEC_HOSTS = SEC_SUMMARY = SEC_DETAIL = SEC_APPENDIX = None
        SEC_SCOPE = 3
    else:
        SEC_HEXMAP, SEC_HOSTS, SEC_SUMMARY, SEC_DETAIL, SEC_SCOPE, SEC_APPENDIX = 3, 4, 5, 6, 7, 8


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

    def upper(self, s):
        """gvm:hx-upper: o translate com as listas $hx-lc / $hx-uc do latex.xsl
        (caixa alta dos chips, acentuadas inclusive)."""
        lc, uc = (self.words(n)[0] for n in ("hx-lc", "hx-uc"))
        return s.translate(str.maketrans(lc, uc))


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
        # O host da instancia (o 1o texto do <host>, normalizado) e o EPSS do
        # NVT como o gvmd o escreve no resultado: nvt/epss/max_epss/score (o
        # CVE do NVT de maior EPSS; gmp.c, results_xml_append_epss).
        self.host = norm_space(xp_first_text(el.find("host")))
        self.epss = [xp_text(s) for s in el.findall("nvt/epss/max_epss/score")]
        # host/text() e a porta como o latex.xsl os le e imprime (sem
        # normalizar): os sistemas afetados do card e as linhas da secao 4.
        self.host_raw = xp_first_text(el.find("host"))
        self.port_raw = xp_text(el.find("port"))

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


def is_fp(sev):
    """Falso positivo: o codigo -1 do gvmd, na faixa fechada do sev-class do
    latex.xsl (-2 debug e -3 erro de scan sao outros codigos)."""
    return isnum(sev) and -1.5 < sev < 0


def xpath_number_str(x):
    """string() de um numero do XPath: inteiro sem ponto decimal."""
    return str(int(x)) if x == int(x) else repr(x)


def client_view(rep):
    """A edicao do cliente le o relatorio SEM os resultados falso positivo, como
    o gvmd o exportaria sem eles (levels sem f), aplicado aqui ao XML, IN PLACE:
      - sai todo results/result de severidade falso positivo;
      - sai toda ports/port que so' eles sustentavam: a de severidade propria
        falso positivo (o gvmd poe na <port> a MAIOR severidade dos resultados
        daquele host e porta) ou, sem severidade propria, a que tem resultado
        no mesmo host e porta e so' falso positivo;
      - o total do scan (o texto do <result_count>) perde os falso positivo:
        os do scan (false_positive/full) quando o gvmd os conta, senao os que o
        export carrega; o false_positive sai."""
    els = rep.findall("results/result")
    fps = [el for el in els if is_fp(xnum(el.findtext("severity")))]
    by_hp = {}
    for el in els:
        by_hp.setdefault((norm_space(xp_first_text(el.find("host"))),
                          norm_space(xp_text(el.find("port")))), []).append(el)
    ports = rep.find("ports")
    if ports is not None:
        for p in list(ports.findall("port")):
            own = xnum(p.findtext("severity"))
            if isnum(own):
                drop = is_fp(own)
            else:
                rs = by_hp.get((norm_space(xp_text(p.find("host"))), norm_space(xp_first_text(p))), [])
                drop = bool(rs) and all(is_fp(xnum(r.findtext("severity"))) for r in rs)
            if drop:
                ports.remove(p)
    results = rep.find("results")
    for el in fps:
        results.remove(el)
    rc = rep.find("result_count")
    if rc is not None:
        t = norm_space(xp_first_text(rc))
        tn = xnum(t)
        fpf = xnum(rc.findtext("false_positive/full"))
        n_fp = fpf if isnum(fpf) else len(fps)
        first = xp_first_text(rc)
        rc.text = (xpath_number_str(tn - n_fp) if t and isnum(tn) and math.floor(tn) == tn
                   else (first or None))
        for c in rc:
            c.tail = None
        fpe = rc.find("false_positive")
        if fpe is not None:
            rc.remove(fpe)


class Model:
    def __init__(self, xml_path, sheet, variant="technical"):
        root = ET.parse(xml_path).getroot()
        # gvm:report(): o <report> interno quando ha um, senao a raiz.
        inner = root.find("report")
        rep = inner if inner is not None else root
        self.path = xml_path
        self.variant = variant
        if variant == "client":
            client_view(rep)
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
        # Grupos consolidados: so' NVT VendorFix CONFIRMADO conta e entra. Na
        # edicao do cliente, tambem so' o que e' achado (severidade maxima >=
        # 0.1): o advisory so' Log nao e' membro, e' um registro informativo
        # como outro qualquer (contado, nunca listado).
        groups = {}
        for n in self.nvts:
            if n.vendorfix and not n.low and (variant != "client" or self.hit(n)):
                groups.setdefault(n.group, []).append(n)
        self.groups = {g: ms for g, ms in groups.items() if len(ms) >= self.group_min}
        self.absorbed = {n.oid for ms in self.groups.values() for n in ms}
        self.hosts = len(rep.findall("host"))

    @staticmethod
    def hit(n):
        """O NVT e' achado: severidade maxima >= 0.1 (nem Log nem falso positivo)."""
        return isnum(n.maxsev) and n.maxsev >= 0.1

    def shown(self, n):
        """O NVT tem linha e card nesta edicao? Na do cliente, o Log nao tem."""
        return self.variant != "client" or self.hit(n)

    def log_units(self, low):
        """Os registros informativos (Log) de um bloco da edicao do cliente: os
        NVTs do bloco (confirmados ou indicadores) que nenhum card consolidado
        absorveu e que nao sao achado. Fora da edicao do cliente, nenhum."""
        if self.variant != "client":
            return []
        return [n for n in self.nvts
                if n.low == low and n.oid not in self.absorbed and not self.hit(n)]

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
# O link da tabela de prioridades (secao 2) para o card do achado. E' um
# \hyperlink por dentro (suricatoos-blocks.sty), com outro nome no .tex para
# ficar fora da conta exata alvos == links + cortes do gates.sh: o card que ele
# abre ja' tem o link da sua linha no sumario de achados.
PRIO_LINK = re.compile(r"\\priolink\{([^}]*)\}")


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
    for mode, block in tex.blocks(SEC_SUMMARY):
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
    for mode, block in tex.blocks(SEC_DETAIL):
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
    for sec in (SEC_SUMMARY, SEC_DETAIL):
        if sec not in tex.sections:
            fails.append("secao %d ausente" % sec)
            continue
        modes = []
        text, _ = tex.section(sec)
        slabs = len(macros(text, "suriSummaryHead", 1))
        for mode, block in tex.blocks(sec):
            modes.append(mode)
            items = (len(macros(block, "findingrow", 5)) if sec == SEC_SUMMARY else
                     len(macros(block, "findingcard", 4)) + len(macros(block, "consolidatedcard", 7)))
            # Secao de cards sem tarja nenhuma e relatorio sem achado: nao ha
            # bloco anunciado que pudesse ficar vazio.
            if items == 0 and not slabs and not m.nvts:
                continue
            # Na edicao do cliente um bloco pode ter so' a contagem de Log (o
            # Log nao tem linha nem card): a tarja anuncia esses registros.
            if items == 0 and not (mode == "confirmados" and none_conf in block) \
                    and not (m.variant == "client" and "\\findinglog{" in block):
                fails.append("secao %d: tarja '%s' sem nenhuma %s" %
                             (sec, mode, "linha" if sec == SEC_SUMMARY else "card"))
            # Uma tabela de sumario sem linha nenhuma (so' o cabecalho) se le
            # como defeito: o bloco sem linha diz por texto o que nao tem.
            if sec == SEC_SUMMARY and items == 0 and "\\begin{findingsummary}" in block:
                fails.append("secao %d: tabela '%s' sem nenhuma linha" % (sec, mode))
        has_ind = "indicadores" in modes
        if has_ind != (n_low > 0):
            fails.append("secao %d: tarja de indicadores %s, mas o relatorio tem %d NVT(s) de baixa"
                         " confianca" % (sec, "presente" if has_ind else "ausente", n_low))
    return fails


def check_consolidado(m, tex, sheet, lang):
    fails = []
    adv_max = sheet.num("adv-max")
    seen = set()
    for mode, block in tex.blocks(SEC_DETAIL):
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
    for mode, block in tex.blocks(SEC_DETAIL):
        for c in finding_cards(block):
            where[c["anchor"]] = mode
    for n in m.nvts:
        a = fnd(n.oid)
        if n.oid in m.absorbed:
            if a in where:
                fails.append("NVT %s absorvido no grupo '%s' e ainda com card proprio" % (n.oid, n.group))
        elif not m.shown(n):
            # Edicao do cliente: o Log nao tem card, so' a contagem do bloco.
            if a in where:
                fails.append("NVT %s (Log) com card na edicao do cliente" % n.oid)
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

    for mode, block in tex.blocks(SEC_SUMMARY):
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
    for mode, block in tex.blocks(SEC_DETAIL):
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
    for mode, block in tex.blocks(SEC_DETAIL):
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
    k = macros(tex.section(SEC_EXEC)[0], "kpirow", 8)
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
    sec1 = tex.section(SEC_EXEC)[0]
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
    plinks = PRIO_LINK.findall(tex.s)
    targets = ANCHOR_TARGET.findall(tex.s)
    bad = sorted({a for a in links + plinks + targets if not re.fullmatch(r"[A-Za-z0-9-]+", a)})
    if bad:
        fails.append("ancora(s) com caractere fora de [A-Za-z0-9-]: %s" % ", ".join(bad[:5]))
    dangling = sorted(set(links + plinks) - set(targets))
    if dangling:
        fails.append("link(s) sem alvo: %s" % ", ".join(dangling[:5]))
    dup = sorted({a for a in targets if targets.count(a) > 1})
    if dup:
        fails.append("alvo(s) repetido(s): %s" % ", ".join(dup[:5]))
    glinks = [a for a in links if a.startswith("grp-")]
    gtargets = [a for a in targets if a.startswith("grp-")]
    # A edicao executiva nao tem card nenhum: nenhuma ancora de grupo.
    ng = 0 if m.variant == "executive" else len(m.groups)
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
    lede = macros(tex.section(SEC_EXEC)[0], "suriLede", 1)
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
    # Titulo do card do mapa de portas (secao 3): o nome NORMALIZADO, teto de
    # 60 e marca "..." sem contagem (hx-board).
    hexcards = macros(tex.section(SEC_HEXMAP)[0], "hexcard", 3)
    whole = norm_space(raw)
    if hexcards and whole:
        title = plain(hexcards[0][1][0])
        if len(whole) > 60 and title.endswith("..."):
            title = title[:-3]
        places.append(("mapa de portas", 60, whole, title, None))
    for where, budget, name, vis, cut in places:
        fails += cut_fails(where, budget, name, vis, cut)
    return fails


def cut_fails(where, budget, name, vis, cut, what="nome"):
    """O texto visivel `vis' de um campo cortado em `budget' caracteres e' o
    texto inteiro `name' (cabe) ou o seu inicio cortado na ULTIMA fronteira de
    palavra da janela (veja check_nome), com o corte declarado `cut' (None: a
    marca nao traz contagem) batendo com o que sobrou. `what' nomeia o campo
    nas mensagens (o nome do projeto, a acao de uma prioridade...)."""
    k = len(vis)
    if cut is None:
        cut = len(name) - k
    if len(name) <= budget:
        if cut or vis != name:
            return ["%s: %s cabe (%d <= %d) e saiu '%s' (+%d)"
                    % (where, what, len(name), budget, vis[:40], cut)]
        return []
    if not name.startswith(vis) or cut != len(name) - k:
        return ["%s: '%s' (+%d) nao e' o inicio do(a) %s com o corte declarado"
                % (where, vis[:40], cut, what)]
    back = min(budget // 2, 199)
    spaces = [i for i in range(budget - back, budget + 1) if name[i] in WS]
    want = spaces[-1] if spaces else budget
    if k != want:
        return ["%s: corte em %d caracteres ('...%s|%s...'), esperado %d (%s)"
                % (where, k, vis[-12:], name[k:k + 12], want,
                   "fronteira de palavra" if spaces else "sem fronteira na janela")]
    return []


# ---------------------------------------------------------------------------
# Secao 7: escopo, metodologia e limitacoes
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
    """As tres regras de estado do latex.xsl, que a secao 1 e a secao 7 leem:
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
    """O que a secao 7 deveria dizer, recalculado do XML: por bloco, as linhas
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
        # A edicao do cliente nao fala de falso positivo: a letra f sai da
        # lista de niveis (o termo do filtro continua como o gvmd o ecoou).
        if m.variant == "client":
            lv = lv.replace("f", "")
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
        return cut_fails(where, want[2], want[1], plain(got), trunc_count(got), what="valor")
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
    """A secao 7 (escopo, metodologia e limitacoes) diz a verdade sobre o XML,
    linha a linha: cada \\scopefact com o rotulo e o valor que o relatorio
    sustenta -- \\scopena EXATAMENTE quando o dado falta, os textos livres com
    o teto e o corte declarado --, as tabelas de autenticacao e de erros com
    as linhas e as celulas certas, na ordem, ate' o teto $scope-rows-max, e o
    corte declarado ("+ N") so' acima dele, com o N certo; as notas e os itens
    de limitacoes conforme o estado do scan (nunca iniciou, nao terminou,
    inventario do agente) e a versao do feed."""
    fails = []
    if SEC_SCOPE not in tex.sections:
        return ["secao %d ausente" % SEC_SCOPE]
    text, _ = tex.section(SEC_SCOPE)
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
        where = "secao %d / %s" % (SEC_SCOPE, lbl)
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
        fails.append("%d \\scopena na secao %d, esperado %d (um por dado ausente)"
                     % (total_na, SEC_SCOPE, n_na))
    return fails


def check_alerta(m, tex, sheet, lang):
    """O resumo executivo (secao 1) abre com o alerta de "nada medido" se e
    somente se o relatorio nao tem host, e o alerta da' a causa que o dado
    sustenta, pelas MESMAS regras das notas da secao 7: a tarefa que nunca
    iniciou nao recebe o conselho de corrigir um alive test que nao rodou; o
    scan que iniciou e nao terminou recebe o corpo neutro (nao terminou, nenhum
    host registrado), sem diagnostico; so' o scan que terminou sem achar host
    recebe o conselho do alive test."""
    boxes = macros(tex.section(SEC_EXEC)[0], "alertbox", 2)
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


# ---------------------------------------------------------------------------
# Secao 2: prioridades e proximos passos
# ---------------------------------------------------------------------------
# Palavras que, terminadas em ponto, NAO fecham a primeira frase da solucao:
# abreviacoes, comparadas pelo radical (a palavra sem o ponto) em minusculas,
# so' A-Z rebaixado, como o translate do latex.xsl. Item numerado ("1.") e
# palavra de uma letra ("p.") tambem nao fecham, pela regra do radical.
PRIO_ABBREV = ("e.g", "i.e", "p.ex", "p.ej", "ex", "ej", "vs", "cf", "approx", "incl")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
NOSOL = "\\prionosol"    # a acao de um card cuja solucao o relatorio nao traz


def prio_stop(word):
    """A palavra fecha a primeira frase: termina em ponto, e o radical tem mais
    de um caractere, nao e' so' digito (item numerado) e nao e' abreviacao."""
    if not word.endswith("."):
        return False
    stem = word[:-1]
    return (len(stem) > 1 and any(c not in "0123456789" for c in stem)
            and stem.translate(ASCII_LOWER) not in PRIO_ABBREV)


def first_sentence(s):
    """A primeira frase de um texto ja' normalizado (espaco simples): as
    palavras ate' a primeira que fecha frase (prio_stop), inclusive; sem
    nenhuma, o texto inteiro."""
    words = s.split(" ")
    for i, w in enumerate(words):
        if prio_stop(w):
            return " ".join(words[:i + 1])
    return s


def epss_cell(score, lang):
    """O EPSS em porcentagem, como o format-number(x * 100, '0.0##') do
    latex.xsl: 3 casas no maximo, 1 no minimo, virgula decimal em pt/es. O
    arredondamento e' o do libxslt na faixa que o gvmd escreve (score com 5
    casas, %0.5f: x * 100 tem no maximo 3), medido valor a valor de 0.00000 a
    1.00000."""
    n = math.floor(score * 100 * 1000 + 0.5)
    ip, fr = divmod(n, 1000)
    frs = ("%03d" % fr).rstrip("0") or "0"
    return "%d%s%s\\%%" % (ip, "." if bucket(lang) == "en" else ",", frs)


class PrioOracle:
    """O que a secao 2 deveria dizer, recalculado do XML.

    Uma ACAO por card de achado confirmado, como a secao de achados detalhados
    o mostra: o card de um NVT confirmado que nenhum card consolidado absorveu,
    ou o card consolidado de um grupo (Model.groups: VendorFix confirmados com
    as mesmas duas primeiras palavras, >= group-min), que e' UMA acao com as
    instancias de todos os membros. Entra a acao de severidade maxima >= 0.1 --
    sem Log, sem falso positivo; o indicador (todas as instancias abaixo do
    piso de QoD) fica fora do plano e e' contado numa nota. Ordem: classe de
    severidade (decrescente), hosts afetados (distintos -- num grupo, a uniao
    --, entre as instancias com severidade >= 0.1; decrescente), EPSS
    (max_epss/score, o maior entre as mesmas instancias com severidade >= 0.1;
    decrescente, sem EPSS por ultimo), maior CVSS (decrescente), nome (o do
    NVT como no feed,
    normalizado; num grupo, a chave do produto) crescente e OID (o do NVT, ou
    o do representante do grupo, o 1o membro) crescente -- texto comparado
    ponto de codigo a ponto de codigo, como o xsl:sort do libxslt sem @lang.
    A acao de um grupo e' a acao unica do card: a solucao do membro mais
    severo (Model.group_top), nao a do representante. Ate' $prio-rows-max
    linhas; X e Y contam as instancias com severidade >= 7.0 das N primeiras
    acoes e de todas (num grupo, as dos membros)."""

    def __init__(self, m, sheet, lang, bundle, tex):
        self.sheet, self.lang = sheet, lang
        t = self.t
        self.cap = sheet.num("prio-rows-max")
        self.act_max = sheet.num("prio-action-max")
        # O numero que cada card de achado CONFIRMADO tem no .tex (secao 6): o
        # card normal pelo "#N" dele, o consolidado pela ordem (o N da linha do
        # grupo no sumario e do marcador). A numeracao em si e' a regua do
        # check_numeracao; aqui ela so' diz que numero o link tem de mostrar.
        self.cards = {}
        ncons = 0
        for mode, block in tex.blocks(SEC_DETAIL):
            if mode != "confirmados":
                continue
            for c in consolidated_cards(block):
                ncons += 1
                self.cards[c["anchor"]] = str(ncons)
            for c in finding_cards(block):
                self.cards[c["anchor"]] = c["num"]

        def card(kind, insts, sev, name, oid):
            """Os valores de ordem de uma acao, a partir das instancias dela.
            Hosts e EPSS so' das instancias que sao achado (>= 0.1): falso
            positivo e Log nao contam -- num grupo, o advisory so' com falso
            positivo continua membro, mas o EPSS dele nao entra."""
            hits = [r for r in insts if isnum(r.sev) and r.sev >= 0.1]
            scores = [v for v in (xnum(s) for r in hits for s in r.epss) if isnum(v)]
            return {"kind": kind, "sev": sev, "name": name, "oid": oid,
                    "rank": 1 + (sev >= 4.0) + (sev >= 7.0) + (sev >= 9.0),
                    "hosts": len({r.host for r in hits if r.host}),
                    "epss": max(scores) if scores else None,
                    "x": sum(1 for r in insts if isnum(r.sev) and r.sev >= 7.0)}

        acts = []
        # O card de um NVT: o confirmado que nenhum card consolidado absorveu.
        for n in m.nvts:
            if n.low or n.oid in m.absorbed or not (isnum(n.maxsev) and n.maxsev >= 0.1):
                continue
            a = card("nvt", n.inst, n.maxsev, norm_space(n.rep.name), n.oid)
            a["nvt"] = n
            acts.append(a)
        # O card consolidado: UMA acao, com as instancias de todos os membros;
        # nome = a chave do produto, OID = o do representante (o 1o membro, dono
        # da ancora grp-).
        for g, members in m.groups.items():
            sev = m.group_maxsev(g)
            if not (isnum(sev) and sev >= 0.1):
                continue
            a = card("grupo", [r for n in members for r in n.inst], sev, g, members[0].oid)
            a["group"] = g
            acts.append(a)
        acts.sort(key=lambda a: (-a["rank"], -a["hosts"],
                                 (0, -a["epss"]) if a["epss"] is not None else (1, 0),
                                 -a["sev"], a["name"], a["oid"]))
        self.acts = acts
        shown = acts[:self.cap]
        cat = catalog(bundle, lang)

        def solution(r):
            """A solucao que o card imprime para a instancia r: o catalogo do
            idioma, senao nvt/solution, senao a tag solution."""
            tr = cat.get(r.oid)
            orig = r.solution if norm_space(r.solution) else r.tag("solution")
            tr_sol = (tr.findtext("solution") or "") if tr is not None else ""
            return norm_space(tr_sol if norm_space(tr_sol) else orig)

        self.rows = []
        for i, a in enumerate(shown, 1):
            if a["kind"] == "grupo":
                g = a["group"]
                # A acao unica do card consolidado e o CVSS do chip dele: o
                # membro mais severo (o 1o no empate), nao o representante.
                top = m.group_top(g)
                sol = solution(top)
                name = t("grp_title") + ": " + g
                tlabel = t("st_VendorFix")
                cvss = top.sev_raw.strip()
                anchor = "grp-" + m.groups[g][0].oid.replace(".", "-")
            else:
                n = a["nvt"]
                sol = solution(n.rep)
                tr = cat.get(n.oid)
                tr_name = (tr.findtext("name") or "") if tr is not None else ""
                name = tr_name if norm_space(tr_name) else n.rep.name
                stype = n.rep.soltype or ""
                tlabel = ((t("st_" + stype) if "st_" + stype in sheet.i18n else stype)
                          if stype else "---")
                cvss = n.maxsev_raw.strip()
                anchor = fnd(n.oid)
            self.rows.append({
                "num": str(i),
                "kind": a["kind"],
                "action": ("corte", first_sentence(sol), self.act_max) if sol else NOSOL,
                "name": norm_space(name),
                "type": tlabel,
                "hosts": gvm_num(a["hosts"], lang),
                "sev": sev_key_row(a["sev"]),
                "cvss": cvss,
                "epss": epss_cell(a["epss"], lang) if a["epss"] is not None else "---",
                "anchor": anchor})
        N = len(shown)
        X = sum(a["x"] for a in shown)
        Y = sum(a["x"] for a in acts)
        self.N, self.X, self.Y = N, X, Y
        if not acts and m.hosts == 0:
            self.summary = t("prio_sum_nohost")
        elif Y == 0:
            self.summary = t("prio_sum_none")
        elif Y == 1:
            self.summary = t("prio_sum_one")
        elif N == 1:
            self.summary = "%s%d%s%d%s" % (t("prio_sum_1"), X, t("prio_sum_of"), Y,
                                           t("prio_sum_tail"))
        else:
            self.summary = "%s%d%s%d%s%d%s" % (t("prio_sum_n_a"), N, t("prio_sum_n_b"), X,
                                               t("prio_sum_of"), Y, t("prio_sum_tail"))
        self.paras = [t("prio_intro_a") + str(m.floor) + t("prio_intro_b")]
        # A frase da ordem da edicao do cliente nao fala de falso positivo.
        if acts:
            self.paras.append(t("prio_order_client" if m.variant == "client" else "prio_order"))
        # O corte da executiva nao manda o leitor a uma secao de achados
        # detalhados que ela nao tem.
        tail = (t("prio_trunc_exec") if m.variant == "executive"
                else t("prio_trunc_a") + t("sec_detailed") + t("prio_trunc_b"))
        self.trunc = (["\\suriEllip\\ + " + gvm_num(len(acts) - self.cap, lang) + tail]
                      if len(acts) > self.cap else [])
        notes = []
        if not acts and m.hosts > 0:
            notes.append(t("prio_none"))
        epss_any = any(isnum(xnum(s)) for r in m.results for s in r.epss)
        if acts and not epss_any:
            notes.append(t("prio_epss_none"))
        elif acts and any(a["epss"] is None for a in shown):
            notes.append(t("prio_epss_some"))
        nind = sum(1 for n in m.nvts if n.low and isnum(n.maxsev) and n.maxsev >= 0.1)
        if nind:
            notes.append("%s%d%s%d%s" % (t("prio_ind_a"), nind, t("prio_ind_b"), m.floor,
                                         t("prio_ind_c")))
        # Export parcial: a regra unica do latex.xsl ($export-partial), a mesma
        # do aviso do resumo executivo e da secao 7.
        total = len(m.results)
        rcs = norm_space(xp_first_text(m.report.find("result_count")))
        rcn = xnum(rcs)
        if rcs and isnum(rcn) and math.floor(rcn) == rcn and rcn > total:
            notes.append("%s%d%s%d%s" % (t("prio_partial_a"), total, t("prio_partial_b"),
                                         int(rcn), t("prio_partial_c")))
        self.notes = notes

    def t(self, key):
        return self.sheet.t(key, self.lang)


def check_prioridades(m, tex, sheet, lang, bundle):
    """A secao 2 (prioridades e proximos passos) diz a verdade sobre o XML: as
    acoes (uma por card; o consolidado e' uma) na ordem documentada, cada uma
    com a posicao, a acao (primeira frase da solucao, teto e corte declarado;
    \\prionosol so' sem solucao), o nome, o tipo de solucao traduzido, os
    hosts distintos, a severidade, o EPSS e o link para o card do achado com o
    numero que esse card tem; o "+ N" so' acima do teto; a frase calculada; as
    notas (EPSS, indicadores fora do plano, export parcial); e os blocos na
    ordem introducao, frase, tabela, corte, notas.
    Na edicao executiva a tabela nao tem a coluna de card (os cards nao
    existem nela): \\priorowsemcard, oito argumentos, nenhum link; e o corte
    nao cita a secao de achados detalhados."""
    if SEC_PRIO not in tex.sections:
        return ["secao %d ausente" % SEC_PRIO]
    text, _ = tex.section(SEC_PRIO)
    want = PrioOracle(m, sheet, lang, bundle, tex)
    where = "secao %d" % SEC_PRIO
    fails = []
    exe = m.variant == "executive"
    rowmac, nargs, env = (("priorowsemcard", 8, "prioritytablesemcard") if exe
                          else ("priorow", 9, "prioritytable"))
    paras = macros(text, "suriPara", 1)
    if [a[0] for _, a in paras] != want.paras:
        fails.append("%s: introducao %s, esperado %s"
                     % (where, [a[0][:50] for _, a in paras], [x[:50] for x in want.paras]))
    sums = macros(text, "priosummary", 1)
    if [a[0] for _, a in sums] != [want.summary]:
        fails.append("%s: frase %s, esperado '%s' (N=%d, X=%d, Y=%d)"
                     % (where, [a[0] for _, a in sums], want.summary, want.N, want.X, want.Y))
    rows = macros(text, rowmac, nargs)
    if len(rows) != len(want.rows):
        fails.append("%s: %d \\%s, esperado %d (%d acao(oes), teto %d)"
                     % (where, len(rows), rowmac, len(want.rows), len(want.acts), want.cap))
    other = "priorow" if exe else "priorowsemcard"
    if re.search(r"\\%s(?![A-Za-z@])" % other, text):
        fails.append("%s: \\%s na edicao %s" % (where, other, m.variant))
    if ("\\begin{%s}" % env in text) != bool(want.rows):
        fails.append("%s: tabela %s, e o plano tem %d acao(oes)"
                     % (where, "presente" if want.rows == [] else "ausente", len(want.acts)))
    for (_, a), w in zip(rows, want.rows):
        cell = "%s / acao #%s" % (where, w["num"])
        if a[0].strip() != w["num"]:
            fails.append("%s: numerada '%s'" % (cell, a[0].strip()))
        act = a[1].strip()
        if w["action"] == NOSOL:
            if act != NOSOL:
                fails.append("%s: acao '%s', esperado \\prionosol (o card nao traz solucao)"
                             % (cell, flat(act)[:60]))
        elif act == NOSOL:
            fails.append("%s: \\prionosol, e o card traz a solucao '%s'"
                         % (cell, w["action"][1][:60]))
        else:
            fails += cut_fails(cell, w["action"][2], w["action"][1],
                               plain(act), trunc_count(act), what="acao")
        for k, label in ((2, "name"), (3, "type")):
            if flat(a[k]) != norm_space(w[label]):
                fails.append("%s: %s '%s', esperado '%s'"
                             % (cell, "nome" if label == "name" else "tipo de solucao",
                                flat(a[k])[:60], norm_space(w[label])[:60]))
        for k, label, what in ((4, "hosts", "hosts"), (5, "sev", "severidade"),
                               (6, "cvss", "CVSS"), (7, "epss", "EPSS")):
            if a[k].strip() != w[label]:
                fails.append("%s: %s '%s', esperado '%s'" % (cell, what, a[k].strip(), w[label]))
        if exe:
            continue
        links = macros(a[8], "priolink", 2)
        if len(links) != 1:
            fails.append("%s: %d \\priolink na celula do achado, esperado 1" % (cell, len(links)))
            continue
        anchor, label = links[0][1][0].strip(), links[0][1][1].strip()
        num = want.cards.get(w["anchor"])
        if anchor != w["anchor"]:
            fails.append("%s: o link leva a %s, esperado %s" % (cell, anchor, w["anchor"]))
        elif num is None:
            fails.append("%s: o card %s nao existe entre os confirmados da secao %d"
                         % (cell, w["anchor"], SEC_DETAIL))
        elif label != "\\#" + num:
            fails.append("%s: o link mostra '%s', e o card %s e' o #%s" % (cell, label, anchor, num))
    trunc = macros(text, "priotrunc", 1)
    if [a[0] for _, a in trunc] != want.trunc:
        fails.append("%s: corte declarado %s, esperado %s (%d acao(oes), teto %d)"
                     % (where, [a[0] for _, a in trunc], want.trunc, len(want.acts), want.cap))
    notes = macros(text, "blocknote", 1)
    if [a[0] for _, a in notes] != want.notes:
        fails.append("%s: notas %s, esperado %s"
                     % (where, [a[0][:50] for _, a in notes], [x[:50] for x in want.notes]))
    # Os blocos na ordem: introducao, frase, tabela, corte, notas.
    seq = sorted([(p, "p") for p, _ in paras] + [(p, "s") for p, _ in sums]
                 + [(p, "r") for p, _ in rows] + [(p, "t") for p, _ in trunc]
                 + [(p, "n") for p, _ in notes])
    kinds = "".join(k for _, k in seq)
    if not re.fullmatch(r"p+sr*t?n*", kinds):
        fails.append("%s: blocos fora de ordem (%s; esperado introducao, frase, tabela,"
                     " corte, notas)" % (where, kinds))
    # Os links da tabela sao \priolink: um \hyperlink aqui entraria na conta
    # exata alvos == links + cortes do gates.sh, que e' a do sumario de achados.
    if ANCHOR_LINK.search(text):
        fails.append("%s: \\hyperlink na secao; o link da tabela e' \\priolink" % where)
    # Na executiva nenhum link: o card que ele abriria nao existe.
    if exe and PRIO_LINK.search(text):
        fails.append("%s: \\priolink na edicao executiva, que nao tem cards" % where)
    return fails


# ---------------------------------------------------------------------------
# Cards: instancias e sistemas afetados
# ---------------------------------------------------------------------------
def port_max_sev(rs):
    """port-max-sev do latex.xsl: o texto da severidade do 1o resultado na
    ordem numerica decrescente (estavel; sem numero, por ultimo); '' sem
    resultado."""
    if not rs:
        return ""
    return sorted(rs, key=lambda r: (0, -r.sev) if isnum(r.sev) else (1, 0))[0].sev_raw


def check_afetados(m, tex, sheet, lang):
    """Cada card de achado diz quantas instancias o NVT tem (o chip N
    INSTANCIA(S)) e lista, como \\chiphost, os host:porta DISTINTOS delas, em
    ordem de host (o 1o de cada par na ordem do documento), ate' 40, com o resto
    declarado num chip "+N"; o card consolidado, o chip HOST <ip> (um host) ou
    N HOSTS e os hosts, em ordem, das instancias dos membros. Na edicao do
    cliente as instancias sao as do relatorio sem falso positivo: o host que so'
    um falso positivo alcancava nao aparece."""
    fails = []
    inst_lbl = sheet.upper(sheet.t("lbl_instances", lang))
    more = sheet.upper(sheet.t("more_word", lang))
    for mode, block in tex.blocks(SEC_DETAIL):
        for (c, seg), (_, a) in zip(card_segments(block), macros(block, "findingcard", 4)):
            n = m.by_anchor.get(c["anchor"])
            if n is None:
                continue        # a checagem `instancias' ja' reprova o OID desconhecido
            got = [plain(x) for x in (b[0] for _, b in macros(a[3], "chip", 1))
                   if plain(x).endswith(" " + inst_lbl)]
            want = "%d %s" % (len(n.inst), inst_lbl)
            if got != [want]:
                fails.append("card %s: chip de instancias %s, esperado '%s'" % (n.oid, got, want))
            pairs, seen = [], set()
            for r in n.inst:
                if (r.host_raw, r.port_raw) not in seen:
                    seen.add((r.host_raw, r.port_raw))
                    pairs.append((r.host_raw, r.port_raw))
            pairs.sort(key=lambda hp: hp[0])
            want = [h + (":" + p if p else "") for h, p in pairs[:40]]
            if len(pairs) > 40:
                want.append("+%d %s" % (len(pairs) - 40, more))
            got = [plain(b[0]) for _, b in macros(seg, "chiphost", 1)]
            if got != want:
                fails.append("card %s: sistemas afetados %s, esperado %s"
                             % (n.oid, got[:6], want[:6]))
        for _, a in macros(block, "consolidatedcard", 7):
            mt = re.match(r"\\hypertarget\{[^}]*\}\{\}", a[1])
            g = card_group({"title": a[1][mt.end():] if mt else a[1]}, sheet, lang)
            if g not in m.groups:
                continue        # a checagem `consolidado' ja' reprova
            hosts = sorted({r.host_raw for n in m.groups[g] for r in n.inst})
            if len(hosts) == 1:
                want = ["%s %s" % (sheet.t("chip_host", lang), hosts[0])]
            else:
                want = ["%d %s" % (len(hosts), sheet.t("chip_hosts", lang))] + hosts[:40]
                if len(hosts) > 40:
                    want.append("+%d %s" % (len(hosts) - 40, more))
            got = [plain(b[0]) for _, b in macros(a[3], "chip", 1)][1:]
            if got != want:
                fails.append("card consolidado '%s': hosts %s, esperado %s" % (g, got[:6], want[:6]))
    return fails


# ---------------------------------------------------------------------------
# Secao 4: hosts e portas abertas
# ---------------------------------------------------------------------------
def hp_sev_key(s):
    """hp-sev-key do latex.xsl: a chave da maior severidade de uma linha."""
    if s == "":
        return "neutro"
    x = xnum(s)
    if isnum(x):
        if x >= 9.0:
            return "critico"
        if x >= 7.0:
            return "alto"
        if x >= 4.0:
            return "medio"
        if x >= 0.1:
            return "baixo"
        if -1.5 < x < 0:
            return "neutro"
    return "logsev"


def port_number(s):
    """number(substring-before(s, '/')): NaN sem barra ou sem numero."""
    return xnum(s.split("/", 1)[0]) if "/" in s else float("nan")


def check_hosts(m, tex, sheet, lang):
    """A secao 4 diz a verdade sobre o XML, host a host (na ordem do ip, como
    o xsl:sort de hosts-ports): o card com o ip, o hostname e o numero de
    portas reais; as linhas de porta -- o inventario <ports> do host (sem as
    general/*) em ordem numerica, ou, sem inventario, as portas distintas dos
    resultados dele, mais a linha `geral' quando ha achado ou inventario
    general/* --, cada uma com o numero de resultados daquele host e porta, a
    chave da maior severidade (`neutro' sem resultado ou com falso positivo no
    topo, `logsev' para Log) e o CVSS; e a nota que decompoe a linha `geral'
    por classe, com a maior pontuacao. Na edicao do cliente o modelo e' o
    relatorio sem os falso positivo: nenhuma porta que so' eles sustentavam,
    nenhuma contagem com eles, nenhuma classe "falso positivo" na nota."""
    if SEC_HOSTS not in tex.sections:
        return ["secao %d ausente" % SEC_HOSTS]
    text, _ = tex.section(SEC_HOSTS)
    rep = m.report

    def t(k):
        return sheet.t(k, lang)

    results = m.results
    geral = t("hp_general").translate(ASCII_LOWER)
    want_hosts = []
    for h in sorted(rep.findall("host"), key=lambda h: xp_text(h.find("ip"))):
        ip = xp_text(h.find("ip"))
        dets = h.findall("detail")
        hostname = next((xp_text(d.find("value")) for d in detail_named(dets, "hostname")), "")
        os_txt = next((xp_text(d.find("value")) for d in detail_named(dets, "best_os_txt")), "")
        os_cpe = next((xp_text(d.find("value")) for d in detail_named(dets, "best_os_cpe")), "")
        os_name = os_txt or os_cpe
        fromports = [p for p in rep.findall("ports/port")
                     if any(xp_text(x) == ip for x in p.findall("host"))]
        mine = [r for r in results if r.host_raw == ip]
        if fromports:
            ports = [xp_first_text(p) for p in fromports if not xp_first_text(p).startswith("general")]
            realcount = len(ports)
        else:
            ports, seen = [], set()
            for r in mine:
                if not r.port_raw.startswith("general") and r.port_raw not in seen:
                    seen.add(r.port_raw)
                    ports.append(r.port_raw)
            realcount = len(ports)
        ports.sort(key=lambda p: (0, 0) if not isnum(port_number(p)) else (1, port_number(p)))
        genres = [r for r in mine if r.port_raw.startswith("general")]
        hasgen = bool(genres) or any(xp_first_text(p).startswith("general") for p in fromports)
        rows = []
        for p in ports:
            rs = [r for r in mine if r.port_raw == p]
            top = port_max_sev(rs)
            key = hp_sev_key(top)
            rows.append((p, str(len(rs)), key, top if key not in ("logsev", "neutro") else ""))
        if hasgen:
            top = port_max_sev(genres)
            key = hp_sev_key(top)
            rows.append((geral, str(len(genres)), key, top if key not in ("logsev", "neutro") else ""))
        note = None
        if genres:
            cnt = {"c": 0, "h": 0, "m": 0, "l": 0, "f": 0}
            for r in genres:
                if isnum(r.sev):
                    if r.sev >= 9.0:
                        cnt["c"] += 1
                    elif r.sev >= 7.0:
                        cnt["h"] += 1
                    elif r.sev >= 4.0:
                        cnt["m"] += 1
                    elif r.sev >= 0.1:
                        cnt["l"] += 1
                    elif is_fp(r.sev):
                        cnt["f"] += 1
            nlog = len(genres) - sum(cnt.values())
            parts = ["%d %s" % (c, t(k)) for c, k in
                     ((cnt["c"], "sev_critical"), (cnt["h"], "sev_high"), (cnt["m"], "sev_medium"),
                      (cnt["l"], "sev_low"), (nlog, "sev_log"), (cnt["f"], "sev_falsepos")) if c > 0]
            tail = ", ".join(parts)
            top = port_max_sev(genres)
            if isnum(xnum(top)) and xnum(top) >= 0.1:
                tail += " \\textperiodcentered\\ " + t("hx_th_cvss") + " " + top
            if not tail.endswith("."):
                tail += "."
            note = (t("hp_gen_note_a") + str(len(genres)) + " " + t("hx_findings_n")
                    + t("hp_gen_note_b") + "\\dat{" + geral + "}: " + tail)
        want_hosts.append((ip, hostname, os_name, str(realcount), rows, note))

    # O .tex: um trecho por host, aberto pelo marcador dele (bm-host-N).
    marks = [mt.start() for mt in re.finditer(r"\\suriBookmark\{1\}\{bm-host-", text)]
    segs = [text[p:(marks[i + 1] if i + 1 < len(marks) else len(text))] for i, p in enumerate(marks)]
    fails = []
    if len(segs) != len(want_hosts):
        return ["secao %d: %d host(s), esperado %d" % (SEC_HOSTS, len(segs), len(want_hosts))]
    for seg, (ip, hostname, os_name, realcount, rows, note) in zip(segs, want_hosts):
        cards = macros(seg, "hostcard", 5)
        if not cards:
            fails.append("host %s: sem \\hostcard" % ip)
            continue
        a = cards[0][1]
        # O selo de SO: o do host, cortado em 37 + "..." acima de 40, ou a
        # forma curta de "nao identificado".
        os_chip = (sheet.t("hp_os_unknown_chip", lang) if not os_name
                   else os_name[:37] + "..." if len(os_name) > 40 else os_name)
        if (plain(a[0]), plain(a[1]), plain(a[2]), a[3].strip()) != (ip, hostname, os_chip, realcount):
            fails.append("host %s: card %s/%s/%s/%s, esperado %s/%s/%s/%s portas"
                         % (ip, plain(a[0]), plain(a[1]), plain(a[2]), a[3].strip(),
                            ip, hostname, os_chip, realcount))
        got = [(plain(b[0]), b[1].strip(), b[2].strip(), b[3].strip())
               for _, c in cards for _, b in macros(c[4], "hostrow", 4)]
        if got != rows:
            diff = next((i for i, (x, y) in enumerate(zip(got, rows)) if x != y), min(len(got), len(rows)))
            fails.append("host %s: %d linha(s), esperado %d; 1a diferenca na #%d: %s x %s"
                         % (ip, len(got), len(rows), diff + 1,
                            got[diff] if diff < len(got) else None, rows[diff] if diff < len(rows) else None))
        if not rows and not any(b[0].strip() == t("hp_no_ports") for _, b in macros(a[4], "blocknote", 1)):
            fails.append("host %s: card sem porta e sem a nota de host sem porta" % ip)
        notes = [b[0].strip() for _, b in macros(seg, "blocknote", 1)
                 if b[0].startswith(t("hp_gen_note_a"))]
        if notes != ([note] if note else []):
            fails.append("host %s: nota da linha geral %s, esperado %s"
                         % (ip, [x[-70:] for x in notes], [note[-70:]] if note else []))
    return fails


# ---------------------------------------------------------------------------
# Edicoes
# ---------------------------------------------------------------------------
def log_line(n, sheet, lang):
    """A contagem de Log de um bloco da edicao do cliente (\\findinglog)."""
    return ("\\suriEllip\\ + " + gvm_num(n, lang)
            + sheet.t("client_log_1" if n == 1 else "client_log_n", lang))


def port_key(s):
    """(numero, transporte) de uma porta "443/tcp", como a chave do mapa de
    portas (transporte em minuscula); None para general/* e porta malformada."""
    num, _, proto = norm_space(s).partition("/")
    return (num, proto.translate(ASCII_LOWER)) if num.isdigit() and proto else None


def port_observations(rep):
    """As portas que o mapa de portas observa (o inventario <ports> e a porta de
    cada resultado): (conjunto global, {ip: conjunto do host})."""
    glob, per = set(), {}
    for p in rep.findall("ports/port"):
        k = port_key(xp_first_text(p))
        if k:
            glob.add(k)
            per.setdefault(norm_space(xp_text(p.find("host"))).split(" ")[0], set()).add(k)
    for r in rep.findall("results/result"):
        k = port_key(xp_text(r.find("port")))
        if k:
            glob.add(k)
            per.setdefault(norm_space(xp_first_text(r.find("host"))).split(" ")[0], set()).add(k)
    return glob, per


def check_cliente(m, tex, sheet, lang):
    """A edicao do cliente nao tem falso positivo em lugar nenhum e so' tem o
    Log como contagem:
      - nenhuma palavra de falso positivo do relatorio (sev_falsepos,
        lvl_falsepos, nas tres linguas) e nenhuma linha, card, advisory ou chip
        com a chave de Log ou de falso positivo;
      - em cada bloco das secoes 5 e 6 (confirmados, indicadores), a contagem
        de Log (\\findinglog) diz quantos registros informativos o bloco tem no
        XML -- os NVTs que nenhum card consolidado absorveu e que nao sao achado
        --, fecha o bloco, e nao aparece em nenhum outro lugar;
      - o NVT so' com falso positivo nao deixa ancora, link nem marcador;
      - a porta que so' falso positivo sustentava nao aparece no mapa de portas
        (celula e tabela da secao 3) nem no tabuleiro do host no apendice.
    As contagens (total do scan, linhas da secao 4, instancias e hosts dos
    cards, plano da secao 2) sao conferidas pelas outras checagens sobre o
    MESMO modelo sem falso positivo."""
    fails = []
    s = tex.s
    for k in ("sev_falsepos", "lvl_falsepos"):
        for b in ("en", "pt", "es"):
            w = sheet.i18n[k][0].get(b)
            if w and w in s:
                fails.append("a palavra '%s' (%s) no documento" % (w, k))
    for mac, nargs, idx in (("findingrow", 5, 3), ("findingcard", 4, 0),
                            ("consolidatedcard", 7, 0), ("advisoryrow", 3, 1), ("chipsev", 2, 0)):
        bad = ("logsev", "neutro") if mac == "findingrow" else ("logsev", "falsepos")
        for _, a in macros(s, mac, nargs):
            if a[idx].strip() in bad:
                fails.append("\\%s com a chave '%s' (Log ou falso positivo)" % (mac, a[idx].strip()))
    total = 0
    for sec in (SEC_SUMMARY, SEC_DETAIL):
        for mode, block in tex.blocks(sec):
            units = m.log_units(mode == "indicadores")
            want = [log_line(len(units), sheet, lang)] if units else []
            got = macros(block, "findinglog", 1)
            if [a[0].strip() for _, a in got] != want:
                fails.append("secao %d / %s: contagem de Log %s, esperado %s (%s)"
                             % (sec, mode, [a[0][:60] for _, a in got], want,
                                ", ".join(n.oid.rsplit(".", 1)[-1] for n in units) or "nenhum"))
            total += len(want)
            if got and re.search(r"\\(findingrow|findingcard|consolidatedcard)(?![A-Za-z@])",
                                 block[got[-1][0]:]):
                fails.append("secao %d / %s: linha ou card depois da contagem de Log" % (sec, mode))
    if len(macros(s, "findinglog", 1)) != total:
        fails.append("%d \\findinglog no documento, esperado %d (um por bloco com Log)"
                     % (len(macros(s, "findinglog", 1)), total))
    tech = Model(m.path, sheet)
    for n in tech.nvts:
        if all(is_fp(r.sev) for r in n.inst) and re.search(r"\{(?:bm-)?%s\}" % re.escape(fnd(n.oid)), s):
            fails.append("NVT %s, so' com falso positivo, deixa ancora ou marcador" % n.oid)
    tg, tp = port_observations(tech.report)
    cg, cp = port_observations(m.report)
    hexmap, _ = tex.section(SEC_HEXMAP)
    for num, proto in sorted(tg - cg):
        if any(plain(a[0]).strip() == num and plain(a[2]).strip() == proto
               for _, a in macros(hexmap, "portrow", 8)):
            fails.append("secao %d: linha da porta %s/%s, que so' falso positivo sustentava"
                         % (SEC_HEXMAP, num, proto))
        if any(plain(a[1]).strip() == "%s/%s" % (num, proto.upper()) for _, a in macros(hexmap, "hexport", 4)):
            fails.append("secao %d: celula da porta %s/%s, que so' falso positivo sustentava"
                         % (SEC_HEXMAP, num, proto))
    appendix, _ = tex.section(SEC_APPENDIX)
    for _, a in macros(appendix, "hexcard", 3):
        ip = plain(a[0]).strip()
        for num, proto in sorted(tp.get(ip, set()) - cp.get(ip, set())):
            if any(plain(b[1]).strip() == "%s/%s" % (num, proto.upper()) for _, b in macros(a[2], "hexport", 4)):
                fails.append("secao %d / %s: celula da porta %s/%s, que so' falso positivo sustentava"
                             % (SEC_APPENDIX, ip, num, proto))
    return fails


def check_executiva(m, tex, sheet, lang):
    """A edicao executiva tem SO' o resumo executivo, as prioridades e o escopo,
    numerados 1..3 com os mesmos titulos; nenhum card, host, porta, sumario de
    achados, marcador de nivel 1, ancora que nao seja de secao, link de
    prioridade, nem mencao a uma secao que ela nao tem (os titulos do mapa de
    portas, de hosts e portas, do sumario de achados, dos achados detalhados,
    do apendice e do bloco de indicadores)."""
    fails = []
    s = tex.s

    def t(k):
        return sheet.t(k, lang)

    secs = [(a[0].strip(), plain(a[1])) for _, a in macros(s, "suriSection", 2)]
    want = [("1", t("sec_exec")), ("2", t("sec_prio")), ("3", t("sec_scope"))]
    if secs != want:
        fails.append("secoes %s, esperado %s" % (secs, want))
    for mac in ("findingrow", "findingcard", "consolidatedcard", "advisoryrow", "hostcard",
                "hostrow", "hexcard", "hexport", "portrow", "findingtrunc", "findinglog",
                "suriBookmark", "suriSummaryHead", "priorow", "priolink"):
        n = len(re.findall(r"\\%s(?![A-Za-z@])" % mac, s))
        if n:
            fails.append("%d \\%s na edicao executiva" % (n, mac))
    extra = sorted(set(ANCHOR_LINK.findall(s) + ANCHOR_TARGET.findall(s)) - {"sec-1", "sec-2", "sec-3"})
    if extra:
        fails.append("ancora(s) fora das secoes: %s" % ", ".join(extra[:5]))
    for k in ("sec_hexmap", "sec_hosts_ports", "sec_findings_summary", "sec_detailed",
              "sec_hexmap_host", "sub_indicators"):
        if t(k) in s:
            fails.append("cita '%s', que a edicao executiva nao tem" % t(k))
    return fails


def check_edicao(m, tex, sheet, lang):
    """A capa diz a edicao (o kicker: o de sempre no tecnico, o da edicao do
    cliente e o da executiva) e a contagem de Log (\\findinglog) so' existe na
    edicao do cliente."""
    key = {"technical": "cover_kicker", "client": "kicker_client",
           "executive": "kicker_executive"}[m.variant]
    cov = macros(tex.s, "suriCover", 1)
    if not cov:
        return ["sem \\suriCover"]
    body = cov[0][1][0]
    k = body.find("kicker=")
    try:
        val = plain(group_at(body, skip_blank(body, k + len("kicker=")))[0]) if k >= 0 else None
    except TexError:
        val = None
    fails = []
    if val != sheet.t(key, lang):
        fails.append("kicker da capa %r, esperado %r (edicao %s)" % (val, sheet.t(key, lang), m.variant))
    if m.variant != "client" and "\\findinglog{" in tex.s:
        fails.append("\\findinglog (contagem de Log da edicao do cliente) na edicao %s" % m.variant)
    return fails


CHECKS = [
    ("numeracao", check_numeracao), ("secoes", check_secoes),
    ("consolidado", check_consolidado), ("instancias", check_instancias),
    ("afetados", check_afetados),
    ("acao", None), ("vulns-unicas", check_vulns_unicas), ("faixas", check_faixas),
    ("ancoras", check_ancoras), ("nome", check_nome), ("prioridades", None),
    ("hosts", check_hosts), ("escopo", check_escopo), ("alerta", check_alerta),
    ("edicao", check_edicao), ("cliente", check_cliente), ("executiva", check_executiva),
]
# As checagens de cada edicao. A executiva so' tem as secoes 1 (resumo), 2
# (prioridades) e 3 (escopo): as checagens das outras secoes nao rodam nela, e
# a `executiva' confere que elas nao existem.
BY_VARIANT = {
    "technical": [n for n, _ in CHECKS if n not in ("cliente", "executiva")],
    "client": [n for n, _ in CHECKS if n != "executiva"],
    "executive": ["vulns-unicas", "faixas", "ancoras", "nome", "prioridades", "escopo",
                  "alerta", "edicao", "executiva"],
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", required=True)
    ap.add_argument("--xml", required=True)
    ap.add_argument("--tex", required=True)
    ap.add_argument("--variant", default="technical", choices=VARIANTS)
    ap.add_argument("--bundle", default=os.path.join(os.path.dirname(HERE), "suricatoos-premium-pdf"))
    ap.add_argument("--only", action="append", default=[])
    args = ap.parse_args()
    use_variant(args.variant)
    try:
        sheet = Stylesheet(os.path.join(args.bundle, "latex.xsl"))
        model = Model(args.xml, sheet, args.variant)
        tex = Tex(args.tex)
    except (OSError, ET.ParseError, TexError, StylesheetError) as e:
        print("check-veracity: ERRO de leitura: %s" % e)
        return 2
    failed = 0
    for name, fn in CHECKS:
        if name not in BY_VARIANT[args.variant]:
            continue
        if args.only and name not in args.only:
            continue
        try:
            if name == "acao":
                fails = check_acao(model, tex, sheet, args.lang, args.bundle)
            elif name == "prioridades":
                fails = check_prioridades(model, tex, sheet, args.lang, args.bundle)
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
