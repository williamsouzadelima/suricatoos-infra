#!/usr/bin/env python3
"""Checagens de NAVEGACAO do Suricatoos Premium PDF: o sumario e a arvore de
marcadores.

O check-veracity.py prova que o .tex diz a verdade sobre o XML; o gates.sh
prova que o documento compila. Isto prova que o leitor CONSEGUE ANDAR pelo
documento -- e que cada atalho leva aonde diz:

  sumario        a pagina "Sumario/Contents/Indice" existe, entre o resumo
                 executivo e a secao 2, com as seis secoes em ordem; cada linha
                 e' \\hyperlink{sec-N} com o MESMO titulo do \\suriSection{N}, e
                 cada \\hypertarget{sec-N}{} abre a sua secao (vem colado antes
                 do \\suriSection{N});
  marcadores     cada \\suriBookmark do .tex vem colado antes da caixa que o
                 emite; a secao 3 tem um por host do XML e a 5 um por card, com
                 o MESMO numero e o MESMO titulo que o card mostra (cortado em
                 fronteira de palavra no teto $bookmark-max); as tarjas da
                 secao 5 entram so' quando o documento as mostra;
  hyperref       o preambulo carrega o hyperref com bookmarksopen/
                 bookmarksopenlevel=0 (so' o nivel 0 aberto) como opcao de CARGA;

e, com --pdf (o PDF que o generate entregou), sobre o documento compilado:

  pdf-arvore     o PDF TEM arvore de marcadores: seis itens de nivel 0
                 "N  Titulo", os filhos de cada um sao os marcadores do .tex
                 daquela secao, na ordem, com o mesmo texto; nada abaixo do
                 nivel 1; secao com filhos fechada (Count < 0);
  pdf-destinos   todo marcador aponta para um destino que EXISTE no PDF, os
                 filhos caem dentro da secao do pai e em ordem de pagina, e o
                 marcador de cada secao cai na mesma pagina que o \\hypertarget
                 do sumario (sec-N);
  pdf-paginas    (com --aux) a pagina que o sumario IMPRIME para cada secao (o
                 rotulo suri-sec-N do .aux da compilacao) e' a pagina em que o
                 marcador da secao cai;
  pdf-texto      o que as paginas MOSTRAM, pelo pdftotext do poppler: o
                 marcador de cada secao cai na pagina que abre com "N Titulo";
                 o sumario (a folha antes da secao 2) imprime, linha a linha, a
                 pagina em que cai o marcador de cada secao; e cada marcador de
                 card cai numa pagina com o "#N" DELE, cada um de host numa com
                 o IP dele, cada tarja numa que a mostra -- um marcador uma
                 pagina adiantado, ainda dentro da secao e em ordem, reprova.
                 Sem pdftotext (ou se ele falhar) a checagem REPROVA.

O PDF e' lido aqui mesmo, so' com a biblioteca padrao (zlib): objetos soltos e
object streams (o pdfTeX comprime quase tudo nelas), arvore de paginas, arvore
de nomes (/Dests) e /Outlines. O texto das paginas vem do pdftotext
(poppler-utils, que o runner ja' instala para pdfinfo/pdffonts/pdftoppm).

Os textos (titulos das secoes, das tarjas e do sumario) e o teto
$bookmark-max sao LIDOS do proprio latex.xsl, como no check-veracity.py.

Uso:
    check-navigation.py --lang <en|pt_BR|es> --xml <fixture.xml> --tex <report.tex>
                        [--pdf <generate.pdf>] [--aux <report.aux>]
                        [--pdftotext <pdftotext>]
                        [--bundle <suricatoos-premium-pdf/>] [--only <checagem>...]

Sai 0 se tudo passa, 1 se alguma checagem reprova, 2 em erro de uso/leitura.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET
import zlib

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))


def load_veracity():
    """Reusa os leitores do check-veracity.py (macros, group_at, plain, Tex,
    Stylesheet): a regra de ler o .tex e o latex.xsl e' uma so'."""
    spec = importlib.util.spec_from_file_location(
        "check_veracity", os.path.join(HERE, "check-veracity.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = load_veracity()
macros, group_at, skip_blank, plain = V.macros, V.group_at, V.skip_blank, V.plain
norm_space, TexError, StylesheetError = V.norm_space, V.TexError, V.StylesheetError

# As seis secoes do documento e a chave de i18n do titulo de cada uma: e' o
# CONTRATO do relatorio (real-report no latex.xsl), escrito aqui de proposito em
# vez de lido da tabela $sections -- uma tabela errada la' nao pode aprovar a
# si mesma.
SECTIONS = [(1, "sec_exec"), (2, "sec_hexmap"), (3, "sec_hosts_ports"),
            (4, "sec_findings_summary"), (5, "sec_detailed"), (6, "sec_hexmap_host")]
BOXES = ("hostcard", "findingcard", "consolidatedcard", "suriSummaryHead")


def nfc(s):
    return unicodedata.normalize("NFC", s)


def bm_plain(t):
    """O texto que o hyperref poe no painel, a partir do LaTeX do marcador: o
    \\space vale um espaco (o espaco digitado logo depois dele o TeX come), a
    reticencia e' U+2026, e o resto e' o escape_text desfeito (plain)."""
    t = re.sub(r"\\space(?![A-Za-z]) ?", " ", t)
    t = re.sub(r"\\textellipsis(?![A-Za-z])(?:\{\})?", "\u2026", t)
    return plain(t)


def expect_text(head, text, budget):
    """O texto que bookmark-text (latex.xsl) escreve: cabeca e texto, cada um
    normalizado, separados por DOIS espacos; o conjunto, acima do teto, cortado
    na ULTIMA fronteira de palavra (um espaco no indice 0-based i quer dizer que
    os i primeiros caracteres sao palavras inteiras), recuando no maximo metade
    do teto -- sem fronteira na janela, corta no teto --, sem espaco sobrando
    antes da reticencia (U+2026)."""
    head, text = norm_space(head), norm_space(text)
    s = head + "  " + text if head and text else head or text
    if len(s) <= budget:
        return s
    back = min(budget // 2, 199)
    spaces = [i for i in range(budget - back, budget + 1) if s[i] == " "]
    return s[:spaces[-1] if spaces else budget].rstrip(" ") + "\u2026"


def macro_at(s, k, name, nargs):
    """Os nargs argumentos do \\name que comeca EXATAMENTE em s[k] (sem varrer
    o resto do documento, que numa tortura e' quase 1 MB por chamada)."""
    head = "\\" + name
    if not s.startswith(head, k) or re.match(r"[A-Za-z@]", s[k + len(head):k + len(head) + 1]):
        raise TexError("esperava \\%s na posicao %d" % (name, k))
    i, args = k + len(head), []
    for _ in range(nargs):
        i = skip_blank(s, i)
        a, i = group_at(s, i)
        args.append(a)
    return args


# ---------------------------------------------------------------------------
# O .tex
# ---------------------------------------------------------------------------
class Nav:
    """O que o .tex declara de navegacao, na ordem do documento."""

    def __init__(self, s):
        self.s = s
        self.secs = [(p, a) for p, a in macros(s, "suriSection", 2)]
        self.bookmarks = []   # (pos, nivel, nome, texto, macro seguinte, pos dela)
        for p, a in macros(s, "suriBookmark", 3):
            end = p + len("\\suriBookmark")
            for x in a:
                end = skip_blank(s, end)
                _, end = group_at(s, end)
            k = skip_blank(s, end)
            m = re.match(r"\\([A-Za-z@]+)", s[k:])
            self.bookmarks.append((p, a[0].strip(), a[1].strip(), a[2],
                                   m.group(1) if m else None, k))

    def section_of(self, pos):
        n = None
        for p, a in self.secs:
            if p <= pos:
                n = a[0].strip()
        return n


def check_sumario(m, tex, nav, sheet, lang):
    fails = []
    s = tex.s
    nums = [a[0].strip() for _, a in nav.secs]
    if nums != [str(n) for n, _ in SECTIONS]:
        return ["\\suriSection na ordem %s, esperado 1..6" % " ".join(nums)]
    want_title = {n: sheet.t(k, lang) for n, k in SECTIONS}
    for p, a in nav.secs:
        n = int(a[0])
        if plain(a[1]) != want_title[n]:
            fails.append("\\suriSection{%d} com titulo '%s', esperado '%s'"
                         % (n, plain(a[1]), want_title[n]))
    # O alvo de cada secao: um so', colado antes do \suriSection dela.
    for p, a in nav.secs:
        n = int(a[0])
        tgts = [mt.start() for mt in re.finditer(r"\\hypertarget\{sec-%d\}\{\}" % n, s)]
        if len(tgts) != 1:
            fails.append("\\hypertarget{sec-%d}{} aparece %d vez(es), esperado 1" % (n, len(tgts)))
            continue
        k = skip_blank(s, tgts[0] + len("\\hypertarget{sec-%d}{}" % n))
        if k != p:
            fails.append("\\hypertarget{sec-%d}{} nao abre a secao %d (nao vem colado antes"
                         " do \\suriSection{%d})" % (n, n, n))
    heads = macros(s, "suriContents", 1)
    if len(heads) != 1:
        return fails + ["%d \\suriContents, esperado 1" % len(heads)]
    hp, ha = heads[0]
    if plain(ha[0]) != sheet.t("toc_title", lang):
        fails.append("titulo do sumario '%s', esperado '%s'" % (plain(ha[0]), sheet.t("toc_title", lang)))
    p1, p2 = nav.secs[0][0], nav.secs[1][0]
    if not (p1 < hp < p2):
        fails.append("o sumario nao esta entre o resumo executivo (secao 1) e a secao 2")
    b = s.find("\\begin{suritoc}", hp)
    e = s.find("\\end{suritoc}", hp)
    if b < 0 or e < b or e > p2:
        return fails + ["sem o ambiente suritoc logo depois do \\suriContents"]
    rows = macros(s[b:e], "suritocrow", 1)
    got = []
    for _, a in rows:
        mt = re.match(r"\\hyperlink\{(sec-(\d+))\}", a[0].strip())
        if not mt:
            fails.append("linha do sumario sem \\hyperlink{sec-N}: %s" % a[0][:60])
            continue
        try:
            inner, _ = group_at(a[0].strip(), mt.end())
        except TexError as ex:
            fails.append("linha do sumario ilegivel (%s)" % ex)
            continue
        line = macros(inner, "suritocline", 2)
        if len(line) != 1:
            fails.append("o link sec-%s nao embrulha um \\suritocline" % mt.group(2))
            continue
        n, title = line[0][1][0].strip(), plain(line[0][1][1])
        if n != mt.group(2):
            fails.append("linha do sumario: link sec-%s com numero %s" % (mt.group(2), n))
        got.append((int(mt.group(2)), title))
    want = [(n, want_title[n]) for n, _ in SECTIONS]
    if got != want:
        fails.append("o sumario lista %s, esperado %s"
                     % (["%d %s" % x for x in got], ["%d %s" % x for x in want]))
    return fails


def card_title(arg):
    """O titulo que o \\findingcard mostra (o nome traduzido), sem o original."""
    k = arg.find("\\findingorig")
    return plain(arg[:k] if k >= 0 else arg)


def check_marcadores(m, tex, nav, sheet, lang):
    fails = []
    s = tex.s
    budget = sheet.num("bookmark-max")
    names = [b[2] for b in nav.bookmarks]
    dup = sorted({x for x in names if names.count(x) > 1})
    if dup:
        fails.append("nome de marcador repetido: %s" % ", ".join(dup[:5]))
    for pos, lvl, name, text, nxt, _ in nav.bookmarks:
        if lvl != "1":
            fails.append("\\suriBookmark %s com nivel %s (nivel 0 e' do \\suriSection)" % (name, lvl))
        if not re.fullmatch(r"bm-[A-Za-z0-9-]+", name):
            fails.append("nome de marcador fora de bm-[A-Za-z0-9-]: %s" % name)
        if nxt not in BOXES:
            fails.append("\\suriBookmark %s nao vem colado antes de uma caixa que o emita"
                         " (vem \\%s)" % (name, nxt))
        sec = nav.section_of(pos)
        if sec not in ("3", "5"):
            fails.append("\\suriBookmark %s na secao %s (so' 3 e 5 tem nivel 1)" % (name, sec))
    by_sec = {"3": [], "5": []}
    for b in nav.bookmarks:
        sec = nav.section_of(b[0])
        if sec in by_sec:
            by_sec[sec].append(b)

    # Secao 3: um marcador por host do XML, com o IP e o hostname do card.
    hosts = m.report.findall("host")
    bms = by_sec["3"]
    if len(bms) != len(hosts):
        fails.append("secao 3: %d marcador(es) de host, o XML tem %d host(s)" % (len(bms), len(hosts)))
    seen_ips = []
    for pos, lvl, name, text, nxt, k in bms:
        if nxt != "hostcard":
            continue
        a = macro_at(s, k, "hostcard", 2)
        ip, hn = norm_space(plain(a[0])), norm_space(plain(a[1]))
        seen_ips.append(ip)
        want = expect_text(ip, hn, budget) if (ip or hn) else None
        got = nfc(bm_plain(text))
        if want is not None and got != nfc(want):
            fails.append("%s: '%s', o card mostra '%s'" % (name, got[:70], want[:70]))
    want_ips = sorted(norm_space(h.findtext("ip") or "") for h in hosts)
    if sorted(seen_ips) != want_ips:
        fails.append("secao 3: hosts com marcador %s, esperado %s" % (sorted(seen_ips)[:6], want_ips[:6]))

    # Secao 5: um marcador por card, o numero e o titulo do card; as tarjas
    # entram exatamente quando o documento as mostra.
    sec5, _ = tex.section(5)
    off = tex.sections[5][0]
    n_low = sum(1 for n in m.nvts if n.low)
    slabs = [b for b in by_sec["5"] if b[4] == "suriSummaryHead"]
    want_slabs = ([("confirmados", sheet.t("sub_confirmed", lang)),
                   ("indicadores", sheet.t("sub_indicators", lang))] if n_low else [])
    got_slabs = []
    for pos, lvl, name, text, nxt, k in slabs:
        mode = macro_at(s, k, "suriSummaryHead", 1)[0].strip()
        got_slabs.append((mode, nfc(bm_plain(text))))
    if got_slabs != [(a, nfc(b)) for a, b in want_slabs]:
        fails.append("secao 5: tarjas no painel %s, esperado %s" % (got_slabs, want_slabs))
    cards = sorted([(p + off, "findingcard", a) for p, a in macros(sec5, "findingcard", 4)] +
                   [(p + off, "consolidatedcard", a) for p, a in macros(sec5, "consolidatedcard", 7)])
    cbms = [b for b in by_sec["5"] if b[4] in ("findingcard", "consolidatedcard")]
    if len(cbms) != len(cards):
        fails.append("secao 5: %d marcador(es) de card, %d card(s)" % (len(cbms), len(cards)))
    at = {b[5]: b for b in cbms}
    ncons = 0
    for p, kind, a in cards:
        b = at.get(p)
        if kind == "consolidatedcard":
            ncons += 1
            num = str(ncons)
            mt = re.match(r"\\hypertarget\{[^}]*\}\{\}", a[1])
            title = plain(a[1][mt.end():] if mt else a[1])
        else:
            mt = re.match(r"\\hypertarget\{([^}]*)\}\{\}\\#(\d+)$", a[1].strip())
            num = mt.group(2) if mt else "?"
            title = card_title(a[2])
        if b is None:
            fails.append("card #%s ('%s') sem marcador" % (num, norm_space(title)[:50]))
            continue
        want = nfc(expect_text("#" + num, title, budget))
        got = nfc(bm_plain(b[3]))
        if got != want:
            fails.append("marcador %s: '%s', o card mostra '%s'" % (b[2], got[:70], want[:70]))
    return fails


def check_hyperref(m, tex, nav, sheet, lang):
    whole = tex.whole
    mt = re.search(r"\\usepackage\[([^\]]*)\]\{hyperref\}", whole)
    if not mt:
        return ["o preambulo nao carrega o hyperref com opcoes"]
    opts = {o.strip() for o in mt.group(1).split(",")}
    want = {"bookmarksopen=true", "bookmarksopenlevel=0"}
    if not want <= opts:
        return ["hyperref carregado com [%s]; falta %s" % (mt.group(1), ", ".join(sorted(want - opts)))]
    return []


# ---------------------------------------------------------------------------
# O PDF, so' com a biblioteca padrao
# ---------------------------------------------------------------------------
class PdfError(Exception):
    pass


class Ref:
    __slots__ = ("num",)

    def __init__(self, num):
        self.num = num

    def __repr__(self):
        return "%d 0 R" % self.num


class Name(str):
    pass


WSP = frozenset(b" \t\r\n\f\x00")
DELIMS = frozenset(b"()<>[]{}/%")
NUMCH = frozenset(b"0123456789+-.")
ESC = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b",
       ord("f"): b"\f", ord("("): b"(", ord(")"): b")", ord("\\"): b"\\"}


class Lexer:
    def __init__(self, data, pos=0):
        self.d = data
        self.i = pos

    def skip(self):
        d, i, n = self.d, self.i, len(self.d)
        while i < n:
            c = d[i]
            if c in WSP:
                i += 1
            elif c == 0x25:  # % comentario
                while i < n and d[i] not in (0x0A, 0x0D):
                    i += 1
            else:
                break
        self.i = i

    def token(self):
        """Proxima palavra (numero ou palavra-chave), sem consumir delimitador."""
        self.skip()
        d, i, n = self.d, self.i, len(self.d)
        j = i
        while j < n and d[j] not in WSP and d[j] not in DELIMS:
            j += 1
        return d[i:j], j

    def value(self):
        self.skip()
        d = self.d
        if self.i >= len(d):
            raise PdfError("fim inesperado do PDF")
        c = d[self.i]
        if c == 0x2F:  # /nome
            j = self.i + 1
            while j < len(d) and d[j] not in WSP and d[j] not in DELIMS:
                j += 1
            raw = d[self.i + 1:j]
            self.i = j
            return Name(re.sub(rb"#([0-9A-Fa-f]{2})", lambda x: bytes([int(x.group(1), 16)]),
                               raw).decode("latin-1"))
        if c == 0x28:
            return self.literal()
        if c == 0x3C:
            if d[self.i + 1:self.i + 2] == b"<":
                self.i += 2
                out = {}
                while True:
                    self.skip()
                    if d[self.i:self.i + 2] == b">>":
                        self.i += 2
                        return out
                    k = self.value()
                    if not isinstance(k, Name):
                        raise PdfError("chave de dicionario nao e' nome na posicao %d" % self.i)
                    out[str(k)] = self.value()
            j = d.index(b">", self.i)
            hexs = re.sub(rb"\s", b"", d[self.i + 1:j])
            if len(hexs) % 2:
                hexs += b"0"
            self.i = j + 1
            return bytes.fromhex(hexs.decode("ascii"))
        if c == 0x5B:
            self.i += 1
            out = []
            while True:
                self.skip()
                if d[self.i:self.i + 1] == b"]":
                    self.i += 1
                    return out
                out.append(self.value())
        if c in NUMCH:
            tok, j = self.token()
            self.i = j
            try:
                num = int(tok)
            except ValueError:
                return float(tok)
            # "N G R" e' referencia; senao, so' o numero.
            save = self.i
            t2, j2 = self.token()
            if t2.isdigit():
                self.i = j2
                t3, j3 = self.token()
                if t3 == b"R":
                    self.i = j3
                    return Ref(num)
            self.i = save
            return num
        tok, j = self.token()
        if not tok:
            raise PdfError("caractere inesperado %r na posicao %d" % (bytes([c]), self.i))
        self.i = j
        return {b"true": True, b"false": False, b"null": None}.get(tok, tok)

    def literal(self):
        d = self.d
        i = self.i + 1
        depth = 1
        out = bytearray()
        while i < len(d):
            c = d[i]
            if c == 0x5C:
                i += 1
                e = d[i]
                if e in ESC:
                    out += ESC[e]
                    i += 1
                elif 0x30 <= e <= 0x37:
                    j = i
                    while j < i + 3 and j < len(d) and 0x30 <= d[j] <= 0x37:
                        j += 1
                    out.append(int(d[i:j], 8) & 0xFF)
                    i = j
                elif e == 0x0D:
                    i += 2 if d[i + 1:i + 2] == b"\n" else 1
                elif e == 0x0A:
                    i += 1
                else:
                    out.append(e)
                    i += 1
                continue
            if c == 0x28:
                depth += 1
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    self.i = i + 1
                    return bytes(out)
            if c == 0x0D:
                out += b"\n"
                i += 2 if d[i + 1:i + 2] == b"\n" else 1
                continue
            out.append(c)
            i += 1
        raise PdfError("string literal sem fim")


class Pdf:
    """Os objetos do PDF: os soltos (N G obj ... endobj) e os de object stream.
    Sem confiar na tabela xref: varre o arquivo em ordem, pulando o miolo de
    cada stream pelo /Length (o pdfTeX escreve direto). Objeto definido duas
    vezes (atualizacao incremental) vale o da posicao mais adiante."""

    OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")

    def __init__(self, path):
        with open(path, "rb") as fh:
            d = fh.read()
        if not d.startswith(b"%PDF"):
            raise PdfError("%s nao comeca com %%PDF" % path)
        self.d = d
        objs = {}    # num -> (posicao, valor)
        streams = []  # (posicao, dict, dados)
        trailers = []
        pos = 0
        while True:
            mt = self.OBJ.search(d, pos)
            if not mt:
                break
            num = int(mt.group(1))
            lx = Lexer(d, mt.end())
            val = lx.value()
            lx.skip()
            if isinstance(val, dict) and d[lx.i:lx.i + 6] == b"stream":
                k = lx.i + 6
                if d[k:k + 2] == b"\r\n":
                    k += 2
                elif d[k:k + 1] in (b"\n", b"\r"):
                    k += 1
                ln = val.get("Length")
                if isinstance(ln, int) and d[k + ln:k + ln + 30].lstrip().startswith(b"endstream"):
                    data, end = d[k:k + ln], k + ln
                else:
                    end = d.index(b"endstream", k)
                    data = d[k:end]
                streams.append((mt.start(), val, data))
                if val.get("Type") == "XRef":
                    trailers.append((mt.start(), val))
                pos = d.index(b"endstream", end) + 9
            else:
                pos = lx.i
            objs[num] = (mt.start(), val)
        for mt in re.finditer(rb"trailer\s*<<", d):
            lx = Lexer(d, mt.end() - 2)
            trailers.append((mt.start(), lx.value()))
        for spos, sd, data in streams:
            if sd.get("Type") != "ObjStm":
                continue
            raw = self.decode(sd, data)
            n, first = int(sd["N"]), int(sd["First"])
            head = Lexer(raw, 0)
            pairs = []
            for _ in range(n):
                onum = head.value()
                ooff = head.value()
                pairs.append((onum, ooff))
            for onum, ooff in pairs:
                val = Lexer(raw, first + ooff).value()
                if onum not in objs or objs[onum][0] < spos:
                    objs[onum] = (spos, val)
        if not trailers:
            raise PdfError("sem trailer nem stream XRef")
        trailers.sort(key=lambda t: t[0])
        self.root_ref = trailers[-1][1].get("Root")
        self.objs = {k: v for k, (_, v) in objs.items()}
        self._pages = None
        self._dests = None

    @staticmethod
    def decode(sd, data):
        f = sd.get("Filter")
        if isinstance(f, list):
            f = f[0] if len(f) == 1 else f
        if f is None:
            return data
        if f == "FlateDecode":
            return zlib.decompress(data)
        raise PdfError("filtro de object stream nao suportado: %r" % (f,))

    def get(self, v):
        seen = 0
        while isinstance(v, Ref):
            v = self.objs.get(v.num)
            seen += 1
            if seen > 50:
                raise PdfError("referencia circular")
        return v

    def catalog(self):
        cat = self.get(self.root_ref)
        if not isinstance(cat, dict):
            raise PdfError("catalogo (/Root) ilegivel")
        return cat

    def pages(self):
        """num do objeto de cada pagina -> numero da pagina (1..N)."""
        if self._pages is None:
            order = []

            def walk(ref, depth=0):
                if depth > 64:
                    raise PdfError("arvore de paginas funda demais")
                node = self.get(ref)
                kids = node.get("Kids") if isinstance(node, dict) else None
                if kids is not None:
                    for k in kids:
                        walk(k, depth + 1)
                elif isinstance(ref, Ref):
                    order.append(ref.num)
            walk(self.catalog().get("Pages"))
            self._pages = {num: i + 1 for i, num in enumerate(order)}
        return self._pages

    def dests(self):
        """nome (bytes) -> destino (array), da arvore /Names/Dests (e do /Dests
        antigo do catalogo, se houver)."""
        if self._dests is None:
            out = {}

            def walk(node, depth=0):
                node = self.get(node)
                if not isinstance(node, dict) or depth > 64:
                    return
                names = self.get(node.get("Names"))
                if isinstance(names, list):
                    for i in range(0, len(names) - 1, 2):
                        k = names[i]
                        out[bytes(k) if isinstance(k, (bytes, bytearray)) else str(k).encode()] = names[i + 1]
                for kid in self.get(node.get("Kids")) or []:
                    walk(kid, depth + 1)
            cat = self.catalog()
            nm = self.get(cat.get("Names"))
            if isinstance(nm, dict) and nm.get("Dests") is not None:
                walk(nm.get("Dests"))
            old = self.get(cat.get("Dests"))
            if isinstance(old, dict):
                for k, v in old.items():
                    out.setdefault(k.encode(), v)
            self._dests = out
        return self._dests

    def dest_page(self, dest):
        """Pagina (1..N) de um destino: nome, string, array, ou dict com /D."""
        d = self.get(dest)
        for _ in range(4):
            if isinstance(d, (bytes, bytearray, Name)):
                key = bytes(d) if isinstance(d, (bytes, bytearray)) else str(d).encode()
                d = self.get(self.dests().get(key))
            elif isinstance(d, dict):
                d = self.get(d.get("D"))
            else:
                break
        if isinstance(d, list) and d and isinstance(d[0], Ref):
            return self.pages().get(d[0].num)
        return None

    def outline(self):
        """[(titulo, destino, count, filhos)] a partir de /Outlines."""
        root = self.get(self.catalog().get("Outlines"))
        if not isinstance(root, dict):
            return None
        seen = set()

        def items(first, depth=0):
            out = []
            ref = first
            while isinstance(ref, Ref):
                if ref.num in seen or depth > 16:
                    raise PdfError("arvore de marcadores com ciclo")
                seen.add(ref.num)
                it = self.get(ref)
                if not isinstance(it, dict):
                    break
                dest = it.get("Dest")
                act = self.get(it.get("A"))
                if dest is None and isinstance(act, dict) and act.get("S") == "GoTo":
                    dest = act.get("D")
                kids = items(it.get("First"), depth + 1) if it.get("First") is not None else []
                out.append((pdf_text(self.get(it.get("Title"))), dest,
                            self.get(it.get("Count")), kids))
                ref = it.get("Next")
            return out
        return items(root.get("First"))


def pdf_text(b):
    """String de texto do PDF: UTF-16BE com BOM (o que o hyperref escreve com
    unicode=true), UTF-8 com BOM, ou PDFDocEncoding (~latin-1)."""
    if b is None:
        return ""
    if isinstance(b, Name):
        return str(b)
    b = bytes(b)
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", "replace")
    if b.startswith(b"\xef\xbb\xbf"):
        return b[3:].decode("utf-8", "replace")
    return b.decode("latin-1")


def pdf_pages_text(path, cmd):
    """O texto de cada pagina, pelo pdftotext do poppler (-layout: uma linha do
    sumario sai numa linha so', numero, titulo e pagina). Uma chamada para o
    documento inteiro, com as paginas separadas por form feed -- o mesmo texto
    de `pdftotext -f P -l P` pagina a pagina, sem 290 processos na tortura.
    Devolve (paginas, erro): paginas[0] e' a pagina 1."""
    try:
        r = subprocess.run([cmd, "-layout", "-enc", "UTF-8", path, "-"],
                           capture_output=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "%s nao executou: %s" % (cmd, e)
    if r.returncode != 0:
        return None, "%s saiu %d: %s" % (cmd, r.returncode,
                                         r.stderr.decode("utf-8", "replace").strip()[:200])
    pages = r.stdout.decode("utf-8", "replace").split("\f")
    if pages and not pages[-1].strip():
        pages = pages[:-1]   # o form feed depois da ultima pagina
    return pages, None


def words_re(text):
    """Um titulo como o pdftotext o escreve: as palavras na ordem, com qualquer
    branco horizontal entre elas."""
    return r"[ \t]+".join(re.escape(w) for w in nfc(text).split())


def chars_re(text):
    """Um IP ou hostname de faixa de card: os caracteres na ordem, aceitando
    quebra de linha entre quaisquer dois (o TeX pode quebrar nos \\surjb)."""
    return r"\s*".join(re.escape(c) for c in nfc(text) if not c.isspace())


def check_text(pages, pdf, tree, sec_pages, nav, sheet, lang):
    """O que o leitor VE nas paginas para onde os atalhos levam:
      - cada marcador de secao cai na pagina que abre com "N Titulo";
      - o sumario (a folha antes da secao 2) IMPRIME, para cada secao, a pagina
        em que o marcador dela cai;
      - cada marcador de card cai numa pagina que mostra o "#N" DELE, e cada
        marcador de host numa que mostra o IP dele (o hostname, sem IP) -- cair
        uma pagina antes, ainda dentro da secao e em ordem, nao passa mais;
      - cada tarja da secao 5 numa pagina que a mostra."""
    fails = []
    if len(pages) != len(pdf.pages()):
        return ["o pdftotext leu %d pagina(s), o PDF tem %d" % (len(pages), len(pdf.pages()))]

    def text(p):
        return nfc(pages[p - 1]) if p and 0 < p <= len(pages) else ""

    for i, (t, _, _, _) in enumerate(tree[:len(SECTIONS)]):
        n, p = i + 1, sec_pages[i]
        title = t.split("  ", 1)[1] if "  " in t else t
        if p and not re.search(r"(?m)^[ \t]*%d[ \t]+%s[ \t]*\r?$" % (n, words_re(title)), text(p)):
            fails.append("secao %d: a pagina %d, do marcador, nao abre com '%d %s'" % (n, p, n, title))
    # O sumario: a folha logo antes da que abre a secao 2.
    if len(sec_pages) >= 2 and sec_pages[1]:
        tp = sec_pages[1] - 1
        page = text(tp)
        toc_title = sheet.t("toc_title", lang)
        if not re.search(r"(?m)^[ \t]*%s[ \t]*\r?$" % words_re(toc_title), page):
            fails.append("a pagina %d (antes da secao 2) nao e' o sumario: sem a linha '%s'" % (tp, toc_title))
        for i, (t, _, _, _) in enumerate(tree[:len(SECTIONS)]):
            n = i + 1
            title = t.split("  ", 1)[1] if "  " in t else t
            mt = re.search(r"(?m)^[ \t]*%d[ \t]+%s[ \t]{2,}(\d+)[ \t]*\r?$" % (n, words_re(title)), page)
            if not mt:
                fails.append("o sumario (pagina %d) nao mostra a linha '%d %s  <pagina>'" % (tp, n, title))
            elif sec_pages[i] and int(mt.group(1)) != sec_pages[i]:
                fails.append("o sumario imprime a pagina %s para a secao %d, e o marcador dela cai na %d"
                             % (mt.group(1), n, sec_pages[i]))
    # Nivel 1: cada filho com o marcador do .tex que o declarou (mesma ordem; o
    # que o pdf-arvore ja' reprovou por texto diferente fica de fora aqui).
    for i, (t, _, _, kids) in enumerate(tree[:len(SECTIONS)]):
        sec = str(i + 1)
        bms = [b for b in nav.bookmarks if nav.section_of(b[0]) == sec]
        for (kt, kd, _, _), b in zip(kids, bms):
            if nfc(kt) != nfc(bm_plain(b[3])):
                continue
            name, k = b[2], b[5]
            kp = pdf.dest_page(kd)
            if kp is None:      # destino inexistente: o pdf-destinos ja' reprova
                continue
            page = text(kp)
            if name.startswith("bm-fnd-"):
                mt = re.match(r"#(\d+)", bm_plain(b[3]))
                if mt and not re.search(r"(?<![\w#])#%s(?!\d)" % mt.group(1), page):
                    fails.append("'%s' cai na pagina %d, que nao mostra o #%s do card"
                                 % (kt[:60], kp, mt.group(1)))
            elif name.startswith("bm-grp-"):
                # O card consolidado nao imprime "#N" (o numero e' o da linha do
                # grupo no sumario): a pagina tem de mostrar o TITULO dele, que
                # pode quebrar de linha.
                a = macro_at(nav.s, k, "consolidatedcard", 2)
                title = norm_space(plain(re.sub(r"^\\hypertarget\{[^}]*\}\{\}", "", a[1])))
                pat = r"\s+".join(re.escape(w) for w in nfc(title).split())
                if title and not re.search(pat, page):
                    fails.append("'%s' cai na pagina %d, que nao mostra o titulo do card ('%s')"
                                 % (kt[:60], kp, title[:50]))
            elif name.startswith("bm-host-"):
                a = macro_at(nav.s, k, "hostcard", 2)
                ip, hn = norm_space(plain(a[0])), norm_space(plain(a[1]))
                # O IP inteiro, com fronteira dos dois lados (192.0.2.1 nao
                # casa dentro de 192.0.2.10); sem IP, o comeco do hostname.
                pat = (r"(?<![\w.:])%s(?![\w.:])" % chars_re(ip) if ip else
                       r"(?<![\w.:])%s" % chars_re(hn[:30]) if hn else None)
                if pat and not re.search(pat, page):
                    fails.append("'%s' cai na pagina %d, que nao mostra o %s do host"
                                 % (kt[:60], kp, "IP " + ip if ip else "hostname"))
            elif name.startswith("bm-s5-"):
                if not re.search(words_re(nfc(kt).upper()), page):
                    fails.append("'%s' cai na pagina %d, que nao mostra a tarja" % (kt, kp))
    return fails


def expected_tree(nav, sheet, lang):
    """A arvore que o .tex declara: [(titulo da secao, [titulos dos filhos])]."""
    tree = []
    for p, a in nav.secs:
        n = a[0].strip()
        kids = [nfc(bm_plain(b[3])) for b in nav.bookmarks if nav.section_of(b[0]) == n]
        tree.append((nfc("%s  %s" % (n, norm_space(plain(a[1])))), kids))
    return tree


def check_pdf(pdf, aux, nav, sheet, lang, pages=None, perr=None):
    """pdf-arvore, pdf-destinos, pdf-paginas e pdf-texto, numa leitura so' do
    PDF. pages/perr: o texto das paginas (pdf_pages_text) ou o erro do
    pdftotext -- erro e' FALHA do pdf-texto, nunca checagem pulada."""
    out = {"pdf-arvore": [], "pdf-destinos": [], "pdf-paginas": [], "pdf-texto": []}
    tree = pdf.outline()
    if not tree:
        # Sem arvore nao ha destino nem pagina a conferir: as duas checagens
        # saem do relatorio em vez de aparecerem como OK sem ter olhado nada.
        return {"pdf-arvore": ["o PDF nao tem arvore de marcadores (/Outlines vazio ou ausente)"]}
    want = expected_tree(nav, sheet, lang)
    got = [(nfc(t), [nfc(k[0]) for k in kids]) for t, _, _, kids in tree]
    if [t for t, _ in got] != [t for t, _ in want]:
        out["pdf-arvore"].append("nivel 0 = %s, esperado %s" % ([t for t, _ in got], [t for t, _ in want]))
    else:
        for (t, gk), (_, wk) in zip(got, want):
            if gk != wk:
                diff = next((i for i, (x, y) in enumerate(zip(gk, wk)) if x != y), min(len(gk), len(wk)))
                out["pdf-arvore"].append(
                    "'%s': %d filho(s), esperado %d; primeira diferenca no #%d: %r x %r"
                    % (t, len(gk), len(wk), diff + 1, gk[diff] if diff < len(gk) else None,
                       wk[diff] if diff < len(wk) else None))
    for t, _, count, kids in tree:
        if kids and not (isinstance(count, int) and count < 0):
            out["pdf-arvore"].append("'%s' abre expandido (Count %r): bookmarksopenlevel=0 deixa o"
                                     " nivel 0 fechado" % (t, count))
        for kt, _, _, gk in kids:
            if gk:
                out["pdf-arvore"].append("'%s' tem filhos: a arvore so' tem 2 niveis" % kt)
    # Destinos: existem, a secao cai na pagina do alvo do sumario, os filhos
    # dentro da secao e em ordem de pagina.
    npages = len(pdf.pages())
    sec_pages = []
    for i, (t, dest, _, kids) in enumerate(tree):
        pg = pdf.dest_page(dest)
        sec_pages.append(pg)
        if pg is None:
            out["pdf-destinos"].append("'%s': destino %r nao existe no PDF" % (t, dest))
    for i, (t, dest, _, kids) in enumerate(tree):
        lo = sec_pages[i]
        # Toda secao abre numa folha nova: a secao i vai ate' a folha ANTES da
        # que abre a proxima (a ultima, ate' o fim do documento).
        hi = next((p - 1 for p in sec_pages[i + 1:] if p), npages)
        last = lo
        for kt, kd, _, _ in kids:
            kp = pdf.dest_page(kd)
            if kp is None:
                out["pdf-destinos"].append("'%s': destino %r nao existe no PDF" % (kt, kd))
                continue
            if lo and not (lo <= kp <= hi):
                out["pdf-destinos"].append("'%s' cai na pagina %d, fora da secao '%s' (%s..%s)"
                                           % (kt, kp, t, lo, hi))
            if last and kp < last:
                out["pdf-destinos"].append("'%s' (pagina %d) depois de um filho da pagina %d"
                                           % (kt, kp, last))
            last = kp
    for i, (n, _) in enumerate(SECTIONS):
        tp = pdf.dest_page(("sec-%d" % n).encode())
        if tp is None:
            out["pdf-destinos"].append("o alvo do sumario sec-%d nao existe no PDF" % n)
        elif i < len(sec_pages) and sec_pages[i] and tp != sec_pages[i]:
            out["pdf-destinos"].append("secao %d: o marcador cai na pagina %d e o link do sumario"
                                       " na %d" % (n, sec_pages[i], tp))
    # O que as paginas MOSTRAM (pdftotext): o #N/IP de cada filho na pagina dele
    # e os numeros que o sumario imprime.
    if pages is None:
        out["pdf-texto"].append(perr or "sem o texto das paginas (pdftotext)")
    else:
        out["pdf-texto"] = check_text(pages, pdf, tree, sec_pages, nav, sheet, lang)
    # A pagina impressa no sumario (rotulo suri-sec-N do .aux) e' a do marcador.
    if aux is None:
        out.pop("pdf-paginas")
        return out
    labels = {}
    for mt in re.finditer(r"\\newlabel\{suri-sec-(\d+)\}", aux):
        # \newlabel{rotulo}{{texto}{pagina}{titulo}{ancora}{}}: a pagina e' o
        # SEGUNDO grupo, lido por chaves balanceadas (o texto pode ter chaves).
        try:
            body, _ = group_at(aux, skip_blank(aux, mt.end()))
            _, j = group_at(body, skip_blank(body, 0))
            page, _ = group_at(body, skip_blank(body, j))
            labels[mt.group(1)] = page
        except TexError:
            labels[mt.group(1)] = "?"
    for i, (n, _) in enumerate(SECTIONS):
        lp = labels.get(str(n))
        if lp is None:
            out["pdf-paginas"].append("o .aux nao tem o rotulo suri-sec-%d" % n)
        elif i < len(sec_pages) and str(sec_pages[i]) != lp.strip():
            out["pdf-paginas"].append("secao %d: o sumario imprime a pagina %s e a secao abre na %s"
                                      % (n, lp, sec_pages[i]))
    return out


CHECKS = [("sumario", check_sumario), ("marcadores", check_marcadores),
          ("hyperref", check_hyperref)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", required=True)
    ap.add_argument("--xml", required=True)
    ap.add_argument("--tex", required=True)
    ap.add_argument("--pdf")
    ap.add_argument("--aux")
    ap.add_argument("--pdftotext", default="pdftotext",
                    help="o pdftotext do poppler (padrao: o do PATH; no runner, poppler-utils)")
    ap.add_argument("--bundle", default=os.path.join(os.path.dirname(HERE), "suricatoos-premium-pdf"))
    ap.add_argument("--only", action="append", default=[])
    args = ap.parse_args()
    try:
        sheet = V.Stylesheet(os.path.join(args.bundle, "latex.xsl"))
        model = V.Model(args.xml, sheet)
        tex = V.Tex(args.tex)
        with open(args.tex, encoding="utf-8") as fh:
            tex.whole = fh.read()
        nav = Nav(tex.s)
        aux = None
        if args.aux:
            with open(args.aux, encoding="utf-8", errors="replace") as fh:
                aux = fh.read()
    except (OSError, ET.ParseError, TexError, StylesheetError) as e:
        print("check-navigation: ERRO de leitura: %s" % e)
        return 2
    results = []
    for name, fn in CHECKS:
        if args.only and name not in args.only:
            continue
        try:
            results.append((name, fn(model, tex, nav, sheet, args.lang)))
        except TexError as e:
            results.append((name, ["o .tex nao pode ser lido: %s" % e]))
        except StylesheetError as e:
            print("check-navigation: ERRO no latex.xsl (checagem %s): %s" % (name, e))
            return 2
    if args.pdf and not (args.only and not any(o.startswith("pdf") for o in args.only)):
        try:
            pdf = Pdf(args.pdf)
            pages, perr = pdf_pages_text(args.pdf, args.pdftotext)
            for name, fails in check_pdf(pdf, aux, nav, sheet, args.lang, pages, perr).items():
                if not args.only or name in args.only:
                    results.append((name, fails))
        except (OSError, PdfError, ValueError, KeyError, IndexError, zlib.error) as e:
            results.append(("pdf-arvore", ["o PDF nao pode ser lido: %s: %s" % (type(e).__name__, e)]))
    failed = 0
    for name, fails in results:
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
