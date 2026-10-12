#!/usr/bin/env python3
"""Mutantes das EDICOES do Suricatoos Premium PDF (tecnica, cliente, executiva).

FERRAMENTA DE DESENVOLVIMENTO: o CI NAO roda isto. Prova que os portoes das
edicoes -- o check-veracity.py e o check-navigation.py com --variant, e o
ci/check-manifest.py -- REPROVAM cada defeito que uma edicao pode ter, e refaz
essa prova quando o latex.xsl, o build-feed-xml.py ou os checadores mudarem.
Roda com python3 e lxml (o libxslt do lxml e' o do `xsltproc` do generate);
nao precisa de TeX.

Quatro modos:

  xslt  cada mutante troca um trecho do latex.xsl numa COPIA do bundle, gera o
        .tex das fixtures da edicao nos 3 idiomas e roda os dois checadores com
        --variant e --bundle no bundle MUTADO, como no CI. Cada mutante tem de
        ser REPROVADO em pelo menos uma execucao; o controle (sem troca) roda
        TODA fixture nas tres edicoes e nos tres idiomas e tem de passar.
  tex   cada caso edita o .tex que o latex.xsl INTACTO gerou (uma fixture, um
        idioma, uma edicao): os checadores tem de reprovar cada edicao, e os
        controles (o .tex intacto) tem de passar.
  feed  cada mutante troca um trecho do build-feed-xml.py (ou do generate
        canonico) numa COPIA de report-formats/ (o builder, o bundle e o
        ci/check-manifest.py), roda o builder la' e o check-manifest.py contra
        o que ele escreveu: tem de reprovar (o builder recusar tambem conta). O
        controle (sem troca) tem de passar. Cobre a igualdade de conteudo (o
        objeto leva EXATAMENTE os bytes do bundle) e a VERSION no objeto.
  versao cada mutante quebra uma propriedade da VERSION por conteudo (constante,
        hora do build, caminho da pasta, data de arquivo, so' parte do conteudo,
        marcador sem preencher...) numa COPIA do builder e roda o
        tests/test_feed.py contra ela: algum teste tem de reprovar. O mutante
        tem de rodar (um que nao roda e' invalido, nao reprovado).

E um modo a parte, fora de `todos':

  regressao --base <commit>  a edicao tecnica do latex.xsl de agora sai
        IDENTICA, byte a byte, a do latex.xsl do commit (sample, fixtures e
        tortura, nos 3 idiomas, na mesma execucao); precisa do git.

Uso (de qualquer diretorio; os caminhos saem da posicao deste arquivo):

  python3 report-formats/tests/mutantes-variantes.py [xslt|tex|feed|versao|todos]
          [--so NOME ...] [--trabalho DIR] [--manter]
  python3 report-formats/tests/mutantes-variantes.py regressao --base <commit>

Sai 0 se todo mutante foi reprovado e todo controle passou. Um trecho que nao
casa exatamente uma vez para a execucao com erro, para o mutante nunca passar
por nao ter mudado nada.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    from lxml import etree as E
except ImportError:  # pragma: no cover - ferramenta de desenvolvimento
    sys.exit("mutantes-variantes.py precisa do lxml (pip install lxml)")

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.dirname(HERE)
BUNDLE = os.path.join(RF, "suricatoos-premium-pdf")
FIX = os.path.join(HERE, "fixtures")
CI = os.path.join(RF, "ci")
LANGS = ("en", "pt_BR", "es")
VARIANTS = ("technical", "client", "executive")

ALL_FIX = sorted(f[:-4] for f in os.listdir(FIX) if f.endswith(".xml"))
V3, V4, V6, V7A, V8, V11 = ("v3-consolidado-qod", "v4-instancias", "v6-vulns-unicas", "v7a-faixas",
                            "v8-ancora", "v11-escopo-autenticado")
V12, V16, V21, V22 = ("v12-escopo-nao-iniciado", "v16-escopo-agente-limpo", "v21-prioridades-ordem",
                      "v22-prioridades-cortes")
V26, V27, V28 = "v26-prioridades-cards", "v27-cliente-falso-positivo", "v28-cliente-so-log"
# As fixtures com falso positivo, com Log, com grupo consolidado e as que a
# edicao executiva exercita (corte da tabela, export parcial com piso de QoD,
# nada medido, inventario do agente).
COM_FP = [V6, V21, V26, V27, V28]
COM_LOG = ["v1-numeracao", V6, "v7c-todos-lowconf", "v10-navegacao", V16, V21,
           "v23-prioridades-sem-criticos", V26, V27, V28]
COM_GRUPO = [V3, V4, V8, V22, V26, V27]
EXECUTIVA = [V7A, V11, V12, V16, V22, V26, V27]


def jobs(variant, fixtures):
    return [(variant, fx) for fx in fixtures]


FP_RES = 'match="report/results/result[number(severity) &lt; 0 and number(severity) &gt; -1.5]"'
PORT_OWN = '<xsl:when test="$own = $own and $own &lt; 0 and $own &gt; -1.5"/>'
PORT_RES = ('<xsl:when test="not($own = $own) and count($rs) &gt; 0\n'
            '                      and not($rs[not(number(severity) &lt; 0 and number(severity) &gt; -1.5)])"/>')
GRP_FUNC_LOG = ("[$variant != 'client' or gvm:sev-max(key('by-nvt', nvt/@oid)) &gt;= 0.1]\"/>\n"
                "  </func:function>")
ROWS_LOG = ("and ($variant != 'client' or gvm:sev-max(key('by-nvt', nvt/@oid)) &gt;= 0.1))]\"/>")
# O $grp-reps de antes da R5: gvm:grp-confreps chamada de uma variavel global,
# que na copia da edicao do cliente procura no documento de origem.
GRP_REPS_INLINE = re.compile(r'<xsl:variable name="grp-reps"\n    select="\$nvt-conf.*?/>', re.S)
GRP_REPS_OLD = ('<xsl:variable name="grp-reps"\n'
                '    select="$nvt-conf[nvt/solution/@type=\'VendorFix\']\n'
                '                     [generate-id() = generate-id(gvm:grp-confreps(gvm:grp(nvt/name))[1])]\n'
                '                     [count(gvm:grp-confreps(gvm:grp(nvt/name))) &gt;= $group-min]"/>')
EXE_ROW = ('<xsl:when test="$variant = \'executive\'"><xsl:text>\\priorowsemcard{</xsl:text></xsl:when>')
EXE_LINK = ('<xsl:when test="$variant = \'executive\'">\n            <xsl:text>}\n</xsl:text>\n'
            '          </xsl:when>')
EXE_TAB = '<xsl:when test="$variant = \'executive\'">prioritytablesemcard</xsl:when>'
EXE_SECS = ('<xsl:when test="$variant = \'executive\'">\n        <sec n="1" key="sec_exec"/>')
EXE_SKIP = ('<xsl:if test="$variant != \'executive\'">\n      <xsl:call-template name="hexmap-section"/>')
EXE_APX = ('<xsl:if test="$variant != \'executive\'">\n      <xsl:text>\\clearpage\n</xsl:text>\n'
           '      <xsl:call-template name="hexmap-hosts-section"/>')
# O aviso curto do bloco de indicadores sem item (edicao do cliente).
AVISO_CURTO = "<xsl:when test=\"$variant = 'client' and count($low-show) = 0\">"
COM_INDICADOR = [V27, "v7b-lowconf", "v7c-todos-lowconf"]
# Um template a mais no modo client-view: o host com resultado, todos falso
# positivo, sai da copia (a leitura que o controlador NAO quis).
RC_TEMPLATE = '  <xsl:template match="report/result_count" mode="client-view">'
HOST_FP_DROP = ('  <xsl:template match="report/host[normalize-space(ip) = ../results/result/host/text()]'
                '[not(normalize-space(ip) = ../results/result[not(number(severity) &lt; 0 and '
                'number(severity) &gt; -1.5)]/host/text())]" mode="client-view"/>\n')

# (nome, o que o mutante quebra, [(trecho, troca) ou (regex, troca)], [(edicao, fixture)])
MUTANTES = [
    ("controle", "nenhuma troca", [], [(v, fx) for v in VARIANTS for fx in ALL_FIX]),
    # --- edicao do cliente: falso positivo -------------------------------------
    ("fp-fica-na-copia", "a copia da edicao do cliente mantem os resultados falso positivo",
     [(FP_RES, 'match="report/results/result[false()]"')], jobs("client", COM_FP)),
    ("fp-porta-com-severidade-fica", "a porta de severidade propria falso positivo fica na copia",
     [(PORT_OWN, '<xsl:when test="false()"/>')], jobs("client", COM_FP)),
    ("fp-porta-sem-severidade-fica", "a porta sem severidade propria e so' com falso positivo fica",
     [(PORT_RES, '<xsl:when test="false()"/>')], jobs("client", COM_FP)),
    ("fp-no-total", "o total do scan nao perde os falso positivo",
     [('<xsl:value-of select="number($t) - number($nfp)"/>', '<xsl:value-of select="number($t)"/>')],
     jobs("client", COM_FP)),
    ("fp-total-so-do-export", "o total perde so' os falso positivo que o export carrega, nao os do scan",
     [('<xsl:when test="$fpf = $fpf"><xsl:value-of select="$fpf"/></xsl:when>',
       '<xsl:when test="false()"><xsl:value-of select="$fpf"/></xsl:when>')],
     jobs("client", COM_FP)),
    ("fp-nos-niveis", "a linha de niveis da edicao do cliente cita falso positivo",
     [("<xsl:when test=\"$variant = 'client'\"><xsl:value-of select=\"translate($filter-levels, 'f', '')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"translate($filter-levels, 'f', '')\"/></xsl:when>")],
     jobs("client", COM_FP)),
    ("fp-na-ordem", "a frase da ordem da edicao do cliente fala de falso positivo",
     [("<xsl:when test=\"$variant = 'client'\"><xsl:value-of select=\"gvm:t('prio_order_client')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('prio_order_client')\"/></xsl:when>")],
     jobs("client", COM_FP)),
    ("edicao-cliente-ignorada", "gvm:report() nao reconhece a edicao do cliente (le o original)",
     [("<xsl:when test=\"$variant = 'client'\">\n        <func:result select=\"$client-report\"/>",
       "<xsl:when test=\"$variant = 'cliente'\">\n        <func:result select=\"$client-report\"/>")],
     jobs("client", COM_FP)),
    # (Sem mutante "real-report com o original como no' corrente": hoje ele e'
    # EQUIVALENTE -- toda chamada de func:function que usa key() dentro do
    # relatorio acontece num laco sobre nos da copia, que poe a copia como no'
    # corrente --, e a saida nao muda. O template da raiz roda real-report
    # dentro da copia por defesa: uma chamada dessas no topo de um template
    # leria o documento de origem sem erro nenhum.)
    ("grp-reps-pela-funcao", "$grp-reps volta a chamar gvm:grp-confreps de uma variavel global",
     [(GRP_REPS_INLINE, GRP_REPS_OLD)], jobs("client", COM_GRUPO)),
    # --- edicao do cliente: Log so' como contagem -------------------------------
    ("log-card-na-cliente", "os cards de Log voltam na edicao do cliente",
     [('<xsl:for-each select="$rows-show[$low = 0] | $low-show[$low = 1]">',
       '<xsl:for-each select="$rows-conf[$low = 0] | $low-show[$low = 1]">')], jobs("client", COM_LOG)),
    ("log-linha-na-cliente", "as linhas de Log voltam ao sumario da edicao do cliente",
     [('<xsl:variable name="sel" select="$rows-show[$low = 0] | $low-show[$low = 1]"/>',
       '<xsl:variable name="sel" select="$rows-conf[$low = 0] | $low-show[$low = 1]"/>')],
     jobs("client", COM_LOG)),
    ("log-indicador-na-cliente", "o indicador Log volta a ter linha e card",
     [('<xsl:variable name="sel" select="$rows-show[$low = 0] | $low-show[$low = 1]"/>',
       '<xsl:variable name="sel" select="$rows-show[$low = 0] | $nvt-low[$low = 1]"/>'),
      ('<xsl:for-each select="$rows-show[$low = 0] | $low-show[$low = 1]">',
       '<xsl:for-each select="$rows-show[$low = 0] | $nvt-low[$low = 1]">'),
      ('<xsl:if test="count($low-show) &gt; 0">', '<xsl:if test="true()">')], jobs("client", COM_LOG)),
    ("log-membro-de-grupo", "o advisory so' Log entra no card consolidado da edicao do cliente",
     [(GRP_FUNC_LOG, '"/>\n  </func:function>')], jobs("client", [V27])),
    ("log-de-produto-agrupado-some", "o advisory so' Log de um produto agrupado nao e' contado",
     [(ROWS_LOG, ')]"/>')], jobs("client", [V27])),
    ("sem-contagem-de-log", "a contagem de Log nao sai",
     [("<xsl:if test=\"$variant = 'client' and $n &gt; 0\">", '<xsl:if test="false()">')],
     jobs("client", COM_LOG)),
    ("contagem-de-log-errada", "a contagem de Log diz um a mais",
     [('<xsl:value-of select="gvm:num($n)"/>\n      <xsl:choose>\n        <xsl:when test="$n = 1">',
       '<xsl:value-of select="gvm:num($n + 1)"/>\n      <xsl:choose>\n        <xsl:when test="$n = 1">')],
     jobs("client", COM_LOG)),
    ("contagem-de-log-sem-singular", "a contagem de um registro sai no plural",
     [("<xsl:when test=\"$n = 1\"><xsl:value-of select=\"gvm:t('client_log_1')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('client_log_1')\"/></xsl:when>")],
     jobs("client", COM_LOG)),
    ("tabela-vazia-de-indicadores", "o bloco de indicadores so' de Log abre uma tabela vazia",
     [('<xsl:if test="count($low-show) &gt; 0">', '<xsl:if test="true()">')], jobs("client", [V28])),
    ("aviso-longo-sem-itens", "o bloco de indicadores so' de Log fala dos itens abaixo (o aviso longo)",
     [(AVISO_CURTO, '<xsl:when test="false()">')], jobs("client", [V28])),
    ("aviso-curto-com-itens", "o bloco de indicadores com item leva o aviso curto na edicao do cliente",
     [(AVISO_CURTO, "<xsl:when test=\"$variant = 'client'\">")], jobs("client", COM_INDICADOR)),
    ("aviso-curto-no-tecnico", "o tecnico leva o aviso curto",
     [(AVISO_CURTO, "<xsl:when test=\"$variant = 'technical' or ($variant = 'client' and count($low-show) = 0)\">")],
     jobs("technical", COM_INDICADOR + [V28])),
    ("host-so-fp-some", "a copia da edicao do cliente tira o host que so' falso positivo alcancava",
     [(RC_TEMPLATE, HOST_FP_DROP + RC_TEMPLATE)], jobs("client", COM_FP)),
    ("kicker-do-cliente", "a capa da edicao do cliente nao diz a edicao",
     [("<xsl:when test=\"$variant = 'client'\"><xsl:value-of select=\"gvm:t('kicker_client')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('kicker_client')\"/></xsl:when>")],
     jobs("client", ["v1-numeracao", "v25-prioridades-acao-unica"])),
    # --- edicao executiva ---------------------------------------------------------
    ("link-de-card-na-executiva", "a tabela de prioridades da executiva leva o link do card",
     [(EXE_LINK, EXE_LINK.replace("$variant = 'executive'", "false()"))], jobs("executive", EXECUTIVA)),
    ("tabela-com-card-na-executiva", "a executiva usa a tabela de prioridades com a coluna de card",
     [(EXE_TAB, EXE_TAB.replace("$variant = 'executive'", "false()")),
      (EXE_ROW, EXE_ROW.replace("$variant = 'executive'", "false()")),
      (EXE_LINK, EXE_LINK.replace("$variant = 'executive'", "false()"))], jobs("executive", EXECUTIVA)),
    ("secao-a-mais-na-executiva", "a executiva monta o mapa, os hosts, o sumario e os cards",
     [(EXE_SKIP, EXE_SKIP.replace("$variant != 'executive'", "true()"))], jobs("executive", EXECUTIVA)),
    ("apendice-na-executiva", "a executiva monta o apendice por host",
     [(EXE_APX, EXE_APX.replace("$variant != 'executive'", "true()"))], jobs("executive", EXECUTIVA)),
    ("escopo-com-numero-7-na-executiva", "o escopo da executiva sai com o numero 7",
     [('<xsl:variable name="n-scope" select="$sections[@key = \'sec_scope\']/@n"/>',
       '<xsl:variable name="n-scope" select="7"/>')], jobs("executive", EXECUTIVA)),
    ("sumario-com-oito-na-executiva", "a tabela de secoes da executiva lista as oito",
     [(EXE_SECS, EXE_SECS.replace("$variant = 'executive'", "false()"))], jobs("executive", EXECUTIVA)),
    ("corte-cita-secao-na-executiva", "o corte da tabela da executiva manda aos achados detalhados",
     [("<xsl:when test=\"$variant = 'executive'\"><xsl:value-of select=\"gvm:t('prio_trunc_exec')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('prio_trunc_exec')\"/></xsl:when>")],
     jobs("executive", EXECUTIVA)),
    ("indicadores-citados-na-executiva", "o aviso de export parcial da executiva cita o bloco de indicadores",
     [("<xsl:when test=\"$variant = 'executive'\"><xsl:value-of select=\"gvm:t('sample_qod_b_exec')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('sample_qod_b_exec')\"/></xsl:when>")],
     jobs("executive", EXECUTIVA)),
    ("kicker-da-executiva", "a capa da executiva nao diz a edicao",
     [("<xsl:when test=\"$variant = 'executive'\"><xsl:value-of select=\"gvm:t('kicker_executive')\"/></xsl:when>",
       "<xsl:when test=\"false()\"><xsl:value-of select=\"gvm:t('kicker_executive')\"/></xsl:when>")],
     jobs("executive", ["v1-numeracao", "v25-prioridades-acao-unica"])),
    # --- a edicao pedida -----------------------------------------------------------
    ("edicao-desconhecida-cai-no-tecnico", "o latex.xsl aceita uma edicao fora do contrato",
     [("<xsl:if test=\"not($variant = 'technical' or $variant = 'client' or $variant = 'executive')\">",
       '<xsl:if test="false()">')], [("desconhecida", "v1-numeracao")]),
]


# ---------------------------------------------------------------------------
# Casos do modo tex: edicoes do .tex gerado pelo latex.xsl intacto
# ---------------------------------------------------------------------------
def repl(old, new, count=1):
    def f(s):
        if old not in s:
            raise SystemExit("caso tex: %r nao esta' no .tex" % old[:80])
        return s.replace(old, new, count)
    return f


def rx(pattern, new):
    def f(s):
        s2, n = re.subn(pattern, new, s, count=1, flags=re.S)
        if not n:
            raise SystemExit("caso tex: %r nao casou no .tex" % pattern[:80])
        return s2
    return f


def after_section(n, anchor, text):
    def f(s):
        a = s.find("\\suriSection{%d}" % n)
        k = s.find(anchor, a) if a >= 0 else -1
        if k < 0:
            raise SystemExit("caso tex: %r nao esta' na secao %d" % (anchor[:80], n))
        return s[:k] + text + s[k:]
    return f


def before(anchor, text):
    def f(s):
        k = s.find(anchor)
        if k < 0:
            raise SystemExit("caso tex: %r nao esta' no .tex" % anchor[:80])
        return s[:k] + text + s[k:]
    return f


FP_ROW = ("\\findingrow{10}{\\hyperlink{fnd-1-3-6-1-4-1-25623-1-0-992702}{Example Debug Endpoint Exposed}}"
          "{1}{neutro}{}\n")
LOG_CARD = ("\\findingcard{logsev}{\\hypertarget{fnd-1-3-6-1-4-1-25623-1-0-992731}{}\\#10}"
            "{Example OS Fingerprint}{%\n  \\chipsev{logsev}{}%\n}\n")
AVISO_CURTO_PT = ("\\warnbox{Nenhum indicador a validar acima da severidade informativa: com "
                  "\\textbf{baixa qualidade de detecção} (abaixo de 70\\%), o scanner só reportou "
                  "registros informativos (Log).}")
AVISO_LONGO_PT = ("\\warnbox{O scanner reportou os itens abaixo com \\textbf{baixa qualidade de detecção} "
                  "(abaixo de 70\\%). São inconclusivos por natureza e precisam ser validados manualmente "
                  "antes de qualquer esforço de remediação — trate a severidade exibida como um "
                  "\\textbf{teto}, não como fato confirmado.}")
AVISO_CURTO_EN = ("\\warnbox{No indicators to validate above informational severity: with "
                  "\\textbf{low detection quality} (under 70\\%), the scanner only reported informational "
                  "records (Log).}")
AVISO_LONGO_EN = ("\\warnbox{The scanner reported the items below with \\textbf{low detection quality} "
                  "(under 70\\%). They are inconclusive by nature and must be validated manually before any "
                  "remediation effort — treat the severity shown as an \\textbf{upper bound}, not as a "
                  "confirmed fact.}")
CASOS_TEX = [
    # (nome, fixture, idioma, edicao, edicao ou None = controle)
    ("controle cliente v27", V27, "en", "client", None),
    ("controle cliente v28", V28, "pt_BR", "client", None),
    ("controle cliente v6", V6, "es", "client", None),
    ("controle executiva v26", V26, "es", "executive", None),
    ("controle executiva v22", V22, "en", "executive", None),
    ("controle tecnico v28", V28, "pt_BR", "technical", None),
    # cliente: falso positivo
    ("linha falso positivo no sumario", V27, "en", "client",
     before("\\end{findingsummary}", FP_ROW)),
    ("advisory falso positivo no card consolidado", V27, "en", "client",
     rx(r"(\\advisoryrow\{[^\n]*\n)", r"\1  \\advisoryrow{Example Webmail Advisory (WM-06)}{falsepos}{}\n")),
    ("palavra falso positivo na nota da linha geral", V27, "en", "client",
     repl("1 Low, 1 Log \\textperiodcentered", "1 Low, 1 Log, 1 False pos. \\textperiodcentered")),
    ("porta so' de falso positivo na secao 4", V27, "en", "client",
     repl("\\hostrow{445/\\surjb{}tcp}{4}{alto}{7.8}",
          "\\hostrow{445/\\surjb{}tcp}{4}{alto}{7.8}\n\\hostrow{8443/\\surjb{}tcp}{1}{neutro}{}")),
    ("contagem com falso positivo na secao 4", V27, "en", "client",
     repl("\\hostrow{445/\\surjb{}tcp}{4}{alto}{7.8}", "\\hostrow{445/\\surjb{}tcp}{5}{alto}{7.8}")),
    ("celula so' de falso positivo no mapa", V27, "en", "client",
     before("\\end{hexboard}", "\\hexport{HTTPS}{8443/TCP}{192.0.2.82}{neutro}\n")),
    ("linha so' de falso positivo na tabela de portas", V27, "en", "client",
     before("\\end{porttable}", "  \\portrow{8443}{}{tcp}{https}{neutro}{}{1}{192.0.2.82 }\n")),
    ("host so' de falso positivo nos sistemas afetados", V27, "en", "client",
     repl("\\chiphost{192.\\surjb{}0.\\surjb{}2.\\surjb{}81:443/\\surjb{}tcp}",
          "\\chiphost{192.\\surjb{}0.\\surjb{}2.\\surjb{}81:443/\\surjb{}tcp}%\n"
          "  \\chiphost{192.\\surjb{}0.\\surjb{}2.\\surjb{}82:443/\\surjb{}tcp}")),
    ("instancias com falso positivo", V27, "en", "client", repl("{1 INSTANCE(S)}", "{2 INSTANCE(S)}")),
    ("host so' de falso positivo no card consolidado", V27, "en", "client",
     rx(r"\\chip\{HOST 192\.\\surjb\{\}0\.\\surjb\{\}2\.\\surjb\{\}81\}",
        r"\\chip{2 HOSTS}%\n  \\chip{192.0.2.81}%\n  \\chip{198.51.100.84}")),
    ("total com falso positivo", V27, "en", "client", repl("{TOTAL FINDINGS}{18}", "{TOTAL FINDINGS}{27}")),
    ("niveis com falso positivo", V27, "en", "client",
     repl("Critical, High, Medium, Low, Log}", "Critical, High, Medium, Low, Log, False positive}")),
    ("ordem falando de falso positivo", V27, "en", "client",
     repl("(Log does not count)", "(false positives and Log do not count)")),
    ("ancora do NVT so' de falso positivo", V27, "en", "client",
     before("\\end{document}", "\\hypertarget{fnd-1-3-6-1-4-1-25623-1-0-992702}{}\n")),
    # cliente: Log so' como contagem
    ("card de Log", V27, "en", "client", after_section(6, "\\findinglog{\\suriEllip\\ + 3", LOG_CARD)),
    ("linha de Log", V27, "en", "client",
     before("\\end{findingsummary}", "\\findingrow{10}{\\hyperlink{fnd-1-3-6-1-4-1-25623-1-0-992731}"
                                     "{Example OS Fingerprint}}{1}{logsev}{}\n")),
    ("contagem de Log errada", V27, "en", "client", repl("+ 3 informational records", "+ 2 informational records")),
    ("contagem de Log ausente", V27, "en", "client",
     rx(r"\\findinglog\{\\suriEllip\\ \+ 1 [^\n]*\n", "")),
    ("contagem de Log antes da tabela", V27, "en", "client",
     rx(r"(\\begin\{findingsummary\}\{confirmados\}\n)(.*?\\end\{findingsummary\}\n)(\\findinglog\{[^\n]*\n)",
        r"\3\1\2")),
    ("contagem de Log no plural errado", V28, "pt_BR", "client",
     repl("+ 1 registro informativo (Log), não detalhado", "+ 1 registros informativos (Log), não detalhados")),
    ("tabela vazia de indicadores", V28, "pt_BR", "client",
     before("\\findinglog{\\suriEllip\\ + 1 ", "\\begin{findingsummary}{indicadores}\n\\end{findingsummary}\n")),
    # cliente: o aviso do bloco de indicadores (curto so' no bloco sem item)
    ("aviso longo no bloco sem item", V28, "pt_BR", "client", repl(AVISO_CURTO_PT, AVISO_LONGO_PT)),
    ("aviso curto no bloco com item", V27, "en", "client", repl(AVISO_LONGO_EN, AVISO_CURTO_EN)),
    ("aviso ausente no bloco sem item", V28, "pt_BR", "client", rx(r"\\warnbox\{Nenhum indicador[^\n]*\n", "")),
    # cliente: o host so' com falso positivo continua (host varrido e limpo)
    ("host so' de falso positivo fora da secao 4", V27, "en", "client",
     rx(r"\\suriBookmark\{1\}\{bm-host-5\}.*?recorded on this host\.\}\}\n", "")),
    ("host so' de falso positivo fora da contagem", V27, "en", "client",
     repl("{HOSTS ASSESSED}{5}", "{HOSTS ASSESSED}{4}")),
    ("host so' de falso positivo fora da narrativa", V27, "en", "client",
     repl("} assessed 5 host(s)", "} assessed 4 host(s)")),
    ("capa sem a edicao do cliente", V27, "en", "client", repl("kicker={CLIENT EDITION}", "kicker={VULNERABILITY ASSESSMENT}")),
    # executiva
    ("link de card na executiva", V26, "es", "executive",
     rx(r"(\\priorowsemcard\{1\}.*?\{[0-9.,]+\\%\})", r"\1{\\priolink{grp-1-3-6-1-4-1-25623-1-0-992601}{\\#1}}")),
    ("ancora de card na executiva", V26, "es", "executive",
     before("\\end{document}", "\\hypertarget{fnd-1-3-6-1-4-1-25623-1-0-992611}{}\n")),
    ("secao a mais na executiva", V26, "es", "executive",
     before("\\suriBackCover", "\\clearpage\n\\hypertarget{sec-4}{}%\n\\suriSection{4}{Hosts y Puertos Abiertos}\n")),
    ("escopo com o numero 7 na executiva", V26, "es", "executive",
     repl("\\hypertarget{sec-3}{}%\n\\suriSection{3}", "\\hypertarget{sec-3}{}%\n\\suriSection{7}")),
    ("sumario com 4 linhas na executiva", V26, "es", "executive",
     before("\\end{suritoc}", "\\suritocrow{\\hyperlink{sec-4}{\\suritocline{4}{Hosts y Puertos Abiertos}}}\n")),
    ("marcador de nivel 1 na executiva", V26, "es", "executive",
     before("\\suriSection{2}", "\\suriBookmark{1}{bm-fnd-x}{\\#1\\space\\space X}\n")),
    ("corte citando os achados detalhados", V26, "es", "executive",
     repl("no listada(s) en esta tabla.}",
          "no listada(s) en esta tabla; cada una se describe en la sección Hallazgos Detallados.}")),
    ("aviso citando os indicadores", V22, "en", "executive",
     before("\\blocklabel{\\suriLblSeverityChart}",
            "\\warnbox{The \\textquotedblleft Indicators to validate\\textquotedblright\\ section.}\n")),
    ("capa sem a edicao executiva", V26, "es", "executive",
     repl("kicker={EDICIÓN EJECUTIVA}", "kicker={EVALUACIÓN DE VULNERABILIDADES}")),
]


# ---------------------------------------------------------------------------
# Mutantes do modo feed: o build-feed-xml.py (ou o generate canonico)
# ---------------------------------------------------------------------------
FEED_MUTANTES = [
    # (nome, o que quebra, arquivo relativo a report-formats/, [(trecho, troca)])
    ("controle", "nenhuma troca", "build-feed-xml.py", []),
    ("variante-errada-no-generate", "o generate do objeto da edicao do cliente pede a executiva",
     "build-feed-xml.py",
     [("for token, value in ((LANG_TOKEN, lang), (VARIANT_TOKEN, variant)):",
       "for token, value in ((LANG_TOKEN, lang), (VARIANT_TOKEN, {'client': 'executive'}.get(variant, variant))):")]),
    ("generate-sem-trocar-a-edicao", "o generate de todo objeto fica com a edicao canonica (technical)",
     "build-feed-xml.py",
     [("for token, value in ((LANG_TOKEN, lang), (VARIANT_TOKEN, variant)):",
       "for token, value in ((LANG_TOKEN, lang), (VARIANT_TOKEN, 'technical')):")]),
    ("uuid-do-tecnico-trocado", "o objeto tecnico EN ganha outro UUID",
     "build-feed-xml.py",
     [('("en",    "technical", "c6482c1b-57bb-406b-a501-c97eed86ad05"',
       '("en",    "technical", "c6482c1b-57bb-406b-a501-c97eed86ad06"')]),
    ("uuids-de-edicao-trocados", "os UUIDs do cliente EN e da executiva EN trocados",
     "build-feed-xml.py",
     [('("en",    "client",    "97ce15ea-69b9-4b0e-8799-ca0938b11bd6"',
       '("en",    "client",    "15195ce6-6093-4c4e-8f71-84205ea5a37b"'),
      ('("en",    "executive", "15195ce6-6093-4c4e-8f71-84205ea5a37b"',
       '("en",    "executive", "97ce15ea-69b9-4b0e-8799-ca0938b11bd6"')]),
    ("manifesto-sem-a-executiva", "o manifesto deixa a edicao executiva de fora",
     "build-feed-xml.py",
     [("            for lang, variant, fmt_id, name in FORMATS\n        ],",
       "            for lang, variant, fmt_id, name in FORMATS if variant != 'executive'\n        ],")]),
    ("nome-sem-idioma", "o nome do objeto do cliente PT-BR nao diz o idioma",
     "build-feed-xml.py",
     [('"Suricatoos PDF — Cliente (PT-BR)"', '"Suricatoos PDF — Cliente"')]),
    ("nomes-de-edicao-trocados", "os nomes do cliente EN e da executiva EN trocados (distintos, com idioma)",
     "build-feed-xml.py",
     [('"97ce15ea-69b9-4b0e-8799-ca0938b11bd6", "Suricatoos PDF — Client (EN)"',
       '"97ce15ea-69b9-4b0e-8799-ca0938b11bd6", "Suricatoos PDF — Executive (EN)"'),
      ('"15195ce6-6093-4c4e-8f71-84205ea5a37b", "Suricatoos PDF — Executive (EN)"',
       '"15195ce6-6093-4c4e-8f71-84205ea5a37b", "Suricatoos PDF — Client (EN)"')]),
    ("descritor-de-referencia-velho", "o texto do objeto tecnico EN muda e o descritor de referencia nao e' regerado",
     "build-feed-xml.py",
     [('"finding, the port and IP exposure map and the per-host appendix (English). "',
       '"finding, the port and IP exposure map and the per-host appendix (English), changed. "'),
      ('    with open(REFERENCE, "wb") as fh:\n        fh.write(reference_descriptor(version))\n',
       '    pass  # o descritor de referencia fica como estava\n')]),
    ("token-repetido-no-generate", "o generate canonico cita o par da edicao duas vezes",
     "suricatoos-premium-pdf/generate",
     [("rc=0\nxsltproc --stringparam lang en", "# --stringparam variant technical\nrc=0\nxsltproc --stringparam lang en")]),
    # --- o objeto leva EXATAMENTE os bytes do bundle (igualdade de conteudo) -----------------------
    ("membro-do-bundle-truncado", "o build embute um membro do bundle sem o ultimo byte",
     "build-feed-xml.py",
     [("        return b64_bytes(fh.read())\n", "        return b64_bytes(fh.read()[:-1])\n")]),
    ("sty-fora-do-objeto", "o build deixa um .sty do bundle de fora dos objetos (e da lista que declara)",
     "build-feed-xml.py",
     [('    styles = sorted(n for n in os.listdir(BUNDLE) if n.endswith(".sty"))\n',
       '    styles = sorted(n for n in os.listdir(BUNDLE) if n.endswith(".sty") and n != "suricatoos-hex.sty")\n')]),
    ("generate-alterado-alem-do-par", "o generate embutido ganha uma linha a mais, alem dos dois valores da edicao",
     "build-feed-xml.py",
     [("    return script\n", '    return script + b"# alterado\\n"\n')]),
    # --- a VERSION no objeto e no manifesto ---------------------------------------------------------
    ("marcador-de-versao-vazando", "a VERSION nunca e' preenchida: o marcador @VERSION@ vai para o objeto",
     "build-feed-xml.py",
     [("    return text.replace(VERSION_TOKEN, version)\n", "    return text\n")]),
    ("versao-velha-no-descritor-embutido", "o descritor embutido diz outra VERSION que o resumo do objeto",
     "build-feed-xml.py",
     [("% b64_bytes(report_format_xml_for(fmt_id, name, lang, variant, version)))",
       '% b64_bytes(report_format_xml_for(fmt_id, name, lang, variant, "sha256-000000000000")))')]),
    ("resumo-sem-a-versao", "o resumo do objeto tecnico EN nao diz a VERSION",
     "build-feed-xml.py",
     [('"finding, the port and IP exposure map and the per-host appendix (English). "\n'
       '        "Version " + VERSION_TOKEN + "."),',
       '"finding, the port and IP exposure map and the per-host appendix (English). "\n'
       '        "Version unknown."),')]),
    ("versao-no-manifesto", "o manifesto versionado volta a trazer a VERSION",
     "build-feed-xml.py",
     [('    return {\n        "report_formats": [', '    return {\n        "version": derive_version(),\n        "report_formats": [')]),
]
# O descritor de referencia velho so' existe se um build do builder INTACTO o escreveu antes.
FEED_PRE_BUILD = {"descritor-de-referencia-velho"}

# ---------------------------------------------------------------------------
# Mutantes da VERSION: o test_feed.py roda contra um build-feed-xml.py mutado
# (REPORT_FORMATS_DIR). Cada mutante quebra uma propriedade da VERSION por
# conteudo, e pelo menos um teste tem de reprovar.
# ---------------------------------------------------------------------------
SORTED_LOOP = "    for fname, text in sorted(feed_objects(VERSION_TOKEN), key=lambda o: o[0]):\n"
DIGEST_LOOP = SORTED_LOOP + "        data = text.encode(\"utf-8\")\n"
VERSAO_MUTANTES = [
    ("controle", "nenhuma troca", []),
    ("versao-fixa", "a VERSION e' uma constante: nenhum byte a mais a muda",
     [("    return VERSION_PREFIX + content_digest()[:VERSION_DIGITS]\n",
       '    return VERSION_PREFIX + "000000000000"\n')]),
    ("versao-com-relogio", "a VERSION mistura a hora do build: duas execucoes dao duas VERSIONs",
     [("    return VERSION_PREFIX + content_digest()[:VERSION_DIGITS]\n",
       "    import time\n"
       "    return VERSION_PREFIX + hashlib.sha256((content_digest() + repr(time.time())).encode()).hexdigest()"
       "[:VERSION_DIGITS]\n")]),
    ("versao-depende-do-diretorio", "o caminho da pasta do build entra na VERSION",
     [("    h = hashlib.sha256()\n" + SORTED_LOOP,
       "    h = hashlib.sha256(HERE.encode())\n" + SORTED_LOOP)]),
    ("versao-depende-da-data-do-arquivo", "a data de modificacao do latex.xsl entra na VERSION",
     [("    h = hashlib.sha256()\n" + SORTED_LOOP,
       "    h = hashlib.sha256(repr(os.path.getmtime(os.path.join(BUNDLE, 'latex.xsl'))).encode())\n" + SORTED_LOOP)]),
    ("versao-depende-da-ordem-de-FORMATS", "os objetos entram no hash na ordem de FORMATS: reordenar a lista muda a VERSION",
     [(SORTED_LOOP, "    for fname, text in feed_objects(VERSION_TOKEN):\n")]),
    ("versao-so-do-latex-xsl", "a VERSION so' olha o latex.xsl (os .sty, o catalogo e o texto do build nao a mudam)",
     [(DIGEST_LOOP,
       "    for fname, text in [('latex.xsl', open(os.path.join(BUNDLE, 'latex.xsl'), 'rb').read().decode('latin-1'))]:\n"
       "        data = text.encode(\"utf-8\")\n")]),
    ("versao-sem-os-objetos-es", "a VERSION ignora os objetos em espanhol (o catalogo es nao a muda)",
     [(DIGEST_LOOP,
       "    for fname, text in [o for o in feed_objects(VERSION_TOKEN) if o[0].split('-', 2)[2][:8] not in "
       "('91afce49', '9ebc0c90', '330072bd')]:\n        data = text.encode(\"utf-8\")\n")]),
    ("versao-sem-o-texto-do-build", "a VERSION so' olha os membros do bundle (resumo, descricao e nome nao a mudam)",
     [(DIGEST_LOOP,
       "    for fname, text in [(feed_object_name(f), ''.join(b64_file(os.path.join(BUNDLE, m)) for m in shared_files(l)))\n"
       "                        for l, v, f, n in FORMATS]:\n"
       "        data = text.encode(\"utf-8\")\n")]),
    ("marcador-de-versao-vazando", "a VERSION nunca e' preenchida: o marcador @VERSION@ vai para o objeto",
     [("    return text.replace(VERSION_TOKEN, version)\n", "    return text\n")]),
    ("manifesto-com-versao", "o manifesto versionado volta a trazer a VERSION",
     [('    return {\n        "report_formats": [', '    return {\n        "version": derive_version(),\n        "report_formats": [')]),
]


# ---------------------------------------------------------------------------
def transform(xsl, src, lang, variant, out):
    with open(out, "wb") as fh:
        fh.write(bytes(xsl(E.parse(src), lang=E.XSLT.strparam(lang), variant=E.XSLT.strparam(variant))))


def checks(lang, variant, xml, tex, bundle=None):
    """(reprovou?, [(checador, checagens reprovadas)], 1a mensagem)."""
    out_all, failed, msg = [], [], ""
    rc = 0
    for script in ("check-veracity.py", "check-navigation.py"):
        cmd = [sys.executable, "-X", "utf8", os.path.join(CI, script), "--lang", lang,
               "--variant", variant, "--xml", xml, "--tex", tex]
        if bundle:
            cmd += ["--bundle", bundle]
        r = subprocess.run(cmd, capture_output=True)
        out = r.stdout.decode("utf-8", "replace").splitlines()
        rc |= r.returncode
        names = [l.split()[1] for l in out if l.startswith("  FALHA ")]
        if names:
            failed.append("%s:%s" % (script.split("-")[1].split(".")[0], ",".join(names)))
        if r.returncode and not msg:
            msg = next((l.strip(" |") for l in out if l.startswith("           | ")),
                       r.stderr.decode("utf-8", "replace").strip()[-150:])
    return rc != 0, failed, msg


def mutate_bundle(work, name, subs):
    d = os.path.join(work, "m-" + name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for f in os.listdir(BUNDLE):
        if f == "latex.xsl" or f.startswith("nvt-i18n-"):
            shutil.copy(os.path.join(BUNDLE, f), d)
    p = os.path.join(d, "latex.xsl")
    s = open(p, encoding="utf-8").read()
    for a, b in subs:
        if isinstance(a, re.Pattern):
            s, n = a.subn(lambda _m: b, s)
        else:
            n = s.count(a)
            s = s.replace(a, b)
        if n != 1:
            raise SystemExit("mutante %s: trecho achado %d vez(es), esperado 1: %r"
                             % (name, n, (a.pattern if isinstance(a, re.Pattern) else a)[:90]))
    open(p, "w", encoding="utf-8", newline="\n").write(s)
    return d


def modo_xslt(work, only):
    bad = 0
    for name, what, subs, todo in MUTANTES:
        if only and name not in only and name != "controle":
            continue
        bundle = mutate_bundle(work, name, subs)
        try:
            xsl = E.XSLT(E.parse(os.path.join(bundle, "latex.xsl")))
        except (E.XSLTParseError, E.XMLSyntaxError) as e:
            print("%-36s %s\n    MUTANTE INVALIDO (o latex.xsl mutado nao compila): %s" % (name, what, e))
            bad += 1
            continue
        hits, n = [], 0
        for variant, fx in todo:
            for lang in LANGS:
                n += 1
                src = os.path.join(FIX, fx + ".xml")
                tex = os.path.join(bundle, "%s-%s-%s.tex" % (lang, variant, fx))
                if variant not in VARIANTS:
                    # A edicao fora do contrato: o latex.xsl tem de PARAR. Sair um
                    # .tex qualquer e' o defeito.
                    try:
                        transform(xsl, src, lang, variant, tex)
                    except E.XSLTApplyError:
                        continue
                    hits.append((lang, variant, fx, ["xslt:sem-erro"], "a edicao '%s' gerou um .tex" % variant))
                    continue
                try:
                    transform(xsl, src, lang, variant, tex)
                except E.XSLTApplyError as e:
                    hits.append((lang, variant, fx, ["xslt:erro"], "MUTANTE INVALIDO? o XSLT parou: %s" % e))
                    continue
                failed_run, failed, msg = checks(lang, variant, src, tex, bundle)
                if failed_run:
                    hits.append((lang, variant, fx, failed, msg))
        if name == "controle":
            ok = not hits
            verdict = "passa em todas (%d)" % n if ok else "REPROVOU: %s" % hits[:2]
        elif subs and todo and todo[0][0] not in VARIANTS:
            # O mutante da edicao desconhecida: reprovado se o .tex saiu.
            ok = bool(hits)
            verdict = ("REPROVADO em %d de %d; 1a: %s" % (len(hits), n, hits[0][4]) if ok
                       else "SOBREVIVEU (o latex.xsl intacto tambem para?)")
        else:
            ok = bool(hits)
            verdict = ("REPROVADO em %d de %d (%s); 1a: [%s/%s/%s %s] %s"
                       % (len(hits), n, ", ".join(sorted({h[2][:3] + "/" + h[1][:4] for h in hits})),
                          hits[0][0], hits[0][1], hits[0][2][:3], " ".join(hits[0][3]), hits[0][4][:140])
                       if ok else "SOBREVIVEU")
        bad += not ok
        print("%-36s %s\n    %s" % (name, what, verdict), flush=True)
    # O latex.xsl INTACTO para numa edicao fora do contrato (o par do mutante
    # acima): sem isso, o mutante provaria so' o checador.
    if not only or "edicao-desconhecida-cai-no-tecnico" in only:
        xsl = E.XSLT(E.parse(os.path.join(BUNDLE, "latex.xsl")))
        try:
            transform(xsl, os.path.join(FIX, "v1-numeracao.xml"), "en", "desconhecida",
                      os.path.join(work, "desconhecida.tex"))
            print("controle da edicao desconhecida: ERRO, o latex.xsl intacto gerou um .tex")
            bad += 1
        except E.XSLTApplyError as e:
            print("controle da edicao desconhecida: o latex.xsl intacto para (%s)" % str(e)[:90])
    return bad


def modo_tex(work, only):
    xsl = E.XSLT(E.parse(os.path.join(BUNDLE, "latex.xsl")))
    texdir = os.path.join(work, "tex")
    os.makedirs(texdir, exist_ok=True)
    bad = 0
    for name, fx, lang, variant, fn in CASOS_TEX:
        if only and name not in only and fn is not None:
            continue
        xml = os.path.join(FIX, fx + ".xml")
        orig = os.path.join(texdir, "%s-%s-%s.tex" % (lang, variant, fx))
        if not os.path.exists(orig):
            transform(xsl, xml, lang, variant, orig)
        s = open(orig, encoding="utf-8").read()
        if fn is not None:
            s2 = fn(s)
            if s2 == s:
                print("%-48s NADA MUDOU (caso mal escrito)" % name)
                bad += 1
                continue
            s = s2
        p = os.path.join(texdir, "caso.tex")
        open(p, "w", encoding="utf-8", newline="\n").write(s)
        failed_run, failed, msg = checks(lang, variant, xml, p)
        must_fail = fn is not None
        ok = failed_run == must_fail
        bad += not ok
        print("%-48s %-6s %-6s %-9s %s %s" % (name, fx[:6], lang, variant, "OK  " if ok else "ERRO",
                                             ("reprovou em %s: %s" % (" ".join(failed), msg[:100]))
                                             if failed_run else "passou"), flush=True)
    return bad


def copia_do_feed(work, name, rel, subs, pre_build=False):
    """Uma COPIA de report-formats/ so' com o que o build precisa (o builder, o
    check-manifest, o Dockerfile -- o test_feed.py executa a guarda do RUN dele --
    e o bundle, sem o descritor gerado: como numa `git archive'), com `subs'
    aplicadas ao arquivo `rel'. `pre_build' roda antes o builder INTACTO, para
    existir no disco o que o build mutado nao reescreve."""
    d = os.path.join(work, "feed-" + name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "ci"))
    shutil.copy(os.path.join(RF, "build-feed-xml.py"), d)
    shutil.copy(os.path.join(RF, "Dockerfile"), d)
    shutil.copy(os.path.join(CI, "check-manifest.py"), os.path.join(d, "ci"))
    shutil.copytree(BUNDLE, os.path.join(d, "suricatoos-premium-pdf"),
                    ignore=shutil.ignore_patterns("__pycache__", "report_format.xml"))
    if pre_build:
        subprocess.run([sys.executable, "-X", "utf8", os.path.join(d, "build-feed-xml.py")],
                       capture_output=True, check=True)
    p = os.path.join(d, rel)
    s = open(p, "rb").read().decode("utf-8")
    for a, b in subs:
        n = s.count(a)
        if n != 1:
            raise SystemExit("mutante feed %s: trecho achado %d vez(es), esperado 1: %r" % (name, n, a[:90]))
        s = s.replace(a, b)
    open(p, "wb").write(s.encode("utf-8"))
    return d


def modo_feed(work, only):
    bad = 0
    for name, what, rel, subs in FEED_MUTANTES:
        if only and name not in only and name != "controle":
            continue
        d = copia_do_feed(work, name, rel, subs, pre_build=name in FEED_PRE_BUILD)
        b = subprocess.run([sys.executable, "-X", "utf8", os.path.join(d, "build-feed-xml.py")],
                           capture_output=True)
        if b.returncode != 0:
            failed, msg = True, "o build recusou: " + b.stderr.decode("utf-8", "replace").strip().splitlines()[-1][:120]
        else:
            r = subprocess.run([sys.executable, "-X", "utf8", os.path.join(d, "ci", "check-manifest.py"),
                                "--dir", d], capture_output=True)
            out = r.stdout.decode("utf-8", "replace").splitlines()
            failed = r.returncode != 0
            msg = next((l.strip(" |") for l in out if l.startswith("  | ")), out[-1] if out else "")
        ok = (not failed) if name == "controle" else failed
        bad += not ok
        print("%-34s %s\n    %s %s" % (name, what, "OK  " if ok else "ERRO",
                                       ("reprovado: " + msg[:140]) if failed else "passou"), flush=True)
    return bad


def modo_versao(work, only):
    """Roda o tests/test_feed.py contra um build-feed-xml.py mutado: cada mutante
    quebra uma propriedade da VERSION por conteudo e algum teste tem de reprovar.
    O mutante tem de COMPILAR e RODAR (o build sai 0): um mutante invalido nao
    conta como reprovado."""
    bad = 0
    for name, what, subs in VERSAO_MUTANTES:
        if only and name not in only and name != "controle":
            continue
        d = copia_do_feed(work, "versao-" + name, "build-feed-xml.py", subs)
        b = subprocess.run([sys.executable, "-X", "utf8", os.path.join(d, "build-feed-xml.py")],
                           capture_output=True)
        if b.returncode != 0:
            print("%-34s %s\n    MUTANTE INVALIDO (o build mutado nao roda): %s"
                  % (name, what, b.stderr.decode("utf-8", "replace").strip().splitlines()[-1][:140]), flush=True)
            bad += 1
            continue
        env = dict(os.environ, REPORT_FORMATS_DIR=d)
        r = subprocess.run([sys.executable, "-X", "utf8", "-m", "unittest", "test_feed"],
                           cwd=HERE, env=env, capture_output=True)
        err = r.stderr.decode("utf-8", "replace").splitlines()
        reprovados = [l.split()[1] for l in err if l.startswith(("FAIL:", "ERROR:"))]
        failed = r.returncode != 0
        msg = ("%d teste(s): %s" % (len(reprovados), ", ".join(reprovados[:3]) + (", ..." if len(reprovados) > 3 else ""))
               if reprovados else (err[-1] if err else ""))
        ok = (not failed) if name == "controle" else failed
        bad += not ok
        print("%-34s %s\n    %s %s" % (name, what, "OK  " if ok else "ERRO",
                                       ("reprovado em " + msg[:170]) if failed else "passou"), flush=True)
    return bad


def modo_regressao(work, base):
    """A edicao tecnica sai IDENTICA, byte a byte, a do latex.xsl de `base' (um
    commit do git): o mesmo XML, o mesmo idioma, na mesma execucao (a data do
    relatorio e' a mesma nos dois). Roda a sample, toda fixture e a tortura
    (pt_BR e es), nos 3 idiomas; a tortura en usa a pt_BR, como o CI."""
    d = os.path.join(work, "regressao-base")
    os.makedirs(d, exist_ok=True)
    for f in ("latex.xsl",) + tuple("nvt-i18n-%s.xml" % lang for lang in LANGS):
        r = subprocess.run(["git", "-C", RF, "show", "%s:report-formats/suricatoos-premium-pdf/%s" % (base, f)],
                           capture_output=True)
        if r.returncode != 0:
            raise SystemExit("git show %s:%s falhou: %s" % (base, f, r.stderr.decode("utf-8", "replace")[-200:]))
        open(os.path.join(d, f), "wb").write(r.stdout)
    old = E.XSLT(E.parse(os.path.join(d, "latex.xsl")))
    new = E.XSLT(E.parse(os.path.join(BUNDLE, "latex.xsl")))
    inputs = [("sample", os.path.join(RF, "sample", "sample-report.xml"))]
    inputs += [(fx, os.path.join(FIX, fx + ".xml")) for fx in ALL_FIX]
    tort = {}
    for lang in ("pt_BR", "es"):
        p = os.path.join(work, "tortura-%s.xml" % lang)
        r = subprocess.run([sys.executable, "-X", "utf8", os.path.join(BUNDLE, "tools", "build-torture-fixture.py"),
                            lang], cwd=BUNDLE, capture_output=True)
        if r.returncode != 0 or not r.stdout:
            raise SystemExit("build-torture-fixture.py %s falhou" % lang)
        open(p, "wb").write(r.stdout)
        tort[lang] = p
    n = bad = 0
    for lang in LANGS:
        for name, src in inputs + [("tortura", tort["pt_BR" if lang == "en" else lang])]:
            a = bytes(old(E.parse(src), lang=E.XSLT.strparam(lang)))
            b = bytes(new(E.parse(src), lang=E.XSLT.strparam(lang), variant=E.XSLT.strparam("technical")))
            n += 1
            if a != b:
                bad += 1
                k = next(i for i in range(min(len(a), len(b)) + 1) if i >= min(len(a), len(b)) or a[i] != b[i])
                print("DIFERENTE %-44s %-6s 1o byte diferente em %d: %r x %r"
                      % (name, lang, k, a[max(0, k - 30):k + 30], b[max(0, k - 30):k + 30]))
    print("regressao da edicao tecnica contra %s: %d de %d .tex identicos" % (base, n - bad, n))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("modo", nargs="?", default="todos",
                    choices=("xslt", "tex", "feed", "versao", "regressao", "todos"))
    ap.add_argument("--so", nargs="*", default=[])
    ap.add_argument("--trabalho")
    ap.add_argument("--manter", action="store_true")
    ap.add_argument("--base", help="regressao: o commit cujo latex.xsl a edicao tecnica tem de reproduzir")
    a = ap.parse_args()
    if a.modo == "regressao" and not a.base:
        ap.error("regressao precisa de --base <commit>")
    work = a.trabalho or tempfile.mkdtemp(prefix="mutantes-variantes-")
    os.makedirs(work, exist_ok=True)
    bad = 0
    try:
        if a.modo == "regressao":
            print("== regressao da edicao tecnica", flush=True)
            bad += modo_regressao(work, a.base)
        if a.modo in ("xslt", "todos"):
            print("== mutantes do latex.xsl", flush=True)
            bad += modo_xslt(work, set(a.so))
        if a.modo in ("tex", "todos"):
            print("== edicoes do .tex", flush=True)
            bad += modo_tex(work, set(a.so))
        if a.modo in ("feed", "todos"):
            print("== mutantes do build-feed-xml.py e do generate", flush=True)
            bad += modo_feed(work, set(a.so))
        if a.modo in ("versao", "todos"):
            print("== mutantes da VERSION por conteudo (tests/test_feed.py)", flush=True)
            bad += modo_versao(work, set(a.so))
    finally:
        if not a.manter and not a.trabalho:
            shutil.rmtree(work, ignore_errors=True)
    ok = ("edicao tecnica identica a %s" % a.base if a.modo == "regressao"
          else "todo mutante reprovado, controles passam")
    print("RESULTADO: %s" % (ok if not bad else "%d problema(s)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
