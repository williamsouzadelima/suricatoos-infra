#!/usr/bin/env python3
"""Mutantes da secao 2 (prioridades e proximos passos) do Suricatoos Premium PDF.

FERRAMENTA DE DESENVOLVIMENTO: o CI NAO roda isto. Serve para provar que o
oraculo (report-formats/ci/check-veracity.py, checagem `prioridades' e as que
ela usa) REPROVA cada defeito que a secao 2 pode ter, e para refazer essa prova
quando o latex.xsl ou o oraculo mudarem. Roda em qualquer maquina com python3
e lxml (o libxslt do lxml e' o mesmo do `xsltproc --stringparam lang L' do
generate); nao precisa de TeX.

Dois modos:

  xslt  cada mutante troca um trecho do latex.xsl numa COPIA do bundle (o
        latex.xsl e os catalogos nvt-i18n-*), gera o .tex das fixtures nos 3
        idiomas e roda o check-veracity.py com --bundle no bundle MUTADO, como
        no CI (o oraculo le os parametros e as frases do latex.xsl que o
        generate usa). Cada mutante tem de ser REPROVADO (exit != 0) em pelo
        menos uma fixture; o controle (sem troca) tem de passar em todas. Os
        mutantes de traducao rodam na v5, na v22 e na tortura (pt_BR e es),
        gerada por tools/build-torture-fixture.py.
  tex   cada caso edita o .tex que o latex.xsl INTACTO gerou (uma fixture, um
        idioma): o oraculo tem de reprovar cada edicao, e os controles (o .tex
        intacto) tem de passar.

Uso (de qualquer diretorio; os caminhos saem da posicao deste arquivo):

  python3 report-formats/tests/mutantes-prioridades.py [xslt|tex|todos]
          [--so NOME ...] [--trabalho DIR] [--manter]

  --so        roda so' os mutantes/casos com esses nomes (o controle sempre);
  --trabalho  diretorio de trabalho (padrao: um temporario, apagado no fim);
  --manter    nao apaga o diretorio de trabalho (para ler os .tex mutados).

Sai 0 se todo mutante foi reprovado e todo controle passou. Para acrescentar um
mutante: uma entrada em MUTANTES (trecho EXATO do latex.xsl, que tem de
aparecer uma vez so', e a troca) ou em CASOS_TEX; um trecho que nao casa
exatamente uma vez para a execucao com erro, para o mutante nunca passar por
nao ter mudado nada.
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
    sys.exit("mutantes-prioridades.py precisa do lxml (pip install lxml)")

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.dirname(HERE)
BUNDLE = os.path.join(RF, "suricatoos-premium-pdf")
FIX = os.path.join(HERE, "fixtures")
CHECK = os.path.join(RF, "ci", "check-veracity.py")
LANGS = ("en", "pt_BR", "es")

V3, V4, V5, V8 = "v3-consolidado-qod", "v4-instancias", "v5-acao-traduzida", "v8-ancora"
V16 = "v16-escopo-agente-limpo"
V21, V22, V23 = "v21-prioridades-ordem", "v22-prioridades-cortes", "v23-prioridades-sem-criticos"
V24, V25, V26 = "v24-prioridades-vinte-acoes", "v25-prioridades-acao-unica", "v26-prioridades-cards"
NOVAS = [V21, V22, V23, V24, V25, V26]
ANTIGAS = ["v2-indicadores-vazios", V3, "v12-escopo-nao-iniciado", V16,
           "v17-escopo-concluido-vazio"]
GRUPOS = [V3, V4, V8, V22, V26]

# ---------------------------------------------------------------------------
# Trechos do latex.xsl (template priorities-section)
# ---------------------------------------------------------------------------
SORT = '<xsl:sort select="@%s" data-type="%s" order="%s"/>'
# O card de um NVT (1o passo, acts-rtf)
N_LOOP = '<!-- O card de um NVT. -->\n      <xsl:for-each select="$rows-conf">'
N_EPSS = 'math:max($inst[number(severity) &gt;= 0.1]/nvt/epss/max_epss/score[number(.) = number(.)])'
N_IF = ('<xsl:if test="$smax &gt;= 0.1">\n          <xsl:variable name="emax" '
        'select="' + N_EPSS + '"/>')
N_H = ('h="{count($inst[number(severity) &gt;= 0.1][string-length(normalize-space(host/text())) &gt; 0]\n'
       '                            [generate-id() = generate-id(key(\'by-prio-host\', '
       'concat(nvt/@oid, \'|\', normalize-space(host/text())))[1])])}"')
N_SOL = ('<sol>\n              <xsl:call-template name="nvt-i18n">\n'
         '                <xsl:with-param name="field" select="\'solution\'"/>\n'
         '                <xsl:with-param name="orig" select="string($sol-orig)"/>\n'
         '              </xsl:call-template>\n            </sol>')
N_NM = ('<nm>\n              <xsl:call-template name="nvt-i18n">\n'
        '                <xsl:with-param name="field" select="\'name\'"/>\n'
        '                <xsl:with-param name="orig" select="string(nvt/name)"/>\n'
        '              </xsl:call-template>\n            </nm>')
# O card consolidado (1o passo, acts-rtf)
G_LOOP = ('<xsl:for-each select="$grp-reps">\n'
          '        <xsl:sort select="gvm:sev-max(gvm:grp-members(gvm:grp(nvt/name)))" '
          'data-type="number" order="descending"/>\n'
          '        <xsl:variable name="g" select="gvm:grp(nvt/name)"/>\n'
          '        <xsl:variable name="members" select="gvm:grp-members($g)"/>\n'
          '        <xsl:variable name="smax" select="gvm:sev-max($members)"/>')
G_GNUM = '<xsl:variable name="gnum" select="position()"/>'
G_EPSS = 'math:max($members[number(severity) &gt;= 0.1]/nvt/epss/max_epss/score[number(.) = number(.)])'
G_IF = ('<xsl:if test="$smax &gt;= 0.1">\n          <xsl:variable name="emax" '
        'select="' + G_EPSS + '"/>')
G_HFILTER = ('<xsl:for-each select="$members[number(severity) &gt;= 0.1]'
             '[string-length(normalize-space(host/text())) &gt; 0]">')
G_A = '          <a o="{nvt/@oid}" n="{$g}" k="{$g}" s="{$smax}"'
G_H = 'h="{count(exsl:node-set($gh-rtf)/h[not(@v = preceding-sibling::h[1]/@v)])}"'
G_X = 'x="{count($members[number(severity) &gt;= 7.0])}" t="VendorFix"'
G_LK = 'lk="{concat(\'grp-\', translate(nvt/@oid, \'.\', \'-\'))}" ln="{$gnum}">'
G_CV = '<xsl:attribute name="cv"><xsl:value-of select="severity"/></xsl:attribute>'
G_ACT = ('                    <xsl:when test="string-length(normalize-space(nvt/solution)) &gt; 0">\n'
         '                      <xsl:value-of select="nvt/solution"/>')
G_SOL = ('<sol>\n                  <xsl:call-template name="nvt-i18n">\n'
         '                    <xsl:with-param name="field" select="\'solution\'"/>\n'
         '                    <xsl:with-param name="orig" select="string($act-orig)"/>\n'
         '                  </xsl:call-template>\n                </sol>')
G_TITLE = ('<xsl:call-template name="escape_name">\n'
           '              <xsl:with-param name="string" select="string(@k)"/>\n'
           '            </xsl:call-template>')
# A expressao do `use' de by-updgrp (a chave do produto), por extenso.
GRP_USE = ("concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',"
           "substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' '))")
PRIO_KEY_USE = '           use="concat(nvt/@oid, \'|\', normalize-space(host/text()))"/>'
REP = G_GNUM + '\n        <xsl:variable name="rep" select="."/>'

# (nome, o que o mutante quebra, [(trecho, troca)], fixtures)
MUTANTES = [
    ("controle", "nenhuma troca", [], sorted(set(NOVAS + ANTIGAS + GRUPOS))),
    # --- a ordem ------------------------------------------------------------
    ("hosts-crescente", "hosts afetados em ordem crescente",
     [(SORT % ("h", "number", "descending"), SORT % ("h", "number", "ascending"))], NOVAS),
    ("ignora-hosts", "tira a chave de hosts afetados",
     [(SORT % ("h", "number", "descending") + "\n", "")], NOVAS),
    ("ignora-epss", "tira a chave do EPSS",
     [(SORT % ("e", "number", "descending") + "\n", "")], NOVAS),
    ("epss-crescente", "EPSS em ordem crescente",
     [(SORT % ("e", "number", "descending"), SORT % ("e", "number", "ascending"))], NOVAS),
    ("cvss-crescente", "maior CVSS em ordem crescente",
     [(SORT % ("s", "number", "descending"), SORT % ("s", "number", "ascending"))], NOVAS),
    ("nome-decrescente", "nome em ordem decrescente",
     [(SORT % ("n", "text", "ascending"), SORT % ("n", "text", "descending"))], NOVAS),
    ("nome-por-idioma", "nome comparado pela colacao do idioma (lang), nao ponto de codigo",
     [(SORT % ("n", "text", "ascending"),
       '<xsl:sort select="@n" data-type="text" order="ascending" lang="en"/>')], NOVAS),
    ("oid-decrescente", "OID em ordem decrescente",
     [(SORT % ("o", "text", "ascending"), SORT % ("o", "text", "descending"))], NOVAS),
    ("hosts-antes-da-classe", "precedencia: hosts antes da classe de severidade",
     [(SORT % ("r", "number", "descending") + "\n        " + SORT % ("h", "number", "descending"),
       SORT % ("h", "number", "descending") + "\n        " + SORT % ("r", "number", "descending"))],
     NOVAS),
    ("cvss-antes-do-epss", "precedencia: maior CVSS antes do EPSS",
     [(SORT % ("e", "number", "descending") + "\n        " + SORT % ("s", "number", "descending"),
       SORT % ("s", "number", "descending") + "\n        " + SORT % ("e", "number", "descending"))],
     NOVAS),
    # --- contagens e conjunto de um NVT ---------------------------------------
    ("hosts-instancias", "hosts de um NVT: conta instancias, nao hosts distintos",
     [(N_H, 'h="{count($inst[number(severity) &gt;= 0.1])}"')], NOVAS),
    ("hosts-com-falso-positivo", "o host de uma instancia falso positivo conta como afetado",
     [('match="result[number(severity) &gt;= 0.1]"\n           use="concat(nvt/@oid',
       'match="result"\n           use="concat(nvt/@oid'),
      ('h="{count($inst[number(severity) &gt;= 0.1][string-length',
       'h="{count($inst[string-length')], NOVAS),
    ("hosts-so-confiaveis", "o host de uma instancia de baixa confianca de NVT confirmado nao conta",
     [('h="{count($inst[number(severity) &gt;= 0.1][string-length',
       'h="{count($inst[number(severity) &gt;= 0.1][not(qod/value and number(qod/value) '
       '&lt; number($qod-min))][string-length')], NOVAS),
    ("epss-do-max-severity", "EPSS do CVE de maior severidade (max_severity), nao o max_epss",
     [(N_EPSS, N_EPSS.replace("/nvt/epss/max_epss/", "/nvt/epss/max_severity/"))], NOVAS),
    ("epss-do-nvt-com-falso-positivo", "EPSS de um NVT: o maior de TODA instancia, falso positivo e Log inclusive",
     [(N_EPSS, N_EPSS.replace("$inst[number(severity) &gt;= 0.1]", "$inst"))], NOVAS),
    ("indicador-no-plano", "o indicador (QoD abaixo do piso) entra no plano",
     [(N_LOOP, N_LOOP.replace('"$rows-conf"', '"$rows-conf | $nvt-low"'))], NOVAS + ANTIGAS),
    ("log-no-plano", "Log e falso positivo entram no plano",
     [(N_IF, N_IF.replace("$smax &gt;= 0.1", "$smax = $smax"))], NOVAS + ANTIGAS),
    ("x-de-todas", "X conta as instancias de todas as acoes, nao so' das N primeiras",
     [('<xsl:variable name="xtop" select="sum($acts[position() &lt;= $nshow]/@x)"/>',
       '<xsl:variable name="xtop" select="sum($acts/@x)"/>')], NOVAS),
    ("y-instancias-do-nvt", "Y conta toda instancia de NVT critico/alto, nao as >= 7.0",
     [('x="{count($inst[number(severity) &gt;= 7.0])}"', 'x="{count($inst[$smax &gt;= 7.0])}"')],
     NOVAS),
    # --- o card consolidado: UMA acao ------------------------------------------
    ("grupo-partido", "o card consolidado volta a ser uma acao por advisory",
     [(N_LOOP, N_LOOP.replace('"$rows-conf"', '"$nvt-conf"')),
      (G_IF, G_IF.replace("$smax &gt;= 0.1", "false()"))], GRUPOS),
    ("hosts-do-grupo-somados", "hosts do grupo: a SOMA dos hosts de cada membro, nao a uniao",
     [(G_A, '          <xsl:variable name="gs-rtf">\n'
            '            <xsl:for-each select="gvm:grp-confreps($g)">\n'
            '              <c n="{count(key(\'by-nvt\', nvt/@oid)[number(severity) &gt;= 0.1]'
            '[string-length(normalize-space(host/text())) &gt; 0][generate-id() = '
            'generate-id(key(\'by-prio-host\', concat(nvt/@oid, \'|\', '
            'normalize-space(host/text())))[1])])}"/>\n'
            '            </xsl:for-each>\n'
            '          </xsl:variable>\n' + G_A),
      (G_H, 'h="{sum(exsl:node-set($gs-rtf)/c/@n)}"')], GRUPOS),
    ("hosts-do-grupo-com-falso-positivo", "hosts do grupo: Log e falso positivo contam",
     [(G_HFILTER, '<xsl:for-each select="$members[string-length(normalize-space(host/text())) &gt; 0]">')],
     GRUPOS),
    ("hosts-do-grupo-chave-por-produto",
     "hosts do grupo por uma chave de Muenchian produto+host, no molde do by-updgrp",
     [(PRIO_KEY_USE, PRIO_KEY_USE + '\n  <xsl:key name="by-prio-ghost" '
       'match="result[nvt/solution/@type=\'VendorFix\'][number(severity) &gt;= 0.1]"\n'
       '           use="concat(' + GRP_USE + ', \'|\', normalize-space(host/text()))"/>'),
      (G_H, 'h="{count($members[number(severity) &gt;= 0.1][string-length(normalize-space('
            'host/text())) &gt; 0][generate-id() = generate-id(key(\'by-prio-ghost\', '
            'concat($g, \'|\', normalize-space(host/text())))[1])])}"')], GRUPOS),
    ("epss-do-representante", "EPSS do grupo so' do representante",
     [(G_EPSS, "math:max(key('by-nvt', nvt/@oid)[number(severity) &gt;= 0.1]/nvt/epss/max_epss/score"
               "[number(.) = number(.)])")], GRUPOS),
    ("epss-do-mais-severo", "EPSS do grupo so' do membro mais severo",
     [(G_EPSS, "math:max($members[number(severity) = $smax]/nvt/epss/max_epss/score"
               "[number(.) = number(.)])")], GRUPOS),
    ("epss-do-grupo-com-falso-positivo",
     "EPSS do grupo: o maior de TODA instancia dos membros, falso positivo e Log inclusive",
     [(G_EPSS, G_EPSS.replace("$members[number(severity) &gt;= 0.1]", "$members"))], GRUPOS),
    ("acao-do-representante", "acao do grupo: a do representante, nao a do membro mais severo",
     [(G_GNUM, REP),
      (G_ACT, G_ACT.replace("nvt/solution", "$rep/nvt/solution"))], GRUPOS),
    ("cvss-do-representante", "CVSS do grupo: o do representante, nao o maximo do card",
     [(G_GNUM, REP),
      (G_CV, '<xsl:attribute name="cv"><xsl:value-of select="$rep/severity"/></xsl:attribute>')],
     GRUPOS),
    ("link-do-grupo-no-fnd", "o link do grupo leva ao fnd- de um membro, nao ao card grp-",
     [(G_LK, G_LK.replace("concat('grp-', translate(nvt/@oid,",
                          "concat('fnd-', translate($members[number(severity) = $smax][1]/nvt/@oid,"))],
     GRUPOS),
    ("numero-do-grupo-pelo-documento", "o #N do grupo pela ordem do documento, nao a dos cards",
     [(G_LOOP, G_LOOP.replace(
         '\n        <xsl:sort select="gvm:sev-max(gvm:grp-members(gvm:grp(nvt/name)))" '
         'data-type="number" order="descending"/>', ""))], GRUPOS),
    ("grupo-com-indicador", "advisory indicador do produto (nao membro) entra no grupo",
     [(G_LOOP, G_LOOP.replace('select="gvm:grp-members($g)"', 'select="key(\'by-updgrp\', $g)"'))],
     GRUPOS),
    ("grupo-so-log-no-plano", "grupo cujos membros sao todos Log/falso positivo entra no plano",
     [(G_IF, G_IF.replace("$smax &gt;= 0.1", "$smax = $smax"))], GRUPOS),
    ("nome-do-grupo-pelo-titulo", "chave de nome do grupo: o titulo traduzido, nao a do produto",
     [(G_A, G_A.replace('n="{$g}"', 'n="{concat(gvm:t(\'grp_title\'), \': \', $g)}"'))], GRUPOS),
    ("nome-do-grupo-do-representante", "chave de nome do grupo: o nome do representante",
     [(G_A, G_A.replace('n="{$g}"', 'n="{normalize-space(nvt/name)}"'))], GRUPOS),
    ("oid-do-grupo-mais-severo", "chave de OID do grupo: a do membro mais severo",
     [(G_A, G_A.replace('o="{nvt/@oid}"', 'o="{$members[number(severity) = $smax][1]/nvt/@oid}"'))],
     GRUPOS),
    ("x-do-grupo-so-representante", "X/Y de um grupo: so' as instancias do representante",
     [(G_X, G_X.replace("count($members[", "count(key('by-nvt', nvt/@oid)["))], GRUPOS),
    ("tipo-do-grupo-ausente", "o tipo do grupo sai vazio (travessao)",
     [(G_X, G_X.replace('t="VendorFix"', 't=""'))], GRUPOS),
    ("titulo-do-grupo-sem-escape", "o titulo do grupo sai sem o escape do card",
     [(G_TITLE, '<xsl:value-of select="@k"/>')], GRUPOS),
    # --- teto, corte e frase -----------------------------------------------------
    ("corte-com-maior-igual", "declara corte com exatamente 20 acoes (+ 0)",
     [('<xsl:if test="$nact &gt; number($prio-rows-max)">',
       '<xsl:if test="$nact &gt;= number($prio-rows-max)">')], NOVAS),
    ("tabela-com-19", "a tabela para uma linha antes do teto",
     [('<xsl:for-each select="$acts[position() &lt;= $nshow]">',
       '<xsl:for-each select="$acts[position() &lt; $nshow]">')], NOVAS),
    ("frase-sem-forma-de-um", "sem a forma do achado unico (sai '1 de 1')",
     [('<xsl:when test="$ytot = 1"><xsl:value-of select="gvm:t(\'prio_sum_one\')"/></xsl:when>', "")],
     NOVAS + ANTIGAS),
    ("frase-sem-forma-sem-host", "sem a forma de nada medido (sai 'nao ha criticos')",
     [('<xsl:when test="$nact = 0 and $nhosts = 0"><xsl:value-of '
       'select="gvm:t(\'prio_sum_nohost\')"/></xsl:when>', "")], NOVAS + ANTIGAS),
    ("frase-sem-forma-de-uma-acao", "sem a forma de uma acao so' (sai 'As 1 primeiras')",
     [('<xsl:when test="$nshow = 1">', '<xsl:when test="false()">')], NOVAS),
    # --- a coluna de acao ----------------------------------------------------------
    ("acao-solucao-inteira", "a acao e' a solucao inteira, nao a primeira frase",
     [('<xsl:with-param name="string" select="string($fs)"/>',
       '<xsl:with-param name="string" select="$S"/>')], NOVAS),
    ("item-numerado-fecha", '"1." e "10." fecham a primeira frase',
     [("and translate($stem, '0123456789', '') != ''\n", "\n")], NOVAS),
    ("abreviacao-fecha", '"e.g." fecha a primeira frase',
     [("and not(contains(' e.g i.e p.ex p.ej ex ej vs cf approx incl ',", "and not(contains(' ',")],
     NOVAS),
    ("uma-letra-fecha", '"p." (uma letra) fecha a primeira frase',
     [("and string-length($stem) &gt; 1\n", "and string-length($stem) &gt; 0\n")], NOVAS),
    ("acao-teto-200", "corta a acao em 200, nao em $prio-action-max",
     [('<xsl:with-param name="max" select="$prio-action-max"/>',
       '<xsl:with-param name="max" select="200"/>')], NOVAS),
    ("sem-solucao-vazio", "card sem solucao sai com a celula vazia",
     [('<xsl:when test="string-length($S) = 0"><xsl:text>\\prionosol</xsl:text></xsl:when>',
       '<xsl:when test="string-length($S) = 0"/>')], NOVAS),
    ("acao-sem-normalizar", "a solucao nao e' normalizada antes da primeira frase",
     [('<xsl:variable name="S" select="normalize-space(sol)"/>',
       '<xsl:variable name="S" select="string(sol)"/>')], NOVAS),
    # --- as outras colunas -----------------------------------------------------------
    ("tipo-ausente-vira-vendorfix", "NVT sem tipo de solucao sai como Vendor Fix",
     [('<xsl:otherwise><xsl:text>---</xsl:text></xsl:otherwise>\n        </xsl:choose>\n'
       '        <xsl:text>}{</xsl:text><xsl:value-of select="gvm:num(@h)"/>',
       '<xsl:otherwise><xsl:value-of select="gvm:t(\'st_VendorFix\')"/></xsl:otherwise>\n'
       '        </xsl:choose>\n'
       '        <xsl:text>}{</xsl:text><xsl:value-of select="gvm:num(@h)"/>')], NOVAS),
    ("epss-sem-porcentagem", "EPSS impresso como fracao (sem * 100)",
     [("format-number(number($e) * 100, '0.0##')", "format-number(number($e), '0.0##')"),
      ("format-number(number($e) * 100, '0,0##', 'ptes')", "format-number(number($e), '0,0##', 'ptes')")],
     NOVAS),
    ("card-sem-os-grupos", "o numero do card normal ignora os cards consolidados",
     [('<c o="{nvt/@oid}" n="{position() + count($grp-reps)}"/>', '<c o="{nvt/@oid}" n="{position()}"/>')],
     NOVAS),
    ("link-hyperlink", "o link da tabela sai como \\hyperlink (entraria na conta exata do gates.sh)",
     [('<xsl:text>}{\\priolink{</xsl:text>', '<xsl:text>}{\\hyperlink{</xsl:text>')], NOVAS),
    # --- notas ---------------------------------------------------------------------------
    ("sem-nota-de-indicadores", "tira a nota dos indicadores fora do plano",
     [('<xsl:if test="$nind &gt; 0">', '<xsl:if test="false()">')], NOVAS + ANTIGAS),
    ("sem-nota-de-export-parcial", "tira a nota de export parcial",
     [('<xsl:if test="$export-partial">\n      <xsl:text>\\blocknote{</xsl:text><xsl:value-of '
       'select="gvm:t(\'prio_partial_a\')"/>',
       '<xsl:if test="false()">\n      <xsl:text>\\blocknote{</xsl:text><xsl:value-of '
       'select="gvm:t(\'prio_partial_a\')"/>')], NOVAS),
    ("sem-nota-epss-ausente", "tira a nota de EPSS nao informado",
     [('<xsl:when test="$nact &gt; 0 and not($epss-any)">', '<xsl:when test="false()">')],
     NOVAS + ANTIGAS),
    ("sem-nota-epss-parcial", "tira a nota do travessao de EPSS",
     [('<xsl:when test="$nact &gt; 0 and $acts[position() &lt;= $nshow][string-length(@e) = 0]">',
       '<xsl:when test="false()">')], NOVAS),
    ("sem-nota-nenhuma-acao", "tira a nota de nenhuma acao",
     [('<xsl:if test="$nact = 0 and $nhosts &gt; 0">', '<xsl:if test="false()">')], NOVAS + ANTIGAS),
    ("ordem-sem-acoes", "imprime a frase da ordem mesmo sem acao",
     [('<xsl:if test="$nact &gt; 0">\n      <xsl:text>\\suriPara{</xsl:text><xsl:value-of '
       'select="gvm:t(\'prio_order\')"/>',
       '<xsl:if test="true()">\n      <xsl:text>\\suriPara{</xsl:text><xsl:value-of '
       'select="gvm:t(\'prio_order\')"/>')], NOVAS + ANTIGAS),
]
# Traducao: a v5 (um grupo de OIDs publicos do catalogo com nome e solucao do
# fornecedor sinteticos, que a traducao troca), a v22 (um NVT avulso no mesmo
# caso) e a tortura (o catalogo inteiro, pt_BR e es; ali o nome e a solucao do
# XML ja' sao os do catalogo, entao ela so' pega o que a v5 e a v22 nao pegam).
MUTANTES_TRADUCAO = [
    ("nome-original", "a linha mostra o nome original do NVT, nao o traduzido",
     [(N_NM, '<nm><xsl:value-of select="nvt/name"/></nm>')]),
    ("solucao-original", "a acao de um NVT vem da solucao do fornecedor, nao da traduzida",
     [(N_SOL, '<sol><xsl:value-of select="$sol-orig"/></sol>')]),
    ("acao-do-grupo-original", "a acao do grupo vem da solucao do fornecedor, nao da traduzida",
     [(G_SOL, '<sol><xsl:value-of select="$act-orig"/></sol>')]),
]


# ---------------------------------------------------------------------------
# Casos do modo tex: edicoes do .tex gerado pelo latex.xsl intacto
# ---------------------------------------------------------------------------
def rows_of(s):
    """[(inicio, fim)] de cada \\priorow do .tex (uma linha logica cada)."""
    out = []
    for m in re.finditer(r"\\priorow\{", s):
        end = s.find("\n\\priorow{", m.start() + 1)
        if end < 0:
            end = s.find("\n\\end{prioritytable}", m.start())
        out.append((m.start(), end + 1))
    return out


def swap_rows(i, j):
    def f(s):
        r = rows_of(s)
        a, b = s[r[i][0]:r[i][1]], s[r[j][0]:r[j][1]]
        na = re.sub(r"^\\priorow\{\d+\}", "\\\\priorow{%d}" % (j + 1), a)
        nb = re.sub(r"^\\priorow\{\d+\}", "\\\\priorow{%d}" % (i + 1), b)
        return s[:r[i][0]] + nb + s[r[i][1]:r[j][0]] + na + s[r[j][1]:]
    return f


def in_row(i, old, new):
    def f(s):
        r = rows_of(s)
        a = s[r[i][0]:r[i][1]]
        if old not in a:
            raise SystemExit("caso tex: %r nao esta' na linha %d: %r" % (old, i + 1, a[:200]))
        return s[:r[i][0]] + a.replace(old, new, 1) + s[r[i][1]:]
    return f


def repl(old, new):
    def f(s):
        if old not in s:
            raise SystemExit("caso tex: %r nao esta' no .tex" % old)
        return s.replace(old, new, 1)
    return f


def drop_row(i):
    def f(s):
        r = rows_of(s)
        return s[:r[i][0]] + s[r[i][1]:]
    return f


def dup_last_row(s):
    r = rows_of(s)
    a = s[r[-1][0]:r[-1][1]]
    return s[:r[-1][1]] + re.sub(r"^\\priorow\{\d+\}", "\\\\priorow{%d}" % (len(r) + 1), a) + s[r[-1][1]:]


def move_summary_after_table(s):
    m = re.search(r"\\priosummary\{[^\n]*\}\n", s)
    s2 = s[:m.start()] + s[m.end():]
    k = s2.find("\\end{prioritytable}\n") + len("\\end{prioritytable}\n")
    return s2[:k] + m.group(0) + s2[k:]


def drop_note(prefix):
    def f(s):
        return re.sub(r"\\blocknote\{%s[^\n]*\}\n" % re.escape(prefix), "", s, count=1)
    return f


def add_before_sec3(line):
    def f(s):
        k = s.rfind("\\clearpage", 0, s.find("\\hypertarget{sec-3}{}"))
        return s[:k] + line + "\n" + s[k:]
    return f


V8_TITLE = ("{Outstanding update: Acme\\_\\surjb{}\\&\\surjb{}\\%\\#%\n\\surwbvis{}\\$ "
            "Wid\\textasciitilde{}\\textasciicircum{}e%\n\\surwbvis{}t}")
FAB = "grp-1-3-6-1-4-1-25623-1-0-992601"
CASOS_TEX = [
    # (nome, fixture, idioma, edicao ou None = controle)
    ("controle v21", V21, "en", None),
    ("controle v22", V22, "pt_BR", None),
    ("controle v26", V26, "es", None),
    ("controle v16", V16, "es", None),
    # ordem
    ("duas linhas trocadas", V21, "en", swap_rows(1, 2)),
    ("empate de nome invertido", V21, "en", swap_rows(5, 6)),
    ("empate de OID invertido", V21, "en", swap_rows(10, 11)),
    ("empate de caixa invertido (Zeta, beta)", V21, "en", swap_rows(13, 14)),
    ("empate de acento invertido (Bravo, Agata)", V21, "en", swap_rows(15, 16)),
    ("grupo e avulso de mesmo nome invertidos", V26, "en", swap_rows(2, 3)),
    ("grupo e critico avulso invertidos (EPSS)", V26, "en", swap_rows(0, 1)),
    # colunas
    ("numero da linha errado", V21, "en", in_row(2, "\\priorow{3}", "\\priorow{4}")),
    ("hosts errado", V21, "en", in_row(0, "}{3}{critico}", "}{2}{critico}")),
    ("severidade errada", V21, "en", in_row(0, "}{critico}{9.8}", "}{alto}{9.8}")),
    ("CVSS errado", V21, "en", in_row(0, "{critico}{9.8}", "{critico}{9.9}")),
    ("EPSS errado", V21, "en", in_row(1, "{50.0\\%}", "{0.5\\%}")),
    ("EPSS inventado", V21, "en", in_row(3, "{9.8}{---}", "{9.8}{1.0\\%}")),
    ("EPSS omitido", V21, "en", in_row(1, "{50.0\\%}", "{---}")),
    ("tipo de solucao errado", V21, "en", in_row(1, "{Mitigation}", "{Workaround}")),
    ("tipo ausente com palavra", V22, "en", in_row(4, "}{---}{1}", "}{Vendor Fix}{1}")),
    ("nome do NVT errado", V21, "en", in_row(0, "Gateway", "Gate")),
    ("acao com a solucao inteira", V21, "en",
     in_row(0, "later.\\surjb{}}", "later.\\surjb{} Restart the appliance afterwards.}")),
    ("acao cortada sem declarar", V22, "en", repl("\\suriTruncMark{135}", "")),
    ("corte declarado com N errado", V22, "en", repl("\\suriTruncMark{135}", "\\suriTruncMark{134}")),
    ("sem solucao com texto", V22, "en", in_row(4, "\\prionosol", "Unknown.")),
    ("solucao trocada por sem solucao", V21, "en", lambda s: re.sub(
        r"(\\priorow\{1\}\{).*?(\}\{Example %)", r"\1\\prionosol\2", s, count=1, flags=re.S)),
    # links
    ("link para outro card", V21, "en",
     in_row(0, "fnd-1-3-6-1-4-1-25623-1-0-992101", "fnd-1-3-6-1-4-1-25623-1-0-992103")),
    ("numero do card errado", V21, "en", in_row(0, "{\\#1}", "{\\#2}")),
    ("link para alvo inexistente", V21, "en",
     in_row(0, "fnd-1-3-6-1-4-1-25623-1-0-992101", "fnd-1-3-6-1-4-1-25623-1-0-999999")),
    ("\\hyperlink no lugar do \\priolink", V21, "en", in_row(0, "\\priolink{", "\\hyperlink{")),
    # o card consolidado
    ("grupo com a acao do representante", V4, "en", in_row(1, "ory 2.\\surjb{}}", "ory 1.\\surjb{}}")),
    ("grupo com hosts somados", V26, "en", in_row(0, "}{3}{critico}", "}{7}{critico}")),
    ("grupo com os hosts do chip do card", V26, "en", in_row(0, "}{3}{critico}", "}{6}{critico}")),
    ("grupo com o EPSS do representante", V26, "en", in_row(0, "{42.0\\%}", "{---}")),
    ("grupo com o EPSS do mais severo", V26, "en", in_row(0, "{42.0\\%}", "{12.0\\%}")),
    ("grupo com o EPSS do membro so' falso positivo", V26, "en", in_row(0, "{42.0\\%}", "{77.0\\%}")),
    ("NVT com o EPSS da instancia falso positivo", V26, "en", in_row(1, "{30.0\\%}", "{95.0\\%}")),
    ("grupo com o CVSS do representante", V26, "en", in_row(0, "{critico}{9.6}", "{critico}{7.4}")),
    ("grupo com o nome do representante", V26, "en",
     in_row(0, "{Outstanding update: Fabrikam Portal}", "{Fabrikam Portal Advisory (FB-01)}")),
    ("grupo sem solucao com o texto do representante", V26, "en",
     in_row(2, "{\\prionosol}", "{Upgrade Contoso Gateway to version 3.1 or later.}")),
    ("grupo com tipo ausente", V26, "en", in_row(2, "{Vendor Fix}", "{---}")),
    ("link do grupo para o fnd do membro", V26, "en",
     in_row(0, FAB, "fnd-1-3-6-1-4-1-25623-1-0-992603")),
    ("link do grupo com o numero de um card normal", V26, "en", in_row(0, "{\\#1}", "{\\#5}")),
    ("titulo do grupo sem escape", V8, "en", in_row(0, V8_TITLE, "{Outstanding update: Acme_&%#$ Wid~^et}")),
    # quantidade de linhas, corte e frase
    ("linha a mais", V21, "en", dup_last_row),
    ("linha a menos", V21, "en", drop_row(12)),
    ("sem o corte declarado", V26, "en", lambda s: re.sub(r"\\priotrunc\{[^\n]*\}\n", "", s)),
    ("corte com N errado", V26, "pt_BR", repl("\\suriEllip\\ + 3 ", "\\suriEllip\\ + 2 ")),
    ("corte indevido", V24, "es", add_before_sec3(
        "\\priotrunc{\\suriEllip\\ + 0 acción(es) más, no listada(s) en esta tabla; cada una se "
        "describe en la sección Hallazgos Detallados.}")),
    ("frase com X errado", V26, "en", repl("address 32 of the 33", "address 31 of the 33")),
    ("frase com Y errado", V26, "en", repl("address 32 of the 33", "address 32 of the 34")),
    ("frase com N errado", V21, "pt_BR", repl("As 17 primeiras", "As 16 primeiras")),
    ("frase 0 de 0", V23, "en", repl(
        "This report has no confirmed critical or high findings.",
        "The first 3 actions address 0 of the 0 confirmed critical and high findings.")),
    ("frase 1 de 1", V24, "pt_BR", repl(
        "A primeira ação trata o único achado crítico ou alto confirmado.",
        "As 20 primeiras ações tratam 1 de 1 achados críticos e altos confirmados.")),
    ("frase de nada medido em relatorio com host", V16, "en", repl(
        "This report has no confirmed critical or high findings.",
        "No host was measured, so there is nothing to prioritise --- and that is not evidence "
        "that there is nothing to fix.")),
    # notas e blocos
    ("sem a nota de indicadores", V21, "en", drop_note("Left out of this plan")),
    ("sem a nota de indicadores (advisory do grupo)", V26, "en", drop_note("Left out of this plan")),
    ("sem a nota de export parcial", V22, "en", drop_note("Partial export")),
    ("sem a nota do travessao de EPSS", V21, "en", drop_note("In the EPSS column")),
    ("nota de EPSS ausente indevida", V25, "en", add_before_sec3(
        "\\blocknote{EPSS not stated in the report: the EPSS column reads --- and the criterion "
        "plays no part in the order.}")),
    ("nota de indicadores com N errado", V21, "pt_BR",
     repl("Fora deste plano: 1 indicador", "Fora deste plano: 2 indicador")),
    ("introducao com outro piso", V21, "en", repl("at least 70\\%) of Low", "at least 80\\%) of Low")),
    ("frase da ordem sem acao", V16, "en", lambda s: s.replace(
        "\\priosummary{", "\\suriPara{Order: severity class (Critical, High, Medium, Low).}\n"
        "\\priosummary{", 1)),
    ("frase depois da tabela", V21, "en", move_summary_after_table),
    ("tabela vazia sem acao", V16, "en", lambda s: s.replace(
        "\\blocknote{No action", "\\begin{prioritytable}\n\\end{prioritytable}\n\\blocknote{No action", 1)),
]


# ---------------------------------------------------------------------------
def transform(xsl, src, lang, out):
    with open(out, "wb") as fh:
        fh.write(bytes(xsl(E.parse(src), lang=E.XSLT.strparam(lang))))


def veracity(lang, xml, tex, bundle=None):
    """(reprovou?, checagens reprovadas, 1a mensagem) do check-veracity.py."""
    cmd = [sys.executable, "-X", "utf8", CHECK, "--lang", lang, "--xml", xml, "--tex", tex]
    if bundle:
        cmd += ["--bundle", bundle]
    r = subprocess.run(cmd, capture_output=True)
    out = r.stdout.decode("utf-8", "replace").splitlines()
    failed = [l.split()[1] for l in out if l.startswith("  FALHA ")]
    msg = next((l.strip(" |") for l in out if l.startswith("           | ")),
               r.stderr.decode("utf-8", "replace").strip()[-150:])
    return r.returncode != 0, failed, msg


def mutate(work, name, subs):
    d = os.path.join(work, "m-" + name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for f in os.listdir(BUNDLE):
        if f == "latex.xsl" or f.startswith("nvt-i18n-"):
            shutil.copy(os.path.join(BUNDLE, f), d)
    p = os.path.join(d, "latex.xsl")
    s = open(p, encoding="utf-8").read()
    for a, b in subs:
        n = s.count(a)
        if n != 1:
            raise SystemExit("mutante %s: trecho achado %d vez(es), esperado 1: %r" % (name, n, a[:90]))
        s = s.replace(a, b)
    open(p, "w", encoding="utf-8", newline="\n").write(s)
    return d


def run_bundle(bundle, jobs):
    """jobs: [(lang, fixture-name, xml-path)] -> [(lang, fx, checagens, msg)] reprovados."""
    xsl = E.XSLT(E.parse(os.path.join(bundle, "latex.xsl")))
    hits = []
    for lang, fx, src in jobs:
        tex = os.path.join(bundle, "%s-%s.tex" % (lang, fx))
        transform(xsl, src, lang, tex)
        bad, failed, msg = veracity(lang, src, tex, bundle)
        if bad:
            hits.append((lang, fx, failed, msg))
    return hits


def torture(work, lang):
    tp = os.path.join(work, "tortura-%s.xml" % lang)
    if not os.path.exists(tp):
        r = subprocess.run([sys.executable, "-X", "utf8",
                            os.path.join(BUNDLE, "tools", "build-torture-fixture.py"), lang],
                           cwd=BUNDLE, capture_output=True)
        if r.returncode != 0 or not r.stdout:
            raise SystemExit("build-torture-fixture.py %s falhou: %s" % (lang, r.stderr[-300:]))
        with open(tp, "wb") as fh:
            fh.write(r.stdout)
    return tp


def modo_xslt(work, only):
    bad = 0
    for name, what, subs, fixtures in MUTANTES:
        if only and name not in only and name != "controle":
            continue
        jobs = [(lang, fx, os.path.join(FIX, fx + ".xml")) for lang in LANGS for fx in fixtures]
        hits = run_bundle(mutate(work, name, subs), jobs)
        if name == "controle":
            ok = not hits
            verdict = "passa em todas (%d)" % len(jobs) if ok else "REPROVOU: %s" % hits[:2]
        else:
            ok = bool(hits)
            verdict = ("REPROVADO em %d de %d (%s); 1a: [%s/%s %s] %s"
                       % (len(hits), len(jobs), ", ".join(sorted({h[1] for h in hits})),
                          hits[0][0], hits[0][1], ",".join(hits[0][2]), hits[0][3][:140])
                       if ok else "SOBREVIVEU")
        bad += not ok
        print("%-36s %s\n    %s" % (name, what, verdict), flush=True)
    todo = [m for m in MUTANTES_TRADUCAO if not only or m[0] in only]
    if todo:
        tort = {lang: torture(work, lang) for lang in ("pt_BR", "es")}
        for name, what, subs in todo:
            jobs = [(lang, fx, os.path.join(FIX, fx + ".xml")) for lang in LANGS for fx in (V5, V22)]
            jobs += [(lang, "tortura", tort[lang]) for lang in ("pt_BR", "es")]
            hits = run_bundle(mutate(work, name, subs), jobs)
            ok = bool(hits)
            verdict = ("REPROVADO em %d de %d (%s); 1a: [%s/%s %s] %s"
                       % (len(hits), len(jobs), ", ".join(sorted({h[0] + "/" + h[1] for h in hits})),
                          hits[0][0], hits[0][1], ",".join(hits[0][2]), hits[0][3][:140])
                       if ok else "SOBREVIVEU")
            bad += not ok
            print("%-36s %s\n    %s" % (name, what, verdict), flush=True)
    return bad


def modo_tex(work, only):
    xsl = E.XSLT(E.parse(os.path.join(BUNDLE, "latex.xsl")))
    texdir = os.path.join(work, "tex")
    os.makedirs(texdir, exist_ok=True)
    bad = 0
    for name, fx, lang, fn in CASOS_TEX:
        if only and name not in only and fn is not None:
            continue
        xml = os.path.join(FIX, fx + ".xml")
        orig = os.path.join(texdir, "%s-%s.tex" % (lang, fx))
        if not os.path.exists(orig):
            transform(xsl, xml, lang, orig)
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
        failed_run, failed, msg = veracity(lang, xml, p)
        must_fail = fn is not None
        ok = failed_run == must_fail
        bad += not ok
        print("%-48s %-6s %-6s %s %s" % (name, fx[:6], lang, "OK  " if ok else "ERRO",
                                        ("reprovou em %s: %s" % (",".join(failed), msg[:110]))
                                        if failed_run else "passou"), flush=True)
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("modo", nargs="?", default="todos", choices=("xslt", "tex", "todos"))
    ap.add_argument("--so", nargs="*", default=[])
    ap.add_argument("--trabalho")
    ap.add_argument("--manter", action="store_true")
    a = ap.parse_args()
    work = a.trabalho or tempfile.mkdtemp(prefix="mutantes-prioridades-")
    os.makedirs(work, exist_ok=True)
    bad = 0
    try:
        if a.modo in ("xslt", "todos"):
            print("== mutantes do latex.xsl", flush=True)
            bad += modo_xslt(work, set(a.so))
        if a.modo in ("tex", "todos"):
            print("== edicoes do .tex", flush=True)
            bad += modo_tex(work, set(a.so))
    finally:
        if not a.manter and not a.trabalho:
            shutil.rmtree(work, ignore_errors=True)
    print("RESULTADO: %s" % ("todo mutante reprovado, controles passam" if not bad
                             else "%d problema(s)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
