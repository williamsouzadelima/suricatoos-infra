<?xml version="1.0"?>

<!--
Suricatoos Premium PDF - Vulnerability Assessment Report (v3, i18n + ports).

Transforms a GVM report XML into a premium, pentest-style LaTeX document that
is compiled to PDF with pdflatex. Findings are GROUPED BY NVT (Muenchian
grouping) so each unique vulnerability appears once, with every affected
host:port instance listed together.

INTERNATIONALISATION
  The document chrome (section titles, field labels, narrative, dates, severity
  words) is rendered in the language given by the top-level string parameter
  `lang` (en | pt_BR | es), defaulting to English. The per-language generate
  scripts pass it via an "xsltproc stringparam". Only the report chrome
  is translated; vulnerability text (name / summary / impact / solution) comes
  verbatim from the Greenbone NVT feed, which is English-only, and is therefore
  left in its source language. No language-specific LaTeX package (e.g. babel)
  is required: accented Latin text is emitted as UTF-8 and typeset via the
  inputenc/fontenc already loaded, so the format still compiles on the stock
  gvmd image's TeX Live with no extra packages.

Copyright (C) 2010-2019 Greenbone AG
Copyright (C) 2026 Suricatoos
SPDX-License-Identifier: GPL-2.0-or-later
-->

<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func="http://exslt.org/functions"
    xmlns:str="http://exslt.org/strings"
    xmlns:exsl="http://exslt.org/common"
    xmlns:gvm="http://greenbone.net"
    xmlns:date="http://exslt.org/dates-and-times"
    extension-element-prefixes="str func date exsl gvm">
  <xsl:output method="text" encoding="string" indent="no"/>
  <!-- Milhar com ponto, para os numeros exibidos em pt-BR e es. O formato
       padrao (milhar com virgula) continua valendo para o ingles. -->
  <xsl:decimal-format name="ptes" decimal-separator="," grouping-separator="."/>
  <xsl:strip-space elements="*"/>

  <!-- Report language, passed by the generate script (en | pt_BR | es). -->
  <xsl:param name="lang" select="'en'"/>
  <!-- Normalised two-letter language bucket used for all lookups. -->
  <xsl:variable name="L">
    <xsl:choose>
      <xsl:when test="starts-with($lang, 'pt')">pt</xsl:when>
      <xsl:when test="starts-with($lang, 'es')">es</xsl:when>
      <xsl:otherwise>en</xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <!-- Detection-quality threshold. At or above it a result is reported as a
       confirmed finding; below it, as an indicator that must be validated by
       hand. 70 mirrors the min_qod the GSA offers by default. Results carrying
       no <qod> at all are treated as confirmed: absence of the field is not
       evidence of low quality. -->
  <xsl:param name="qod-min" select="70"/>

  <!-- Teto do nome da tarefa na capa e na narrativa executiva. NAO e' um limite de
       largura (o escape_break ja da' pontos de quebra, entao nome colado nao sai
       mais da folha): e' um limite de ALTURA, porque o quadro da capa cresce para
       CIMA a partir da base e um nome de milhares de caracteres passaria por cima
       do logotipo e do titulo.

       O valor foi MEDIDO na capa renderizada (2 passadas de pdflatex, que o
       `remember picture,overlay` do TikZ exige), conferindo a folga entre o topo
       do bloco do nome e o elemento fixo acima dele:
         246 chars ->  5 linhas, 174pt de folga
         600 chars -> 11 linhas,  93pt de folga   <- escolhido
         900 chars -> 16 linhas,  25pt de folga
        1200 chars -> 22 linhas, ja engole a linha "Elaborado pela Plataforma"
       O teto anterior era 160, cerca de 4x abaixo do que a pagina comporta, e
       cortava nome de engajamento legitimo — o tipo de truncagem que este
       relatorio existe para nao fazer. Um so' ponto de verdade para os dois usos. -->
  <xsl:param name="task-name-max" select="600"/>

  <!-- Group all result elements by their NVT oid (Muenchian grouping). -->
  <xsl:key name="by-nvt" match="result" use="nvt/@oid"/>
  <!-- Composite key to de-duplicate a vulnerability's affected systems: the same
       NVT often fires many times on one host:port (e.g. one advisory per package),
       which would otherwise list that host:port repeatedly. -->
  <xsl:key name="by-nvt-hostport" match="result" use="concat(nvt/@oid, '|', host/text(), '|', port)"/>
  <!-- Distinct host:port pairs, used to derive a host's port inventory from the
       results when the report has no <ports> element for that host. -->
  <xsl:key name="by-host-port" match="result" use="concat(host/text(), '|', port)"/>

  <!-- Cumulative-advisory grouping. Only vendor-fix results participate: those
       are the "upgrade the product" advisories that pile up per release. The
       group key is the product's first two words, which is where advisory
       names carry vendor + product. Restricting to VendorFix is what keeps the
       heuristic safe: name families that merely share a prefix (protocol or
       inventory checks, say) do not carry a vendor fix and never group. Host is
       deliberately NOT part of the key: an NVT seen on several hosts would then
       be only partly collapsed, and suppressing its card would hide the
       instances on the hosts that did not reach the threshold. The consolidated
       card lists every affected host instead. -->
  <xsl:key name="by-updgrp" match="result[nvt/solution/@type='VendorFix']"
           use="concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' '))"/>
  <!-- Same grouping, further split per NVT, so distinct advisories can be
       counted WITHIN a group (a plain by-nvt key is global and would count
       occurrences on other hosts too). -->
  <xsl:key name="by-updgrp-nvt" match="result[nvt/solution/@type='VendorFix']"
           use="concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid)"/>

  <!-- Minimum distinct advisories for a group to be collapsed into one card.
       Below it the individual cards are more informative than a roll-up. -->
  <xsl:param name="group-min" select="5"/>

  <!-- Quantos advisories o card consolidado lista antes de resumir o resto.
       Os mais severos são os que orientam a urgência; o restante é enumeração
       do mesmo produto, resolvida pela mesma ação. -->
  <xsl:param name="adv-max" select="10"/>

  <!-- Teto de LINHAS de cada tabela do sumario de achados (secao 4).
       O sumario existe para ser lido de uma olhada; um scan real produz dezenas
       de deteccoes informativas (Log) que enchem paginas sem orientar decisao
       nenhuma. A truncagem e' seletiva, nao um corte cego pelo fim da lista:
       NENHUM achado com severidade >= 0.1 e' escondido — se so' os acionaveis ja
       passarem deste teto, a tabela cresce e nada e' cortado. O que sobra do
       teto e' preenchido com os informativos, e a linha \findingtrunc declara
       QUANTOS ficaram de fora e onde le-los (a secao de achados detalhados
       continua listando todos). -->
  <xsl:param name="summary-max" select="20"/>

  <!-- ================================================================= -->
  <!-- Hexmap: port exposure panel                                       -->
  <!-- ================================================================= -->

  <!-- Cell budget of the GLOBAL board. The hex-blob sizes are 19 (radius 2),
       37 (radius 3) and 61 (radius 4); anything above the budget is cut by
       severity and rolled into a single "+N" cell (the ports themselves are
       never dropped: the Port -> IP table below the board lists them all). -->
  <xsl:param name="hexmap-max" select="37"/>
  <!-- The per-host appendix is only drawn for reports small enough for it to
       be readable. Above this many hosts it is skipped, with a sentence saying
       so and how many hosts there were. -->
  <xsl:param name="hexmap-per-host-max" select="12"/>
  <!-- Cell budget of each per-host board. -->
  <xsl:param name="hexmap-per-host-cells" select="19"/>
  <!-- 1 = label a well-known port whose service the scan did NOT identify with
       its IANA registry name, flagged with a dagger and a footnote. 0 = fall
       back to the bare transport (TCP / UDP). -->
  <xsl:param name="hexmap-iana-names" select="1"/>

  <!-- Every port string in the report, indexed by the NORMALISED cell key
       "proto/number". Both sources match the same pattern: <ports><port> (the
       scanner's port inventory) and <result><port> (the port a finding fired
       on). Reports exported through some filters carry no <ports> element at
       all, so the results are not a fallback but a first-class source. -->
  <xsl:key name="hx-pkey" match="ports/port | result/port"
           use="concat(translate(substring-after(normalize-space(text()),'/'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'/',substring-before(normalize-space(text()),'/'))"/>
  <!-- Same nodes, keyed by cell AND host, which is what de-duplicates the IP
       list of a cell (and, read the other way round, the cell list of a host).
       The host is the <host> CHILD for a ports/port and the parent result's
       <host> text node for a result/port; the union picks whichever exists. -->
  <xsl:key name="hx-ipkey" match="ports/port | result/port"
           use="concat(translate(substring-after(normalize-space(text()),'/'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'/',substring-before(normalize-space(text()),'/'),'#',substring-before(concat(normalize-space(string(host/text() | ../host/text())),' '),' '))"/>
  <!-- Same nodes, keyed by HOST alone. The per-host appendix starts from this
       key instead of re-scanning every port node in the report once per host,
       which is what turned the appendix into an O(hosts x ports) sweep. -->
  <xsl:key name="hx-hostkey" match="ports/port | result/port"
           use="substring-before(concat(normalize-space(string(host/text() | ../host/text())),' '),' ')"/>
  <!-- Host detail "Services" carries "22/tcp/ssh". Keyed by "proto/number" so a
       cell resolves its service name in one lookup instead of scanning every
       host (a /16 report has tens of thousands of these). A value with fewer
       than two slashes yields a key that can never match, which is the
       defensive behaviour we want. -->
  <xsl:key name="hx-svc" match="host/detail[name='Services']"
           use="concat(translate(substring-before(substring-after(value,'/'),'/'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'/',substring-before(value,'/'))"/>
  <!-- Host-level pseudo-ports (general/tcp, general/*), keyed by host, so the
       panel can say how many hosts carry host-level findings without drawing
       them as ports. -->
  <xsl:key name="hx-genip" match="ports/port[starts-with(normalize-space(text()),'general')] | result/port[starts-with(normalize-space(text()),'general')]"
           use="substring-before(concat(normalize-space(string(host/text() | ../host/text())),' '),' ')"/>

  <!-- ================================================================= -->
  <!-- Internationalised strings                                          -->
  <!-- ================================================================= -->

  <!-- One <s> per translatable chrome string; @en/@pt/@es carry the wording.
       Keep values free of LaTeX-special characters ($ & % # _ { } ~ ^) except
       where a literal control sequence is intended (e.g. \# for the "#" column
       header), because gvm:t() output is emitted WITHOUT escaping. -->
  <xsl:variable name="i18n-rtf">
    <!-- Running header / footer -->
    <s k="running_header" en="Vulnerability Assessment Report" pt="Relatório de Avaliação de Vulnerabilidades" es="Informe de Evaluación de Vulnerabilidades"/>
    <s k="confidential_caps" en="CONFIDENTIAL" pt="CONFIDENCIAL" es="CONFIDENCIAL"/>
    <s k="page_word" en="Page" pt="Página" es="Página"/>
    <s k="of_word" en="of" pt="de" es="de"/>
    <s k="pdftitle" en="Suricatoos Vulnerability Assessment Report" pt="Relatório de Avaliação de Vulnerabilidades Suricatoos" es="Informe de Evaluación de Vulnerabilidades Suricatoos"/>
    <!-- Cover page -->
    <s k="cover_kicker" en="VULNERABILITY ASSESSMENT" pt="AVALIAÇÃO DE VULNERABILIDADES" es="EVALUACIÓN DE VULNERABILIDADES"/>
    <s k="cover_title" en="Vulnerability\\Assessment Report" pt="Relatório de Avaliação\\de Vulnerabilidades" es="Informe de Evaluación\\de Vulnerabilidades"/>
    <s k="cover_prepared" en="Prepared by the Suricatoos Security Platform" pt="Elaborado pela Plataforma de Segurança Suricatoos" es="Elaborado por la Plataforma de Seguridad Suricatoos"/>
    <s k="lbl_engagement" en="ENGAGEMENT" pt="PROJETO" es="PROYECTO"/>
    <s k="lbl_hosts_assessed" en="HOSTS ASSESSED" pt="HOSTS AVALIADOS" es="HOSTS EVALUADOS"/>
    <s k="lbl_scan_started" en="SCAN STARTED" pt="INÍCIO DO SCAN" es="INICIO DEL ESCANEO"/>
    <s k="lbl_scan_completed" en="SCAN COMPLETED" pt="FIM DO SCAN" es="FIN DEL ESCANEO"/>
    <s k="lbl_report_date" en="REPORT DATE" pt="DATA DO RELATÓRIO" es="FECHA DEL INFORME"/>
    <s k="lbl_classification" en="CLASSIFICATION" pt="CLASSIFICAÇÃO" es="CLASIFICACIÓN"/>
    <s k="val_confidential" en="Confidential" pt="Confidencial" es="Confidencial"/>
    <!-- Executive summary -->
    <s k="sec_exec" en="Executive Summary" pt="Resumo Executivo" es="Resumen Ejecutivo"/>
    <s k="overall_risk" en="OVERALL RISK RATING" pt="CLASSIFICAÇÃO GERAL DE RISCO" es="CLASIFICACIÓN GENERAL DE RIESGO"/>
    <s k="m_hosts" en="HOSTS ASSESSED" pt="HOSTS AVALIADOS" es="HOSTS EVALUADOS"/>
    <s k="m_total" en="TOTAL FINDINGS" pt="TOTAL DE ACHADOS" es="TOTAL DE HALLAZGOS"/>
    <s k="m_uniq" en="UNIQUE VULNS" pt="VULNS ÚNICAS" es="VULNS ÚNICAS"/>
    <s k="findings_by_sev" en="Findings by severity" pt="Achados por severidade" es="Hallazgos por severidad"/>
    <s k="no_findings" en="No findings above informational severity were recorded for this assessment." pt="Nenhum achado acima da severidade informativa foi registrado nesta avaliação." es="No se registraron hallazgos por encima de la severidad informativa en esta evaluación."/>
    <s k="timeline" en="Assessment timeline" pt="Linha do tempo da avaliação" es="Cronología de la evaluación"/>
    <s k="t_generated" en="REPORT GENERATED" pt="RELATÓRIO GERADO" es="INFORME GENERADO"/>
    <!-- Sampling disclosure: shown only when the report filter returned fewer
         results than the scan actually produced, so the reader is never led to
         believe a truncated window is the whole scan. -->
    <s k="m_analyzed" en="DETAILED HERE" pt="DETALHADOS AQUI" es="DETALLADOS AQUÍ"/>
    <s k="sample_hdr" en="Partial view of the scan" pt="Visão parcial da varredura" es="Vista parcial del escaneo"/>
    <s k="sample_a" en="This report details " pt="Este relatório detalha " es="Este informe detalla "/>
    <s k="sample_b" en=" of the " pt=" dos " es=" de los "/>
    <s k="sample_c" en=" results the scan produced, because a display filter was applied when it was exported. Findings outside that filter are NOT described here." pt=" resultados que a varredura produziu, porque um filtro de exibição foi aplicado na exportação. Achados fora desse filtro NÃO estão descritos aqui." es=" resultados que produjo el escaneo, porque se aplicó un filtro de visualización al exportarlo. Los hallazgos fuera de ese filtro NO se describen aquí."/>
    <!-- Detection confidence (QoD). Anything below the threshold is reported as
         an indicator to validate, never as a confirmed finding. -->
    <s k="lbl_lowconf" en="LOW CONFIDENCE" pt="BAIXA CONFIANÇA" es="BAJA CONFIANZA"/>
    <!-- Palavras que o DESIGN SYSTEM imprime e que ainda nao tinham chave aqui.
         Cada uma corresponde a um \suriLbl... de um .sty (veja a tabela
         macro -> chave no template `header`); sem elas o relatorio existiria em
         uma lingua so'. -->
    <s k="th_ach" en="Find." pt="Ach." es="Hall."/>
    <!-- th_sev_ceiling (o outro cabecalho desta linha) vive junto do bloco de
         achados confirmados/indicadores, mais abaixo: dois agentes a
         acrescentaram em paralelo e a entrada duplicada saiu daqui. -->
    <s k="lbl_cvss" en="CVSS" pt="CVSS" es="CVSS"/>
    <s k="hx_ports_mapped" en="Observed ports \textperiodcentered\ Mapped addresses" pt="Portas observadas \textperiodcentered\ Endereços mapeados" es="Puertos observados \textperiodcentered\ Direcciones mapeadas"/>
    <!-- Substantivo sozinho: o numero e a relacao (>= / &lt;) sao compostos no
         preambulo a partir do parametro $qod-min, nunca escritos na traducao. -->
    <s k="qod_quality" en="detection quality" pt="qualidade de detecção" es="calidad de detección"/>
    <!-- Consolidated update card -->
    <s k="grp_title" en="Outstanding update" pt="Atualização pendente" es="Actualización pendiente"/>
    <s k="grp_badge" en="CONSOLIDATED" pt="CONSOLIDADO" es="CONSOLIDADO"/>
    <s k="grp_intro_a" en="The scanner reported " pt="O scanner reportou " es="El escáner reportó "/>
    <!-- O paragrafo do card consolidado vem em tres pedacos porque o miolo sai
         em NEGRITO: a versao anterior gritava "UNICA acao" em caixa alta por
         nao ter onde por o realce. -->
    <s k="grp_intro_b" en=" separate advisories for this product. They accumulate one per vendor release and are resolved by a " pt=" advisories separados para este produto. Eles se acumulam um por versão do fornecedor e são resolvidos por uma " es=" advisories separados para este producto. Se acumulan uno por versión del proveedor y se resuelven con una "/>
    <s k="grp_intro_c" en="single action" pt="única ação" es="única acción"/>
    <s k="grp_intro_d" en=": updating the product to a supported version." pt=": atualizar o produto para uma versão suportada." es=": actualizar el producto a una versión soportada."/>
    <!-- Palavras de CHIP: entram em caixa alta dentro do chip, como no modelo.
         Iguais nas tres linguas, mas declaradas assim mesmo para que traduzir o
         relatorio continue sendo mexer NESTA tabela e em lugar nenhum. -->
    <s k="grp_adv_caps" en="ADVISORIES" pt="ADVISORIES" es="ADVISORIES"/>
    <s k="chip_host" en="HOST" pt="HOST" es="HOST"/>
    <s k="chip_hosts" en="HOSTS" pt="HOSTS" es="HOSTS"/>
    <s k="grp_th_adv" en="Advisory" pt="Advisory" es="Advisory"/>
    <s k="grp_more_a" en=" more advisories for this product, up to " pt=" advisories a mais deste produto, até " es=" advisories más de este producto, hasta "/>
    <s k="grp_more_b" en=" — all resolved by the same update." pt=" — todos resolvidos pela mesma atualização." es=" — todos resueltos por la misma actualización."/>
    <s k="grp_action" en="Single remediation action" pt="Ação única de remediação" es="Acción única de remediación"/>
    <s k="grp_host" en="Affected hosts" pt="Hosts afetados" es="Hosts afectados"/>
    <s k="sub_confirmed" en="Confirmed findings" pt="Achados confirmados" es="Hallazgos confirmados"/>
    <s k="sub_indicators" en="Indicators to validate" pt="Indicadores a validar" es="Indicadores a validar"/>
    <s k="conf_intro" en="Findings below were reported by the scanner with a detection quality of at least " pt="Os achados abaixo foram reportados pelo scanner com qualidade de detecção de pelo menos " es="Los hallazgos siguientes fueron reportados por el escáner con una calidad de detección de al menos "/>
    <s k="ind_intro" en="The scanner reported the items below with LOW detection quality (under " pt="O scanner reportou os itens abaixo com BAIXA qualidade de detecção (abaixo de " es="El escáner reportó los elementos siguientes con BAJA calidad de detección (por debajo de "/>
    <s k="ind_intro2" en="). They are inconclusive by nature and must be validated manually before any remediation effort — treat the severity shown as an upper bound, not as a confirmed fact." pt="). São inconclusivos por natureza e precisam ser validados manualmente antes de qualquer esforço de remediação — trate a severidade exibida como um teto, não como fato confirmado." es="). Son inconclusos por naturaleza y deben validarse manualmente antes de cualquier esfuerzo de remediación — trate la severidad mostrada como un techo, no como un hecho confirmado."/>
    <s k="none_confirmed" en="No confirmed findings above informational severity were recorded." pt="Nenhum achado confirmado acima da severidade informativa foi registrado." es="No se registraron hallazgos confirmados por encima de la severidad informativa."/>
    <!-- Appended after a bare count, so it must read correctly for 1 and for N:
         no conjugated verb agreeing with the number. -->
    <s k="of_which_lowconf" en=" of them low-confidence (manual validation required)" pt=" de baixa confiança (validação manual necessária)" es=" de baja confianza (validación manual necesaria)"/>
    <!-- The remediation clause of the narrative, in three forms.  Which one runs
         is decided by how many of the High/Critical findings carry a QoD below
         the minimum, and it matters: telling the reader to remediate at once
         and, in the same breath, that every one of those findings still needs
         manual validation is advice that contradicts itself.  That is the exact
         failure the QoD segregation of this report exists to prevent, so the
         summary must not reintroduce it one page earlier. -->
    <s k="exec_warrant" en=" and warrant prompt remediation" pt=" e exigem remediação imediata" es=" y requieren remediación inmediata"/>
    <s k="exec_all_lowconf" en=" --- but every one of them was reported with a low detection quality and must be validated manually before any remediation effort; treat the severity shown as an upper bound." pt=" --- mas todos foram reportados com baixa qualidade de detecção e precisam ser validados manualmente antes de qualquer esforço de remediação; trate a severidade exibida como um teto." es=" --- pero todos fueron reportados con baja calidad de detección y deben validarse manualmente antes de cualquier esfuerzo de remediación; trate la severidad mostrada como un techo."/>
    <!-- Risk words (uppercase, used in the risk badge and narrative) -->
    <!-- "The measurement did not happen."
         A scan whose alive detection reaches no host still ends as Done, with an
         empty report. Printing the normal summary over that reads as a clean bill
         of health, which is the worst thing this document can say. These three
         strings exist so it says the opposite, loudly. -->
    <!-- Quando o filtro da exportacao carrega um piso de QoD, o que ele descarta
         sao justamente os achados de baixa confianca: os mesmos que a secao
         "Indicadores a validar" existe para mostrar. O leitor precisa saber. -->
    <s k="sample_qod_a" en=" The export filter required QoD " pt=" O filtro da exportação exigiu QoD " es=" El filtro de la exportación exigió QoD "/>
    <s k="sample_qod_b" en="\% or higher, so low-confidence findings were dropped before this document was written --- the \textquotedblleft Indicators to validate\textquotedblright\ section is likely incomplete." pt="\% ou mais, então achados de baixa confiança foram descartados antes deste documento ser escrito --- a seção \textquotedblleft Indicadores a validar\textquotedblright\ provavelmente está incompleta." es="\% o más, así que los hallazgos de baja confianza se descartaron antes de escribir este documento --- la sección \textquotedblleft Indicadores a validar\textquotedblright\ probablemente está incompleta."/>
    <s k="risk_notmeasured" en="NOT MEASURED" pt="NÃO MEDIDO" es="NO MEDIDO"/>
    <s k="nohost_title" en="This scan measured nothing" pt="Este scan não mediu nada" es="Este escaneo no midió nada"/>
    <!-- Split in three because these are attribute VALUES, and an attribute in a
         literal result element is an attribute value template: a brace is markup
         there, so "\textbf{...}" cannot live in the string. The emphasis is
         applied by the stylesheet around part B instead. -->
    <s k="nohost_body_a" en="No host answered the alive test, so no port was scanned and no check was run. " pt="Nenhum host respondeu à detecção de host vivo, então nenhuma porta foi varrida e nenhum teste foi executado. " es="Ningún host respondió a la detección de host vivo, así que no se escaneó ningún puerto ni se ejecutó ninguna comprobación. "/>
    <s k="nohost_body_b" en="The absence of findings in this report is not evidence of the absence of vulnerabilities" pt="A ausência de achados neste relatório não é evidência de ausência de vulnerabilidades" es="La ausencia de hallazgos en este informe no es evidencia de ausencia de vulnerabilidades"/>
    <s k="nohost_body_c" en=" --- it is the absence of a measurement. The usual cause is the target answering none of the probes selected in its Alive Test (a firewall dropping ICMP, for instance). Fix that setting and scan again before treating this result as a clean scan." pt=" --- é ausência de medição. A causa usual é o alvo não responder a nenhuma das sondas escolhidas no Alive Test dele (um firewall descartando ICMP, por exemplo). Corrija essa configuração e refaça o scan antes de tratar este resultado como um scan limpo." es=" --- es ausencia de medición. La causa habitual es que el objetivo no responda a ninguna de las sondas elegidas en su Alive Test (un firewall descartando ICMP, por ejemplo). Corrija esa configuración y repita el escaneo antes de tratar este resultado como un escaneo limpio."/>
    <s k="risk_critical" en="CRITICAL" pt="CRÍTICO" es="CRÍTICO"/>
    <s k="risk_high" en="HIGH" pt="ALTO" es="ALTO"/>
    <s k="risk_medium" en="MEDIUM" pt="MÉDIO" es="MEDIO"/>
    <s k="risk_low" en="LOW" pt="BAIXO" es="BAJO"/>
    <s k="risk_info" en="INFORMATIONAL" pt="INFORMATIVO" es="INFORMATIVO"/>
    <!-- Severity class words (title case, used in pills and the chart axis) -->
    <s k="sev_critical" en="Critical" pt="Crítico" es="Crítico"/>
    <s k="sev_high" en="High" pt="Alto" es="Alto"/>
    <s k="sev_medium" en="Medium" pt="Médio" es="Medio"/>
    <s k="sev_low" en="Low" pt="Baixo" es="Bajo"/>
    <s k="sev_log" en="Log" pt="Log" es="Log"/>
    <s k="sev_falsepos" en="False pos." pt="Falso pos." es="Falso pos."/>
    <!-- Findings summary -->
    <s k="sec_findings_summary" en="Findings Summary" pt="Sumário de Achados" es="Resumen de Hallazgos"/>
    <s k="fs_intro" en="The table below lists every unique vulnerability identified during the assessment, ordered by severity. Each vulnerability is analysed in detail in the following section." pt="A tabela abaixo lista cada vulnerabilidade única identificada durante a avaliação, ordenada por severidade. Cada vulnerabilidade é analisada em detalhe na seção seguinte." es="La tabla siguiente enumera cada vulnerabilidad única identificada durante la evaluación, ordenada por severidad. Cada vulnerabilidad se analiza en detalle en la sección siguiente."/>
    <s k="th_num" en="\#" pt="\#" es="\#"/>
    <s k="th_vuln" en="Vulnerability" pt="Vulnerabilidade" es="Vulnerabilidad"/>
    <s k="th_inst" en="Inst." pt="Inst." es="Inst."/>
    <s k="th_severity" en="Severity" pt="Severidade" es="Severidad"/>
    <!-- Cabecalho da coluna de severidade na tabela de INDICADORES: ali a
         severidade e' um TETO (a deteccao e' de baixa qualidade), nao um fato.
         Alimenta \suriLblSevCeiling do design system. -->
    <s k="th_sev_ceiling" en="Severity (ceiling)" pt="Severidade (teto)" es="Severidad (techo)"/>
    <!-- Cauda truncada do sumario: so' entram achados informativos, e eles
         continuam inteiros na secao de achados detalhados — a frase diz onde. -->
    <s k="fs_trunc" en=" informational (Log) findings — detailed in the section that follows." pt=" achados informativos (Log) — detalhados na seção seguinte." es=" hallazgos informativos (Log) — detallados en la sección siguiente."/>
    <!-- Hosts &amp; ports -->
    <s k="sec_hosts_ports" en="Hosts and Open Ports" pt="Hosts e Portas Abertas" es="Hosts y Puertos Abiertos"/>
    <!-- Runner of the running header: shorter than the printed section title,
         which is why it is a key of its own. Upper case, no accent needed. -->
    <s k="sec_hosts_ports_run" en="HOSTS AND PORTS" pt="HOSTS E PORTAS" es="HOSTS Y PUERTOS"/>
    <s k="hp_intro" en="Network services discovered on each assessed host, with the number of findings and the highest severity observed on each port." pt="Serviços de rede descobertos em cada host avaliado, com o número de achados e a maior severidade observada em cada porta." es="Servicios de red descubiertos en cada host evaluado, con el número de hallazgos y la mayor severidad observada en cada puerto."/>
    <s k="th_port" en="Port" pt="Porta" es="Puerto"/>
    <s k="th_proto" en="Proto" pt="Proto" es="Proto"/>
    <s k="th_findings" en="Findings" pt="Achados" es="Hallazgos"/>
    <s k="th_max_sev" en="Highest severity" pt="Maior severidade" es="Mayor severidad"/>
    <s k="hp_general" en="General" pt="Geral" es="General"/>
    <s k="hp_hostlevel" en="host-level" pt="nível de host" es="nivel de host"/>
    <s k="hp_no_ports" en="No network services with findings were recorded on this host." pt="Nenhum serviço de rede com achados foi registrado neste host." es="No se registraron servicios de red con hallazgos en este host."/>
    <s k="hp_os_unknown" en="Operating system not identified" pt="Sistema operacional não identificado" es="Sistema operativo no identificado"/>
    <s k="hp_open_ports" en="open port(s) with findings" pt="porta(s) com achados" es="puerto(s) con hallazgos"/>
    <!-- Short form of hp_os_unknown: it goes inside the OS badge of the host
         card's title band, which is a chip and not a sentence. -->
    <s k="hp_os_unknown_chip" en="OS not identified" pt="SO não identificado" es="SO no identificado"/>
    <!-- Note under a host card. Every general/* pseudo-port of the host collapses
         into ONE `geral' row, so the note is where the composition of that row is
         spelled out: how many findings, of which severity, and the highest CVSS.
         Without it the row would be a number nobody could take apart. -->
    <s k="hp_gen_note_a" en="Host-level findings (general/*) are not network ports --- " pt="Achados de nível de host (general/*) não são portas de rede --- " es="Los hallazgos de nivel de host (general/*) no son puertos de red --- "/>
    <s k="hp_gen_note_b" en=" aggregated into the row " pt=" agregados na linha " es=" agregados en la fila "/>
    <!-- Detailed findings -->
    <s k="sec_detailed" en="Detailed Findings" pt="Achados Detalhados" es="Hallazgos Detallados"/>
    <s k="lbl_instances" en="instance(s)" pt="instância(s)" es="instancia(s)"/>
    <s k="lbl_cvss_vector" en="CVSS Vector" pt="Vetor CVSS" es="Vector CVSS"/>
    <s k="f_summary" en="Summary" pt="Resumo" es="Resumen"/>
    <s k="f_impact" en="Impact" pt="Impacto" es="Impacto"/>
    <!-- O EN dizia "Insight", que e' o nome do CAMPO no feed Greenbone, nao o
         nome do bloco no design — e as outras duas linguas ja' diziam "Detalhes
         Técnicos". A chave tem um consumidor so' (\suriLblFldTech), entao o
         mesmo rotulo passa a dizer a mesma coisa nas tres. -->
    <s k="f_insight" en="Technical Details" pt="Detalhes Técnicos" es="Detalles Técnicos"/>
    <s k="f_affected_sw" en="Affected Software / OS" pt="Software / SO Afetado" es="Software / SO Afectado"/>
    <s k="f_affected_sys" en="Affected Systems" pt="Sistemas Afetados" es="Sistemas Afectados"/>
    <s k="f_detection" en="Detection Result" pt="Resultado da Detecção" es="Resultado de la Detección"/>
    <s k="f_solution" en="Solution / Remediation" pt="Solução / Remediação" es="Solución / Remediación"/>
    <s k="f_references" en="References" pt="Referências" es="Referencias"/>
    <!-- Aviso de truncagem COM QUANTIDADE. "[saída truncada]" sozinho nao
         diz quanto ficou de fora, e este projeto ja teve numero que mentia:
         o TOTAL DE ACHADOS chegou a exibir a janela do filtro como se fosse
         o scan inteiro. Truncado sem quantidade e' da mesma familia. -->
    <s k="trunc_a" en="[output truncated --- showing " pt="[saída truncada --- exibindo " es="[salida truncada --- mostrando "/>
    <s k="trunc_b" en=" of " pt=" de " es=" de "/>
    <s k="trunc_c" en=" characters]" pt=" caracteres]" es=" caracteres]"/>
    <s k="more_word" en="more" pt="mais" es="más"/>
    <!-- Solution type enum (from the feed) mapped to a localised label -->
    <s k="st_VendorFix" en="Vendor Fix" pt="Correção do Fornecedor" es="Corrección del Proveedor"/>
    <s k="st_Mitigation" en="Mitigation" pt="Mitigação" es="Mitigación"/>
    <s k="st_Workaround" en="Workaround" pt="Solução de Contorno" es="Solución Alternativa"/>
    <s k="st_NoneAvailable" en="None Available" pt="Indisponível" es="No Disponible"/>
    <s k="st_WillNotFix" en="Will Not Fix" pt="Não Será Corrigido" es="No Se Corregirá"/>
    <!-- Colophon -->
    <s k="colophon_1" en="This report was generated automatically by the Suricatoos vulnerability management platform." pt="Este relatório foi gerado automaticamente pela plataforma de gestão de vulnerabilidades Suricatoos." es="Este informe fue generado automáticamente por la plataforma de gestión de vulnerabilidades Suricatoos."/>
    <s k="colophon_2" en="CONFIDENTIAL --- distribute on a need-to-know basis." pt="CONFIDENCIAL --- distribua apenas para quem tem necessidade de conhecer." es="CONFIDENCIAL --- distribuya solo a quien tenga necesidad de conocer."/>
    <!-- Hexmap (port exposure panel). Same rule as every other value here: no
         LaTeX-special character unless a control sequence is intended, because
         gvm:t() output is emitted WITHOUT escaping. -->
    <s k="sec_hexmap" en="Port Exposure Map" pt="Mapa de Exposição de Portas" es="Mapa de Exposición de Puertos"/>
    <!-- Retexto para o desenho novo: o tabuleiro nao tem mais espessura de traco
         nem marcador no vertice, e a tabela nao fica mais logo abaixo dele. -->
    <s k="hx_intro" en="Every hexagon is one network port observed in the assessed scope; the cell key is the pair (transport, port number), so a port seen on many hosts is a single hexagon. Colour and fill carry the HIGHEST severity observed on that port across every host that exposes it. The third line inside the cell names the exposed host, or counts them when the port is open on more than one. The table on the next page lists every port with its mapped IP addresses, up to 40 per port." pt="Cada hexágono é uma porta de rede observada no escopo avaliado; a chave da célula é o par (transporte, porta), então uma porta vista em vários hosts é um único hexágono. Cor e preenchimento carregam a MAIOR severidade observada naquela porta em todos os hosts que a expõem. A terceira linha da célula nomeia o host exposto, ou conta quantos são quando a porta está aberta em mais de um. A tabela da página seguinte lista todas as portas com os endereços IP mapeados, até 40 por porta." es="Cada hexágono es un puerto de red observado en el alcance evaluado; la clave de la celda es el par (transporte, puerto), así que un puerto visto en varios hosts es un único hexágono. Color y relleno llevan la MAYOR severidad observada en ese puerto en todos los hosts que lo exponen. La tercera línea de la celda nombra el host expuesto, o los cuenta cuando el puerto está abierto en más de uno. La tabla de la página siguiente lista todos los puertos con las direcciones IP mapeadas, hasta 40 por puerto."/>
    <s k="hx_state_critico" en="Critical" pt="Crítico" es="Crítico"/>
    <s k="hx_state_alto" en="High" pt="Alto" es="Alto"/>
    <s k="hx_state_medio" en="Medium" pt="Médio" es="Medio"/>
    <s k="hx_state_baixo" en="Low" pt="Baixo" es="Bajo"/>
    <s k="hx_state_exposto" en="Exposed" pt="Exposto" es="Expuesto"/>
    <s k="hx_state_neutro" en="Neutral" pt="Neutro" es="Neutro"/>
    <s k="hx_th_port" en="Port" pt="Porta" es="Puerto"/>
    <s k="hx_th_proto" en="Proto" pt="Proto" es="Proto"/>
    <s k="hx_th_service" en="Service" pt="Serviço" es="Servicio"/>
    <s k="hx_th_state" en="State" pt="Estado" es="Estado"/>
    <s k="hx_th_cvss" en="Max CVSS" pt="CVSS máx." es="CVSS máx."/>
    <s k="hx_th_hosts" en="Hosts" pt="Hosts" es="Hosts"/>
    <s k="hx_th_ips" en="Mapped IP addresses" pt="IPs mapeados" es="IPs mapeados"/>
    <s k="hx_ips_n" en="IPs" pt="IPs" es="IPs"/>
    <s k="hx_findings_n" en="finding(s)" pt="achado(s)" es="hallazgo(s)"/>
    <s k="hx_others" en="OTHERS" pt="OUTRAS" es="OTRAS"/>
    <s k="hx_scope" en="unique ports" pt="portas únicas" es="puertos únicos"/>
    <!-- Runner of the running header: shorter than the section title, and
         already upper case, because \setsectionrunner prints what it is given. -->
    <s k="hx_runner" en="PORT EXPOSURE" pt="MAPA DE EXPOSIÇÃO" es="MAPA DE EXPOSICIÓN"/>
    <s k="hx_host_runner" en="EXPOSURE BY HOST" pt="EXPOSIÇÃO POR HOST" es="EXPOSICIÓN POR HOST"/>
    <!-- When family collapsing merges ports, the header must report BOTH numbers:
         saying only the cell count understates how many ports the scan actually
         observed, and this document has a history of headline numbers that quietly
         meant something narrower than the reader assumed. -->
    <s k="hx_ports_word" en="ports" pt="portas" es="puertos"/>
    <s k="hx_in_word" en="in" pt="em" es="en"/>
    <s k="hx_cells_word" en="cells" pt="células" es="celdas"/>
    <s k="hx_hosts_word" en="host(s)" pt="host(s)" es="host(s)"/>
    <s k="hx_omitted" en=" port(s) did not fit the board and were rolled into the final cell. None was dropped: every one of them is listed in the table on the next page." pt=" porta(s) não couberam no tabuleiro e foram somadas na célula final. Nenhuma foi descartada: todas estão listadas na tabela da página seguinte." es=" puerto(s) no cupieron en el tablero y se sumaron en la celda final. Ninguno fue descartado: todos están listados en la tabla de la página siguiente."/>
    <s k="hx_iana_note" en=" well-known port name taken from the IANA registry: the scan did NOT identify the service running on this port." pt=" nome IANA da porta: o scan NÃO identificou o serviço em execução nesta porta." es=" nombre IANA del puerto: el escaneo NO identificó el servicio en ejecución en este puerto."/>
    <s k="hx_low_qod" en=" the highest-severity finding on this port was reported with LOW detection quality, so the state shown was downgraded one level and must be validated by hand." pt=" o achado de maior severidade nesta porta foi reportado com BAIXA qualidade de detecção, então o estado exibido foi rebaixado um nível e precisa ser validado manualmente." es=" el hallazgo de mayor severidad en este puerto fue reportado con BAJA calidad de detección, así que el estado mostrado fue rebajado un nivel y debe validarse manualmente."/>
    <s k="hx_hostlevel_note" en=" host(s) also carry host-level findings (general/*). Those are not network ports and are deliberately absent from the board; they appear in the Hosts and Open Ports section." pt=" host(s) também têm achados de nível de host (general/*). Esses não são portas de rede e estão deliberadamente fora do tabuleiro; aparecem na seção Hosts e Portas Abertas." es=" host(s) también tienen hallazgos de nivel de host (general/*). Esos no son puertos de red y están deliberadamente fuera del tablero; aparecen en la sección Hosts y Puertos Abiertos."/>
    <s k="hx_malformed_note" en=" malformed port entr(y/ies) in the source report could not be parsed as a port and were discarded." pt=" entrada(s) de porta malformada(s) no relatório de origem não puderam ser interpretadas como porta e foram descartadas." es=" entrada(s) de puerto malformada(s) en el informe de origen no pudieron interpretarse como puerto y fueron descartadas."/>
    <s k="hx_no_ports" en="No network port was observed in this report, so there is no exposure map to draw." pt="Nenhuma porta de rede foi observada neste relatório, portanto não há mapa de exposição a desenhar." es="No se observó ningún puerto de red en este informe, por lo tanto no hay mapa de exposición que dibujar."/>
    <s k="hx_partial" en="The scan produced more results than this export carries, so this map describes only the ports present in the filtered window." pt="A varredura produziu mais resultados do que esta exportação carrega, portanto este mapa descreve apenas as portas presentes na janela filtrada." es="El escaneo produjo más resultados de los que lleva esta exportación, por lo tanto este mapa describe solo los puertos presentes en la ventana filtrada."/>
    <s k="sec_hexmap_host" en="Appendix: Port Exposure by Host" pt="Apêndice: Exposição de Portas por Host" es="Apéndice: Exposición de Puertos por Host"/>
    <s k="hx_host_intro" en="One board per assessed host. The state of each cell is computed from that host's findings alone, so the same port may read differently here and on the global map." pt="Um tabuleiro por host avaliado. O estado de cada célula é calculado apenas com os achados daquele host, então a mesma porta pode aparecer diferente aqui e no mapa global." es="Un tablero por host evaluado. El estado de cada celda se calcula solo con los hallazgos de ese host, así que el mismo puerto puede leerse distinto aquí y en el mapa global."/>
    <s k="hx_host_skipped_a" en="This report covers " pt="Este relatório cobre " es="Este informe cubre "/>
    <s k="hx_host_skipped_b" en=" host(s), above the limit of " pt=" host(s), acima do limite de " es=" host(s), por encima del límite de "/>
    <s k="hx_host_skipped_c" en=" set for the per-host appendix, so the per-host boards were NOT drawn. The global map above already covers every port in the scope." pt=" definido para o apêndice por host, portanto os tabuleiros por host NÃO foram desenhados. O mapa global acima já cobre todas as portas do escopo." es=" definido para el apéndice por host, por lo tanto los tableros por host NO fueron dibujados. El mapa global de arriba ya cubre todos los puertos del alcance."/>
    <s k="hx_host_none" en="No assessed host exposed a network port, so there is no per-host board to draw." pt="Nenhum host avaliado expôs uma porta de rede, portanto não há tabuleiro por host a desenhar." es="Ningún host evaluado expuso un puerto de red, por lo tanto no hay tablero por host que dibujar."/>
    <s k="hx_members" en="members: " pt="membros: " es="miembros: "/>
    <s k="hx_ip_more_a" en="and " pt="e mais " es="y "/>
    <s k="hx_ip_more_b" en=" more not listed here; the full set is in the Hosts and Open Ports section" pt=" não listados aqui; o conjunto completo está na seção Hosts e Portas Abertas" es=" más no listados aquí; el conjunto completo está en la sección Hosts y Puertos Abiertos"/>
    <s k="hx_fam_note" en=" port-family label: the scan did NOT identify a service, so the cell is named after the family of ports it collapses and not after anything observed running on them." pt=" rótulo de família de portas: o scan NÃO identificou serviço, então a célula recebe o nome da família de portas que ela colapsa, e não de algo observado em execução nelas." es=" etiqueta de familia de puertos: el escaneo NO identificó un servicio, así que la celda recibe el nombre de la familia de puertos que colapsa, y no de algo observado en ejecución en ellos."/>
    <s k="hx_noip_note" en=" port observation(s) in the source report carry no host address. They raise no host count and contribute no address to the table." pt=" observação(ões) de porta no relatório de origem não trazem endereço de host. Elas não entram na contagem de hosts nem na lista de endereços da tabela." es=" observación(es) de puerto en el informe de origen no traen dirección de host. No entran en el conteo de hosts ni en la lista de direcciones de la tabla."/>
    <s k="hx_host_noip" en=" host record(s) in this report carry no address, so no board could be drawn for them." pt=" registro(s) de host neste relatório não trazem endereço, portanto nenhum tabuleiro pôde ser desenhado para eles." es=" registro(s) de host en este informe no traen dirección, por lo tanto no se pudo dibujar ningún tablero para ellos."/>
  </xsl:variable>
  <xsl:variable name="i18n" select="exsl:node-set($i18n-rtf)/s"/>

  <!-- Localised month / weekday abbreviations (space-delimited, 1-indexed;
       weekday index follows EXSLT date:day-in-week where 1 = Sunday). -->
  <xsl:variable name="mon-en" select="'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'"/>
  <xsl:variable name="mon-pt" select="'jan fev mar abr mai jun jul ago set out nov dez'"/>
  <xsl:variable name="mon-es" select="'ene feb mar abr may jun jul ago sep oct nov dic'"/>
  <xsl:variable name="dow-en" select="'Sun Mon Tue Wed Thu Fri Sat'"/>
  <xsl:variable name="dow-pt" select="'dom seg ter qua qui sex sáb'"/>
  <xsl:variable name="dow-es" select="'dom lun mar mié jue vie sáb'"/>
  <!-- Full month names, used for the human "report date" line. -->
  <xsl:variable name="monf-en" select="'January February March April May June July August September October November December'"/>
  <xsl:variable name="monf-pt" select="'janeiro fevereiro março abril maio junho julho agosto setembro outubro novembro dezembro'"/>
  <xsl:variable name="monf-es" select="'enero febrero marzo abril mayo junio julio agosto septiembre octubre noviembre diciembre'"/>

  <!-- ================================================================= -->
  <!-- Helper functions                                                  -->
  <!-- ================================================================= -->

  <!-- Translate a chrome string key to the active language, falling back to
       English when a language column is missing. -->
  <func:function name="gvm:t">
    <xsl:param name="k"/>
    <xsl:variable name="node" select="$i18n[@k=$k]"/>
    <xsl:variable name="val" select="string($node/@*[local-name()=$L])"/>
    <func:result>
      <xsl:choose>
        <xsl:when test="string-length($val) &gt; 0"><xsl:value-of select="$val"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$node/@en"/></xsl:otherwise>
      </xsl:choose>
    </func:result>
  </func:function>

  <!-- Nth token (1-indexed) of a localised month/weekday list for language $L. -->
  <func:function name="gvm:month-abbrev">
    <xsl:param name="n"/>
    <xsl:variable name="list">
      <xsl:choose>
        <xsl:when test="$L='pt'"><xsl:value-of select="$mon-pt"/></xsl:when>
        <xsl:when test="$L='es'"><xsl:value-of select="$mon-es"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$mon-en"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <func:result select="string(str:tokenize($list, ' ')[number($n)])"/>
  </func:function>

  <func:function name="gvm:dow-abbrev">
    <xsl:param name="n"/>
    <xsl:variable name="list">
      <xsl:choose>
        <xsl:when test="$L='pt'"><xsl:value-of select="$dow-pt"/></xsl:when>
        <xsl:when test="$L='es'"><xsl:value-of select="$dow-es"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$dow-en"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <func:result select="string(str:tokenize($list, ' ')[number($n)])"/>
  </func:function>

  <func:function name="gvm:month-name">
    <xsl:param name="n"/>
    <xsl:variable name="list">
      <xsl:choose>
        <xsl:when test="$L='pt'"><xsl:value-of select="$monf-pt"/></xsl:when>
        <xsl:when test="$L='es'"><xsl:value-of select="$monf-es"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$monf-en"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <func:result select="string(str:tokenize($list, ' ')[number($n)])"/>
  </func:function>

  <!-- The report generation date ("today"), localised. Emitted instead of
       LaTeX's \today, which is locale-blind and would always read in English.
       en: "July 1, 2026"; pt/es: "1 de julho de 2026" / "1 de julio de 2026". -->
  <xsl:template name="emit-today">
    <xsl:variable name="now" select="date:date-time()"/>
    <xsl:variable name="mn" select="gvm:month-name(date:month-in-year($now))"/>
    <xsl:variable name="d" select="date:day-in-month($now)"/>
    <xsl:variable name="y" select="date:year($now)"/>
    <xsl:choose>
      <xsl:when test="$L='en'"><xsl:value-of select="concat($mn, ' ', $d, ', ', $y)"/></xsl:when>
      <xsl:otherwise><xsl:value-of select="concat($d, ' de ', $mn, ' de ', $y)"/></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <func:function name="gvm:timezone-abbrev">
    <xsl:choose>
      <xsl:when test="/report/@extension='xml'">
        <func:result select="/report/report/timezone_abbrev"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="/report/timezone_abbrev"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Return the inner report element regardless of XML nesting. -->
  <func:function name="gvm:report">
    <xsl:choose>
      <xsl:when test="count(/report/report) &gt; 0">
        <func:result select="/report/report"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="/report"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- NOME DO PROJETO.
       O relatorio nomeia o projeto em quatro lugares (capa, narrativa do resumo
       executivo, titulo do card do mapa de portas e contracapa) e todos os
       quatro liam gvm:report()/task/name direto. Numa exportacao "Anonymous
       XML" o <task> vem SEM <name> — e ai' a capa imprimia o rotulo PROJETO com
       o valor em branco, a narrativa dizia "O projeto ``''" com um par de aspas
       vazias e a contracapa saia com "PROJETO  <ponto> data".

       A identidade do projeto nao se perde nesse export: ela continua no alvo
       da tarefa e no comentario dela. Entao o nome cai, nessa ordem, para
       task/target/name e task/comment. A cadeia so' e' consultada quando o
       nome REAL esta vazio, entao um relatorio normal nunca muda; e nenhum dos
       dois substitutos e' inventado aqui — ambos vem do mesmo <task> do XML.
       Vazio ate' o fim continua vazio: quem chama e' que decide o que fazer
       (o card do hexmap, por exemplo, cai para o titulo da secao). -->
  <func:function name="gvm:project">
    <xsl:variable name="t" select="gvm:report()/task"/>
    <xsl:choose>
      <xsl:when test="string-length(normalize-space($t/name)) &gt; 0">
        <func:result select="string($t/name)"/>
      </xsl:when>
      <xsl:when test="string-length(normalize-space($t/target/name)) &gt; 0">
        <func:result select="string($t/target/name)"/>
      </xsl:when>
      <xsl:when test="string-length(normalize-space($t/comment)) &gt; 0">
        <func:result select="string($t/comment)"/>
      </xsl:when>
      <xsl:otherwise><func:result select="''"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Extract a single value out of the |-delimited nvt/tags string.
       Reads nvt/tags from the CURRENT context node (a result). -->
  <func:function name="gvm:get-nvt-tag">
    <xsl:param name="name"/>
    <xsl:variable name="after" select="substring-after(nvt/tags, concat($name, '='))"/>
    <xsl:choose>
      <xsl:when test="contains($after, '|')">
        <func:result select="substring-before($after, '|')"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$after"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- ================================================================= -->
  <!-- Date formatting (localised)                                       -->
  <!-- ================================================================= -->

  <!-- Emit a scan timestamp in the active language. English keeps the original
       "Mon Jun 28, 2026 09:00 UTC" layout; pt/es use "seg, 28 jun 2026 09:00
       UTC" (day-first, no comma before the year). -->
  <xsl:template name="emit-date">
    <xsl:param name="date"/>
    <xsl:if test="string-length($date)">
      <xsl:variable name="mon" select="gvm:month-abbrev(date:month-in-year($date))"/>
      <xsl:variable name="dow" select="gvm:dow-abbrev(date:day-in-week($date))"/>
      <xsl:variable name="day" select="date:day-in-month($date)"/>
      <xsl:variable name="yr" select="date:year($date)"/>
      <xsl:variable name="hh" select="format-number(date:hour-in-day($date), '00')"/>
      <xsl:variable name="mm" select="format-number(date:minute-in-hour($date), '00')"/>
      <xsl:variable name="tz" select="gvm:timezone-abbrev()"/>
      <xsl:choose>
        <xsl:when test="$L='en'">
          <xsl:value-of select="concat($dow, ' ', $mon, ' ', $day, ', ', $yr, ' ', $hh, ':', $mm, ' ', $tz)"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat($dow, ', ', $day, ' ', $mon, ' ', $yr, ' ', $hh, ':', $mm, ' ', $tz)"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <!-- A newline. -->
  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- LaTeX special-character escaping                                  -->
  <!-- ================================================================= -->

  <!-- Escape everything except backslash. Order matters: braces are escaped
       BEFORE the ~ / ^ replacements introduce their own literal braces. -->
  <xsl:template name="escape_special_chars">
    <xsl:param name="string"/>
    <xsl:value-of select="str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      $string,
      '$', '\$'),
      '_', '\_'),
      '%', '\%'),
      '&amp;', '\&amp;'),
      '#', '\#'),
      '{', '\{'),
      '}', '\}'),
      '~', '\textasciitilde{}'),
      '^', '\textasciicircum{}')"/>
  </xsl:template>

  <!-- Escape completo, barra invertida inclusive.

       A barra NAO pode ser separada com str:tokenize. str:tokenize DESCARTA
       token vazio, entao '\ab', 'ab\' e 'a\\b' perdiam uma barra em SILENCIO:
       'C:\Program Files' saia 'C:Program Files' e um caminho do Windows virava
       OUTRO caminho sem aviso nenhum. Enquanto escape_text era chamado uma vez
       por campo isso so' pegava o primeiro/ultimo caractere; com o fatiamento
       de 8 em 8 do escape_sliced a fronteira passou a existir a cada 8
       posicoes e a perda virou 1 barra em cada 4.

       Aqui a barra vira '\textbackslash' SEM chaves na PRIMEIRA passada,
       atravessa escape_special_chars intacta (a palavra nao contem nenhum dos
       nove caracteres que aquele template procura) e ganha as chaves na
       ULTIMA. str:replace faz UMA varredura da esquerda para a direita e nao
       reexamina o que acabou de inserir — medido: 'a\\b' sai com as DUAS
       barras, e um '\textbackslash' literal do feed sai
       '\textbackslash{}textbackslash', que imprime exatamente o que o scanner
       escreveu. Sem tokenize, sem recursao, e a barra sobrevive no inicio, no
       fim e em sequencia.

       O ramo sem barra continua sendo o caminho curto: escape_text roda uma
       vez por PEDACO de 8 caracteres, entao pagar duas passadas de str:replace
       onde nao ha barra nenhuma sairia caro a toa. -->
  <xsl:template name="escape_text">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="contains($string, '\')">
        <xsl:variable name="bs"
          select="str:replace(string($string), '\', '\textbackslash')"/>
        <xsl:variable name="esc">
          <xsl:call-template name="escape_special_chars">
            <xsl:with-param name="string" select="$bs"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:value-of
          select="str:replace(string($esc), '\textbackslash', '\textbackslash{}')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="escape_special_chars">
          <xsl:with-param name="string" select="$string"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- NOTA: o antigo escape_lines (todo '\n' virava \newline) foi retirado.
       Ele atendia TRES publicos com um comportamento so' — prosa, saida de
       terminal e campo inline — e por isso era impossivel acertar sem separa-lo.
       No lugar dele ficam escape_prose (reflui), escape_verbatim (preserva a
       linha, ganha ponto de quebra) e escape_break (inline). O compromisso de
       NAO-RECURSAO continua valendo nos tres: str:replace encadeado e
       xsl:for-each sobre str:tokenize / escada de inteiros, nunca template que
       se chama. A versao recursiva por linha estourava xsltMaxDepth=3000 em
       deteccao de milhares de linhas e o PDF nao gerava. -->

  <!-- ================================================================= -->
  <!-- Break opportunities, prose reflow and honest truncation           -->
  <!-- ================================================================= -->

  <!-- Escada de inteiros 0..199, montada a partir de $hx-ints (0..24) sem
       recursao: 8 blocos de 25. Serve aos lacos que precisam andar por POSICAO
       DE CARACTERE — fatiar texto em pedacos de $vb-chunk (usada em dois niveis
       aninhados, veja escape_sliced) e recuar ate' 150 caracteres atras do
       corte de 1500 para achar o espaco (gvm:cut-at). -->
  <xsl:variable name="ints200-rtf">
    <xsl:for-each select="$hx-ints/i[number(@v) &lt; 8]">
      <xsl:variable name="hi" select="number(@v)"/>
      <xsl:for-each select="$hx-ints/i">
        <i v="{$hi * 25 + number(@v)}"/>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:variable>
  <xsl:variable name="ints200" select="exsl:node-set($ints200-rtf)"/>

  <!-- Tamanho do pedaco do fatiamento, e quanto UM nivel da escada cobre
       (8 * 200). Com os dois niveis aninhados de escape_sliced o teto real e'
       $vb-cap * 200 = 320.000 caracteres. -->
  <xsl:variable name="vb-chunk" select="8"/>
  <xsl:variable name="vb-cap" select="1600"/>

  <!-- Acima de quantos caracteres uma PALAVRA de prosa passa pelo fatiador.
       A medida do corpo do texto e' 166mm; a palavra mais larga que cabe nela
       tem cerca de 47 caracteres em maiuscula e mais de 160 em minuscula
       estreita. 40 fica abaixo do pior caso e deixa a prosa normal — onde a
       palavra mais longa raramente passa de 20 — completamente fora do
       fatiador. -->
  <xsl:variable name="prose-tok" select="40"/>

  <!-- Insere OPORTUNIDADE DE QUEBRA depois de cada caractere que junta um token
       tecnico: / , ; : @ = ? &amp; . - _ + |
       Nao imprime hifen: \surjb e' so' uma penalidade.

       OPERA SOBRE TEXTO JA ESCAPADO, e tem de ser assim. O escape transforma
       uma barra invertida crua em \textbackslash{} e um sublinhado cru em \_;
       injetar ANTES do escape colocaria a penalidade dentro do nome de um
       comando e quebraria o documento. Depois do escape e' seguro inclusive
       para os escapes de dois caracteres: '_' e '&amp;' so' aparecem como ULTIMO
       caractere de \_ e \&amp;, entao a penalidade cai depois de um comando
       completo, nunca no meio dele. '#', '%', '$', '{' e '}' nao estao na lista
       de busca, e '\' tambem nao.

       A cadeia e' de str:replace de passada unica e \surjb{} nao contem NENHUM
       caractere do conjunto de busca — nem '/', nem '.', nem '-', nem os
       outros — de modo que nenhuma passada seguinte consegue enxergar (e
       requebrar) o que uma anterior inseriu. Nao ha recursao. -->
  <func:function name="gvm:brk">
    <xsl:param name="s"/>
    <func:result select="str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      str:replace(
      string($s),
      '/', '/\surjb{}'),
      ',', ',\surjb{}'),
      ';', ';\surjb{}'),
      ':', ':\surjb{}'),
      '@', '@\surjb{}'),
      '=', '=\surjb{}'),
      '?', '?\surjb{}'),
      '&amp;', '&amp;\surjb{}'),
      '.', '.\surjb{}'),
      '-', '-\surjb{}'),
      '_', '_\surjb{}'),
      '+', '+\surjb{}'),
      '|', '|\surjb{}')"/>
  </func:function>

  <!-- Escapa fatiando: corta o texto CRU em pedacos de $vb-chunk caracteres,
       escapa cada pedaco e emenda com \surwb. E' a rede para o token que nao
       tem UMA junta onde quebrar — hash, base64, chave de host, ou um nome de
       tarefa que o operador escreveu sem espaco. Como \surwb e' penalidade
       alta, o TeX so' o usa quando nao existe espaco nem junta que sirva.

       Fatiar o texto CRU e nao o escapado e' o que impede o corte de cair no
       meio de \textbackslash{}; o resultado e' identico ao de escapar tudo de
       uma vez porque escape_text mapeia caractere a caractere. substring() do
       XPath conta CARACTERE e nao byte, entao UTF-8 nao se parte no meio.

       Abaixo de $vb-chunk*2 caracteres nao ha o que fatiar e o laco nem roda.

       Os dois lacos sao ANINHADOS (200 blocos de 200 pedacos) e nao um laco so'
       de 200: um laco unico cobriria 1600 caracteres e o resto sairia INTEIRO,
       que e' exatamente o defeito que este template existe para evitar — medido:
       com um nome de tarefa de 8001 caracteres, os 6401 do fim viravam uma
       linha unica que saia da folha. Aninhado, o teto vai a $vb-cap * 200
       caracteres, e mesmo assim o laco externo roda UMA vez para qualquer campo
       curto. Acima do teto o texto e' cortado COM MARCA visivel: um campo com
       320 mil caracteres nao e' conteudo, e entre corte marcado e texto fora da
       pagina o corte marcado e' o menos ruim. -->
  <xsl:template name="escape_sliced">
    <xsl:param name="string"/>
    <xsl:param name="wb" select="'\surwb{}'"/>
    <xsl:variable name="len" select="string-length($string)"/>
    <xsl:choose>
      <xsl:when test="$len &lt;= $vb-chunk * 2">
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="$string"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="$ints200/i[number(@v) * $vb-cap &lt; $len]">
          <xsl:variable name="off" select="number(@v) * $vb-cap"/>
          <!-- O BLOCO sai UMA vez do texto completo e o laco de dentro fatia o
               BLOCO, nao a string inteira. substring() do XPath conta a partir
               do INICIO da string, entao fatiar a string inteira custava o
               quadrado do tamanho. Medido no mesmo Mac, campo de 400 mil
               caracteres: 21,96s de xsltproc antes, 6,03s agora. O que ainda
               sobra e' a extracao do bloco, que continua andando desde o
               inicio; com o teto de $vb-cap*200 ela roda no maximo 200 vezes.
               Campo real (deteccao cortada em 1500, nome de NVT, host) nao
               chega perto disso: o custo la' e' de centesimos de segundo. -->
          <xsl:variable name="blk" select="substring($string, $off + 1, $vb-cap)"/>
          <xsl:variable name="blen" select="string-length($blk)"/>
          <xsl:for-each select="$ints200/i[number(@v) * $vb-chunk &lt; $blen]">
            <xsl:if test="$off + number(@v) &gt; 0">
              <!-- '%' + quebra de linha DE FONTE: o pdflatex le no maximo
                   bufsize=200000 caracteres por linha de entrada e aborta o
                   documento no meio quando passa disso (medido: campo de 174
                   KB gerava PDF de 24 KB, e o `generate` faz cat do arquivo
                   sem checar codigo de saida — o cliente baixava o documento
                   mutilado). O '%' come a quebra, entao ela nao vira espaco.
                   A quebra vem ANTES do macro e nao depois: o TeX descarta
                   espaco no INICIO de linha, entao um pedaco que comecasse por
                   espaco perderia esse espaco — medido, "SSL/TLS: Report" saiu
                   "SSL/TLS:Report". Abrindo a linha com o macro (que e' uma
                   sequencia de controle), o espaco do pedaco ja esta no meio da
                   linha e sobrevive. -->
              <xsl:text>%&#10;</xsl:text>
              <xsl:value-of select="$wb"/>
            </xsl:if>
            <xsl:call-template name="escape_text">
              <xsl:with-param name="string"
                select="substring($blk, number(@v) * $vb-chunk + 1, $vb-chunk)"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:for-each>
        <xsl:if test="$len &gt; $vb-cap * 200">
          <xsl:text>\suriTruncMark{</xsl:text>
          <xsl:value-of select="$len - $vb-cap * 200"/>
          <xsl:text>}</xsl:text>
        </xsl:if>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Texto escapado + pontos de quebra. Para campo INLINE (celula de tabela,
       titulo de card, rotulo, IP, nome de NVT, nome da tarefa): nao reflui como
       paragrafo, mas precisa poder quebrar, senao vira texto fora do papel.
       Leva as duas redes: junta (barata) e, dentro do token, \surwb (cara).
       O parametro $max corta o campo e DIZ quanto cortou. Vale 0 (sem corte)
       por padrao; so' o rotulo de chrome que dimensiona a pagina o usa. -->
  <xsl:template name="escape_break">
    <xsl:param name="string"/>
    <xsl:param name="max" select="0"/>
    <xsl:param name="wb" select="'\surwb{}'"/>
    <xsl:variable name="cut">
      <xsl:choose>
        <xsl:when test="number($max) &gt; 0 and string-length($string) &gt; number($max)">
          <xsl:value-of select="substring($string, 1, number($max))"/>
        </xsl:when>
        <xsl:otherwise><xsl:value-of select="$string"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="e">
      <xsl:call-template name="escape_sliced">
        <xsl:with-param name="string" select="string($cut)"/>
        <xsl:with-param name="wb" select="$wb"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:value-of select="gvm:brk(string($e))"/>
    <xsl:if test="number($max) &gt; 0 and string-length($string) &gt; number($max)">
      <xsl:text>\suriTruncMark{</xsl:text>
      <xsl:value-of select="string-length($string) - number($max)"/>
      <xsl:text>}</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- NOME de vulnerabilidade (coluna do Sumario de Achados, titulo do card,
       tabela do grupo). Mesmo escape_break, so' que a quebra de ultimo recurso
       dentro da palavra sai VISIVEL, com hifen. Um nome de uma palavra so' que
       nao cabe na coluna de 92mm partia em silencio —
       "OracleWebLogicServerCoordinatorPortRemot / eCodeExecutionDetection" — e
       ler isso e' ler TEXTO TRUNCADO, que e' uma das quatro queixas que
       abriram este trabalho.
       O bloco de DETECCAO continua com a quebra MUDA de proposito: hifen
       fabricado no meio de um hash ou de um base64 corromperia a evidencia que
       o cliente vai conferir. -->
  <xsl:template name="escape_name">
    <xsl:param name="string"/>
    <xsl:call-template name="escape_break">
      <xsl:with-param name="string" select="$string"/>
      <xsl:with-param name="wb" select="'\surwbvis{}'"/>
    </xsl:call-template>
  </xsl:template>

  <!-- Quantos espacos abrem a linha (0..63). Sem recursao: conta quantos
       prefixos de tamanho k sao SO' espaco em branco. Nunca e' chamado para
       linha inteiramente em branco (essa vira quebra de paragrafo antes).
       O TAB ja chegou aqui expandido em 8 colunas pelo escape_prose — contado
       como UM caractere, ele fazia a linha filha sair MENOS indentada que a
       linha mae e o bloco de configuracao desenhava a hierarquia errada.
       O teto de 63 e' declarado: acima disso a indentacao satura (e o resto do
       branco e' descartado, nao deixado como espaco solto que o LaTeX colapsa
       em silencio). 24 era pouco — bloco de NVT com 30 e com 40 colunas saia
       na MESMA coluna. -->
  <func:function name="gvm:lead">
    <xsl:param name="s"/>
    <xsl:variable name="c">
      <xsl:for-each select="$ints200/i[number(@v) &gt; 0 and number(@v) &lt; 64]">
        <xsl:if test="translate(substring($s, 1, number(@v)), ' &#9;', '') = ''">
          <x/>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <func:result select="count(exsl:node-set($c)/x)"/>
  </func:function>

  <!-- A linha abre um item NUMERADO? Exige a FORMA inteira: um a tres digitos
       seguidos de '.' ou ')' E de espaco — "1. ", "2) ", "10. ". Um digito
       solto NAO basta, e essa era a raiz de um defeito medido: o feed NVT
       quebra em ~65 colunas, e a linha de continuacao que comeca por numero de
       versao, ano, porta ou RFC ("2.0 and therefore...", "2019 and no security
       fixes...") virava "item de lista" e ganhava um \newline duro. No PDF real
       de cliente 99 de 4.199 linhas (2,4%) comecam por digito.
       Um a tres digitos cobre lista de 1 a 999 e nao precisa de recursao: sao
       tres testes de prefixo. -->
  <func:function name="gvm:num-marker">
    <xsl:param name="s"/>
    <xsl:variable name="d1"
      select="string-length($s) &gt;= 1 and
              string-length(translate(substring($s, 1, 1), '0123456789', '')) = 0"/>
    <xsl:variable name="d2"
      select="string-length($s) &gt;= 2 and
              string-length(translate(substring($s, 1, 2), '0123456789', '')) = 0"/>
    <xsl:variable name="d3"
      select="string-length($s) &gt;= 3 and
              string-length(translate(substring($s, 1, 3), '0123456789', '')) = 0"/>
    <func:result select="boolean(
      ($d1 and not($d2) and (substring($s, 2, 2) = '. ' or substring($s, 2, 2) = ') ')) or
      ($d2 and not($d3) and (substring($s, 3, 2) = '. ' or substring($s, 3, 2) = ') ')) or
      ($d3 and (substring($s, 4, 2) = '. ' or substring($s, 4, 2) = ') ')))"/>
  </func:function>

  <!-- A linha tem FORMA de marcador de lista? '- ', '* ', 'o ', bullet, item
       numerado, ou letra seguida de ') '. O ESPACO depois do sinal faz parte da
       regra: sem ele, "*Note:" e "-lo" tambem casavam.
       Letra seguida de '.' continua fora de proposito: uma linha de prosa que
       comeca com "e.g." casaria e ganharia uma quebra dura que nao existe no
       texto.
       FORMA nao basta para decidir: quem decide e' gvm:marker, abaixo. -->
  <func:function name="gvm:marker-form">
    <xsl:param name="s"/>
    <func:result select="boolean(
      starts-with($s, '- ') or $s = '-' or
      starts-with($s, '* ') or $s = '*' or
      starts-with($s, 'o ') or
      starts-with($s, '&#8226; ') or $s = '&#8226;' or
      gvm:num-marker($s) or
      (substring($s, 2, 2) = ') ' and
       string-length(translate(substring($s, 1, 1),
         'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', '')) = 0))"/>
  </func:function>

  <!-- A linha abre um item de lista DE VERDADE? Forma + CONTEXTO.

       Item de lista nao aparece sozinho no meio de um paragrafo: ou a linha
       ANTERIOR fecha o contexto (esta vazia, termina em ':', esta indentada, ou
       ela mesma e' um marcador) ou a SEGUINTE tambem tem forma de marcador.
       Sem o contexto, o aposto entre travessoes de uma frase quebrada pelo feed
       — "...can force the weaker cipher and read" / "- or modify - the
       traffic..." — continuava sendo lido como item de lista e congelava a
       quebra de 65 colunas no meio da frase, que e' exatamente o defeito que o
       refluxo existe para eliminar. -->
  <func:function name="gvm:marker">
    <xsl:param name="s"/>
    <xsl:param name="prev"/>
    <xsl:param name="next"/>
    <func:result select="boolean(gvm:marker-form($s) and (
      normalize-space($prev) = '' or
      substring($prev, string-length($prev)) = ':' or
      gvm:lead($prev) &gt;= 2 or
      gvm:marker-form($prev) or
      gvm:marker-form($next)))"/>
  </func:function>

  <!-- PROSA (summary / impact / insight / affected / solution).

       O texto do feed NVT chega com quebra de linha em ~65 colunas, que e'
       acidente da largura do terminal de quem escreveu o NVT e nao intencao do
       autor. O escape_lines antigo congelava essa quebra num \newline por
       linha numa pagina de 166mm: o texto quebrava cedo E nao justificava
       (linha terminada em \newline e' preenchida com glue, nao esticada). Aqui
       o texto REFLUI:

         linha em branco (2+ '\n')  -> quebra de PARAGRAFO
         '\n' isolado               -> ESPACO (o LaTeX volta a justificar)
         proxima linha com marcador
           de lista ou indentada    -> quebra PRESERVADA

       A excecao existe porque lista e bloco indentado sao forma escolhida pelo
       autor do NVT; um "junta tudo" cego transformaria a recomendacao de tres
       itens num paragrafo corrido e o relatorio passaria a mentir sobre a forma
       da recomendacao. Sair de um bloco indentado tambem preserva a quebra,
       senao a primeira frase depois do bloco gruda na ultima linha dele.

       ORDEM: escape -> refluxo -> pontos de quebra. O escape vem PRIMEIRO
       porque assim nenhum caminho deixa texto do XML chegar cru ao LaTeX: tudo
       que acontece depois so' reescreve caracteres '\n' e insere sequencias de
       controle fixas. Os pontos de quebra vem POR ULTIMO porque o teste de
       marcador olha o inicio da linha, e injetar antes transformaria "- item"
       em "-\surjb{} item", que nao casa mais com marcador nenhum. Injetar
       depois e' seguro: \newline, \par, \mbox{} e '~' nao contem caractere de
       junta.

       LINHA EM BRANCO: str:tokenize descarta token VAZIO, entao a linha em
       branco precisa virar alguma coisa antes de tokenizar. A versao anterior
       usava a sentinela '\surPB' e por isso tinha de escapar ANTES de refluir.
       Aqui a marca e' UM ESPACO ('\n\n' -> '\n \n'): linha so' de espaco em
       branco ja e' tratada como linha em branco logo abaixo, entao a marca nao
       pode colidir com nada que o feed escreva — e o refluxo passa a trabalhar
       sobre o texto CRU, que e' o que permite fatiar token gigante (o escape
       de cada pedaco continua sendo escape_text, no fim de cada ramo).

       TOKEN GIGANTE: cada palavra acima de $prose-tok caracteres passa pelo
       escape_sliced, que poe \surwb dentro dela. Sem essa rede o campo de prosa
       continuava saindo da FOLHA — medido: impressao digital SHA-512 de 128
       hexadecimais num summary saia a 603,3pt numa folha de 595,3pt, com
       Overfull de 306pt e o build dando VEREDITO OK. Palavra curta nao e'
       fatiada: o custo fica proporcional ao token, nao ao campo.

       QUEBRA DE LINHA DE FONTE: as palavras sao emendadas por uma quebra de
       linha e nao por um espaco. Em LaTeX as duas coisas sao o mesmo espaco,
       mas a quebra segura o limite de 200.000 caracteres por linha de entrada
       do pdflatex — que, estourado, aborta o documento no meio.

       Sem recursao: str:replace encadeado + xsl:for-each sobre str:tokenize. -->
  <xsl:template name="escape_prose">
    <xsl:param name="string"/>
    <!-- CR/CRLF -> LF (o parser XML ja normaliza a quebra literal; sobra a
         escrita explicita &#13;); TAB -> 8 colunas (a largura que o autor do
         NVT enxergou no terminal — contado como 1 caractere, ele invertia a
         hierarquia do bloco indentado); linha em branco -> linha de um espaco. -->
    <xsl:variable name="norm" select="str:replace(
      str:replace(
      str:replace(
      str:replace(string($string), '&#13;&#10;', '&#10;'),
      '&#13;', '&#10;'),
      '&#9;', '        '),
      '&#10;&#10;', '&#10; &#10;')"/>
    <!-- RECUO PENDURADO DO FEED.  O bloco <tags> do Greenbone escreve
         "chave=primeira linha" e indenta em DUAS colunas TODA linha de
         continuacao: e' convencao do formato do arquivo, nao intencao do autor
         do NVT.  Medido neste relatorio (797 achados, 1.473 campos de prosa com
         mais de uma linha): 1.606 primeiras linhas, TODAS na coluna 0; 5.144
         linhas de continuacao, das quais 5.142 na coluna 2 e 2 na coluna 4.

         Sem descontar essa base, a regra "$ind >= 2 e' indentacao deliberada"
         logo abaixo casa em 99,96% das linhas de continuacao e o refluxo — a
         razao de existir deste template — nunca acontece: cada paragrafo do PDF
         sai congelado na quebra de ~65 colunas do terminal de quem escreveu o
         NVT, com um recuo falso de 2 colunas por baixo.

         Entao: quando TODA linha de continuacao nao vazia comeca com dois
         brancos, esses dois sao a base do bloco e saem.  A indentacao RELATIVA
         sobrevive intacta (a linha da coluna 4 vai para a 2 e continua sendo
         bloco indentado), marcador de lista continua quebrando por gvm:marker,
         e um bloco recuado de proposito em 4+ colunas nao e' tocado — nesse
         caso a base nao e' 2 e nada e' descontado.

         A PRIMEIRA linha entra na conta de um jeito diferente das outras: no
         campo inteiro ela vem colada no "chave=" e por isso nunca tem recuo,
         mas quem chama aqui e' o prose-block, que ja partiu o campo nas linhas
         em branco — e no segundo pedaco em diante a primeira linha do pedaco e'
         uma linha de continuacao como qualquer outra, com os 2 brancos.  Entao
         ela nao decide se ha recuo pendurado (senao um paragrafo de uma linha
         so' nunca seria reconhecido), mas e' descontada junto quando ha. -->
    <xsl:variable name="rest"
      select="str:tokenize($norm, '&#10;')[position() &gt; 1]
                                          [normalize-space(.) != '']"/>
    <xsl:variable name="body">
      <xsl:choose>
        <xsl:when test="not($rest[substring(string(.), 1, 2) != '  '])">
          <xsl:variable name="ded" select="str:replace($norm, '&#10;  ', '&#10;')"/>
          <xsl:choose>
            <xsl:when test="substring($ded, 1, 2) = '  '">
              <xsl:value-of select="substring($ded, 3)"/>
            </xsl:when>
            <xsl:otherwise><xsl:value-of select="$ded"/></xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:otherwise><xsl:value-of select="$norm"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="flow">
      <xsl:for-each select="str:tokenize(string($body), '&#10;')">
        <xsl:variable name="tok" select="string(.)"/>
        <xsl:variable name="prev" select="string(preceding-sibling::*[1])"/>
        <xsl:variable name="next" select="string(following-sibling::*[1])"/>
        <xsl:choose>
          <!-- Linha em branco: paragrafo. Runs de 4+ quebras viram \par\par,
               que no LaTeX e' inofensivo: o segundo \par fecha um paragrafo ja
               fechado. -->
          <xsl:when test="normalize-space($tok) = ''">
            <xsl:text>\par&#10;</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:variable name="ind" select="gvm:lead($tok)"/>
            <!-- Indentacao DELIBERADA e' 2 colunas ou mais. UM espaco solto no
                 comeco de uma linha de continuacao e' detrito da quebra do
                 feed, e tratado como bloco indentado ele custava DUAS quebras
                 congeladas (a de entrada e a de saida) mais um recuo falso. -->
            <xsl:variable name="pind" select="gvm:lead($prev)"/>
            <xsl:if test="position() &gt; 1 and normalize-space($prev) != ''">
              <xsl:choose>
                <xsl:when test="$ind &gt;= 2 or $pind &gt;= 2 or
                                gvm:marker($tok, $prev, $next)">
                  <xsl:text>\newline&#10;</xsl:text>
                </xsl:when>
                <xsl:otherwise><xsl:text>&#10;</xsl:text></xsl:otherwise>
              </xsl:choose>
            </xsl:if>
            <!-- Indentacao preservada. O \mbox{} e' obrigatorio: sem ele o TeX
                 descarta o espaco no comeco da linha que o \newline abriu. -->
            <xsl:if test="$ind &gt;= 2">
              <xsl:text>\mbox{}</xsl:text>
              <xsl:for-each select="$ints200/i[number(@v) &lt; $ind]">
                <xsl:text>~</xsl:text>
              </xsl:for-each>
            </xsl:if>
            <xsl:for-each select="str:tokenize(substring($tok, $ind + 1), ' ')">
              <xsl:if test="position() &gt; 1"><xsl:text>&#10;</xsl:text></xsl:if>
              <xsl:choose>
                <xsl:when test="string-length(.) &gt; $prose-tok">
                  <xsl:call-template name="escape_sliced">
                    <xsl:with-param name="string" select="string(.)"/>
                  </xsl:call-template>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:call-template name="escape_text">
                    <xsl:with-param name="string" select="string(.)"/>
                  </xsl:call-template>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:for-each>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:for-each>
    </xsl:variable>
    <xsl:value-of select="gvm:brk(string($flow))"/>
  </xsl:template>

  <!-- VERBATIM (RESULTADO DA DETECCAO). Aqui a estrutura de linha E' informacao
       — e' a saida do plugin — entao o '\n' continua virando \newline e NAO ha
       refluxo. O que muda e' que o token ganha onde quebrar:

         * escape_sliced poe \surwb a cada 8 caracteres, para o blob que nao tem
           UMA junta (hash de 384 chars, base64 de chave de host);
         * gvm:brk poe \surjb depois de cada junta.

       Como \surwb e' penalidade alta, o TeX so' o usa quando nao ha espaco nem
       junta que sirva — a saida de terminal continua quebrando onde sempre
       quebrou. -->
  <xsl:template name="escape_verbatim">
    <xsl:param name="string"/>
    <!-- A linha e' recortada AQUI e emendada com \newline, em vez de fatiar o
         campo inteiro e trocar '\n' por \newline no fim. A troca no fim nao
         sabia distinguir a quebra que veio do SCANNER da quebra de linha de
         FONTE que o escape_sliced insere para nao estourar o buffer do
         pdflatex — e teria transformado a segunda em quebra de linha visivel. -->
    <xsl:variable name="norm" select="str:replace(
      str:replace(
      str:replace(string($string), '&#13;&#10;', '&#10;'),
      '&#13;', '&#10;'),
      '&#10;&#10;', '&#10; &#10;')"/>
    <xsl:variable name="body">
      <xsl:for-each select="str:tokenize($norm, '&#10;')">
        <xsl:if test="position() &gt; 1"><xsl:text>\newline&#10;</xsl:text></xsl:if>
        <xsl:call-template name="escape_sliced">
          <xsl:with-param name="string" select="string(.)"/>
        </xsl:call-template>
      </xsl:for-each>
    </xsl:variable>
    <xsl:value-of select="gvm:brk(string($body))"/>
    <xsl:text>\mbox{}</xsl:text>
  </xsl:template>

  <!-- Onde cortar um texto longo sem partir palavra: o maior ponto &lt;= $max em
       que ha espaco em branco, recuando no maximo $back caracteres. Se nao ha
       espaco nenhum em $back caracteres (token gigante, tipo um hash), devolve
       $max — e ai' quem segura a margem e' o \surwb do escape_verbatim.
       Sem recursao: uma passada pela escada de inteiros, ordenada. -->
  <func:function name="gvm:cut-at">
    <xsl:param name="s"/>
    <xsl:param name="max"/>
    <xsl:param name="back"/>
    <xsl:variable name="cands">
      <xsl:for-each select="$ints200/i[number(@v) &lt; $back and number(@v) &lt; $max]">
        <xsl:if test="translate(substring($s, $max - number(@v), 1), ' &#10;&#9;', '') = ''">
          <k v="{$max - number(@v) - 1}"/>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="ks" select="exsl:node-set($cands)/k"/>
    <xsl:variable name="pick">
      <xsl:choose>
        <xsl:when test="count($ks) = 0"><xsl:value-of select="$max"/></xsl:when>
        <xsl:otherwise>
          <xsl:for-each select="$ks">
            <xsl:sort select="@v" data-type="number" order="descending"/>
            <xsl:if test="position() = 1"><xsl:value-of select="@v"/></xsl:if>
          </xsl:for-each>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <func:result select="number($pick)"/>
  </func:function>

  <!-- ================================================================= -->
  <!-- Severity helpers                                                  -->
  <!-- ================================================================= -->

  <!-- `threat-color' (classe -> gvm_critical/gvm_hole/gvm_warning/...) saiu
       daqui junto com `severity-pill', seu unico chamador. Aquelas cores eram
       da paleta indigo/navy anterior e nao existem mais em lugar nenhum: quem
       pinta severidade agora e' \sevcolor/\sevbg do suricatoos-tokens, e a
       CHAVE (critico|alto|medio|baixo|logsev|falsepos) vem de `sevkey-detail'.
       O template ficava como armadilha — a primeira chamada nova quebraria o
       pdflatex num "undefined color", que e' erro de tempo de compilacao. -->

  <!-- Map a numeric severity (CVSS 0–10) to a class token. GVM's <threat> never
       emits "Critical" (it maxes at "High"/"Alarm"), so all severity classing is
       derived from the numeric severity, matching the GSA severity classes.
       The token is language-neutral (used for colour + i18n key lookup). -->
  <xsl:template name="sev-class">
    <xsl:param name="severity"/>
    <xsl:choose>
      <xsl:when test="number($severity) &gt;= 9.0">Critical</xsl:when>
      <xsl:when test="number($severity) &gt;= 7.0">High</xsl:when>
      <xsl:when test="number($severity) &gt;= 4.0">Medium</xsl:when>
      <xsl:when test="number($severity) &gt;= 0.1">Low</xsl:when>
      <!-- O GVM usa severidades negativas como CÓDIGOS, não como pontuação, e
           cada uma significa uma coisa: -1 falso positivo, -2 debug, -3 erro de
           scan. Só o -1 é falso positivo, por isso a faixa é fechada em torno
           dele em vez de "qualquer negativo" — senão um erro de scan (que hoje
           chega em <errors>, mas nada garante que sempre chegue) seria
           apresentado ao leitor como falso positivo.
           A comparação usa faixa, e não igualdade, porque o valor trafega como
           decimal (-1.0) e igualdade com float é frágil.
           Sem este ramo o falso positivo cairia no `otherwise` e apareceria
           como "Log", indistinguível de uma detecção informativa legítima. -->
      <xsl:when test="number($severity) &lt; 0 and number($severity) &gt; -1.5">Falsepos</xsl:when>
      <xsl:otherwise>Log</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Numero inteiro com separador de milhar do idioma ativo. -->
  <func:function name="gvm:num">
    <xsl:param name="n"/>
    <xsl:choose>
      <xsl:when test="$L = 'en'">
        <func:result select="format-number(number($n), '#,##0')"/>
      </xsl:when>
      <xsl:otherwise>
        <!-- O padrao de format-number usa os simbolos LOCALIZADOS do
             xsl:decimal-format: com grouping-separator='.', o separador de
             grupo dentro do padrao tambem se escreve '.', nao ','. -->
        <func:result select="format-number(number($n), '#.##0', 'ptes')"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Localised severity word for a class token (Critical/High/Medium/Low/Log). -->
  <func:function name="gvm:sev-word">
    <xsl:param name="class"/>
    <!-- 'F' entra no translate para a classe Falsepos casar com sev_falsepos. -->
    <func:result select="gvm:t(concat('sev_', translate($class, 'CHMLOF', 'chmlof')))"/>
  </func:function>

  <!-- `severity-pill' saiu daqui: desenhava a pilha antiga com \colorbox e
       \setlength{\fboxsep} sobre a paleta gvm_*, e ficou sem um unico chamador
       quando as tabelas e os cards passaram a mandar a CHAVE de severidade para
       o design system (\sevbadge, \chipsev, \sevstate desenham a pilha agora).
       gvm:sev-word() continua vivo — quem o usa e' a nota da linha `geral' da
       secao 3. -->

  <!-- ================================================================= -->
  <!-- LaTeX preamble                                                    -->
  <!-- ================================================================= -->

  <xsl:template name="header">
    <!-- Tabela macro -> chave de i18n do DESIGN SYSTEM.
         Cada palavra fixa que os modulos .sty imprimem e' um \suriLbl... (ou uma
         string de mobilia de pagina); a traducao continua vindo da tabela
         gvm:t() deste XSLT. Este par de listas e' o que faz UM design system
         existir em tres linguas: o .sty desenha, o XSLT nomeia.
         O que NAO entra aqui, de proposito: \suriPlatform e \suriLockup, que
         sao MARCA ("SURICATOOS SECURITY PLATFORM", "SECURITY PLATFORM") e nao
         se traduzem em lingua nenhuma. -->
    <xsl:variable name="ds-labels-rtf">
      <!-- mobilia de pagina + capa (suricatoos-page.sty) -->
      <m c="suriDocKind"         k="running_header"/>
      <m c="suriConfidential"    k="confidential_caps"/>
      <m c="suriPageWord"        k="page_word"/>
      <m c="suriLblProject"      k="lbl_engagement"/>
      <m c="suriLblHosts"        k="lbl_hosts_assessed"/>
      <m c="suriLblScanStart"    k="lbl_scan_started"/>
      <m c="suriLblScanEnd"      k="lbl_scan_completed"/>
      <m c="suriLblReportDate"   k="lbl_report_date"/>
      <m c="suriLblClass"        k="lbl_classification"/>
      <!-- blocos de conteudo (suricatoos-blocks.sty) -->
      <m c="suriLblRisk"         k="overall_risk"/>
      <m c="suriLblSeverityChart" k="findings_by_sev"/>
      <m c="suriLblTimeline"     k="timeline"/>
      <m c="suriLblPort"         k="hx_th_port"/>
      <m c="suriLblProto"        k="hx_th_proto"/>
      <m c="suriLblService"      k="hx_th_service"/>
      <m c="suriLblState"        k="hx_th_state"/>
      <m c="suriLblCvssMax"      k="hx_th_cvss"/>
      <m c="suriLblHostsCol"     k="hx_th_hosts"/>
      <m c="suriLblIps"          k="hx_th_ips"/>
      <m c="suriLblAch"          k="th_ach"/>
      <m c="suriLblMaxSev"       k="th_max_sev"/>
      <m c="suriLblVuln"         k="th_vuln"/>
      <m c="suriLblInst"         k="th_inst"/>
      <m c="suriLblSev"          k="th_severity"/>
      <m c="suriLblSevCeiling"   k="th_sev_ceiling"/>
      <m c="suriLblAdvisory"     k="grp_th_adv"/>
      <m c="suriLblSingleFix"    k="grp_action"/>
      <m c="suriLblSolution"     k="f_solution"/>
      <m c="suriLblCvssText"     k="lbl_cvss"/>
      <m c="suriLblPortsWith"    k="hp_open_ports"/>
      <!-- cola do pacote guarda-chuva (suricatoos-report.sty) -->
      <m c="suriLblConfirmed"    k="sub_confirmed"/>
      <m c="suriLblIndicators"   k="sub_indicators"/>
      <m c="suriLblPortsMapped"  k="hx_ports_mapped"/>
      <m c="suriLblFldVector"    k="lbl_cvss_vector"/>
      <m c="suriLblFldAffected"  k="f_affected_sys"/>
      <m c="suriLblFldSummary"   k="f_summary"/>
      <m c="suriLblFldTech"      k="f_insight"/>
      <m c="suriLblFldDetection" k="f_detection"/>
      <m c="suriLblFldRefs"      k="f_references"/>
    </xsl:variable>
    <!-- Vocabulario de severidade. A CHAVE (critico|alto|...) e' DADO e nunca
         muda; a palavra impressa e' lingua, e \setsevword e' o gancho que os
         .sty deixam para trocar a lista inteira sem tocar no desenho. -->
    <xsl:variable name="ds-sevwords-rtf">
      <m c="critico" k="sev_critical"/>
      <m c="alto"    k="sev_high"/>
      <m c="medio"   k="sev_medium"/>
      <m c="baixo"   k="sev_low"/>
      <m c="logsev"  k="sev_log"/>
      <m c="exposto" k="hx_state_exposto"/>
      <m c="neutro"  k="hx_state_neutro"/>
      <!-- `falsepos' e' a unica chave de severidade que o .sty NAO traz: o
           \sevword dele cai para imprimir a propria chave, e um achado marcado
           como falso positivo saia com o chip escrito "FALSEPOS". O fixture
           anonimo nao tem severidade negativa, entao isso nunca aparecia no
           teste — mas sev-class produz a classe Falsepos e finding-cards emite
           a chave. A palavra ja' existia na tabela de i18n (sev_falsepos) e so'
           faltava o gancho. -->
      <m c="falsepos" k="sev_falsepos"/>
    </xsl:variable>
    <xsl:text>\documentclass[10pt,a4paper]{article}

% O design system inteiro, em uma linha: tokens (paleta, tipos, escala px->pt),
% mobilia de pagina (geometria, cabecalho, capa), hexmap e blocos de conteudo.
% Nenhuma cor, nenhum comprimento e nenhum \vspace sai deste XSLT: daqui para
% baixo o documento e' so' DADO dentro de macro semantica.
\usepackage{suricatoos-report}

% ---- i18n do design system ------------------------------------------------
% Os .sty desenham; as palavras vem daqui. Cada \renewcommand abaixo troca UMA
% palavra fixa de um modulo pela traducao da tabela gvm:t(), e nenhuma decisao
% visual atravessa junto.
</xsl:text>
    <xsl:for-each select="exsl:node-set($ds-labels-rtf)/m">
      <xsl:text>\renewcommand{\</xsl:text>
      <xsl:value-of select="@c"/>
      <xsl:text>}{</xsl:text>
      <xsl:value-of select="gvm:t(string(@k))"/>
      <xsl:text>}
</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="exsl:node-set($ds-sevwords-rtf)/m">
      <xsl:text>\setsevword{</xsl:text>
      <xsl:value-of select="@c"/>
      <xsl:text>}{</xsl:text>
      <xsl:value-of select="gvm:t(string(@k))"/>
      <xsl:text>}
</xsl:text>
    </xsl:for-each>
    <!-- A legenda das duas tabelas de sumario declara a BANDA de qualidade de
         deteccao. O numero nao pode estar escrito na traducao: ele e' o
         parametro $qod-min, o MESMO que segrega achado confirmado de indicador
         no corpo do relatorio. Se o operador mudar o parametro e a legenda
         continuar dizendo 70, o documento passa a mentir sobre o proprio
         criterio. Por isso a frase e' composta aqui: palavra da tabela de
         i18n + relacao (\suriGeq, o ">=" desenhado na propria Plex) + numero
         do parametro. -->
    <xsl:text>\renewcommand{\suriLblQodConfirmed}{</xsl:text>
    <xsl:value-of select="gvm:t('qod_quality')"/>
    <xsl:text> \suriGeq\ </xsl:text>
    <xsl:value-of select="$qod-min"/>
    <xsl:text>\%}
\renewcommand{\suriLblQodIndicators}{</xsl:text>
    <xsl:value-of select="gvm:t('qod_quality')"/>
    <xsl:text> &lt; </xsl:text>
    <xsl:value-of select="$qod-min"/>
    <xsl:text>\%}

% ---- Fluxo de texto de um relatorio real ----------------------------------
% Nada disso e' decisao de design: sao as travas que um documento de dezenas de
% paginas de dado de scanner precisa para nao jogar linha fora da margem nem
% deixar linha orfa no pe' da pagina.
% Absorb the occasional overfull line in justified narrative paragraphs
% (long unbreakable tokens like CVE ids / package names) instead of letting
% them poke into the margin.
\setlength{\emergencystretch}{3em}
% Uma linha solta no pe' ou no topo da pagina e' das coisas que mais denunciam
% documento gerado. article deixa a penalidade em 150, que quase nao segura
% nada. Aqui a classe e' oneside/raggedbottom, entao subir as duas ao maximo
% custa espaco no fim da pagina e nunca linha esticada.
\widowpenalty=10000
\clubpenalty=10000
\displaywidowpenalty=10000

% ---- Quebra de token longo, sem hifen -------------------------------------
% Texto de scanner traz token que nao tem UM espaco onde quebrar: lista de
% cifras separada por virgula, URL de 120 caracteres, caminho de arquivo,
% regua de tracinhos, hash. \ttfamily nao hifeniza e nao existe ponto de
% quebra em "/ , : @ - _", entao a linha saia da folha e o leitor PERDIA o
% dado. \emergencystretch nao resolve: ele estica glue, nao parte token.
%
% \surjb  entra DEPOIS de cada caractere de junta. A penalidade e' pequena mas
%         POSITIVA de proposito: quebrar num espaco continua muito mais barato,
%         entao a junta so' e' usada quando o token nao cabe de jeito nenhum.
%         Com penalidade 0 o TeX passaria a partir URL no meio so' para encher
%         a linha mais um pouco.
% \surwb  entra a cada 8 caracteres dentro do bloco verbatim, como rede para o
%         blob que nao tem UMA junta (hash, base64, chave de host). Penalidade
%         bem mais alta: e' ultimo recurso, nunca primeira escolha.
% Nenhum dos dois imprime hifen.
\newcommand{\surjb}{\penalty100\relax}
\newcommand{\surwb}{\penalty700\relax}
% \surwbvis e' o MESMO ultimo recurso do \surwb, mas VISIVEL: quando a quebra
% dispara sai um hifen, que avisa o leitor de que a palavra continua na linha
% seguinte. Vale so' para NOME de vulnerabilidade. Um nome de uma palavra so'
% que nao cabe na coluna partia em silencio, no caractere 40 (a grade do
% \surwb), e isso se le como TEXTO TRUNCADO.
% NAO pode ser usado no bloco de DETECCAO: hifen fabricado no meio de um hash
% ou de um base64 corrompe a evidencia que o cliente vai conferir. Sao dois
% macros justamente para que o verbatim continue MUDO.
\newcommand{\surwbvis}{\discretionary{-}{}{}}
% Nome proprio de produto/vulnerabilidade nao se hifeniza ("...(PFS) Ci-pher
% Suites" foi lido como truncagem). Nas colunas onde so' entra nome tecnico a
% hifenizacao e' desligada e a folga vai para o espacamento entre palavras
% (\tolerance), nunca para fora da margem.
% \surname e' o regime da COLUNA de nome tecnico. As tres pecas sao uma coisa
% so' e nenhuma funciona sozinha:
%   sem hifenizacao   - nome proprio nao se parte com hifen;
%   alinhado a esquerda - e' o que torna a quebra no meio da palavra CARA. Numa
%     coluna justificada de 92mm o TeX tinha de escolher entre linha muito
%     frouxa e partir a palavra, e passou a partir: "Unauthenticated Co /
%     nfiguration", pior que o hifen que a gente tinha acabado de tirar. Com
%     \raggedright toda linha tem excesso 0, entao quebrar num espaco custa 100
%     de demerito e quebrar no meio da palavra custa 100 + 700^2. A quebra
%     interna vira ultimo recurso de verdade — existe (nada sai da margem) mas
%     so' aparece se UMA palavra sozinha nao couber na coluna.
%   \arraybackslash - devolve o \\ da tabela, que o \raggedright sequestra.
% Coluna de tabela nao e' prosa: alinhar a esquerda aqui e' o normal
% tipografico, e nao tem relacao com a justificacao do corpo do texto.
% \hyphenpenalty precisa ser FINITA, senao ela desliga tambem o \discretionary
% do \surwbvis e o nome volta a partir sem hifen. Quem impede a hifenizacao
% AUTOMATICA (o "(PFS) Ci-pher Suites" que abriu esta linha de trabalho) e'
% \lefthyphenmin=63: o TeX so' hifeniza palavra de ate' 63 letras, entao exigir
% 63 letras antes do hifen desliga o algoritmo sem tocar em discretionary
% explicito.
% \surnametxt e' o regime de HIFENIZACAO do nome tecnico, sem o alinhamento:
% vale onde o nome aparece fora de coluna de tabela (titulo de card), que ja tem
% seu proprio \raggedright.
\newcommand{\surnametxt}{\hyphenpenalty=700\exhyphenpenalty=10000\lefthyphenmin=63}
\newcommand{\surname}{\surnametxt\hbadness=10000\raggedright\arraybackslash}

% ---- hyperref, por ultimo, so' pelos metadados do documento ---------------
% O design system NAO desenha link: quem pinta a URL de referencia e' \refurl,
% em carmim, e suricatoos-blocks.sty carrega hyperref sozinho [hidelinks] se o
% documento nao tiver carregado. Carregamos aqui, com as MESMAS opcoes, por um
% motivo so': o titulo e o autor do PDF (o que o leitor ve na aba do visualizador
% e no `pdfinfo`) sao dado do relatorio e tem de sair traduzidos.
% Sem `hidelinks` o hyperref desenharia um quadro colorido em volta de cada
% \href, que e' exatamente a moldura que o modelo nao tem.
\usepackage[unicode=true,hidelinks]{hyperref}
% Só metadado aqui. `bookmarks'/`bookmarksopen' NAO cabem em \hypersetup: o
% hyperref so' honra as duas como opcao de CARGA do pacote, e passa-las depois
% rendia o unico warning do log ("Option `bookmarks' has already been used")
% sem produzir arvore nenhuma --- o documento nao usa \section, entao nao ha
% o que indexar. Uma arvore de navegacao de verdade e' \pdfbookmark emitido
% por secao, que e' feature, nao opcao de preambulo.
\hypersetup{pdftitle={</xsl:text>
    <xsl:value-of select="gvm:t('pdftitle')"/>
    <xsl:text>},pdfauthor={Suricatoos Security Platform}}
% A URL de referencia sai do feed com 120+ caracteres. Em \ttfamily (o padrao
% do hyperref) ela ocupa ~40%% mais medida e estourava 138pt para fora da
% margem mesmo dentro de \url. \urlstyle{same} a compoe na fonte do texto, e a
% linha abaixo ACRESCENTA o hifen a lista de quebra do url.sty (que por padrao
% nao quebra em "-", justamente o separador mais comum em caminho de aviso de
% fornecedor). A lista antiga e' preservada com \expandafter em vez de
% redefinida, para nao derrubar os pontos de quebra que o pacote ja oferece.
\urlstyle{same}
\expandafter\def\expandafter\UrlBreaks\expandafter{\UrlBreaks\do\-}
\pagenumbering{arabic}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Cover page                                                        -->
  <!-- ================================================================= -->

  <xsl:template name="cover-page">
    <!-- O corte do nome da tarefa na CAPA e' outro desde o design system, e a
         razao mudou de eixo. No quadro antigo o nome caia num m{102mm} que
         REFLUIA e crescia para CIMA, entao o teto era de ALTURA e $task-name-max
         (600, medido la') era o numero certo. A grade de metadados de
         \suriCover nao reflui: cada valor e' um no de TikZ ancorado pela base
         direita, sem `text width`, portanto uma LINHA so'. Um nome de 600
         caracteres nao empurra o logotipo — ele sai andando para a esquerda por
         cima do rotulo vizinho e para fora da folha.
         Medido na propria geometria do modulo: a coluna da grade e'
         (paperwidth-64-64-42)/2 = ~313px. O orcamento tem que valer para o
         rotulo MAIS LARGO das tres linguas, que e' o ingles ENGAGEMENT (~73px em
         Mono 9.5 com tracking 165), nao para o PROJETO do portugues (~51px): foi
         essa conta pelo rotulo curto que fez o nome do sample atravessar o
         proprio rotulo na capa em ingles. Sobram ~226px; a Mono 11 gasta ~6.6px
         por caractere e a marca de corte ("...(+N)") mais ~30px, o que fecha em
         28 caracteres. Isto e a primeira linha de defesa; a segunda esta em
         suricatoos-page.sty, onde \suri@cvcell mede o rotulo de verdade e
         encolhe o valor para o vao que sobrou: assim um orcamento errado
         degrada para um valor um pouco menor, nunca para uma colisao. $task-name-max continua valendo onde o texto REFLUI (a
         narrativa do resumo executivo); aqui o limite e' a linha.
         escape_break e nao escape_text porque quem nomeia a tarefa e' o
         operador: o nome traz _ & % # $ e til do jeito que ele escreveu. O que
         foi cortado e' DECLARADO na propria capa; o valor inteiro continua no
         relatorio de origem e nenhum dado de achado e' tocado. -->
    <xsl:variable name="cover-name-max" select="28"/>
    <xsl:variable name="task_escaped">
      <xsl:call-template name="escape_break">
        <xsl:with-param name="string" select="gvm:project()"/>
        <xsl:with-param name="max" select="$cover-name-max"/>
      </xsl:call-template>
    </xsl:variable>
    <!-- \suriCover desenha a pagina 1 inteira (fundo navy, hexagonos, masthead,
         titulo, grade de metadados, linha de rodape) e fecha com \clearpage.
         Aqui so' entram DADOS.
         TODO valor vai entre chaves de proposito: as chaves de xkeyval sao
         separadas por virgula e o par e' cortado no primeiro "=", e tres destes
         valores carregam virgula ou "=" com frequencia — a data localizada em
         pt/es sai "ter, 30 jun 2026 00:00 UTC" e o nome de tarefa e' texto livre
         que o operador escreve como quiser. Sem as chaves, "ter" viraria uma
         chave desconhecida de keyval e o run morreria com "undefined key". -->
    <xsl:text>\suriCover{
  kicker={</xsl:text>
    <xsl:value-of select="gvm:t('cover_kicker')"/>
    <xsl:text>},
  title={</xsl:text>
    <xsl:value-of select="gvm:t('cover_title')"/>
    <xsl:text>},
  subtitle={</xsl:text>
    <xsl:value-of select="gvm:t('cover_prepared')"/>
    <xsl:text>},
  projeto={</xsl:text>
    <xsl:value-of select="$task_escaped"/>
    <xsl:text>},
  hosts={</xsl:text>
    <xsl:value-of select="count(gvm:report()/host)"/>
    <xsl:text>},
  inicio={</xsl:text>
    <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_start"/></xsl:call-template>
    <xsl:text>},
  fim={</xsl:text>
    <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_end"/></xsl:call-template>
    <xsl:text>},
  data={</xsl:text>
    <xsl:call-template name="emit-today"/>
    <xsl:text>},
  classificacao={</xsl:text>
    <xsl:value-of select="gvm:t('confidential_caps')"/>
    <xsl:text>}
}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Executive summary                                                 -->
  <!-- ================================================================= -->

  <!-- The KPI strip and the severity bars are \kpirow / \sevbars now: the tiles
       are a design-system block, not a tikzpicture this stylesheet draws.  What
       is left here that the design system cannot supply is the SHAPE of the two
       timeline values, because \timelinestrip takes them as data.

       emit-date-stacked / emit-today-stacked — the same timestamps emit-date and
       emit-today produce, split over the two lines the model's timeline cell
       shows: the calendar date on the first, the clock (or the year) on the
       second.  The cell is 60px tall and top-aligned, so an unbroken date would
       hang alone at its top instead of filling it.  The break is explicit and
       not left to the minipage: at 11px Mono the whole string still fits one
       line of the 222px column, so it would never wrap on its own. -->
  <xsl:template name="emit-date-stacked">
    <xsl:param name="date"/>
    <xsl:choose>
      <xsl:when test="string-length($date)">
        <xsl:variable name="mon" select="gvm:month-abbrev(date:month-in-year($date))"/>
        <xsl:variable name="dow" select="gvm:dow-abbrev(date:day-in-week($date))"/>
        <xsl:variable name="day" select="date:day-in-month($date)"/>
        <xsl:variable name="yr" select="date:year($date)"/>
        <xsl:variable name="hh" select="format-number(date:hour-in-day($date), '00')"/>
        <xsl:variable name="mm" select="format-number(date:minute-in-hour($date), '00')"/>
        <xsl:variable name="tz" select="gvm:timezone-abbrev()"/>
        <xsl:choose>
          <xsl:when test="$L='en'">
            <xsl:value-of select="concat($dow, ' ', $mon, ' ', $day, ', ', $yr)"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="concat($dow, ', ', $day, ' ', $mon, ' ', $yr)"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>\\</xsl:text>
        <xsl:value-of select="normalize-space(concat($hh, ':', $mm, ' ', $tz))"/>
      </xsl:when>
      <!-- A task that never started has no scan_start. The cell still has to
           print something, or the reader reads an empty column as a bug. -->
      <xsl:otherwise><xsl:text>---</xsl:text></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="emit-today-stacked">
    <xsl:variable name="now" select="date:date-time()"/>
    <xsl:variable name="mn" select="gvm:month-name(date:month-in-year($now))"/>
    <xsl:variable name="d" select="date:day-in-month($now)"/>
    <xsl:variable name="y" select="date:year($now)"/>
    <xsl:choose>
      <!-- A quebra vai ANTES do dia, nao depois da virgula: "August 22," /
           "2026" pendurava a virgula no fim da primeira linha e deixava o ano
           sozinho na segunda. "August" / "22, 2026" mantem a data junta e casa
           com o desenho de pt/es ("22 de agosto" / "de 2026"). -->
      <xsl:when test="$L='en'"><xsl:value-of select="concat($mn, '\\', $d, ', ', $y)"/></xsl:when>
      <xsl:otherwise><xsl:value-of select="concat($d, ' de ', $mn, '\\de ', $y)"/></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- How the narrative closes the High/Critical count.
       Three cases, because the honest sentence is not the same in all of them:

         lowconf = 0        the findings are confirmed; say remediate.
         0 < lowconf < N    remediate, and say how many still need validating.
         lowconf = N        do NOT say "remediate at once".  Every one of those
                            findings came in below the QoD minimum, so the only
                            correct instruction is to validate first — and the
                            severity shown is a ceiling, not a fact.

       The last case is not hypothetical: on the scan this design was drawn from,
       all 62 High/Critical findings carry QoD 30.  The old wording told the
       reader to remediate immediately AND that all 62 needed manual validation,
       in the same sentence.  Section 4 already segregates these two populations;
       the summary must not undo that work one page earlier. -->
  <xsl:template name="exec-remediation-clause">
    <xsl:param name="hicrit"/>
    <xsl:param name="lowconf"/>
    <xsl:choose>
      <xsl:when test="$hicrit &gt; 0 and $lowconf &gt;= $hicrit">
        <xsl:value-of select="gvm:t('exec_all_lowconf')"/>
      </xsl:when>
      <xsl:when test="$lowconf &gt; 0">
        <xsl:value-of select="gvm:t('exec_warrant')"/>
        <xsl:text> --- </xsl:text><xsl:value-of select="$lowconf"/>
        <xsl:value-of select="gvm:t('of_which_lowconf')"/>
        <xsl:text>.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="gvm:t('exec_warrant')"/><xsl:text>.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="executive-summary">
    <!-- Severity counts come from gvmd's own <result_count>, band by band, NOT
         from counting the <result> elements this export happens to carry.
         v4 fixed exactly this for the TOTAL and stopped there; the bars kept
         counting the filter window, so a filtered export under-reported them.
         Measured in production: a report whose scan produced 4 High printed
         "ALTO 2", because the default export filter (min_qod=70) had dropped
         the two low-confidence High results before the stylesheet saw them.
         The <full> child is the scan; <filtered> is the window. Fall back to
         counting only when gvmd did not send the element. -->
    <xsl:variable name="rc" select="gvm:report()/result_count"/>
    <xsl:variable name="crit">
      <xsl:choose>
        <xsl:when test="$rc/critical/full"><xsl:value-of select="number($rc/critical/full)"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[number(severity) &gt;= 9.0])"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="high">
      <xsl:choose>
        <xsl:when test="$rc/high/full"><xsl:value-of select="number($rc/high/full)"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[number(severity) &gt;= 7.0 and number(severity) &lt; 9.0])"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="med">
      <xsl:choose>
        <xsl:when test="$rc/medium/full"><xsl:value-of select="number($rc/medium/full)"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[number(severity) &gt;= 4.0 and number(severity) &lt; 7.0])"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="low">
      <xsl:choose>
        <xsl:when test="$rc/low/full"><xsl:value-of select="number($rc/low/full)"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[number(severity) &gt;= 0.1 and number(severity) &lt; 4.0])"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <!-- Log = informativo (severidade 0 a 0.1). Falso positivo tem severidade
         NEGATIVA no GVM e é contado à parte: somá-lo ao Log inflaria o
         informativo com itens que foram explicitamente descartados. -->
    <xsl:variable name="logc" select="count(gvm:report()/results/result[number(severity) &gt;= 0 and number(severity) &lt; 0.1])"/>
    <!-- Mesma faixa usada em sev-class: só -1 é falso positivo. Um -3 (erro de
         scan) não é achado e não entra em contagem nenhuma. -->
    <xsl:variable name="fpc" select="count(gvm:report()/results/result[number(severity) &lt; 0 and number(severity) &gt; -1.5])"/>
    <xsl:variable name="hosts" select="count(gvm:report()/host)"/>
    <!-- Results actually carried by this XML: what the document can describe. -->
    <xsl:variable name="total" select="count(gvm:report()/results/result)"/>
    <!-- Results the SCAN produced. gvmd reports it as the text node of
         <result_count>, with the post-filter count in <filtered> (same contract
         the stock GVM formats rely on). Counting <result> elements instead
         reports the size of the filter window as if it were the whole scan:
         any export carrying a row limit then understates the total, silently
         and by an arbitrary factor. Fall back to $total when it is missing or
         inconsistent, and never claim FEWER results than we actually list. -->
    <xsl:variable name="rc-full" select="normalize-space(gvm:report()/result_count/text())"/>
    <xsl:variable name="total-full">
      <xsl:choose>
        <xsl:when test="string-length($rc-full) &gt; 0 and floor(number($rc-full)) = number($rc-full) and number($rc-full) &gt;= $total">
          <xsl:value-of select="number($rc-full)"/>
        </xsl:when>
        <xsl:otherwise><xsl:value-of select="$total"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="truncated" select="number($total-full) &gt; $total"/>
    <xsl:variable name="rated" select="$crit + $high + $med + $low"/>
    <xsl:variable name="uniq" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])])"/>
    <!-- High/critical results the scanner is NOT confident about. Reported apart
         so "warrant prompt remediation" never silently includes guesses. -->
    <xsl:variable name="lowconf-hi" select="count(gvm:report()/results/result[number(severity) &gt;= 7.0][qod/value][number(qod/value) &lt; number($qod-min)])"/>

    <!-- Overall risk rating derivation -->
    <xsl:variable name="riskWord">
      <xsl:choose>
        <!-- Zero hosts reached: the rating is not "informational", it is absent.
             Saying anything on the severity ramp here would be a measurement
             this scan never made. -->
        <xsl:when test="$hosts = 0"><xsl:value-of select="gvm:t('risk_notmeasured')"/></xsl:when>
        <xsl:when test="$crit &gt; 0"><xsl:value-of select="gvm:t('risk_critical')"/></xsl:when>
        <xsl:when test="$high &gt; 0"><xsl:value-of select="gvm:t('risk_high')"/></xsl:when>
        <xsl:when test="$med &gt; 0"><xsl:value-of select="gvm:t('risk_medium')"/></xsl:when>
        <xsl:when test="$low &gt; 0"><xsl:value-of select="gvm:t('risk_low')"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="gvm:t('risk_info')"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <!-- No $riskColor any more: the classification tile is navy with the word in
         the `riskvalue' token whatever the rating is (model pg-02), so the rating
         no longer picks a colour. The DERIVATION above stays exactly as it was —
         highest severity present wins — because it is the rating itself. -->

    <xsl:text>\suriSection{1}{</xsl:text><xsl:value-of select="gvm:t('sec_exec')"/><xsl:text>}

</xsl:text>

    <!-- Narrative (per-language, with counts interpolated) -->
    <!-- Mesmo corte da capa: aqui o nome entra no meio de uma frase, e um nome
         de milhares de caracteres empurraria o paragrafo executivo inteiro. -->
    <xsl:variable name="taskname">
      <xsl:call-template name="escape_break">
        <xsl:with-param name="string" select="gvm:project()"/>
        <xsl:with-param name="max" select="$task-name-max"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="hicrit" select="$crit + $high"/>
    <!-- One \suriPara: the narrative is a single paragraph of running copy and
         the design system owns its measure, its leading and the air under it.
         The overall-risk sentence that used to close it is gone — the rating is
         the navy tile of \kpirow now, and printing it twice on one page reads
         as two different statements of the same thing. -->
    <!-- The narrative only makes sense if something was measured.  With zero
         hosts reached it would read "assessed 0 host(s) and produced 0
         result(s)... 0 findings are of High or Critical severity" — an absurd
         sentence that a reader still parses as good news.  Say what actually
         happened instead. -->
    <xsl:choose>
      <xsl:when test="$hosts = 0">
        <xsl:text>\alertbox{</xsl:text><xsl:value-of select="gvm:t('nohost_title')"/>
        <xsl:text>}{</xsl:text>
        <xsl:value-of select="gvm:t('nohost_body_a')"/>
        <xsl:text>\textbf{</xsl:text><xsl:value-of select="gvm:t('nohost_body_b')"/><xsl:text>}</xsl:text>
        <xsl:value-of select="gvm:t('nohost_body_c')"/>
        <xsl:text>}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
    <xsl:text>\suriPara{</xsl:text>
    <xsl:choose>
      <xsl:when test="$L='pt'">
        <xsl:text>Este relatório apresenta os resultados de uma avaliação de vulnerabilidades realizada pela Plataforma de Segurança Suricatoos. O projeto \textbf{``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>''} avaliou </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) e produziu </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> resultado(s), descrevendo </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> vulnerabilidade(s) única(s). Destas, \textbf{</xsl:text>
        <xsl:value-of select="$hicrit"/><xsl:text> achado(s) são de severidade Alta ou Crítica}</xsl:text>
        <xsl:call-template name="exec-remediation-clause">
          <xsl:with-param name="hicrit" select="$hicrit"/>
          <xsl:with-param name="lowconf" select="$lowconf-hi"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$L='es'">
        <xsl:text>Este informe presenta los resultados de una evaluación de vulnerabilidades realizada por la Plataforma de Seguridad Suricatoos. El proyecto \textbf{``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>''} evaluó </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) y produjo </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> resultado(s), describiendo </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> vulnerabilidad(es) única(s). De estas, \textbf{</xsl:text>
        <xsl:value-of select="$hicrit"/><xsl:text> hallazgo(s) son de severidad Alta o Crítica}</xsl:text>
        <xsl:call-template name="exec-remediation-clause">
          <xsl:with-param name="hicrit" select="$hicrit"/>
          <xsl:with-param name="lowconf" select="$lowconf-hi"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This report presents the findings of a vulnerability assessment performed by the Suricatoos Security Platform. The engagement \textbf{``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>''} assessed </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) and produced </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> result(s), describing </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> unique vulnerabilit</xsl:text>
        <xsl:choose><xsl:when test="$uniq = 1">y</xsl:when><xsl:otherwise>ies</xsl:otherwise></xsl:choose>
        <xsl:text>. Of these, \textbf{</xsl:text><xsl:value-of select="$hicrit"/>
        <xsl:text> finding(s) are of High or Critical severity}</xsl:text>
        <xsl:call-template name="exec-remediation-clause">
          <xsl:with-param name="hicrit" select="$hicrit"/>
          <xsl:with-param name="lowconf" select="$lowconf-hi"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>}
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>

    <!-- KPI strip: the navy risk tile plus the three counted tiles. The tile
         label of the first one is design furniture (\suriLblRisk); the other
         three carry a DATA label, so they keep coming from gvm:t(). -->
    <xsl:text>\kpirow{\suriLblRisk}{</xsl:text><xsl:value-of select="$riskWord"/><xsl:text>}%
       {</xsl:text><xsl:value-of select="gvm:t('m_hosts')"/><xsl:text>}{</xsl:text><xsl:value-of select="$hosts"/><xsl:text>}%
</xsl:text>
    <!-- Total the SCAN produced, not the number of rows this export carries. -->
    <xsl:text>       {</xsl:text><xsl:value-of select="gvm:t('m_total')"/><xsl:text>}{</xsl:text><xsl:value-of select="$total-full"/><xsl:text>}%
       {</xsl:text><xsl:value-of select="gvm:t('m_uniq')"/><xsl:text>}{</xsl:text><xsl:value-of select="$uniq"/><xsl:text>}

</xsl:text>

    <!-- Sampling disclosure. Only rendered when the export really is partial,
         so a complete report carries no needless caveat. -->
    <xsl:if test="$truncated">
      <xsl:text>\warnbox{\textbf{</xsl:text><xsl:value-of select="gvm:t('sample_hdr')"/><xsl:text>} --- </xsl:text>
      <xsl:value-of select="gvm:t('sample_a')"/>
      <xsl:text>\textbf{</xsl:text><xsl:value-of select="$total"/><xsl:text>}</xsl:text>
      <xsl:value-of select="gvm:t('sample_b')"/>
      <xsl:text>\textbf{</xsl:text><xsl:value-of select="$total-full"/><xsl:text>}</xsl:text>
      <xsl:value-of select="gvm:t('sample_c')"/>
      <!-- Name the QoD floor when the export carried one: "51 of 53" alone does
           not tell the reader that what was cut is precisely the low-confidence
           population that section 4 segregates. gvmd echoes the applied filter
           in <filters><term>. -->
      <xsl:variable name="fterm" select="string(gvm:report()/filters/term)"/>
      <xsl:if test="contains($fterm, 'min_qod=')">
        <xsl:variable name="mq"
          select="substring-before(concat(substring-after($fterm,'min_qod='),' '),' ')"/>
        <xsl:if test="number($mq) &gt; 1">
          <xsl:value-of select="gvm:t('sample_qod_a')"/>
          <xsl:text>\textbf{</xsl:text><xsl:value-of select="$mq"/><xsl:text>}</xsl:text>
          <xsl:value-of select="gvm:t('sample_qod_b')"/>
        </xsl:if>
      </xsl:if>
      <xsl:text>}

</xsl:text>
    </xsl:if>

    <!-- Severity breakdown. \sevbars reads its argument twice — once to find the
         largest count, once to draw — so the four \sevbar rows are all this has
         to emit: no scale, no axis, no colours. The keys are the design system's
         language-neutral severity tokens and the printed word comes from
         \sevword, which the preamble localises with \setsevword. -->
    <xsl:text>\blocklabel{\suriLblSeverityChart}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$crit + $high + $med + $low = 0">
        <xsl:text>\blocknote{</xsl:text><xsl:value-of select="gvm:t('no_findings')"/><xsl:text>}

</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\sevbars{\sevbar{critico}{</xsl:text><xsl:value-of select="$crit"/>
        <xsl:text>}\sevbar{alto}{</xsl:text><xsl:value-of select="$high"/>
        <xsl:text>}\sevbar{medio}{</xsl:text><xsl:value-of select="$med"/>
        <xsl:text>}\sevbar{baixo}{</xsl:text><xsl:value-of select="$low"/>
        <xsl:text>}}

</xsl:text>
      </xsl:otherwise>
    </xsl:choose>

    <!-- Scan timeline: three columns under the ink rule. The column labels are
         data (they name a scan event), so they stay on gvm:t(); the heading over
         the strip is furniture and comes from the design system. -->
    <xsl:text>\blocklabel{\suriLblTimeline}
\timelinestrip{</xsl:text><xsl:value-of select="gvm:t('lbl_scan_started')"/><xsl:text>}{</xsl:text>
    <xsl:call-template name="emit-date-stacked"><xsl:with-param name="date" select="gvm:report()/scan_start"/></xsl:call-template>
    <xsl:text>}%
              {</xsl:text><xsl:value-of select="gvm:t('lbl_scan_completed')"/><xsl:text>}{</xsl:text>
    <xsl:call-template name="emit-date-stacked"><xsl:with-param name="date" select="gvm:report()/scan_end"/></xsl:call-template>
    <xsl:text>}%
              {</xsl:text><xsl:value-of select="gvm:t('t_generated')"/><xsl:text>}{</xsl:text>
    <xsl:call-template name="emit-today-stacked"/><xsl:text>}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Hosts and open ports (per-target service inventory)               -->
  <!-- ================================================================= -->

  <!-- Highest numeric severity among a set of results, or the EMPTY string when
       the set is empty.  It returns DATA (the CVSS number), not a rendered pill:
       in the design system the badge is drawn by \sevbadges from two separate
       arguments, the severity KEY and the score, so the two travel apart from
       here on and the caller decides which of them to print.
       The caller passes the node-set because the two kinds of row this section
       draws select their results differently: one port for a normal row, every
       general/* pseudo-port at once for the aggregated host-level row. -->
  <xsl:template name="port-max-sev">
    <xsl:param name="rs"/>
    <xsl:for-each select="$rs">
      <xsl:sort select="severity" data-type="number" order="descending"/>
      <xsl:if test="position() = 1"><xsl:value-of select="severity"/></xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- Numeric severity -> the severity KEY of the design system, the vocabulary
       the .sty files colour and word (critico|alto|medio|baixo|logsev, plus
       neutro for a port that carries no result at all).  The cut points are the
       ones `sev-class' already uses — that template stays the source of truth
       for the localised class WORD; this one only names the key the LaTeX macros
       take, and the two must not drift apart.
       A port whose highest result is a FALSE POSITIVE (-1, a GVM code and not a
       score) reads as `neutro', never as `logsev': folding it into Log would
       make a result the scanner itself disowned indistinguishable from a
       legitimate informational detection, which is the confusion `sev-class'
       was written to avoid.  The range is closed around -1 for the same reason
       it is there: -2 (debug) and -3 (scan error) are other codes entirely. -->
  <xsl:template name="hp-sev-key">
    <xsl:param name="severity"/>
    <xsl:choose>
      <xsl:when test="string-length($severity) = 0">neutro</xsl:when>
      <xsl:when test="number($severity) &gt;= 9.0">critico</xsl:when>
      <xsl:when test="number($severity) &gt;= 7.0">alto</xsl:when>
      <xsl:when test="number($severity) &gt;= 4.0">medio</xsl:when>
      <xsl:when test="number($severity) &gt;= 0.1">baixo</xsl:when>
      <xsl:when test="number($severity) &lt; 0 and number($severity) &gt; -1.5">neutro</xsl:when>
      <xsl:otherwise>logsev</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- One line of a host card: \hostrow{porta}{achados}{sev}{cvss}.
       The port and the transport ride together in the first argument, exactly as
       the scan reports the pair ("21/tcp"), so nothing is split and re-joined:
       PROTO was a column of its own in the old table and is not one here.

       general=1 switches the row to the aggregated HOST-LEVEL line.  Every
       general/* pseudo-port of the host collapses into a single `geral' row —
       one row, the sum of the findings, the highest severity among them — which
       is what the model draws and what the \blocknote under the card takes
       apart.  The old table printed one italic "Geral / nivel de host" line per
       pseudo-port instead, and two of them next to each other read as two ports.

       Scores: a row with no result at all is `neutro' and prints the word alone
       (it replaces the em dash of the old table); a row whose top severity is 0
       is `logsev' and also prints the word alone, because a CVSS of 0.0 beside
       the word LOG is noise, not information. -->
  <xsl:template name="port-row">
    <xsl:param name="ip"/>
    <xsl:param name="pstr"/>
    <xsl:param name="general" select="0"/>
    <xsl:variable name="rs" select="gvm:report()/results/result[host/text()=$ip]
                                    [(number($general) = 1 and starts-with(port, 'general'))
                                     or (number($general) = 0 and port = $pstr)]"/>
    <xsl:variable name="maxsev">
      <xsl:call-template name="port-max-sev">
        <xsl:with-param name="rs" select="$rs"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="key">
      <xsl:call-template name="hp-sev-key">
        <xsl:with-param name="severity" select="string($maxsev)"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:text>\hostrow{</xsl:text>
    <xsl:choose>
      <!-- The label of the aggregated row is set in lower case: it sits in a
           Mono column of port numbers and reads as one of them, not as a title. -->
      <xsl:when test="number($general) = 1">
        <xsl:value-of select="translate(gvm:t('hp_general'),
          'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="escape_break"><xsl:with-param name="string" select="$pstr"/></xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>}{</xsl:text>
    <xsl:value-of select="count($rs)"/>
    <xsl:text>}{</xsl:text>
    <xsl:value-of select="$key"/>
    <xsl:text>}{</xsl:text>
    <xsl:if test="$key != 'logsev' and $key != 'neutro'">
      <xsl:value-of select="$maxsev"/>
    </xsl:if>
    <xsl:text>}
</xsl:text>
  </xsl:template>

  <!-- The HEAD of a host card: emits \hostcard{ip}{hostname}{so}{portas}{ and
       leaves the body argument OPEN.  In the design system the navy title band
       is not a thing of its own — it is the first half of \hostcard, which also
       owns the two mini-tables under it — so there is no free-standing banner to
       draw any more.  Whoever calls this writes the body and closes the braces
       (see hp-host-card); calling it and stopping there leaves a runaway
       argument, which is why nothing outside this section may call it.

       That also retires the overflow this template used to fight: the strip was
       a hand-built \colorbox with an \hfill in it, and a long OS string walked
       off the page (measured: up to +67.9pt outside the margin) until it was
       wrapped in a minipage.  The band, the OS badge and the port tally are laid
       out by \hostcard now, from data alone.

       The OS still comes from the host details (best_os_txt, then best_os_cpe,
       resolved by the caller) and still falls back to a fixed label when the
       scan identified none — but to a SHORT one: the badge is a chip, not a
       sentence, so a 40-character OS is cut here rather than pushing the port
       tally off the band.  The cut is done in XSLT and not with \escape_break's
       breakpoints on purpose: the badge text goes through \MakeUppercase inside
       the .sty, and the fewer macros travel into that argument the better. -->
  <xsl:template name="host-banner">
    <xsl:param name="ip"/>
    <xsl:param name="hostname"/>
    <xsl:param name="os"/>
    <xsl:param name="portcount"/>
    <xsl:variable name="osshown">
      <xsl:choose>
        <xsl:when test="string-length($os) = 0"><xsl:value-of select="gvm:t('hp_os_unknown_chip')"/></xsl:when>
        <xsl:when test="string-length($os) &gt; 40"><xsl:value-of select="concat(substring($os, 1, 37), '...')"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$os"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:text>\hostcard{</xsl:text>
    <xsl:call-template name="escape_break"><xsl:with-param name="string" select="$ip"/></xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:if test="string-length($hostname) &gt; 0">
      <xsl:call-template name="escape_break"><xsl:with-param name="string" select="$hostname"/></xsl:call-template>
    </xsl:if>
    <xsl:text>}{</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($osshown)"/></xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:value-of select="$portcount"/>
    <xsl:text>}{%
</xsl:text>
  </xsl:template>

  <!-- One card per host.  The rows are BUILT FIRST, into a node-set, and only
       then drawn: the design system's \hostcols takes the two columns as two
       separate arguments, so the split point cannot be known while the rows are
       still being emitted one by one.  Each <r> carries the finished \hostrow
       line as text; hp-host-card slices that list.

       Row order and row sources are the ones the old table used: the report's
       <ports> inventory when it has one for this host, the distinct host:port
       pairs of the results when it does not, numeric ascending by port number —
       plus, last, the single aggregated general/* row. -->
  <xsl:template name="hosts-ports">
    <xsl:text>\suriSection{3}{</xsl:text><xsl:value-of select="gvm:t('sec_hosts_ports')"/><xsl:text>}
\setsectionrunner{3}{</xsl:text><xsl:value-of select="gvm:t('sec_hosts_ports_run')"/><xsl:text>}

\suriPara{</xsl:text><xsl:value-of select="gvm:t('hp_intro')"/><xsl:text>}
</xsl:text>
    <xsl:for-each select="gvm:report()/host">
      <xsl:sort select="ip"/>
      <xsl:variable name="ip" select="ip"/>
      <xsl:variable name="hostname" select="detail[name='hostname']/value"/>
      <xsl:variable name="os">
        <xsl:choose>
          <xsl:when test="string-length(detail[name='best_os_txt']/value) &gt; 0"><xsl:value-of select="detail[name='best_os_txt']/value"/></xsl:when>
          <xsl:when test="string-length(detail[name='best_os_cpe']/value) &gt; 0"><xsl:value-of select="detail[name='best_os_cpe']/value"/></xsl:when>
          <xsl:otherwise></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="fromports" select="gvm:report()/ports/port[host=$ip]"/>
      <!-- Count of real (non host-level) ports, for the band tally. -->
      <xsl:variable name="realportcount">
        <xsl:choose>
          <xsl:when test="count($fromports) &gt; 0"><xsl:value-of select="count($fromports[not(starts-with(text(), 'general'))])"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[host/text()=$ip][not(starts-with(port, 'general'))][generate-id() = generate-id(key('by-host-port', concat(host/text(), '|', port))[1])])"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <!-- Host-level findings: they get ONE aggregated row, and the note under
           the card takes it apart.  The row is drawn when the host has such
           findings OR when the inventory lists a general/* pseudo-port with no
           finding on it (then the row reads `neutro', like any empty port). -->
      <xsl:variable name="genres" select="gvm:report()/results/result[host/text()=$ip][starts-with(port, 'general')]"/>
      <xsl:variable name="hasgen"
        select="count($genres) &gt; 0 or count($fromports[starts-with(text(), 'general')]) &gt; 0"/>

      <xsl:variable name="rows-rtf">
        <xsl:choose>
          <!-- Primary source: the report's <ports> inventory for this host. -->
          <xsl:when test="count($fromports) &gt; 0">
            <xsl:for-each select="$fromports[not(starts-with(text(), 'general'))]">
              <xsl:sort select="number(substring-before(text(), '/'))" data-type="number" order="ascending"/>
              <r>
                <xsl:call-template name="port-row">
                  <xsl:with-param name="ip" select="$ip"/>
                  <xsl:with-param name="pstr" select="text()"/>
                </xsl:call-template>
              </r>
            </xsl:for-each>
          </xsl:when>
          <!-- Fallback: derive distinct ports from this host's results. -->
          <xsl:when test="count(gvm:report()/results/result[host/text()=$ip]) &gt; 0">
            <xsl:for-each select="gvm:report()/results/result[host/text()=$ip][not(starts-with(port, 'general'))][generate-id() = generate-id(key('by-host-port', concat(host/text(), '|', port))[1])]">
              <xsl:sort select="number(substring-before(port, '/'))" data-type="number" order="ascending"/>
              <r>
                <xsl:call-template name="port-row">
                  <xsl:with-param name="ip" select="$ip"/>
                  <xsl:with-param name="pstr" select="port"/>
                </xsl:call-template>
              </r>
            </xsl:for-each>
          </xsl:when>
        </xsl:choose>
        <xsl:if test="$hasgen">
          <r>
            <xsl:call-template name="port-row">
              <xsl:with-param name="ip" select="$ip"/>
              <xsl:with-param name="general" select="1"/>
            </xsl:call-template>
          </r>
        </xsl:if>
      </xsl:variable>
      <xsl:variable name="rows" select="exsl:node-set($rows-rtf)/r"/>

      <xsl:choose>
        <!-- No ports and no results: clean host.  The card is still drawn — the
             reader has to see that the host was assessed — with the note in
             place of the mini-tables. -->
        <xsl:when test="count($rows) = 0">
          <xsl:call-template name="host-banner">
            <xsl:with-param name="ip" select="$ip"/>
            <xsl:with-param name="hostname" select="$hostname"/>
            <xsl:with-param name="os" select="$os"/>
            <xsl:with-param name="portcount" select="$realportcount"/>
          </xsl:call-template>
          <xsl:text>\blocknote{</xsl:text><xsl:value-of select="gvm:t('hp_no_ports')"/><xsl:text>}}
</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="hp-host-card">
            <xsl:with-param name="ip" select="$ip"/>
            <xsl:with-param name="hostname" select="$hostname"/>
            <xsl:with-param name="os" select="$os"/>
            <xsl:with-param name="portcount" select="$realportcount"/>
            <xsl:with-param name="rows" select="$rows"/>
            <!-- The first card of the section flows under the opener even when
                 it is a tall one: a \clearpage there would leave the section
                 title alone on a page. -->
            <xsl:with-param name="first" select="position() = 1"/>
          </xsl:call-template>
        </xsl:otherwise>
      </xsl:choose>

      <xsl:if test="count($genres) &gt; 0">
        <xsl:call-template name="hp-general-note">
          <xsl:with-param name="genres" select="$genres"/>
        </xsl:call-template>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- One \hostcard, filled with rows $start..$start+2*$percol-1 of $rows, and
       then itself again for whatever is left over.

       The chunking is not decoration.  \hostcols builds its two columns as
       minipages, and a minipage cannot break across a page: a host with 200
       ports drawn as ONE card would be a box taller than the paper, and TeX
       would let it run off the sheet.  So a card carries at most $percol rows
       per column (the limit suricatoos-blocks.sty documents for A4) and a host
       with more ports becomes several cards, each repeating the title band so
       the reader always knows whose ports these are.

       Few rows go into a single full-width column instead: two columns of one
       row each would print two headers for two lines, which reads as a mistake
       rather than as a layout. -->
  <xsl:template name="hp-host-card">
    <xsl:param name="ip"/>
    <xsl:param name="hostname"/>
    <xsl:param name="os"/>
    <xsl:param name="portcount"/>
    <xsl:param name="rows"/>
    <xsl:param name="start" select="1"/>
    <xsl:param name="first" select="1"/>
    <!-- 25 rows a column, not the 30 the .sty quotes as the A4 ceiling: 30 fills
         the text block edge to edge and leaves nothing for the section opener
         above the first card, so the first card of the section was split with
         its navy band orphaned on the page before (measured).  25 rows land the
         tallest card at ~729px against the 816px the opener leaves. -->
    <xsl:param name="percol" select="25"/>
    <xsl:variable name="total" select="count($rows)"/>
    <xsl:variable name="rest" select="$total - $start + 1"/>
    <xsl:variable name="take">
      <xsl:choose>
        <xsl:when test="$rest &gt; 2 * $percol"><xsl:value-of select="2 * $percol"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$rest"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <!-- The first column fills first, as in the model: it takes the ceiling. -->
    <xsl:variable name="half" select="ceiling(number($take) div 2)"/>
    <xsl:variable name="end" select="$start + number($take)"/>
    <!-- A card that cannot fit in what is left of the page does not fail
         gracefully: tcolorbox breaks it at the only legal point it has, which is
         between the navy band and the body, and the band ends up alone at the
         foot of the page before.  So a card that is taller than about half the
         text block opens a page of its own, and so does every continuation chunk
         of a host too big for one card.  Small cards keep flowing — a report
         with sixty two-port hosts must not become sixty pages. -->
    <xsl:if test="$start &gt; 1 or (number($take) &gt; $percol and number($first) != 1)">
      <xsl:text>\clearpage
</xsl:text>
    </xsl:if>
    <xsl:call-template name="host-banner">
      <xsl:with-param name="ip" select="$ip"/>
      <xsl:with-param name="hostname" select="$hostname"/>
      <xsl:with-param name="os" select="$os"/>
      <xsl:with-param name="portcount" select="$portcount"/>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="number($take) &lt;= 3">
        <xsl:text>\hostcolsingle{%
</xsl:text>
        <xsl:for-each select="$rows">
          <xsl:if test="position() &gt;= $start and position() &lt; $end"><xsl:value-of select="."/></xsl:if>
        </xsl:for-each>
        <xsl:text>}}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\hostcols{%
</xsl:text>
        <xsl:for-each select="$rows">
          <xsl:if test="position() &gt;= $start and position() &lt; $start + $half"><xsl:value-of select="."/></xsl:if>
        </xsl:for-each>
        <xsl:text>}{%
</xsl:text>
        <xsl:for-each select="$rows">
          <xsl:if test="position() &gt;= $start + $half and position() &lt; $end"><xsl:value-of select="."/></xsl:if>
        </xsl:for-each>
        <xsl:text>}}
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:if test="$end &lt;= $total">
      <xsl:call-template name="hp-host-card">
        <xsl:with-param name="ip" select="$ip"/>
        <xsl:with-param name="hostname" select="$hostname"/>
        <xsl:with-param name="os" select="$os"/>
        <xsl:with-param name="portcount" select="$portcount"/>
        <xsl:with-param name="rows" select="$rows"/>
        <xsl:with-param name="start" select="$end"/>
        <xsl:with-param name="first" select="0"/>
        <xsl:with-param name="percol" select="$percol"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- The note under a host card that carries host-level findings.  The card
       shows those findings as ONE `geral' row, so this is where the row is taken
       apart: how many findings, how they split by severity class, and the
       highest CVSS among them.  Without it the aggregate would be a number the
       reader cannot check, which is the failure mode this report has a history
       of.  A class with no finding is not mentioned at all. -->
  <xsl:template name="hp-general-note">
    <xsl:param name="genres"/>
    <xsl:variable name="n" select="count($genres)"/>
    <xsl:variable name="ncrit" select="count($genres[number(severity) &gt;= 9.0])"/>
    <xsl:variable name="nhigh" select="count($genres[number(severity) &gt;= 7.0 and number(severity) &lt; 9.0])"/>
    <xsl:variable name="nmed" select="count($genres[number(severity) &gt;= 4.0 and number(severity) &lt; 7.0])"/>
    <xsl:variable name="nlow" select="count($genres[number(severity) &gt;= 0.1 and number(severity) &lt; 4.0])"/>
    <!-- A false positive is counted apart and named apart: it is a CODE the
         scanner uses to disown a result, not a score, and calling it Log would
         hide that. Whatever is left is informational. -->
    <xsl:variable name="nfp" select="count($genres[number(severity) &lt; 0 and number(severity) &gt; -1.5])"/>
    <xsl:variable name="nlog" select="$n - $ncrit - $nhigh - $nmed - $nlow - $nfp"/>
    <xsl:variable name="maxsev">
      <xsl:call-template name="port-max-sev">
        <xsl:with-param name="rs" select="$genres"/>
      </xsl:call-template>
    </xsl:variable>
    <!-- The tail is built into a variable so the closing full stop can look at
         what came before it: a class word may itself end in a period
         ("Falso pos.", "False pos.") and "1 Falso pos.." is a typo the reader
         would rightly blame on the machine. -->
    <xsl:variable name="tail">
    <xsl:if test="$ncrit &gt; 0">
      <xsl:value-of select="$ncrit"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('Critical')"/>
    </xsl:if>
    <xsl:if test="$nhigh &gt; 0">
      <xsl:if test="$ncrit &gt; 0"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="$nhigh"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('High')"/>
    </xsl:if>
    <xsl:if test="$nmed &gt; 0">
      <xsl:if test="$ncrit + $nhigh &gt; 0"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="$nmed"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('Medium')"/>
    </xsl:if>
    <xsl:if test="$nlow &gt; 0">
      <xsl:if test="$ncrit + $nhigh + $nmed &gt; 0"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="$nlow"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('Low')"/>
    </xsl:if>
    <xsl:if test="$nlog &gt; 0">
      <xsl:if test="$ncrit + $nhigh + $nmed + $nlow &gt; 0"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="$nlog"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('Log')"/>
    </xsl:if>
    <xsl:if test="$nfp &gt; 0">
      <xsl:if test="$ncrit + $nhigh + $nmed + $nlow + $nlog &gt; 0"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="$nfp"/><xsl:text> </xsl:text><xsl:value-of select="gvm:sev-word('Falsepos')"/>
    </xsl:if>
    <xsl:if test="number($maxsev) &gt;= 0.1">
      <xsl:text> \textperiodcentered\ </xsl:text>
      <xsl:value-of select="gvm:t('hx_th_cvss')"/><xsl:text> </xsl:text>
      <xsl:value-of select="$maxsev"/>
    </xsl:if>
    </xsl:variable>
    <xsl:text>\blocknote{</xsl:text>
    <xsl:value-of select="gvm:t('hp_gen_note_a')"/>
    <xsl:value-of select="$n"/><xsl:text> </xsl:text>
    <xsl:value-of select="gvm:t('hx_findings_n')"/>
    <xsl:value-of select="gvm:t('hp_gen_note_b')"/>
    <xsl:text>\dat{</xsl:text>
    <xsl:value-of select="translate(gvm:t('hp_general'),
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:text>}: </xsl:text>
    <xsl:value-of select="$tail"/>
    <xsl:if test="substring($tail, string-length($tail), 1) != '.'"><xsl:text>.</xsl:text></xsl:if>
    <xsl:text>}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Findings summary table (grouped by NVT)                           -->
  <!-- ================================================================= -->

  <xsl:template name="findings-summary">
    <xsl:variable name="n-low" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])][qod/value][number(qod/value) &lt; number($qod-min)])"/>
    <xsl:variable name="n-ok" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])][not(qod/value) or number(qod/value) &gt;= number($qod-min)])"/>
    <xsl:text>\suriSection{4}{</xsl:text><xsl:value-of select="gvm:t('sec_findings_summary')"/><xsl:text>}
</xsl:text>

    <!-- Confirmed findings.  The slab is unconditional now: in the design system
         \suriSummaryHead IS the table's title, and it states the detection-quality
         band the table covers, which is true whether or not a second band exists.
         The old \subsection* + grey intro line is what it replaces. -->
    <xsl:text>\suriSummaryHead{confirmados}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$n-ok = 0">
        <xsl:text>\suriPara{</xsl:text><xsl:value-of select="gvm:t('none_confirmed')"/><xsl:text>}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="findings-summary-table">
          <xsl:with-param name="low" select="0"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>

    <!-- Indicators to validate: what the scanner is not confident about.  The
         caveat is a \warnbox now instead of a grey paragraph, and it still says
         the threshold out loud, because $qod-min is a parameter and the caption
         macros of the design system carry only the default. -->
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\clearpage
\suriSummaryHead{indicadores}
\warnbox{</xsl:text><xsl:value-of select="gvm:t('ind_intro')"/>
      <xsl:value-of select="$qod-min"/><xsl:text>\%</xsl:text><xsl:value-of select="gvm:t('ind_intro2')"/>
      <xsl:text>}
</xsl:text>
      <xsl:call-template name="findings-summary-table">
        <xsl:with-param name="low" select="1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- One summary table. low=1 selects the NVTs whose detection quality is under
       the threshold; low=0 selects the rest. The filter lives in the select
       expression rather than inside the loop, so position() numbers each table
       from 1 independently. -->
  <xsl:template name="findings-summary-table">
    <xsl:param name="low" select="0"/>
    <!-- The column headers, the repeated head on a page break and the closing
         rule all belong to the findingsummary environment now; the mode key it
         takes is what turns SEVERIDADE into SEVERIDADE (TETO) and highlights a
         critical row on the low-confidence table.  Nothing is emitted before
         the variables below are settled, because the truncation budget has to
         be known before the first row is written. -->
    <xsl:variable name="rows" select="gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])]"/>
    <!-- Consolidated groups get one row each, at the top of the confirmed
         table, so the summary and the detail section describe the same set. -->
    <xsl:variable name="groups" select="gvm:report()/results/result[nvt/solution/@type='VendorFix'][generate-id() = generate-id(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[1])][count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])]) &gt;= $group-min]"/>
    <xsl:variable name="ngroups">
      <xsl:choose>
        <xsl:when test="$low = 0"><xsl:value-of select="count($groups)"/></xsl:when>
        <xsl:otherwise>0</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <!-- The rows this table is entitled to, bound once so the truncation budget
         can be counted off exactly the set the loop below walks.  The expression
         is the one the for-each carried before, unchanged: bucket by detection
         quality, then drop whatever a consolidated advisory card already tells. -->
    <xsl:variable name="sel" select="$rows[($low = 1 and qod/value and number(qod/value) &lt; number($qod-min)) or ($low = 0 and (not(qod/value) or number(qod/value) &gt;= number($qod-min)))][not((nvt/solution/@type='VendorFix' and count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])]) &gt;= $group-min))]"/>
    <!-- Truncation budget.  `keep' is how many rows of $sel are printed; it is
         never less than the number of ACIONAVEIS (severity >= 0.1), so what the
         cut can reach is only the informational tail — the rows sort by severity
         descending, so that tail is at the bottom by construction. -->
    <xsl:variable name="n-hard" select="count($sel[number(severity) &gt;= 0.1])"/>
    <xsl:variable name="cap" select="number($summary-max) - number($ngroups)"/>
    <xsl:variable name="keep">
      <xsl:choose>
        <xsl:when test="$cap &gt; $n-hard"><xsl:value-of select="$cap"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$n-hard"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="dropped" select="count($sel) - number($keep)"/>

    <xsl:text>\begin{findingsummary}{</xsl:text>
    <xsl:choose>
      <xsl:when test="$low = 1"><xsl:text>indicadores</xsl:text></xsl:when>
      <xsl:otherwise><xsl:text>confirmados</xsl:text></xsl:otherwise>
    </xsl:choose>
    <xsl:text>}
</xsl:text>

    <xsl:if test="$low = 0">
      <xsl:for-each select="$groups">
        <xsl:sort select="severity" data-type="number" order="descending"/>
        <xsl:variable name="gname" select="concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' '))"/>
        <!-- Severity KEY of the design system.  Same ladder as `sev-class', in
             the vocabulary suricatoos-blocks.sty speaks; kept inline (twice)
             rather than hoisted into a named template, because this file is
             being ported by several hands at once and a new global name is the
             one edit that can collide. -->
        <xsl:variable name="gsev">
          <xsl:choose>
            <xsl:when test="number(severity) &gt;= 9.0">critico</xsl:when>
            <xsl:when test="number(severity) &gt;= 7.0">alto</xsl:when>
            <xsl:when test="number(severity) &gt;= 4.0">medio</xsl:when>
            <xsl:when test="number(severity) &gt;= 0.1">baixo</xsl:when>
            <!-- -1 e' FALSO POSITIVO, nao pontuacao: `neutro' e' a chave sem
                 rampa de severidade do design (a palavra vem de \setsevword). -->
            <xsl:when test="number(severity) &lt; 0 and number(severity) &gt; -1.5">neutro</xsl:when>
            <xsl:otherwise>logsev</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:text>\findingrow{</xsl:text><xsl:value-of select="position()"/><xsl:text>}{</xsl:text>
        <xsl:text>\hyperlink{</xsl:text><xsl:value-of select="concat('grp-', translate($gname, ' ./:,()', '-------'))"/><xsl:text>}{</xsl:text>
        <xsl:call-template name="escape_name">
          <xsl:with-param name="string" select="$gname"/>
        </xsl:call-template>
        <xsl:text> --- </xsl:text><xsl:value-of select="gvm:t('grp_title')"/>
        <xsl:text>}}{</xsl:text>
        <xsl:value-of select="count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])])"/>
        <xsl:text>}{</xsl:text><xsl:value-of select="$gsev"/><xsl:text>}{</xsl:text>
        <xsl:if test="$gsev != 'logsev' and $gsev != 'neutro'"><xsl:value-of select="severity"/></xsl:if>
        <xsl:text>}
</xsl:text>
      </xsl:for-each>
    </xsl:if>
    <xsl:for-each select="$sel">
      <xsl:sort select="severity" data-type="number" order="descending"/>
      <xsl:if test="position() &lt;= number($keep)">
        <xsl:variable name="oid" select="nvt/@oid"/>
        <xsl:variable name="anchor" select="concat('fnd-', translate($oid, '.', '-'))"/>
        <xsl:variable name="instances" select="count(key('by-nvt', $oid))"/>
        <!-- see the note on $gsev above: same ladder, deliberately inline -->
        <xsl:variable name="sevk">
          <xsl:choose>
            <xsl:when test="number(severity) &gt;= 9.0">critico</xsl:when>
            <xsl:when test="number(severity) &gt;= 7.0">alto</xsl:when>
            <xsl:when test="number(severity) &gt;= 4.0">medio</xsl:when>
            <xsl:when test="number(severity) &gt;= 0.1">baixo</xsl:when>
            <xsl:when test="number(severity) &lt; 0 and number(severity) &gt; -1.5">neutro</xsl:when>
            <xsl:otherwise>logsev</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:text>\findingrow{</xsl:text><xsl:value-of select="position() + number($ngroups)"/><xsl:text>}{</xsl:text>
        <xsl:text>\hyperlink{</xsl:text><xsl:value-of select="$anchor"/><xsl:text>}{</xsl:text>
        <xsl:call-template name="escape_name">
          <xsl:with-param name="string" select="nvt/name"/>
        </xsl:call-template>
        <xsl:text>}}{</xsl:text><xsl:value-of select="$instances"/><xsl:text>}{</xsl:text>
        <xsl:value-of select="$sevk"/><xsl:text>}{</xsl:text>
        <xsl:if test="$sevk != 'logsev' and $sevk != 'neutro'"><xsl:value-of select="severity"/></xsl:if>
        <xsl:text>}
</xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>\end{findingsummary}
</xsl:text>
    <!-- What the budget cut off, counted and named.  Never a bare ellipsis: the
         reader has to be able to tell how much of the list is not on the page,
         and that it is still told in full further on. -->
    <xsl:if test="$dropped &gt; 0">
      <xsl:text>\findingtrunc{\suriEllip\ + </xsl:text>
      <xsl:value-of select="gvm:num($dropped)"/>
      <xsl:value-of select="gvm:t('fs_trunc')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Detailed findings (grouped by NVT)                                -->
  <!-- ================================================================= -->

  <!-- Classe de severidade -> CHAVE de severidade do design system.
       O .sty conhece critico/alto/medio/baixo/logsev; `falsepos' nao tem cor
       propria e cai no cinza neutro do \sevcolor, que e' a leitura certa para
       um resultado que o proprio scanner desautorizou. NAO e' dobrado em
       logsev de proposito: essa e' exatamente a confusao que o sev-class foi
       escrito para evitar ("indistinguivel de uma deteccao informativa
       legitima"). O preambulo precisa registrar a palavra de cada chave com
       \setsevword — inclusive a de `falsepos', que o .sty nao traz. -->
  <xsl:template name="sevkey-detail">
    <xsl:param name="severity"/>
    <xsl:variable name="class">
      <xsl:call-template name="sev-class">
        <xsl:with-param name="severity" select="$severity"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:choose>
      <xsl:when test="$class = 'Critical'">critico</xsl:when>
      <xsl:when test="$class = 'High'">alto</xsl:when>
      <xsl:when test="$class = 'Medium'">medio</xsl:when>
      <xsl:when test="$class = 'Low'">baixo</xsl:when>
      <xsl:when test="$class = 'Falsepos'">falsepos</xsl:when>
      <xsl:otherwise>logsev</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Um campo de PROSA, em paragrafos do design system.
       O texto passa pelo escape_prose (que reflui a quebra de terminal do autor
       do NVT) e sai dentro de \suriPara, que e' a medida de leitura do modelo.
       UM \suriPara POR PARAGRAFO, e nao um so' com o campo inteiro dentro: o
       \suriPara compoe numa minipage para encurtar a medida, e minipage NAO
       quebra entre paginas — medido no container, um campo de 12.000 caracteres
       num unico \suriPara estoura a pagina em 587pt e o texto sai POR BAIXO do
       rodape, perdido. Cortado nas linhas em branco que o proprio feed escreve,
       o que precisa caber numa pagina passa a ser o maior PARAGRAFO, nao o
       campo. Um paragrafo unico gigante (acima de ~4.800 caracteres sem uma
       linha em branco) continua sendo um risco: e' limitacao do \suriPara, esta'
       relatada, e a correcao e' no .sty (trocar a minipage por \rightskip). -->
  <xsl:template name="prose-block">
    <xsl:param name="value"/>
    <xsl:variable name="norm" select="str:replace(
      str:replace(string($value), '&#13;&#10;', '&#10;'), '&#13;', '&#10;')"/>
    <xsl:for-each select="str:split($norm, '&#10;&#10;')">
      <xsl:if test="string-length(normalize-space(.)) &gt; 0">
        <xsl:text>\suriPara{</xsl:text>
        <xsl:call-template name="escape_prose">
          <xsl:with-param name="string" select="string(.)"/>
        </xsl:call-template>
        <xsl:text>}
</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- UM CAMPO DE CORPO ROTULADO (RESUMO, IMPACTO, DETALHES TECNICOS,
       SOFTWARE/SO AFETADO). Pulado quando vazio.
       O rotulo entra como esta': quem chama passa ou um macro \suriLbl... do
       design system (traduzido no preambulo) ou uma string do gvm:t().

       O campo do feed vem em duas formas: prosa corrida (que sai em \suriPara)
       e lista de marcadores, uma linha "- CVE-xxxx: ..." por item — que e' o
       que a pg-09 do modelo desenha com `suribullets'.

       A lista NAO e' privilegio do `insight'. Este template era dois: um
       generico, sem deteccao de lista, para resumo/impacto/afetado, e um so'
       para DETALHES TECNICOS, com ela. O resultado e' que a MESMA lista saia
       com marcador de verdade sob DETALHES TECNICOS e como paragrafos soltos
       comecando por hifen sob RESUMO — duas tipografias para a mesma coisa na
       mesma pagina. Contado no relatorio de teste: 152 `insight', mas tambem 67
       `summary', 33 `affected' e 2 `impact' trazem lista. Agora o rotulo e'
       parametro e a deteccao vale para os quatro.

       A deteccao e' conservadora e nao inventa item nenhum: a indentacao do
       marcador e' normalizada (o feed escreve "  - "), o texto ANTES do
       primeiro marcador continua saindo como paragrafo, e cada item passa
       inteiro pelo escape_prose — nada e' descartado.
       O realce do prefixo ("CVE-2025-61984:") so' dispara quando o que vem
       antes dos dois-pontos e' UMA palavra curta, que e' a forma do
       identificador; frase que por acaso tenha ':' no meio nao vira titulo. -->
  <xsl:template name="finding-field">
    <xsl:param name="label"/>
    <xsl:param name="value"/>
    <xsl:if test="string-length(normalize-space($value)) &gt; 0">
      <xsl:variable name="mk" select="concat('&#10;', str:replace(str:replace(str:replace(
        str:replace(str:replace(str:replace(str:replace(str:replace(string($value),
        '&#13;&#10;', '&#10;'), '&#13;', '&#10;'),
        '&#10;      - ', '&#10;- '), '&#10;     - ', '&#10;- '), '&#10;    - ', '&#10;- '),
        '&#10;   - ', '&#10;- '), '&#10;  - ', '&#10;- '), '&#10; - ', '&#10;- '))"/>
      <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="$label"/><xsl:text>}
</xsl:text>
      <xsl:choose>
        <xsl:when test="contains($mk, '&#10;- ')">
          <xsl:variable name="intro" select="substring-before($mk, '&#10;- ')"/>
          <xsl:call-template name="prose-block">
            <xsl:with-param name="value" select="$intro"/>
          </xsl:call-template>
          <xsl:text>\begin{suribullets}
</xsl:text>
          <xsl:for-each select="str:split(substring-after($mk, '&#10;- '), '&#10;- ')">
            <xsl:variable name="it" select="string(.)"/>
            <xsl:variable name="lead" select="substring-before($it, ':')"/>
            <xsl:text>\item </xsl:text>
            <xsl:choose>
              <xsl:when test="string-length($lead) &gt; 0 and string-length($lead) &lt;= 30
                              and not(contains($lead, ' ')) and not(contains($lead, '&#10;'))">
                <xsl:text>\textbf{</xsl:text>
                <xsl:call-template name="escape_text">
                  <xsl:with-param name="string" select="concat($lead, ':')"/>
                </xsl:call-template>
                <!-- O espaco tem de sair DAQUI: o escape_prose come o branco
                     que abre a linha (ele o le como recuo), entao sem este
                     espaco o texto colava no identificador em negrito. -->
                <xsl:text>} </xsl:text>
                <xsl:call-template name="escape_prose">
                  <xsl:with-param name="string" select="substring-after($it, ':')"/>
                </xsl:call-template>
              </xsl:when>
              <xsl:otherwise>
                <xsl:call-template name="escape_prose">
                  <xsl:with-param name="string" select="$it"/>
                </xsl:call-template>
              </xsl:otherwise>
            </xsl:choose>
            <xsl:text>
</xsl:text>
          </xsl:for-each>
          <xsl:text>\end{suribullets}
</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="prose-block">
            <xsl:with-param name="value" select="$value"/>
          </xsl:call-template>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <!-- MIOLO DO \solbox: prosa corrida OU lista de marcadores.
       O campo `solution' do feed vem nas MESMAS duas formas dos campos de
       corpo, mas ate' agora so' os campos de corpo sabiam disso: uma mitigacao
       em lista saia da caixa de remediacao com o hifen cru colado no rotulo
       ("Mitigação: - DHE key exchange should be disabled..."), na mesma pagina
       em que DETALHES TECNICOS e IMPACTO desenhavam marcador de verdade. Duas
       tipografias para a mesma coisa, a dois centimetros uma da outra.
       A deteccao e' a de finding-field (indentacao do marcador normalizada, o
       texto antes do primeiro marcador preservado como prosa), SEM o realce de
       prefixo em negrito: item de solucao e' frase, nao identificador, e o
       \solbox ja' gasta o negrito no que o leitor tem de executar — dois
       negritos na mesma caixa disputariam a mesma enfase.
       A prosa aqui nao passa por prose-block: dentro do \solbox o \suriPara
       traria a propria medida, a propria cor e o proprio ar, e a caixa tem os
       seus. -->
  <xsl:template name="solution-body">
    <xsl:param name="value"/>
    <xsl:variable name="mk" select="concat('&#10;', str:replace(str:replace(str:replace(
      str:replace(str:replace(str:replace(str:replace(str:replace(string($value),
      '&#13;&#10;', '&#10;'), '&#13;', '&#10;'),
      '&#10;      - ', '&#10;- '), '&#10;     - ', '&#10;- '), '&#10;    - ', '&#10;- '),
      '&#10;   - ', '&#10;- '), '&#10;  - ', '&#10;- '), '&#10; - ', '&#10;- '))"/>
    <xsl:choose>
      <xsl:when test="contains($mk, '&#10;- ')">
        <xsl:variable name="intro" select="substring-before($mk, '&#10;- ')"/>
        <xsl:if test="string-length(normalize-space($intro)) &gt; 0">
          <xsl:call-template name="escape_prose">
            <xsl:with-param name="string" select="$intro"/>
          </xsl:call-template>
        </xsl:if>
        <xsl:text>\begin{suribullets}
</xsl:text>
        <xsl:for-each select="str:split(substring-after($mk, '&#10;- '), '&#10;- ')">
          <xsl:text>\item </xsl:text>
          <xsl:call-template name="escape_prose">
            <xsl:with-param name="string" select="string(.)"/>
          </xsl:call-template>
          <xsl:text>
</xsl:text>
        </xsl:for-each>
        <xsl:text>\end{suribullets}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="escape_prose">
          <xsl:with-param name="string" select="$value"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Uma referencia da lista de REFERENCIAS.
       \refurl{u} monta o link com \href{u}{u}, e o argumento de um macro comum
       ja' chega TOKENIZADO: uma URL crua com '_' ou '%' quebraria o pdflatex
       antes de o \href ver a string. Entao a URL entra SEMPRE escapada.
       Medido no container: '\_' e '\#' voltam corretos dentro do /URI do PDF,
       mas qualquer ponto de quebra (\surjb) sai literal no destino — o link
       apontaria para outro lugar SEM AVISO, que e' o defeito que esta lista ja'
       teve uma vez. Por isso a regra e' explicita:
         cabe na linha e so' tem escape que sobrevive  -> link clicavel;
         longa demais ou com escape que nao sobrevive  -> endereco correto e
                                                          quebravel, SEM link.
       Perde o clique, nao perde o endereco.
       126 caracteres e' a medida real de uma linha do \refurl (Mono 9px na
       largura do bloco de texto), conferida no container. -->
  <xsl:template name="reference-line">
    <xsl:param name="u"/>
    <xsl:choose>
      <xsl:when test="string-length($u) &lt;= 126 and
                      not(contains($u, '\')) and not(contains($u, '{')) and
                      not(contains($u, '}')) and not(contains($u, '%')) and
                      not(contains($u, '~')) and not(contains($u, '^')) and
                      not(contains($u, '&amp;')) and not(contains($u, '$'))">
        <xsl:text>  \refurl{</xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="$u"/>
        </xsl:call-template>
        <xsl:text>}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>  {\def\href#1#2{#2}\refurl{</xsl:text>
        <xsl:call-template name="escape_break">
          <xsl:with-param name="string" select="$u"/>
        </xsl:call-template>
        <xsl:text>}}
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Localised label for a feed solution/@type value; unknown types pass
       through verbatim. -->
  <func:function name="gvm:solution-type-label">
    <xsl:param name="type"/>
    <xsl:variable name="node" select="$i18n[@k=concat('st_', $type)]"/>
    <xsl:choose>
      <xsl:when test="count($node) &gt; 0">
        <func:result select="gvm:t(concat('st_', $type))"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$type"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <xsl:template name="detailed-findings">
    <xsl:variable name="n-low" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])][qod/value][number(qod/value) &lt; number($qod-min)])"/>
    <!-- Secao 5 do documento: a ordem das secoes esta' fixada na montagem
         (real-report), entao o numero e' constante e nao um contador do LaTeX
         — \suriSection carrega o numero como DADO, e ele tambem alimenta o
         "S5 . ACHADOS DETALHADOS" do cabecalho corrido. -->
    <xsl:text>\suriSection{5}{</xsl:text><xsl:value-of select="gvm:t('sec_detailed')"/><xsl:text>}
</xsl:text>
    <!-- Confirmed first; the low-confidence block is only introduced when there
         is something in it, so a clean report reads exactly as before.
         A mesma tarja da secao 4 titula os dois blocos: quem le a pagina 6 ja'
         aprendeu o que "ACHADOS CONFIRMADOS" e "INDICADORES A VALIDAR"
         significam, e a faixa de QoD vem escrita na propria tarja. -->
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\suriSummaryHead{confirmados}
</xsl:text>
    </xsl:if>
    <xsl:call-template name="consolidated-update-cards"/>
    <xsl:call-template name="finding-cards">
      <xsl:with-param name="low" select="0"/>
    </xsl:call-template>
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\clearpage
\suriSummaryHead{indicadores}
\warnbox{</xsl:text><xsl:value-of select="gvm:t('ind_intro')"/>
      <xsl:value-of select="$qod-min"/><xsl:text>\%</xsl:text><xsl:value-of select="gvm:t('ind_intro2')"/>
      <xsl:text>}
</xsl:text>
      <xsl:call-template name="finding-cards">
        <xsl:with-param name="low" select="1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Detail cards for one confidence bucket. low=1 renders the findings whose
       detection quality is under the threshold, low=0 the rest. -->
  <xsl:template name="finding-cards">
    <xsl:param name="low" select="0"/>
    <xsl:variable name="rows" select="gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])]"/>
    <!-- Advisories already described by a consolidated update card are dropped
         here so the same vulnerability is not told twice. The trailing
         predicate is the "was I absorbed?" test spelled out inline: XSLT 1.0
         has no way to hoist it into a variable and still use it in a select. -->
    <xsl:for-each select="$rows[($low = 1 and qod/value and number(qod/value) &lt; number($qod-min)) or ($low = 0 and (not(qod/value) or number(qod/value) &gt;= number($qod-min)))][not((nvt/solution/@type='VendorFix' and count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])]) &gt;= $group-min))]">
      <xsl:sort select="severity" data-type="number" order="descending"/>
      <xsl:variable name="oid" select="nvt/@oid"/>
      <xsl:variable name="anchor" select="concat('fnd-', translate($oid, '.', '-'))"/>
      <xsl:variable name="instances" select="count(key('by-nvt', $oid))"/>
      <xsl:variable name="sevkey">
        <xsl:call-template name="sevkey-detail">
          <xsl:with-param name="severity" select="severity"/>
        </xsl:call-template>
      </xsl:variable>
      <!-- Log e falso positivo nao carregam pontuacao: o \chipsev com segundo
           argumento vazio imprime so' a palavra, que e' como o modelo mostra a
           linha Log. Passar "0.0" ali seria afirmar uma nota que nao existe. -->
      <xsl:variable name="score">
        <xsl:if test="$sevkey != 'logsev' and $sevkey != 'falsepos'">
          <xsl:value-of select="severity"/>
        </xsl:if>
      </xsl:variable>
      <xsl:variable name="name_escaped">
        <xsl:call-template name="escape_name">
          <xsl:with-param name="string" select="nvt/name"/>
        </xsl:call-template>
      </xsl:variable>

      <!-- Card: o cabecalho do achado (pg-09 do modelo).
           O \hypertarget entra DENTRO do argumento do numero e nao solto na
           pagina: fora do card ele abre um paragrafo vazio antes de cada
           achado, e o \findingcard ja' traz o proprio ar. Ancorado no numero,
           o link do Sumario de Achados cai no card e nao no branco acima. -->
      <xsl:text>\findingcard{</xsl:text><xsl:value-of select="$sevkey"/>
      <xsl:text>}{\hypertarget{</xsl:text><xsl:value-of select="$anchor"/><xsl:text>}{}\#</xsl:text>
      <xsl:value-of select="position()"/><xsl:text>}{</xsl:text>
      <xsl:value-of select="$name_escaped"/>
      <xsl:text>}{%
  \chipsev{</xsl:text><xsl:value-of select="$sevkey"/><xsl:text>}{</xsl:text>
      <xsl:value-of select="$score"/><xsl:text>}%
</xsl:text>
      <!-- Loud badge so a low-quality detection is never read as a fact, no
           matter how high its CVSS looks next to it: abaixo do limiar o chip e'
           o ambar de alerta e carrega a palavra; acima dele a QoD continua
           visivel, em chip normal, porque e' dado do achado. -->
      <xsl:choose>
        <xsl:when test="qod/value and number(qod/value) &lt; number($qod-min)">
          <xsl:text>  \chipwarn{QoD </xsl:text><xsl:value-of select="qod/value"/>
          <xsl:text>\% \textperiodcentered\ </xsl:text><xsl:value-of select="gvm:t('lbl_lowconf')"/>
          <xsl:text>}%
</xsl:text>
        </xsl:when>
        <xsl:when test="string-length(qod/value) &gt; 0">
          <xsl:text>  \chip{QoD </xsl:text><xsl:value-of select="qod/value"/><xsl:text>\%}%
</xsl:text>
        </xsl:when>
      </xsl:choose>
      <xsl:text>  \chip{</xsl:text><xsl:value-of select="$instances"/><xsl:text> </xsl:text>
      <xsl:value-of select="gvm:hx-upper(gvm:t('lbl_instances'))"/><xsl:text>}%
</xsl:text>
      <!-- CVE chips. Sem teto: a lista reflui sozinha na linha de chips, e
           cortar CVE de um achado seria esconder exatamente o identificador que
           o leitor vai procurar. -->
      <xsl:for-each select="nvt/refs/ref[@type='cve']">
        <xsl:text>  \chip{</xsl:text>
        <xsl:call-template name="escape_break">
          <xsl:with-param name="string" select="@id"/>
        </xsl:call-template>
        <xsl:text>}%
</xsl:text>
      </xsl:for-each>
      <xsl:text>}
</xsl:text>

      <!-- VETOR CVSS ao lado de SISTEMAS AFETADOS (a linha de dois campos da
           pg-09). Sem vetor no feed, os sistemas afetados ocupam a medida
           inteira em vez de deixar meia pagina vazia. -->
      <xsl:variable name="vector" select="gvm:get-nvt-tag('cvss_base_vector')"/>
      <!-- Affected systems (UNIQUE host:port instances of this NVT, capped) -->
      <xsl:variable name="uniqhosts" select="key('by-nvt', $oid)[generate-id() = generate-id(key('by-nvt-hostport', concat($oid, '|', host/text(), '|', port))[1])]"/>
      <!-- Cada endereco e' um chip: o chip nao quebra por dentro, entao o
           "10.20.10.3:22/tcp" nao pode mais sair partido em duas linhas como
           saia na lista corrida. O teto de 40 continua sendo o mesmo de antes,
           e o resto e' DECLARADO num chip final em vez de sumir. -->
      <xsl:variable name="affected">
        <xsl:for-each select="$uniqhosts">
          <xsl:sort select="host/text()"/>
          <xsl:if test="position() &lt;= 40">
            <xsl:text>  \chip{</xsl:text>
            <xsl:call-template name="escape_break">
              <xsl:with-param name="string" select="host/text()"/>
            </xsl:call-template>
            <xsl:if test="string-length(port) &gt; 0">
              <xsl:text>:</xsl:text>
              <xsl:call-template name="escape_break">
                <xsl:with-param name="string" select="port"/>
              </xsl:call-template>
            </xsl:if>
            <xsl:text>}%
</xsl:text>
          </xsl:if>
        </xsl:for-each>
        <xsl:if test="count($uniqhosts) &gt; 40">
          <xsl:text>  \chip{+</xsl:text>
          <xsl:value-of select="count($uniqhosts) - 40"/>
          <xsl:text> </xsl:text><xsl:value-of select="gvm:hx-upper(gvm:t('more_word'))"/>
          <xsl:text>}%
</xsl:text>
        </xsl:if>
      </xsl:variable>
      <!-- Meia medida cabe DOIS chips de "host:porta" por linha. Ate' meia duzia
           de instancias a coluna da direita fica com a altura do vetor e a
           linha de dois campos do modelo se sustenta; acima disso ela vira uma
           torre de vinte linhas com metade da pagina vazia ao lado, entao os
           sistemas afetados descem para a medida inteira e refluem em quatro
           por linha. -->
      <xsl:choose>
        <xsl:when test="string-length($vector) &gt; 0 and count($uniqhosts) &lt;= 6">
          <xsl:text>\fieldcols{%
  \fieldlabel{\suriLblFldVector}%
  \cvssvector{</xsl:text>
          <xsl:call-template name="escape_break">
            <xsl:with-param name="string" select="$vector"/>
          </xsl:call-template>
          <xsl:text>}}{%
  \fieldlabel{\suriLblFldAffected}%
  \affectedchips{%
</xsl:text>
          <xsl:value-of select="$affected"/>
          <xsl:text>}}
</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:if test="string-length($vector) &gt; 0">
            <xsl:text>\fieldcols{%
  \fieldlabel{\suriLblFldVector}%
  \cvssvector{</xsl:text>
            <xsl:call-template name="escape_break">
              <xsl:with-param name="string" select="$vector"/>
            </xsl:call-template>
            <xsl:text>}}{}
</xsl:text>
          </xsl:if>
          <xsl:text>\fieldlabel{\suriLblFldAffected}%
\affectedchips{%
</xsl:text>
          <xsl:value-of select="$affected"/>
          <xsl:text>}
</xsl:text>
        </xsl:otherwise>
      </xsl:choose>

      <!-- Summary / Impact / Insight.
           RESUMO, DETALHES TECNICOS e REFERENCIAS tem macro de rotulo no design
           system (\suriLblFld...), traduzido no preambulo; IMPACTO e
           SOFTWARE/SO AFETADO nao tem, e por isso continuam vindo do gvm:t()
           direto. -->
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="'\suriLblFldSummary'"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('summary')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_impact')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('impact')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="'\suriLblFldTech'"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('insight')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_affected_sw')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('affected')"/>
      </xsl:call-template>

      <!-- Detection result (representative).
           O corte agora cai no LIMITE DE PALAVRA: recua ate' 150 caracteres
           procurando um espaco, e so' corta no meio do token quando nao ha
           espaco nenhum ali atras (hash, base64) — caso em que o \surwb do
           escape_verbatim e' que segura a margem. E o aviso diz QUANTO ficou de
           fora, em vez de um "[saida truncada]" sem numero. -->
      <xsl:if test="string-length(normalize-space(description)) &gt; 0">
        <xsl:variable name="dlen" select="string-length(description)"/>
        <xsl:variable name="dcut">
          <xsl:choose>
            <xsl:when test="$dlen &gt; 1500">
              <xsl:value-of select="gvm:cut-at(string(description), 1500, 150)"/>
            </xsl:when>
            <xsl:otherwise><xsl:value-of select="$dlen"/></xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <!-- O termbox e' um ambiente \obeylines: cada linha de FONTE vira uma
             linha da caixa. O escape_verbatim ja' emenda as linhas do scanner
             com \newline, e emite uma quebra de linha de fonte logo depois
             dela para nao estourar o buffer de 200.000 caracteres por linha do
             pdflatex. Sob \obeylines essa quebra vira um \par e o bloco saia
             com o DOBRO do entrelinhas (medido no container). O '%' come a
             quebra sem tirar o limite de buffer: a linha longa continua
             cortada na fonte, e a caixa continua com o entrelinhas do modelo.
             O \newline e' do escape_verbatim, nunca de dado do feed — o
             escape_text transforma a barra do XML em \textbackslash. -->
        <xsl:variable name="det">
          <xsl:call-template name="escape_verbatim">
            <xsl:with-param name="string" select="substring(description, 1, $dcut)"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:text>\fieldlabel{\suriLblFldDetection}
\begin{termbox}
</xsl:text>
        <xsl:value-of select="str:replace(string($det), '\newline&#10;', '\newline%&#10;')"/>
        <xsl:text>
\end{termbox}
</xsl:text>
        <xsl:if test="$dlen &gt; 1500">
          <!-- O aviso e' META-TEXTO, nao evidencia: sai FORA da caixa, como
               nota do bloco (\blocknote), em vez de disfarcado de saida do
               scanner dentro do terminal verde. De quebra o travessao triplo
               das chaves trunc_* volta a fechar a ligadura, que em
               monoespacada saia como dois hifens soltos. -->
          <xsl:text>\blocknote{</xsl:text>
          <xsl:value-of select="gvm:t('trunc_a')"/>
          <xsl:value-of select="gvm:num($dcut)"/>
          <xsl:value-of select="gvm:t('trunc_b')"/>
          <xsl:value-of select="gvm:num($dlen)"/>
          <xsl:value-of select="gvm:t('trunc_c')"/>
          <xsl:text>}
</xsl:text>
        </xsl:if>
      </xsl:if>

      <!-- Solution / Remediation -->
      <xsl:variable name="solution">
        <xsl:choose>
          <xsl:when test="string-length(normalize-space(nvt/solution)) &gt; 0">
            <xsl:value-of select="nvt/solution"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="gvm:get-nvt-tag('solution')"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:if test="string-length(normalize-space($solution)) &gt; 0">
        <!-- O \solbox imprime o proprio rotulo SOLUCAO / REMEDIACAO, entao aqui
             nao vai \fieldlabel nenhum.
             O NEGRITO marca o que o leitor tem de executar. Numa correcao curta
             ("Update to version 10.1 or later.") isso e' a frase inteira, que e'
             o que a pg-09 do modelo mostra; numa mitigacao de dez linhas o
             negrito vira parede, entao ali ele volta para o rotulo do tipo e o
             texto sai limpo. O criterio e' o tamanho do texto, nao o gosto. -->
        <xsl:variable name="solshort"
          select="string-length(normalize-space($solution)) &lt;= 200
                  and not(contains($solution, '&#10;'))"/>
        <xsl:text>\solbox{</xsl:text>
        <xsl:if test="string-length(nvt/solution/@type) &gt; 0">
          <xsl:if test="not($solshort)"><xsl:text>{\bfseries </xsl:text></xsl:if>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="gvm:solution-type-label(nvt/solution/@type)"/>
          </xsl:call-template>
          <xsl:text>:\ </xsl:text>
          <xsl:if test="not($solshort)"><xsl:text>}</xsl:text></xsl:if>
        </xsl:if>
        <xsl:if test="$solshort"><xsl:text>\textbf{</xsl:text></xsl:if>
        <!-- solution-body, nao escape_prose direto: a mitigacao tambem vem em
             lista de marcadores. O caminho de lista so' dispara com quebra de
             linha no texto, e $solshort exige texto SEM quebra de linha, entao
             o \textbf acima nunca abraca uma lista. -->
        <xsl:call-template name="solution-body">
          <xsl:with-param name="value" select="$solution"/>
        </xsl:call-template>
        <xsl:if test="$solshort"><xsl:text>}</xsl:text></xsl:if>
        <xsl:text>}
</xsl:text>
      </xsl:if>

      <!-- References (url refs).
           Este era o UNICO ponto do arquivo em que texto do XML virava LaTeX
           sem passar por escape. Uma URL de referencia com '}' ou '\' fechava
           o argumento do \url e o pdflatex acusava "Missing $ inserted" /
           "Extra }". E o pior nao era a falha: o `generate` faz `cat` do PDF
           sem checar erro, entao o cliente recebia um documento que parecia
           inteiro com a REFERENCIA CORROMPIDA — apontando para outro lugar,
           sem aviso nenhum. A regra de quem clica e quem nao clica esta' no
           template reference-line, que e' onde essa decisao mora agora. -->
      <xsl:if test="count(nvt/refs/ref[@type='url']) &gt; 0">
        <xsl:text>\fieldlabel{\suriLblFldRefs}
\reflist{%
</xsl:text>
        <xsl:for-each select="nvt/refs/ref[@type='url']">
          <xsl:call-template name="reference-line">
            <xsl:with-param name="u" select="string(@id)"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>}
</xsl:text>
      </xsl:if>
      <!-- Nenhum \vspace fecha o achado: o ar acima de cada bloco pertence ao
           bloco que COMECA (o \suri@air do suricatoos-report), e o proximo
           \findingcard ja' o carrega. -->
      <xsl:text>
</xsl:text>
    </xsl:for-each>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Closing colophon                                                  -->
  <!-- ================================================================= -->


  <!-- One card per product whose vendor-fix advisories piled up past the
       threshold. Replaces N nearly identical cards with the single action that
       actually resolves them. -->
  <xsl:template name="consolidated-update-cards">
    <xsl:for-each select="gvm:report()/results/result[nvt/solution/@type='VendorFix'][generate-id() = generate-id(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[1])]">
      <xsl:sort select="severity" data-type="number" order="descending"/>
      <xsl:variable name="g" select="concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' '))"/>
      <xsl:variable name="ndist" select="count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])])"/>
      <xsl:if test="$ndist &gt;= $group-min">
        <xsl:variable name="members" select="key('by-updgrp', $g)"/>
        <!-- Highest severity in the group drives the card colour. -->
        <xsl:variable name="maxsev">
          <xsl:for-each select="$members">
            <xsl:sort select="severity" data-type="number" order="descending"/>
            <xsl:if test="position() = 1"><xsl:value-of select="severity"/></xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:variable name="sevkey">
          <xsl:call-template name="sevkey-detail">
            <xsl:with-param name="severity" select="$maxsev"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:variable name="gname">
          <xsl:call-template name="escape_name">
            <xsl:with-param name="string" select="$g"/>
          </xsl:call-template>
        </xsl:variable>
        <!-- Affected hosts (each host once, however many advisories hit it).
             O mesmo teste de "ja' apareceu antes?" de sempre, so' que agora o
             resultado e' MATERIALIZADO num node-set: o card precisa saber
             QUANTOS hosts sao (o chip diz o numero) e nao so' cuspir a lista.
             De quebra some um defeito da versao em prosa: o separador olhava a
             posicao dentro de $members, entao quando o primeiro host unico nao
             era o primeiro membro do grupo a lista abria com uma virgula solta. -->
        <xsl:variable name="ghosts-rtf">
          <xsl:for-each select="$members">
            <xsl:sort select="host/text()"/>
            <xsl:variable name="h" select="host/text()"/>
            <xsl:if test="not(preceding::result[nvt/solution/@type='VendorFix'][host/text() = $h][concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')) = $g])">
              <h v="{$h}"/>
            </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:variable name="ghosts" select="exsl:node-set($ghosts-rtf)/h"/>

        <!-- Card consolidado (pg-08 do modelo). O \hypertarget vai dentro do
             titulo pelo mesmo motivo do card de achado: solto na pagina ele
             abriria um paragrafo vazio antes do card. -->
        <xsl:text>\consolidatedcard{</xsl:text><xsl:value-of select="$sevkey"/>
        <xsl:text>}{\hypertarget{</xsl:text>
        <xsl:value-of select="concat('grp-', translate(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')), ' ./:,()', '-------'))"/>
        <xsl:text>}{}</xsl:text><xsl:value-of select="gvm:t('grp_title')"/><xsl:text>: </xsl:text>
        <xsl:value-of select="$gname"/><xsl:text>}{</xsl:text>
        <xsl:value-of select="gvm:t('grp_badge')"/><xsl:text>}{%
  \chipsev{</xsl:text><xsl:value-of select="$sevkey"/><xsl:text>}{</xsl:text>
        <xsl:if test="$sevkey != 'logsev' and $sevkey != 'falsepos'">
          <xsl:value-of select="$maxsev"/>
        </xsl:if>
        <xsl:text>}%
  \chip{</xsl:text><xsl:value-of select="$ndist"/><xsl:text> </xsl:text>
        <xsl:value-of select="gvm:t('grp_adv_caps')"/><xsl:text>}%
</xsl:text>
        <!-- Um host: o chip nomeia o endereco, como no modelo. Varios: o
             primeiro chip conta e os seguintes enumeram, com teto declarado. -->
        <xsl:choose>
          <xsl:when test="count($ghosts) = 1">
            <xsl:text>  \chip{</xsl:text><xsl:value-of select="gvm:t('chip_host')"/><xsl:text> </xsl:text>
            <xsl:call-template name="escape_break">
              <xsl:with-param name="string" select="string($ghosts[1]/@v)"/>
            </xsl:call-template>
            <xsl:text>}%
</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>  \chip{</xsl:text><xsl:value-of select="count($ghosts)"/><xsl:text> </xsl:text>
            <xsl:value-of select="gvm:t('chip_hosts')"/><xsl:text>}%
</xsl:text>
            <xsl:for-each select="$ghosts">
              <xsl:if test="position() &lt;= 40">
                <xsl:text>  \chip{</xsl:text>
                <xsl:call-template name="escape_break">
                  <xsl:with-param name="string" select="string(@v)"/>
                </xsl:call-template>
                <xsl:text>}%
</xsl:text>
              </xsl:if>
            </xsl:for-each>
            <xsl:if test="count($ghosts) &gt; 40">
              <xsl:text>  \chip{+</xsl:text><xsl:value-of select="count($ghosts) - 40"/>
              <xsl:text> </xsl:text><xsl:value-of select="gvm:hx-upper(gvm:t('more_word'))"/>
              <xsl:text>}%
</xsl:text>
            </xsl:if>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>}{%
  </xsl:text><xsl:value-of select="gvm:t('grp_intro_a')"/>
        <xsl:text>\textbf{</xsl:text><xsl:value-of select="$ndist"/><xsl:text>}</xsl:text>
        <xsl:value-of select="gvm:t('grp_intro_b')"/>
        <xsl:text>\textbf{</xsl:text><xsl:value-of select="gvm:t('grp_intro_c')"/><xsl:text>}</xsl:text>
        <xsl:value-of select="gvm:t('grp_intro_d')"/>
        <xsl:text>}{%
</xsl:text>

        <!-- The advisories rolled up here, most severe first. -->
        <xsl:for-each select="$members[generate-id() = generate-id(key('by-updgrp-nvt',concat($g,'||',nvt/@oid))[1])]">
          <xsl:sort select="severity" data-type="number" order="descending"/>
          <!-- Lista só os mais severos. O restante vira UMA linha que declara
               quantos ficaram de fora e até onde vai a severidade deles: um
               corte silencioso faria o card parecer completo, e este documento
               é material de auditoria. A ação de remediação é a mesma para
               todos, então o que se perde é enumeração, não decisão. -->
          <xsl:if test="position() &lt;= number($adv-max)">
            <xsl:variable name="asev">
              <xsl:call-template name="sevkey-detail">
                <xsl:with-param name="severity" select="severity"/>
              </xsl:call-template>
            </xsl:variable>
            <xsl:text>  \advisoryrow{</xsl:text>
            <xsl:call-template name="escape_name">
              <xsl:with-param name="string" select="nvt/name"/>
            </xsl:call-template>
            <xsl:text>}{</xsl:text><xsl:value-of select="$asev"/><xsl:text>}{</xsl:text>
            <xsl:if test="$asev != 'logsev' and $asev != 'falsepos'">
              <xsl:value-of select="severity"/>
            </xsl:if>
            <xsl:text>}
</xsl:text>
          </xsl:if>
          <xsl:if test="position() = number($adv-max) + 1">
            <xsl:text>  \advisorytrunc{+ </xsl:text><xsl:value-of select="$ndist - number($adv-max)"/>
            <xsl:value-of select="gvm:t('grp_more_a')"/>
            <xsl:text>CVSS </xsl:text>
            <xsl:value-of select="format-number(severity, '0.0')"/>
            <xsl:value-of select="gvm:t('grp_more_b')"/>
            <xsl:text>}
</xsl:text>
          </xsl:if>
        </xsl:for-each>

        <!-- Single remediation action: the fix of the most severe advisory.
             O \consolidatedcard compoe esta faixa em monoespacada sobre navy e
             ja' escreve o proprio rotulo AÇÃO ÚNICA DE REMEDIAÇÃO. -->
        <xsl:text>}{</xsl:text>
        <xsl:for-each select="$members">
          <xsl:sort select="severity" data-type="number" order="descending"/>
          <xsl:if test="position() = 1">
            <xsl:call-template name="escape_prose">
              <xsl:with-param name="string" select="nvt/solution"/>
            </xsl:call-template>
          </xsl:if>
        </xsl:for-each>
        <xsl:text>}
</xsl:text>
        <!-- Um card consolidado por pagina, como a pg-08 do modelo.
             O \consolidatedcard e' um tcolorbox `breakable' e a faixa navy da
             ACAO UNICA e' o ULTIMO pedaco dele, entao quando dois cards
             dividiam a pagina o segundo partia na unica junta que tem e a faixa
             de remediacao ia sozinha para o alto da pagina seguinte, desgarrada
             do card que ela resolve (medido: pg-08 -> pg-09 do primeiro build).
             O card tem altura limitada — $adv-max linhas de advisory mais a
             linha de corte — entao uma pagina sempre o comporta inteiro.
             O \clearpage vem DEPOIS: antes do primeiro card ele deixaria o
             titulo da secao 5 sozinho numa pagina em branco. -->
        <xsl:text>\clearpage
</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>


  <!-- ================================================================= -->
  <!-- Hexmap: lookup tables and small helpers                           -->
  <!-- ================================================================= -->

  <!-- Small integer ladder, so row loops need no recursion. 25 entries covers
       every board up to k=8 (217 cells), far beyond any sane hexmap-max. -->
  <xsl:variable name="hx-ints-rtf">
    <i v="0"/><i v="1"/><i v="2"/><i v="3"/><i v="4"/><i v="5"/><i v="6"/><i v="7"/>
    <i v="8"/><i v="9"/><i v="10"/><i v="11"/><i v="12"/><i v="13"/><i v="14"/><i v="15"/>
    <i v="16"/><i v="17"/><i v="18"/><i v="19"/><i v="20"/><i v="21"/><i v="22"/><i v="23"/><i v="24"/>
  </xsl:variable>
  <xsl:variable name="hx-ints" select="exsl:node-set($hx-ints-rtf)"/>

  <!-- Largest board the geometry below can lay out: the k=8 blob, 1+3*8*9 cells.
       The cut in hx-draw-cells is clamped to it, so a hexmap-max above this
       rolls the surplus into the "+N" cell and the footnote instead of letting
       the drawing loop run out of seats in silence (the legend counts the cells
       it was given, so a silent drop makes the legend lie). -->
  <xsl:variable name="hx-cap" select="217"/>

  <!-- Port families that collapse into ONE cell. This is a FIXED table on
       purpose: a generic "contiguous numbers" rule would happily fuse 8080 with
       8081, which share nothing but a neighbouring number. A family collapses
       only when at least two of its members are present on the SAME transport,
       and the printed label is derived from the members actually present
       (137+138 on udp reads "137-138", not "135-139"), so the label never
       claims a port the scan did not see. @n is the name printed in the table
       and @s the short form the board uses; both name the FAMILY, never a
       service observed running, and never a registry entry - 135 is the MS RPC
       endpoint mapper and not NetBIOS, so the family that collapses it cannot
       be called "netbios". Cells named this way carry their own marker and
       footnote, apart from the IANA dagger. -->
  <xsl:variable name="hx-fam-rtf">
    <f id="ftp"  p=" 20 21 "            n="ftp"            s="ftp"/>
    <f id="dhcp" p=" 67 68 "            n="dhcp"           s="dhcp"/>
    <f id="nbt"  p=" 135 137 138 139 "  n="netbios-rpc"    s="nbt-rpc"/>
    <f id="snmp" p=" 161 162 "          n="snmp"           s="snmp"/>
  </xsl:variable>
  <xsl:variable name="hx-fam" select="exsl:node-set($hx-fam-rtf)/f"/>

  <!-- Well-known port names, IANA service registry. Used ONLY when the scan did
       not identify the service, and always flagged with a dagger plus a
       footnote, because a registry name is an expectation and not an
       observation. Entries whose registry name is a legacy oddity that would
       mislead the reader (1521 "ncube-lm", 3128 "ndl-aas", 8443
       "pcsync-https", ...) are deliberately ABSENT: such a cell falls back to
       the bare transport instead of asserting the wrong product. Cross-checked
       entry by entry against the registry - note 1433/tcp is ms-sql-s, the real
       Microsoft SQL Server port; 156 is the unrelated legacy "sqlsrv". -->
  <xsl:variable name="hx-iana-rtf">
    <p k="tcp/20" n="ftp-data"/><p k="tcp/21" n="ftp"/><p k="tcp/22" n="ssh"/>
    <p k="tcp/23" n="telnet"/><p k="tcp/25" n="smtp"/><p k="tcp/37" n="time"/>
    <p k="tcp/49" n="tacacs"/><p k="tcp/53" n="domain"/><p k="tcp/70" n="gopher"/>
    <p k="tcp/79" n="finger"/><p k="tcp/80" n="http"/><p k="tcp/88" n="kerberos"/>
    <p k="tcp/102" n="iso-tsap"/><p k="tcp/110" n="pop3"/><p k="tcp/111" n="sunrpc"/>
    <p k="tcp/113" n="ident"/><p k="tcp/119" n="nntp"/><p k="tcp/123" n="ntp"/>
    <p k="tcp/135" n="epmap"/><p k="tcp/137" n="netbios-ns"/><p k="tcp/138" n="netbios-dgm"/>
    <p k="tcp/139" n="netbios-ssn"/><p k="tcp/143" n="imap"/><p k="tcp/161" n="snmp"/>
    <p k="tcp/162" n="snmptrap"/><p k="tcp/179" n="bgp"/><p k="tcp/194" n="irc"/>
    <p k="tcp/389" n="ldap"/><p k="tcp/427" n="svrloc"/><p k="tcp/443" n="https"/>
    <p k="tcp/445" n="microsoft-ds"/><p k="tcp/465" n="submissions"/><p k="tcp/500" n="isakmp"/>
    <p k="tcp/512" n="exec"/><p k="tcp/513" n="login"/><p k="tcp/514" n="shell"/>
    <p k="tcp/515" n="printer"/><p k="tcp/543" n="klogin"/><p k="tcp/544" n="kshell"/>
    <p k="tcp/548" n="afp"/><p k="tcp/554" n="rtsp"/><p k="tcp/587" n="submission"/>
    <p k="tcp/631" n="ipp"/><p k="tcp/636" n="ldaps"/><p k="tcp/873" n="rsync"/>
    <p k="tcp/989" n="ftps-data"/><p k="tcp/990" n="ftps"/><p k="tcp/993" n="imaps"/>
    <p k="tcp/995" n="pop3s"/><p k="tcp/1080" n="socks"/><p k="tcp/1099" n="rmiregistry"/>
    <p k="tcp/1194" n="openvpn"/><p k="tcp/1352" n="lotusnote"/><p k="tcp/1433" n="ms-sql-s"/>
    <p k="tcp/1434" n="ms-sql-m"/><p k="tcp/1723" n="pptp"/><p k="tcp/1883" n="mqtt"/>
    <p k="tcp/2049" n="nfs"/><p k="tcp/3268" n="msft-gc"/><p k="tcp/3269" n="msft-gc-ssl"/>
    <p k="tcp/3306" n="mysql"/><p k="tcp/3389" n="ms-wbt-server"/><p k="tcp/5060" n="sip"/>
    <p k="tcp/5061" n="sips"/><p k="tcp/5222" n="xmpp-client"/><p k="tcp/5432" n="postgresql"/>
    <p k="tcp/5672" n="amqp"/><p k="tcp/5900" n="rfb"/><p k="tcp/5985" n="wsman"/>
    <p k="tcp/5986" n="wsmans"/><p k="tcp/6379" n="redis"/><p k="tcp/8080" n="http-alt"/>
    <p k="tcp/11211" n="memcache"/>
    <p k="udp/53" n="domain"/><p k="udp/67" n="bootps"/><p k="udp/68" n="bootpc"/>
    <p k="udp/69" n="tftp"/><p k="udp/88" n="kerberos"/><p k="udp/111" n="sunrpc"/>
    <p k="udp/123" n="ntp"/><p k="udp/137" n="netbios-ns"/><p k="udp/138" n="netbios-dgm"/>
    <p k="udp/161" n="snmp"/><p k="udp/162" n="snmptrap"/><p k="udp/500" n="isakmp"/>
    <p k="udp/514" n="syslog"/><p k="udp/520" n="router"/><p k="udp/623" n="asf-rmcp"/>
    <p k="udp/1194" n="openvpn"/><p k="udp/1434" n="ms-sql-m"/><p k="udp/1701" n="l2tp"/>
    <p k="udp/1812" n="radius"/><p k="udp/1813" n="radius-acct"/><p k="udp/1900" n="ssdp"/>
    <p k="udp/4500" n="ipsec-nat-t"/><p k="udp/5060" n="sip"/><p k="udp/5353" n="mdns"/>
    <p k="udp/11211" n="memcache"/>
  </xsl:variable>
  <xsl:variable name="hx-iana" select="exsl:node-set($hx-iana-rtf)/p"/>

  <!-- Normalised cell key "proto/number" of a port string. -->
  <func:function name="gvm:hx-pk">
    <xsl:param name="p"/>
    <func:result select="concat(translate(substring-after(normalize-space($p),'/'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'/',substring-before(normalize-space($p),'/'))"/>
  </func:function>

  <!-- The host a port node belongs to: the <host> child for a ports/port, the
       parent result's <host> TEXT for a result/port (result/host also carries a
       <hostname> child, so its string-value would read "10.0.0.1srv01"). Only
       the first whitespace-delimited token counts, so a malformed element with
       two addresses in it still yields ONE identifier and the invariant
       "one token in @ips per counted host" holds. Missing host = empty string,
       which is not a host: such observations are counted and reported, never
       folded into a phantom address. -->
  <func:function name="gvm:hx-ip">
    <xsl:param name="n"/>
    <func:result select="substring-before(concat(normalize-space(string($n/host/text() | $n/../host/text())),' '),' ')"/>
  </func:function>

  <!-- A port string is drawable only when it is not a host-level pseudo-port and
       parses as <integer>/<transport>. Everything else is counted and reported,
       never silently dropped. -->
  <func:function name="gvm:hx-valid">
    <xsl:param name="p"/>
    <func:result select="not(starts-with(normalize-space($p),'general'))
                         and string-length(substring-before(normalize-space($p),'/')) &gt; 0
                         and string-length(substring-after(normalize-space($p),'/')) &gt; 0
                         and floor(number(substring-before(normalize-space($p),'/'))) = number(substring-before(normalize-space($p),'/'))"/>
  </func:function>

  <!-- Nth octet of a dotted IPv4 address, NaN for anything else. Used as sort
       keys: an IPv4 address sorts by octet value, everything else ties on NaN
       and falls through to the plain alphabetical tiebreaker. -->
  <func:function name="gvm:hx-oct">
    <xsl:param name="s"/>
    <xsl:param name="i"/>
    <xsl:choose>
      <xsl:when test="$i = 1"><func:result select="number(substring-before($s,'.'))"/></xsl:when>
      <xsl:when test="$i = 2"><func:result select="number(substring-before(substring-after($s,'.'),'.'))"/></xsl:when>
      <xsl:when test="$i = 3"><func:result select="number(substring-before(substring-after(substring-after($s,'.'),'.'),'.'))"/></xsl:when>
      <xsl:otherwise><func:result select="number(substring-after(substring-after(substring-after($s,'.'),'.'),'.'))"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Octet of the address a port node belongs to, in ONE call: used as a sort
       key on every node of every cell, where nesting hx-oct(hx-ip(.)) doubled
       the number of function instantiations. -->
  <func:function name="gvm:hx-noct">
    <xsl:param name="n"/>
    <xsl:param name="i"/>
    <func:result select="gvm:hx-oct(substring-before(concat(normalize-space(string($n/host/text() | $n/../host/text())),' '),' '), $i)"/>
  </func:function>

  <xsl:variable name="hx-lc" select="'abcdefghijklmnopqrstuvwxyzáàâãéêíóôõúüçñ'"/>
  <xsl:variable name="hx-uc" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZÁÀÂÃÉÊÍÓÔÕÚÜÇÑ'"/>

  <func:function name="gvm:hx-upper">
    <xsl:param name="s"/>
    <func:result select="translate($s, $hx-lc, $hx-uc)"/>
  </func:function>

  <func:function name="gvm:hx-min2">
    <xsl:param name="a"/>
    <xsl:param name="b"/>
    <xsl:choose>
      <xsl:when test="number($a) &lt;= number($b)"><func:result select="number($a)"/></xsl:when>
      <xsl:otherwise><func:result select="number($b)"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <func:function name="gvm:hx-max2">
    <xsl:param name="a"/>
    <xsl:param name="b"/>
    <xsl:choose>
      <xsl:when test="number($a) &gt;= number($b)"><func:result select="number($a)"/></xsl:when>
      <xsl:otherwise><func:result select="number($b)"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Aqui viviam cinco funcoes da geometria do tabuleiro ANTIGO, todas sem um
       unico chamador depois que o favo passou a ser desenhado pelo
       suricatoos-hex (\hexcard / hexboard / \hexport):

         gvm:hx-wlen    contagem de caracteres ponderada pelas maiusculas largas
         gvm:hx-fit     corpo de fonte calculado para caber no hexagono
         gvm:hx-color   estado -> hexCrit/hexHigh/... (paleta escura)
         gvm:hx-tcolor  estado -> hexCritT/hexHighT/... (variantes da tabela)
         gvm:hx-fillop  estado -> opacidade do preenchimento

       As duas de medida existiam porque o XSLT calculava o \fontsize de cada
       node de TikZ; o .sty faz isso agora. As tres de cor devolviam nomes da
       paleta hex* que nao existe mais em .sty nenhum — se alguem as religasse,
       o pdflatex morreria num "undefined color". O estado viaja como CHAVE
       (critico|alto|medio|baixo|exposto|neutro) e quem pinta e' \sevcolor. -->

  <!-- One state down the ladder. Applied when the highest CONFIRMED finding on a
       port is milder than the highest finding overall, i.e. the peak severity
       rests on a low detection-quality result. -->
  <func:function name="gvm:hx-downgrade">
    <xsl:param name="st"/>
    <xsl:choose>
      <xsl:when test="$st='critico'"><func:result select="'alto'"/></xsl:when>
      <xsl:when test="$st='alto'"><func:result select="'medio'"/></xsl:when>
      <xsl:when test="$st='medio'"><func:result select="'baixo'"/></xsl:when>
      <xsl:when test="$st='baixo'"><func:result select="'exposto'"/></xsl:when>
      <xsl:otherwise><func:result select="$st"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <func:function name="gvm:hx-rank">
    <xsl:param name="st"/>
    <xsl:choose>
      <xsl:when test="$st='critico'"><func:result select="1"/></xsl:when>
      <xsl:when test="$st='alto'"><func:result select="2"/></xsl:when>
      <xsl:when test="$st='medio'"><func:result select="3"/></xsl:when>
      <xsl:when test="$st='baixo'"><func:result select="4"/></xsl:when>
      <xsl:when test="$st='exposto'"><func:result select="5"/></xsl:when>
      <xsl:otherwise><func:result select="6"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Drop the LAST internal vowel of an uppercase label (never the first
       character). Walks the string from the end; recursion depth is bounded by
       the label length, which is itself capped at 40. -->
  <xsl:template name="hx-drop-vowel">
    <xsl:param name="s"/>
    <xsl:param name="i"/>
    <xsl:choose>
      <xsl:when test="number($i) &lt; 2"><xsl:value-of select="$s"/></xsl:when>
      <xsl:when test="contains('AEIOU', substring($s, number($i), 1))">
        <xsl:value-of select="concat(substring($s, 1, number($i) - 1), substring($s, number($i) + 1))"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="hx-drop-vowel">
          <xsl:with-param name="s" select="$s"/>
          <xsl:with-param name="i" select="number($i) - 1"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Squeeze an uppercase service label down to $max characters by removing
       internal vowels from the right, exactly as the spec prescribes; a label
       with no internal vowel left is hard-truncated. The integral name always
       survives in the Port -> IP table, so nothing is lost. -->
  <xsl:template name="hx-abbrev">
    <xsl:param name="s"/>
    <xsl:param name="max" select="8"/>
    <xsl:param name="guard" select="40"/>
    <xsl:choose>
      <xsl:when test="string-length($s) &lt;= number($max)"><xsl:value-of select="$s"/></xsl:when>
      <xsl:when test="number($guard) &lt;= 0"><xsl:value-of select="substring($s, 1, number($max))"/></xsl:when>
      <xsl:otherwise>
        <xsl:variable name="t">
          <xsl:call-template name="hx-drop-vowel">
            <xsl:with-param name="s" select="$s"/>
            <xsl:with-param name="i" select="string-length($s)"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:choose>
          <xsl:when test="string-length($t) = string-length($s)">
            <xsl:value-of select="substring($s, 1, number($max))"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="hx-abbrev">
              <xsl:with-param name="s" select="string($t)"/>
              <xsl:with-param name="max" select="$max"/>
              <xsl:with-param name="guard" select="number($guard) - 1"/>
            </xsl:call-template>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Hexmap: cell aggregation                                          -->
  <!-- ================================================================= -->

  <!-- Every port string the report carries, from BOTH sources. -->
  <xsl:variable name="hx-allports" select="gvm:report()/ports/port | gvm:report()/results/result/port"/>

  <!-- Distinct hosts carrying a host-level (general/*) entry, and distinct port
       strings that could not be parsed. Both are reported under the board
       instead of vanishing. -->
  <xsl:variable name="hx-genhosts"
    select="count($hx-allports[starts-with(normalize-space(text()),'general')]
                              [generate-id() = generate-id(key('hx-genip', gvm:hx-ip(.))[1])])"/>
  <!-- Port observations that name no host at all. An empty address is not a
       host: counting it would inflate the host column and it can never appear
       in the IP list, so it is excluded from both and reported instead. -->
  <xsl:variable name="hx-noip"
    select="count($hx-allports[gvm:hx-valid(text())][string-length(gvm:hx-ip(.)) = 0])"/>
  <xsl:variable name="hx-malformed"
    select="count($hx-allports[generate-id() = generate-id(key('hx-pkey', gvm:hx-pk(text()))[1])]
                              [not(starts-with(normalize-space(text()),'general'))]
                              [not(gvm:hx-valid(text()))])"/>

  <!-- One <c> per distinct (transport, port) in scope. $scope says WHICH scope,
       explicitly: 'all' is the whole report and 'host' is $hostip alone. The
       scope is a separate parameter and not an empty $hostip, because an empty
       address is a value the data can legitimately carry (a <host> element with
       no <ip>), and overloading it as "the whole report" made such a host
       inherit every port in the scan. -->
  <xsl:template name="hx-raw-cells">
    <xsl:param name="scope" select="'all'"/>
    <xsl:param name="hostip" select="''"/>
    <!-- A per-host board starts from the host index, so it costs the ports of
         that host and not a sweep of every port node in the report. -->
    <xsl:variable name="src"
      select="$hx-allports[$scope = 'all'] | key('hx-hostkey', $hostip)[$scope = 'host']"/>
    <xsl:for-each select="$src[gvm:hx-valid(text())][
            ($scope = 'all' and generate-id() = generate-id(key('hx-pkey', gvm:hx-pk(text()))[1]))
         or ($scope = 'host' and generate-id() = generate-id(key('hx-ipkey', concat(gvm:hx-pk(text()),'#',gvm:hx-ip(.)))[1]))
       ]">
      <xsl:variable name="ps" select="normalize-space(text())"/>
      <xsl:variable name="num" select="substring-before($ps,'/')"/>
      <xsl:variable name="proto" select="translate(substring-after($ps,'/'), $hx-uc, $hx-lc)"/>
      <xsl:variable name="k" select="concat($proto,'/',$num)"/>
      <!-- Every node (inventory + result) for this cell, scoped to the host. -->
      <xsl:variable name="pn" select="key('hx-pkey', $k)[$scope = 'all']
                                    | key('hx-ipkey', concat($k,'#',$hostip))[$scope = 'host']"/>
      <!-- Rated results only: -1 is a false positive, -2 debug, -3 a scan error.
           None of them may raise a cell's state. -->
      <xsl:variable name="rs" select="$pn[parent::result]/parent::result[number(severity) &gt;= 0]"/>
      <xsl:variable name="rsconf" select="$rs[not(qod/value) or number(qod/value) &gt;= number($qod-min)]"/>
      <xsl:variable name="cvssmax">
        <xsl:choose>
          <xsl:when test="count($rs) = 0">-1</xsl:when>
          <xsl:otherwise>
            <xsl:for-each select="$rs">
              <xsl:sort select="number(severity)" data-type="number" order="descending"/>
              <xsl:if test="position() = 1"><xsl:value-of select="number(severity)"/></xsl:if>
            </xsl:for-each>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="cvssconf">
        <xsl:choose>
          <xsl:when test="count($rsconf) = 0">-1</xsl:when>
          <xsl:otherwise>
            <xsl:for-each select="$rsconf">
              <xsl:sort select="number(severity)" data-type="number" order="descending"/>
              <xsl:if test="position() = 1"><xsl:value-of select="number(severity)"/></xsl:if>
            </xsl:for-each>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <!-- Distinct exposing hosts. An observation that names no host is not
           one of them: it would count as a host the table can never show. -->
      <xsl:variable name="ipn" select="$pn[string-length(gvm:hx-ip(.)) &gt; 0]
                                          [generate-id() = generate-id(key('hx-ipkey', concat($k,'#',gvm:hx-ip(.)))[1])]"/>
      <!-- Service name: what the scan actually identified, else the IANA
           registry name, else the bare transport. -->
      <xsl:variable name="svcnode" select="key('hx-svc', $k)[$scope = 'all' or normalize-space(../ip) = $hostip][1]"/>
      <xsl:variable name="svcraw" select="substring-after(substring-after($svcnode/value,'/'),'/')"/>
      <xsl:variable name="ianan" select="string($hx-iana[@k = $k]/@n)"/>
      <xsl:variable name="svcsrc">
        <xsl:choose>
          <xsl:when test="string-length($svcraw) &gt; 0">scan</xsl:when>
          <xsl:when test="number($hexmap-iana-names) = 1 and string-length($ianan) &gt; 0">iana</xsl:when>
          <xsl:otherwise>proto</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="svc">
        <xsl:choose>
          <xsl:when test="$svcsrc = 'scan'"><xsl:value-of select="$svcraw"/></xsl:when>
          <xsl:when test="$svcsrc = 'iana'"><xsl:value-of select="$ianan"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="$proto"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <!-- State. A port with no rated result is "exposto" when the scan named a
           service on it and "neutro" when it did not; a registry name is an
           expectation, not an observation, so it does not promote the cell. -->
      <xsl:variable name="base">
        <xsl:choose>
          <xsl:when test="count($rs) = 0 and $svcsrc = 'scan'">exposto</xsl:when>
          <xsl:when test="count($rs) = 0">neutro</xsl:when>
          <xsl:when test="number($cvssmax) &gt;= 9.0">critico</xsl:when>
          <xsl:when test="number($cvssmax) &gt;= 7.0">alto</xsl:when>
          <xsl:when test="number($cvssmax) &gt;= 4.0">medio</xsl:when>
          <xsl:when test="number($cvssmax) &gt;= 0.1">baixo</xsl:when>
          <xsl:otherwise>exposto</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="qodlow" select="count($rs) &gt; 0 and number($cvssconf) &lt; number($cvssmax)"/>
      <xsl:variable name="state">
        <xsl:choose>
          <xsl:when test="$qodlow"><xsl:value-of select="gvm:hx-downgrade(string($base))"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="$base"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="fam" select="$hx-fam[contains(@p, concat(' ', $num, ' '))]"/>
      <c num="{$num}" proto="{$proto}" label="{$num}" members="{$num}"
         blabel="{concat($num,'/',gvm:hx-upper($proto))}"
         famn="{$fam/@n}" fams="{$fam/@s}" svc="{$svc}" svcsrc="{$svcsrc}"
         state="{$state}" srank="{gvm:hx-rank(string($state))}"
         cvss="{$cvssmax}" nfind="{count($rs)}" nips="{count($ipn)}">
        <xsl:attribute name="qodlow"><xsl:choose><xsl:when test="$qodlow">1</xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose></xsl:attribute>
        <xsl:attribute name="gk">
          <xsl:choose>
            <xsl:when test="count($fam) &gt; 0"><xsl:value-of select="concat($proto,'#f',$fam/@id)"/></xsl:when>
            <xsl:otherwise><xsl:value-of select="concat($proto,'#p',$num)"/></xsl:otherwise>
          </xsl:choose>
        </xsl:attribute>
        <xsl:attribute name="ips">
          <xsl:text> </xsl:text>
          <xsl:for-each select="$ipn">
            <xsl:sort select="gvm:hx-noct(.,1)" data-type="number"/>
            <xsl:sort select="gvm:hx-noct(.,2)" data-type="number"/>
            <xsl:sort select="gvm:hx-noct(.,3)" data-type="number"/>
            <xsl:sort select="gvm:hx-noct(.,4)" data-type="number"/>
            <xsl:sort select="gvm:hx-ip(.)"/>
            <xsl:value-of select="gvm:hx-ip(.)"/><xsl:text> </xsl:text>
          </xsl:for-each>
        </xsl:attribute>
      </c>
    </xsl:for-each>
  </xsl:template>

  <!-- Collapse the fixed port families into one cell each. Only a cell that
       belongs to a family can group, so only those are matched against each
       other: scanning the whole set once per cell is quadratic in the number of
       distinct ports (a 1500-port report spent 80% of the run in here), while
       the families never hold more than a dozen cells between them. The output
       order is irrelevant, hx-ordered-cells ranks everything right after. -->
  <xsl:template name="hx-collapse">
    <xsl:param name="raw"/>
    <xsl:variable name="famc" select="$raw/c[string-length(@famn) &gt; 0]"/>
    <xsl:copy-of select="$raw/c[string-length(@famn) = 0]"/>
    <xsl:for-each select="$famc">
      <xsl:sort select="number(@num)" data-type="number"/>
      <xsl:variable name="me" select="."/>
      <xsl:variable name="grp" select="$famc[@gk = $me/@gk]"/>
      <!-- The lowest-numbered member speaks for the group. -->
      <xsl:if test="count($grp[number(@num) &lt; number($me/@num)]) = 0">
        <xsl:choose>
          <xsl:when test="count($grp) &gt;= 2">
            <xsl:variable name="hi">
              <xsl:for-each select="$grp">
                <xsl:sort select="number(@num)" data-type="number" order="descending"/>
                <xsl:if test="position() = 1"><xsl:value-of select="@num"/></xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <xsl:variable name="best">
              <xsl:for-each select="$grp">
                <xsl:sort select="number(@srank)" data-type="number"/>
                <xsl:sort select="number(@num)" data-type="number"/>
                <xsl:if test="position() = 1"><xsl:value-of select="@state"/></xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <xsl:variable name="cv">
              <xsl:for-each select="$grp">
                <xsl:sort select="number(@cvss)" data-type="number" order="descending"/>
                <xsl:if test="position() = 1"><xsl:value-of select="@cvss"/></xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <xsl:variable name="scanned" select="$grp[@svcsrc = 'scan']"/>
            <xsl:variable name="merged">
              <xsl:for-each select="$grp"><xsl:value-of select="@ips"/></xsl:for-each>
            </xsl:variable>
            <xsl:variable name="uips">
              <xsl:text> </xsl:text>
              <xsl:for-each select="str:tokenize(string($merged),' ')">
                <xsl:sort select="gvm:hx-oct(string(.),1)" data-type="number"/>
                <xsl:sort select="gvm:hx-oct(string(.),2)" data-type="number"/>
                <xsl:sort select="gvm:hx-oct(string(.),3)" data-type="number"/>
                <xsl:sort select="gvm:hx-oct(string(.),4)" data-type="number"/>
                <xsl:sort select="string(.)"/>
                <xsl:if test="not(string(.) = preceding-sibling::*)">
                  <xsl:value-of select="."/><xsl:text> </xsl:text>
                </xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <c num="{@num}" proto="{@proto}" gk="{@gk}" famn="{@famn}" fams="{@fams}"
               label="{concat(@num,'-',$hi)}" collapsed="1"
               blabel="{concat(@num,'-',$hi,'/',gvm:hx-upper(@proto))}"
               state="{$best}" srank="{gvm:hx-rank(string($best))}" cvss="{$cv}"
               nfind="{sum($grp/@nfind)}"
               nips="{count(str:tokenize(string($merged),' ')[not(string(.) = preceding-sibling::*)])}"
               ips="{$uips}">
              <xsl:attribute name="qodlow"><xsl:choose><xsl:when test="count($grp[@qodlow='1']) &gt; 0">1</xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose></xsl:attribute>
              <xsl:attribute name="members">
                <xsl:for-each select="$grp">
                  <xsl:sort select="number(@num)" data-type="number"/>
                  <xsl:if test="position() != 1"><xsl:text> </xsl:text></xsl:if>
                  <xsl:value-of select="@num"/>
                </xsl:for-each>
              </xsl:attribute>
              <!-- A family label ("netbios-rpc" over 135-139) is neither an
                   observation nor a registry entry for any single member, so it
                   gets its own source, marker and footnote instead of borrowing
                   the IANA dagger. @svcs is the short form the board prints. -->
              <xsl:attribute name="svcsrc">
                <xsl:choose>
                  <xsl:when test="count($scanned) &gt; 0">scan</xsl:when>
                  <xsl:when test="number($hexmap-iana-names) = 1">fam</xsl:when>
                  <xsl:otherwise>proto</xsl:otherwise>
                </xsl:choose>
              </xsl:attribute>
              <xsl:attribute name="svc">
                <xsl:choose>
                  <xsl:when test="count($scanned) &gt; 0">
                    <xsl:for-each select="$scanned">
                      <xsl:sort select="number(@num)" data-type="number"/>
                      <xsl:if test="position() = 1"><xsl:value-of select="@svc"/></xsl:if>
                    </xsl:for-each>
                  </xsl:when>
                  <xsl:when test="number($hexmap-iana-names) = 1"><xsl:value-of select="@famn"/></xsl:when>
                  <xsl:otherwise><xsl:value-of select="@proto"/></xsl:otherwise>
                </xsl:choose>
              </xsl:attribute>
              <xsl:attribute name="svcs">
                <xsl:choose>
                  <xsl:when test="count($scanned) &gt; 0">
                    <xsl:for-each select="$scanned">
                      <xsl:sort select="number(@num)" data-type="number"/>
                      <xsl:if test="position() = 1"><xsl:value-of select="@svc"/></xsl:if>
                    </xsl:for-each>
                  </xsl:when>
                  <xsl:when test="number($hexmap-iana-names) = 1"><xsl:value-of select="@fams"/></xsl:when>
                  <xsl:otherwise><xsl:value-of select="@proto"/></xsl:otherwise>
                </xsl:choose>
              </xsl:attribute>
              <!-- The addresses of each member port, so the table can stop
                   asserting that every member sits on the union of the family's
                   hosts (137 was on one host, 139 on two: printing the union
                   against the member list invents a pair the scan never saw). -->
              <xsl:for-each select="$grp">
                <xsl:sort select="number(@num)" data-type="number"/>
                <m num="{@num}" ips="{@ips}" nips="{@nips}"/>
              </xsl:for-each>
            </c>
          </xsl:when>
          <xsl:otherwise>
            <xsl:copy-of select="."/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- Cells of a scope, collapsed and ranked. @ord is the triage rank (severity
       descending, port ascending on a tie), which is what the board cut uses;
       the DRAW order is port ascending and is applied later. -->
  <xsl:template name="hx-ordered-cells">
    <xsl:param name="scope" select="'all'"/>
    <xsl:param name="hostip" select="''"/>
    <!-- Family collapsing is a GLOBAL-board device. On a per-host board it would
         assert exposure the scan never saw: a host running only 135 and 139 gets
         the family label "135-139", and the per-host boards carry no table and no
         "members:" line to walk that back, so the range reads as the whole of
         135..139 on that host. The global board can afford the label because its
         table opens the member ports and their addresses one by one. Per host the
         boards are small anyway, so the collapse buys no room — only the false
         claim. Rule 1 of the spec ("do not invent data") outranks its label rule. -->
    <xsl:param name="collapse" select="1"/>
    <xsl:variable name="raw-rtf">
      <xsl:call-template name="hx-raw-cells">
        <xsl:with-param name="scope" select="$scope"/>
        <xsl:with-param name="hostip" select="$hostip"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="col-rtf">
      <xsl:choose>
        <xsl:when test="number($collapse) = 1">
          <xsl:call-template name="hx-collapse">
            <xsl:with-param name="raw" select="exsl:node-set($raw-rtf)"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
          <xsl:copy-of select="exsl:node-set($raw-rtf)/c"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:for-each select="exsl:node-set($col-rtf)/c">
      <xsl:sort select="number(@srank)" data-type="number"/>
      <xsl:sort select="number(@num)" data-type="number"/>
      <xsl:sort select="@proto"/>
      <c ord="{position()}"><xsl:copy-of select="@*|node()"/></c>
    </xsl:for-each>
  </xsl:template>

  <!-- The kept cells, in DRAW order (port ascending, tcp before udp), plus the
       "+N" roll-up cell when the board budget was exceeded. -->
  <xsl:template name="hx-draw-cells">
    <xsl:param name="ord"/>
    <xsl:param name="max"/>
    <xsl:variable name="n" select="count($ord/c)"/>
    <!-- The budget can never exceed what the board can actually hold. -->
    <xsl:variable name="maxeff" select="gvm:hx-max2(1, gvm:hx-min2(number($max), $hx-cap))"/>
    <xsl:variable name="keep">
      <xsl:choose>
        <xsl:when test="$n &gt; number($maxeff)"><xsl:value-of select="number($maxeff) - 1"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$n"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:for-each select="$ord/c[number(@ord) &lt;= number($keep)]">
      <xsl:sort select="number(@num)" data-type="number"/>
      <xsl:sort select="@proto"/>
      <xsl:copy-of select="."/>
    </xsl:for-each>
    <xsl:if test="$n &gt; number($keep)">
      <c num="0" proto="" label="{concat('+', $n - number($keep))}" members="" famn=""
         blabel="{concat('+', $n - number($keep))}"
         svc="" svcs="" svcsrc="over" state="neutro" srank="6" cvss="-1" qodlow="0"
         nfind="0" nips="0" ips=" " over="1" gk="" ord="0"/>
    </xsl:if>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Hexmap: emission of the board                                     -->
  <!-- ================================================================= -->

  <!-- Characters a cell label may carry. \hexport hands its first argument both
       to the printed name and to \csname (the icon lookup), so anything that
       escape_text would turn into a control sequence, and anything that utf8x
       makes active, has to stay out of it. Upper case only: gvm:hx-upper has
       already run by the time this is applied. -->
  <xsl:variable name="hx-svcsafe">ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.+</xsl:variable>

  <!-- One cell of the honeycomb, emitted as \hexport{SERVICO}{PORTA/PROTO}{3a
       linha}{chave de severidade}. Nothing is drawn here any more: the hexagon,
       its colour, its icon and the clamping of every line belong to
       suricatoos-hex.sty. What stays is the DATA of the cell: which service
       name it carries (abbreviated by hx-abbrev), which label, which third line
       and which severity key. -->
  <xsl:template name="hx-hex">
    <xsl:param name="third"/>
    <!-- line 1: service, upper case, at most 8 characters. A collapsed family
         prints its short form (@svcs), the table keeps the integral name. -->
    <xsl:variable name="svcsrc0">
      <xsl:choose>
        <xsl:when test="string-length(@svcs) &gt; 0"><xsl:value-of select="@svcs"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="@svc"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="svcup">
      <xsl:choose>
        <xsl:when test="@svcsrc = 'over'"><xsl:value-of select="gvm:t('hx_others')"/></xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="hx-abbrev">
            <xsl:with-param name="s" select="substring(gvm:hx-upper(string($svcsrc0)), 1, 40)"/>
          </xsl:call-template>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <!-- The abbreviated name is what \hexport prints AND what it looks the icon
         up by: suricatoos-hex.sty builds a \csname out of the same argument
         (\icofor). A control sequence left behind by escape_text (\_, \&, \#)
         or an active UTF-8 byte would break that lookup, so the CELL label
         keeps only characters that mean the same thing raw and escaped. The
         integral service name is never lost: the port table below prints it in
         full, through hx-brk/escape_text. Fitting the line inside the hexagon
         is now the .sty's job (\adjustbox), not a font-size guess here. -->
    <xsl:variable name="svcsafe"
      select="translate(string($svcup), translate(string($svcup), $hx-svcsafe, ''), '')"/>
    <!-- Line 2 of the cell is @blabel: the port WITH its transport (or the
         collapsed range, or "+N"). Without the transport the same number on tcp
         and on udp draws two cells whose three lines are identical, and the
         per-host board has no table underneath to tell them apart.
         Line 3 is the mapped host (global board) or the finding tally
         (per-host board). -->
    <xsl:variable name="l3">
      <xsl:choose>
        <xsl:when test="@svcsrc = 'over'"></xsl:when>
        <xsl:when test="$third = 'find'">
          <xsl:value-of select="concat(@nfind, ' ', gvm:t('hx_findings_n'))"/>
        </xsl:when>
        <xsl:when test="number(@nips) = 1">
          <!-- The .sty scales this line down to fit between the slanted sides,
               so a long address no longer runs into the next cell — but past
               ~26 characters the scaling is what makes it unreadable instead.
               It is elided head and tail at that point; the integral address is
               in the port table either way. -->
          <xsl:variable name="ip1" select="normalize-space(@ips)"/>
          <xsl:choose>
            <xsl:when test="string-length($ip1) &lt;= 26"><xsl:value-of select="$ip1"/></xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="concat(substring($ip1,1,11),'...',substring($ip1,string-length($ip1) - 10))"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:when test="number(@nips) &gt; 1">
          <xsl:value-of select="concat(@nips, ' ', gvm:t('hx_ips_n'))"/>
        </xsl:when>
      </xsl:choose>
    </xsl:variable>
    <xsl:text>\hexport{</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($svcsafe)"/></xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@blabel)"/></xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($l3)"/></xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:value-of select="@state"/>
    <xsl:text>}
</xsl:text>
  </xsl:template>

  <!-- The port-exposure card: \hexcard{titulo}{meta}{tabuleiro + legenda}.
       The geometry of the honeycomb — cell footprint, pitch, how many fit in a
       row, how the rows interlock and centre — now belongs entirely to
       suricatoos-hex.sty. What is decided HERE is data: which cells go on the
       board and in which order (hx-draw-cells decided that already), the three
       lines each cell carries, and the six legend counts.
       $cells must already be in draw order. $title is plain text and is clamped
       and escaped below; $meta arrives as ready LaTeX, because its parts are
       clamped, escaped and joined with \textperiodcentered by the caller. -->
  <xsl:template name="hx-board">
    <xsl:param name="cells"/>
    <xsl:param name="title"/>
    <xsl:param name="meta"/>
    <xsl:param name="third" select="'ip'"/>

    <!-- The title of a per-host card is the host address, but the title of the
         global one is the task name, which the scanner does not bound: an 8000
         character name would run off the card and out of the page. It is cut,
         and what was cut is declared. The integral value is on the cover and in
         the source report. (The narrative's own cut is another one:
         $task-name-max, by page height.) -->
    <xsl:variable name="title-c">
      <xsl:value-of select="substring($title, 1, 60)"/>
      <xsl:if test="string-length($title) &gt; 60"><xsl:text>...</xsl:text></xsl:if>
    </xsl:variable>
    <xsl:text>\hexcard{</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="string($title-c)"/>
    </xsl:call-template>
    <xsl:text>}{</xsl:text>
    <xsl:value-of select="$meta"/>
    <xsl:text>}{%
\begin{hexboard}
</xsl:text>
    <xsl:for-each select="$cells">
      <xsl:call-template name="hx-hex">
        <xsl:with-param name="third" select="$third"/>
      </xsl:call-template>
    </xsl:for-each>
    <xsl:text>\end{hexboard}
\hexlegend{</xsl:text>
    <xsl:value-of select="count($cells[@state='critico'])"/><xsl:text>}{</xsl:text>
    <xsl:value-of select="count($cells[@state='alto'])"/><xsl:text>}{</xsl:text>
    <xsl:value-of select="count($cells[@state='medio'])"/><xsl:text>}{</xsl:text>
    <xsl:value-of select="count($cells[@state='baixo'])"/><xsl:text>}{</xsl:text>
    <xsl:value-of select="count($cells[@state='exposto'])"/><xsl:text>}{</xsl:text>
    <xsl:value-of select="count($cells[@state='neutro'])"/><xsl:text>}}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Hexmap: Port -> IP table and the two document sections            -->
  <!-- ================================================================= -->

  <!-- Escaped text with a break opportunity every 6 characters, for the two
       fixed-width columns of the table below. A p{} column does not break a run
       of letters, so a 16 character service name or an IPv6 in long form simply
       printed past the column and over its neighbour (35pt to 88pt of overhang,
       four Overfull boxes on one page). Runs short enough to fit are left whole
       so an IPv4 address never breaks in half. The hard cut at 96 characters
       bounds a field that is, after all, scanner-supplied text. -->
  <xsl:template name="hx-brk">
    <xsl:param name="s"/>
    <xsl:param name="min" select="8"/>
    <xsl:variable name="t" select="substring($s, 1, 96)"/>
    <xsl:choose>
      <xsl:when test="string-length($t) &lt;= number($min)">
        <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$t"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="$hx-ints/i[number(@v) * 6 &lt; string-length($t)]">
          <xsl:if test="number(@v) &gt; 0"><xsl:text>\hspace{0pt}</xsl:text></xsl:if>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="substring($t, number(@v) * 6 + 1, 6)"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
    <!-- O corte duro em 96 caracteres tambem diz QUANTO ficou de fora: um
         "..." sozinho e' truncagem sem quantidade, a mesma familia do aviso do
         bloco de deteccao. Na pratica este ramo quase nunca dispara (o maior
         IPv6 tem 39 caracteres), mas quando disparar o leitor ve o tamanho. -->
    <xsl:if test="string-length($s) &gt; 96">
      <xsl:text>\suriTruncMark{</xsl:text>
      <xsl:value-of select="string-length($s) - 96"/>
      <xsl:text>}</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- Every port in the scope, INCLUDING the ones the board could not hold:
       nothing disappears between the picture and the table.
       The table is now the `porttable' environment of suricatoos-blocks.sty:
       it owns the column widths, the repeating Mono header, the rules and the
       tinted alto/critico rows, so all that is emitted here is one \portrow per
       port carrying eight fields of data. -->
  <xsl:template name="hx-table">
    <xsl:param name="ord"/>
    <xsl:text>\begin{porttable}
</xsl:text>
    <xsl:for-each select="$ord/c">
      <xsl:sort select="number(@num)" data-type="number"/>
      <xsl:sort select="@proto"/>
      <!-- \portrow{porta}{marcas}{proto}{servico}{sev}{cvss}{hosts}{ips} -->
      <xsl:text>  \portrow{</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@label)"/></xsl:call-template>
      <!-- the mark beside the port NUMBER: low detection quality on the peak
           finding, i.e. the state in the ESTADO cell was downgraded a level -->
      <xsl:text>}{</xsl:text>
      <xsl:if test="@qodlow = '1'"><xsl:text>\ddag</xsl:text></xsl:if>
      <xsl:text>}{</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@proto)"/></xsl:call-template>
      <xsl:text>}{</xsl:text>
      <xsl:call-template name="hx-brk"><xsl:with-param name="s" select="string(@svc)"/></xsl:call-template>
      <!-- the mark beside the SERVICE name: where that name came from -->
      <xsl:if test="@svcsrc = 'iana'"><xsl:text>\portmark{\dag}</xsl:text></xsl:if>
      <xsl:if test="@svcsrc = 'fam'"><xsl:text>\portmark{*}</xsl:text></xsl:if>
      <xsl:text>}{</xsl:text>
      <xsl:value-of select="@state"/>
      <xsl:text>}{</xsl:text>
      <!-- No rated result at all leaves the score EMPTY, which is the design's
           own idiom for "no number" (\hostrow{...}{logsev}{}); printing 0.0
           there would assert a measurement the scan never made. -->
      <xsl:if test="number(@cvss) &gt;= 0">
        <xsl:value-of select="format-number(number(@cvss), '0.0')"/>
      </xsl:if>
      <xsl:text>}{</xsl:text>
      <xsl:value-of select="@nips"/>
      <xsl:text>}{</xsl:text>
      <!-- A collapsed family is ONE cell on the board but it is not one port
           here: printing the union of the family's hosts next to the member
           list asserts pairs the scan never saw (137 was on a single host while
           the family spanned two). When the members do not share the same
           addresses, each member gets its own line; when they do, the member
           ports are still named, so "135-139" is never read as the whole of
           135..139. -->
      <xsl:variable name="cips" select="normalize-space(@ips)"/>
      <xsl:choose>
        <xsl:when test="@collapsed = '1' and count(m[normalize-space(@ips) != $cips]) &gt; 0">
          <xsl:for-each select="m">
            <xsl:if test="position() != 1"><xsl:text>\newline </xsl:text></xsl:if>
            <xsl:text>{\bfseries </xsl:text>
            <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@num)"/></xsl:call-template>
            <xsl:text>:} </xsl:text>
            <xsl:call-template name="hx-ip-list"/>
          </xsl:for-each>
        </xsl:when>
        <xsl:otherwise>
          <xsl:if test="@collapsed = '1'">
            <xsl:value-of select="gvm:t('hx_members')"/>
            <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@members)"/></xsl:call-template>
            <xsl:text>\newline </xsl:text>
          </xsl:if>
          <xsl:call-template name="hx-ip-list"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>}
</xsl:text>
    </xsl:for-each>
    <xsl:text>\end{porttable}
</xsl:text>
  </xsl:template>

  <!-- The addresses of the context node's @ips, capped and breakable. -->
  <xsl:template name="hx-ip-list">
    <xsl:for-each select="str:tokenize(string(@ips), ' ')">
      <xsl:if test="position() &lt;= 40">
        <xsl:call-template name="hx-brk">
          <xsl:with-param name="s" select="string(.)"/>
          <xsl:with-param name="min" select="34"/>
        </xsl:call-template>
        <xsl:text> </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:if test="number(@nips) &gt; 40">
      <!-- The cell is already muted Mono; the aside only changes face, and the
           colour it used to force belongs to the design system now. -->
      <!-- \suriSans, NOT \rmfamily: the bundle ships no serif face, so \rmfamily
           falls back to Computer Modern and pdftex renders it as a Type 3
           bitmap. -->
      <xsl:text>{\suriSans\itshape </xsl:text>
      <xsl:value-of select="gvm:t('hx_ip_more_a')"/>
      <xsl:value-of select="number(@nips) - 40"/>
      <xsl:value-of select="gvm:t('hx_ip_more_b')"/>
      <xsl:text>}</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- (The column header of the port table used to be emitted here; the
       `porttable' environment of suricatoos-blocks.sty owns it now, and takes
       its words from \suriLblPort / \suriLblProto / \suriLblService /
       \suriLblState / \suriLblCvssMax / \suriLblHostsCol / \suriLblIps, which
       the preamble renews from gvm:t('hx_th_...'). -->

  <!-- How many ports the board stands for, and in how many cells. Family
       collapsing makes the two numbers differ (135, 137, 138 and 139 ride in one
       "135-139" cell), and printing only the cell count would understate the
       scan: the header would read "25 unique ports" for a scope where the
       scanner actually observed 32. When nothing collapsed, both numbers agree
       and the shorter phrase is used. -->
  <xsl:template name="hx-scope-phrase">
    <xsl:param name="cells"/>
    <xsl:param name="ports"/>
    <xsl:choose>
      <xsl:when test="number($ports) &gt; number($cells)">
        <xsl:value-of select="$ports"/>
        <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_ports_word')"/>
        <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_in_word')"/>
        <xsl:text> </xsl:text><xsl:value-of select="$cells"/>
        <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_cells_word')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$cells"/>
        <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_scope')"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Global port exposure map. -->
  <xsl:template name="hexmap-section">
    <xsl:variable name="ord" select="exsl:node-set($hx-ord-rtf)"/>
    <xsl:variable name="n" select="count($ord/c)"/>
    <!-- Distinct (transport, port) pairs behind the cells: a collapsed cell
         carries one <m> per member port, an uncollapsed one stands for itself. -->
    <xsl:variable name="nraw" select="count($ord/c[not(@collapsed = '1')]) + count($ord/c/m)"/>
    <!-- Section 2 of the report. The runner of the running header is set apart
         from the title because the title does not fit it (\suriSection would
         otherwise upper-case the whole "Mapa de Exposicao de Portas"). -->
    <xsl:text>\suriSection{2}{</xsl:text>
    <xsl:value-of select="gvm:t('sec_hexmap')"/>
    <xsl:text>}
\setsectionrunner{2}{</xsl:text>
    <xsl:value-of select="gvm:t('hx_runner')"/>
    <xsl:text>}
\suriPara{</xsl:text>
    <xsl:value-of select="gvm:t('hx_intro')"/>
    <xsl:text>}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$n = 0">
        <xsl:text>\blocknote{</xsl:text>
        <xsl:value-of select="gvm:t('hx_no_ports')"/>
        <xsl:text>}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="draw-rtf">
          <xsl:call-template name="hx-draw-cells">
            <xsl:with-param name="ord" select="$ord"/>
            <xsl:with-param name="max" select="$hexmap-max"/>
          </xsl:call-template>
        </xsl:variable>
        <!-- The card names the engagement and the scope: title = task name,
             meta = hosts, ports and the moment the scan closed. $meta is built
             as ready LaTeX, so each part is escaped on its own and the
             separator can be the design's own \textperiodcentered. -->
        <xsl:variable name="meta">
          <xsl:value-of select="count(gvm:report()/host)"/>
          <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_hosts_word')"/>
          <xsl:text> \textperiodcentered\ </xsl:text>
          <xsl:call-template name="hx-scope-phrase">
            <xsl:with-param name="cells" select="$n"/>
            <xsl:with-param name="ports" select="$nraw"/>
          </xsl:call-template>
          <xsl:text> \textperiodcentered\ </xsl:text>
          <xsl:call-template name="emit-date">
            <xsl:with-param name="date" select="gvm:report()/scan_end"/>
          </xsl:call-template>
        </xsl:variable>
        <!-- gvm:project() ja' cobre a exportacao "Anonymous XML" (cai para o
             alvo e depois para o comentario da tarefa). Se nem assim houver
             nome, o card ainda tem de ser rotulado: cai para o nome da secao,
             em vez de inventar um projeto. -->
        <xsl:variable name="board-title">
          <xsl:choose>
            <xsl:when test="string-length(normalize-space(gvm:project())) &gt; 0">
              <xsl:value-of select="normalize-space(gvm:project())"/>
            </xsl:when>
            <xsl:otherwise><xsl:value-of select="gvm:t('sec_hexmap')"/></xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:call-template name="hx-board">
          <xsl:with-param name="cells" select="exsl:node-set($draw-rtf)/c"/>
          <xsl:with-param name="title" select="string($board-title)"/>
          <xsl:with-param name="meta" select="string($meta)"/>
          <xsl:with-param name="third" select="'ip'"/>
        </xsl:call-template>
        <!-- Everything the board could not show, said out loud, under the card. -->
        <xsl:call-template name="hx-notes">
          <xsl:with-param name="omitted" select="$n - count(exsl:node-set($draw-rtf)/c[not(@over)])"/>
        </xsl:call-template>
        <!-- The table opens its own page: it is the second half of the section
             and the model gives it one. -->
        <xsl:text>\clearpage
\blocklabel{\suriLblPortsMapped}
</xsl:text>
        <xsl:call-template name="hx-table">
          <xsl:with-param name="ord" select="$ord"/>
        </xsl:call-template>
        <!-- The footnotes of the table belong under the table, not under the
             board: they explain marks that only the table carries. -->
        <xsl:call-template name="hx-portnotes">
          <xsl:with-param name="iana" select="count($ord/c[@svcsrc='iana'])"/>
          <xsl:with-param name="fam" select="count($ord/c[@svcsrc='fam'])"/>
          <xsl:with-param name="qodlow" select="count($ord/c[@qodlow='1'])"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- What the BOARD could not show, under the card: one \blocknote per fact.
       The marks of the table (\dag \ddag *) are not here — they explain the
       table and hang under it, in \portnotes. -->
  <xsl:template name="hx-notes">
    <xsl:param name="omitted"/>
    <xsl:variable name="total" select="count(gvm:report()/results/result)"/>
    <xsl:variable name="rc-full" select="normalize-space(gvm:report()/result_count/text())"/>
    <xsl:variable name="partial"
      select="string-length($rc-full) &gt; 0 and floor(number($rc-full)) = number($rc-full) and number($rc-full) &gt; $total"/>
    <xsl:if test="$omitted &gt; 0">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="$omitted"/><xsl:value-of select="gvm:t('hx_omitted')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
    <xsl:if test="number($hx-genhosts) &gt; 0">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="$hx-genhosts"/><xsl:value-of select="gvm:t('hx_hostlevel_note')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
    <xsl:if test="number($hx-malformed) &gt; 0">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="$hx-malformed"/><xsl:value-of select="gvm:t('hx_malformed_note')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
    <xsl:if test="number($hx-noip) &gt; 0">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="$hx-noip"/><xsl:value-of select="gvm:t('hx_noip_note')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
    <xsl:if test="$partial">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="gvm:t('hx_partial')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- The footnotes of the port table: what each mark beside a service name or
       a port number means. Emitted only for the marks the table actually
       carries, so a report with no IANA-named port shows no dagger note. -->
  <xsl:template name="hx-portnotes">
    <xsl:param name="iana"/>
    <xsl:param name="fam" select="0"/>
    <xsl:param name="qodlow"/>
    <xsl:if test="$iana &gt; 0 or $fam &gt; 0 or $qodlow &gt; 0">
      <xsl:text>\portnotes{%
</xsl:text>
      <xsl:if test="$fam &gt; 0">
        <xsl:text>  \portnote{*}{</xsl:text>
        <xsl:value-of select="normalize-space(gvm:t('hx_fam_note'))"/>
        <xsl:text>}
</xsl:text>
      </xsl:if>
      <xsl:if test="$iana &gt; 0">
        <xsl:text>  \portnote{\dag}{</xsl:text>
        <xsl:value-of select="normalize-space(gvm:t('hx_iana_note'))"/>
        <xsl:text>}
</xsl:text>
      </xsl:if>
      <xsl:if test="$qodlow &gt; 0">
        <xsl:text>  \portnote{\ddag}{</xsl:text>
        <xsl:value-of select="normalize-space(gvm:t('hx_low_qod'))"/>
        <xsl:text>}
</xsl:text>
      </xsl:if>
      <xsl:text>}
</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- Appendix: one board per host, drawn only for reports small enough for it
       to be readable. When it is skipped the reader is told so, and why. -->
  <xsl:template name="hexmap-hosts-section">
    <xsl:variable name="nhosts" select="count(gvm:report()/host)"/>
    <!-- A host record with no address cannot have a board: it has no identity
         to put in the title and nothing to match its ports by. It is left out
         and counted, never given the whole scope's ports by default. -->
    <xsl:variable name="hosts" select="gvm:report()/host[string-length(normalize-space(ip)) &gt; 0]"/>
    <xsl:variable name="noiph" select="$nhosts - count($hosts)"/>
    <xsl:variable name="nglobal" select="count(exsl:node-set($hx-ord-rtf)/c)"/>
    <xsl:text>\suriSection{6}{</xsl:text>
    <xsl:value-of select="gvm:t('sec_hexmap_host')"/>
    <xsl:text>}
\setsectionrunner{6}{</xsl:text>
    <xsl:value-of select="gvm:t('hx_host_runner')"/>
    <xsl:text>}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$nhosts &gt; number($hexmap-per-host-max)">
        <xsl:text>\suriPara{</xsl:text>
        <xsl:value-of select="gvm:t('hx_host_skipped_a')"/>
        <xsl:value-of select="$nhosts"/>
        <xsl:value-of select="gvm:t('hx_host_skipped_b')"/>
        <xsl:value-of select="$hexmap-per-host-max"/>
        <xsl:value-of select="gvm:t('hx_host_skipped_c')"/>
        <xsl:text>}
</xsl:text>
      </xsl:when>
      <xsl:when test="count($hosts) = 0 or $nglobal = 0">
        <xsl:text>\blocknote{</xsl:text><xsl:value-of select="gvm:t('hx_host_none')"/><xsl:text>}
</xsl:text>
        <xsl:call-template name="hx-noip-hosts-note"><xsl:with-param name="n" select="$noiph"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\suriPara{</xsl:text>
        <xsl:value-of select="gvm:t('hx_host_intro')"/>
        <xsl:text>}
</xsl:text>
        <xsl:call-template name="hx-noip-hosts-note"><xsl:with-param name="n" select="$noiph"/></xsl:call-template>
        <xsl:for-each select="$hosts">
          <xsl:sort select="gvm:hx-oct(string(ip),1)" data-type="number"/>
          <xsl:sort select="gvm:hx-oct(string(ip),2)" data-type="number"/>
          <xsl:sort select="gvm:hx-oct(string(ip),3)" data-type="number"/>
          <xsl:sort select="gvm:hx-oct(string(ip),4)" data-type="number"/>
          <xsl:sort select="string(ip)"/>
          <xsl:variable name="ip" select="substring-before(concat(normalize-space(ip),' '),' ')"/>
          <xsl:variable name="hostname" select="string(detail[name='hostname']/value)"/>
          <xsl:variable name="os">
            <xsl:choose>
              <xsl:when test="string-length(detail[name='best_os_txt']/value) &gt; 0"><xsl:value-of select="detail[name='best_os_txt']/value"/></xsl:when>
              <xsl:otherwise><xsl:value-of select="detail[name='best_os_cpe']/value"/></xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:variable name="hord-rtf">
            <xsl:call-template name="hx-ordered-cells">
              <xsl:with-param name="scope" select="'host'"/>
              <xsl:with-param name="hostip" select="$ip"/>
              <xsl:with-param name="collapse" select="0"/>
            </xsl:call-template>
          </xsl:variable>
          <xsl:variable name="hord" select="exsl:node-set($hord-rtf)"/>
          <xsl:choose>
            <xsl:when test="count($hord/c) = 0">
              <!-- No card at all would drop the host from the appendix, so the
                   address is still named, in the note that explains why it has
                   no board. -->
              <xsl:text>\blocknote{\dat{</xsl:text>
              <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($ip)"/></xsl:call-template>
              <xsl:text>} \textperiodcentered\ </xsl:text>
              <xsl:value-of select="gvm:t('hp_no_ports')"/>
              <xsl:text>}
</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="hdraw-rtf">
                <xsl:call-template name="hx-draw-cells">
                  <xsl:with-param name="ord" select="$hord"/>
                  <xsl:with-param name="max" select="$hexmap-per-host-cells"/>
                </xsl:call-template>
              </xsl:variable>
              <!-- The card has no OS badge of its own, so what the host banner
                   used to show (hostname, operating system) rides in the meta
                   line. Both are scanner text: escaped, and cut so the pair
                   cannot outgrow the head of the card. -->
              <xsl:variable name="hmeta">
                <xsl:if test="string-length(normalize-space($hostname)) &gt; 0">
                  <xsl:call-template name="escape_text">
                    <xsl:with-param name="string" select="substring(normalize-space($hostname), 1, 48)"/>
                  </xsl:call-template>
                  <xsl:text> \textperiodcentered\ </xsl:text>
                </xsl:if>
                <xsl:if test="string-length(normalize-space($os)) &gt; 0">
                  <xsl:call-template name="escape_text">
                    <xsl:with-param name="string" select="substring(normalize-space($os), 1, 40)"/>
                  </xsl:call-template>
                  <xsl:text> \textperiodcentered\ </xsl:text>
                </xsl:if>
                <xsl:call-template name="hx-scope-phrase">
                  <xsl:with-param name="cells" select="count($hord/c)"/>
                  <xsl:with-param name="ports"
                    select="count($hord/c[not(@collapsed = '1')]) + count($hord/c/m)"/>
                </xsl:call-template>
              </xsl:variable>
              <xsl:call-template name="hx-board">
                <xsl:with-param name="cells" select="exsl:node-set($hdraw-rtf)/c"/>
                <xsl:with-param name="title" select="$ip"/>
                <xsl:with-param name="meta" select="string($hmeta)"/>
                <xsl:with-param name="third" select="'find'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="hx-noip-hosts-note">
    <xsl:param name="n"/>
    <xsl:if test="number($n) &gt; 0">
      <xsl:text>\blocknote{</xsl:text>
      <xsl:value-of select="$n"/><xsl:value-of select="gvm:t('hx_host_noip')"/>
      <xsl:text>}
</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- The global scope's cells, aggregated once and shared by the board and the
       Port -> IP table. -->
  <xsl:variable name="hx-ord-rtf">
    <xsl:call-template name="hx-ordered-cells">
      <xsl:with-param name="scope" select="'all'"/>
    </xsl:call-template>
  </xsl:variable>

  <!-- Contracapa (pg-10). O colofao deixou de ser um bloco no fim da ultima
       pagina de conteudo e virou PAGINA: \suriBackCover abre com \clearpage,
       pinta a folha de navy, desenha a marca, o logotipo, o paragrafo
       institucional, o aviso de confidencialidade e a linha de rodape, e fecha
       devolvendo o papel claro. Como na capa, aqui so' entram DADOS. -->
  <xsl:template name="branded-footer">
    <!-- Mesmo raciocinio do corte da capa, outra medida: a linha de rodape da
         contracapa e' UMA linha centrada de Mono 8.5 com tracking 220 (~7px por
         caractere), e ela ja carrega o rotulo PROJETO, a data por extenso e
         "PAGINA n / N" — cerca de 48 caracteres fixos dentro dos ~95 que cabem
         entre as margens. Sobram ~47 para o nome; 40 deixa folga para a marca de
         corte. Nao reflui: e' no de TikZ, uma linha so'. -->
    <xsl:variable name="backcover-name-max" select="40"/>
    <xsl:variable name="task_escaped">
      <xsl:call-template name="escape_break">
        <xsl:with-param name="string" select="gvm:project()"/>
        <xsl:with-param name="max" select="$backcover-name-max"/>
      </xsl:call-template>
    </xsl:variable>
    <!-- Chaves em TODO valor pelo mesmo motivo da capa: a data localizada e o
         nome de tarefa carregam virgula, e o aviso de confidencialidade em
         ingles termina em ponto depois de um travessao. -->
    <xsl:text>\suriBackCover{
  projeto={</xsl:text>
    <xsl:value-of select="$task_escaped"/>
    <xsl:text>},
  data={</xsl:text>
    <xsl:call-template name="emit-today"/>
    <xsl:text>},
  texto={</xsl:text>
    <xsl:value-of select="gvm:t('colophon_1')"/>
    <xsl:text>},
  aviso={</xsl:text>
    <xsl:value-of select="gvm:t('colophon_2')"/>
    <xsl:text>}
}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Document assembly                                                 -->
  <!-- ================================================================= -->

  <!-- O esqueleto do documento, na ordem do modelo: capa, resumo, mapa de
       portas, hosts, sumario, detalhados, apendice, contracapa.
       \clearpage e nao \newpage. As duas terminam a pagina, mas \newpage deixa
       material flutuante pendurado para a proxima, e o design abre CADA secao
       com \suriSection, que e' desenhado para ser a primeira coisa da folha (o
       ar acima dele e' descartado no topo da pagina, como qualquer \addvspace).
       Com \newpage uma longtable que ainda estivesse escoando podia empurrar o
       titulo para baixo e a secao abriria fora da grade.
       \pagestyle{suricatoos} nao e' emitido aqui: suricatoos-page.sty ja o
       instala como padrao do documento, e a capa e a contracapa trocam para
       `suribare' sozinhas, dentro de \suriCover / \suriBackCover.
       Numeracao das secoes, para quem emite \suriSection: 1 resumo executivo,
       2 mapa de exposicao de portas, 3 hosts e portas abertas, 4 sumario de
       achados, 5 achados detalhados, 6 apendice (exposicao por host). -->
  <xsl:template name="real-report">
    <xsl:call-template name="header"/>
    <xsl:call-template name="newline"/>
    <xsl:text>\begin{document}
</xsl:text>
    <!-- \suriCover fecha com \clearpage: a pagina 2 ja abre no papel claro. -->
    <xsl:call-template name="cover-page"/>
    <xsl:call-template name="executive-summary"/>
    <xsl:text>\clearpage
</xsl:text>
    <xsl:call-template name="hexmap-section"/>
    <xsl:text>\clearpage
</xsl:text>
    <xsl:call-template name="hosts-ports"/>
    <xsl:text>\clearpage
</xsl:text>
    <xsl:call-template name="findings-summary"/>
    <xsl:text>\clearpage
</xsl:text>
    <xsl:call-template name="detailed-findings"/>
    <xsl:text>\clearpage
</xsl:text>
    <xsl:call-template name="hexmap-hosts-section"/>
    <!-- \suriBackCover abre com \clearpage por conta propria. -->
    <xsl:call-template name="branded-footer"/>
    <xsl:text>\end{document}
</xsl:text>
  </xsl:template>

  <xsl:template match="report">
    <xsl:choose>
      <xsl:when test="@extension='xml'">
        <xsl:apply-templates select="report"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="real-report"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates/>
  </xsl:template>

</xsl:stylesheet>
