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
    <!-- Consolidated update card -->
    <s k="grp_title" en="Outstanding update" pt="Atualização pendente" es="Actualización pendiente"/>
    <s k="grp_badge" en="CONSOLIDATED" pt="CONSOLIDADO" es="CONSOLIDADO"/>
    <s k="grp_intro_a" en="The scanner reported " pt="O scanner reportou " es="El escáner reportó "/>
    <s k="grp_intro_b" en=" separate advisories for this product. They accumulate one per vendor release and are resolved by a SINGLE action: updating the product to a supported version. They are listed together below instead of as one finding each." pt=" advisories separados para este produto. Eles se acumulam um por versão do fornecedor e são resolvidos por uma ÚNICA ação: atualizar o produto para uma versão suportada. São listados juntos abaixo em vez de um achado para cada." es=" advisories separados para este producto. Se acumulan uno por versión del proveedor y se resuelven con una ÚNICA acción: actualizar el producto a una versión soportada. Se listan juntos abajo en lugar de un hallazgo para cada uno."/>
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
    <s k="of_which_lowconf" en=" of low confidence (manual validation required)" pt=" de baixa confiança (validação manual necessária)" es=" de baja confianza (validación manual necesaria)"/>
    <!-- Risk words (uppercase, used in the risk badge and narrative) -->
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
    <!-- Findings summary -->
    <s k="sec_findings_summary" en="Findings Summary" pt="Sumário de Achados" es="Resumen de Hallazgos"/>
    <s k="fs_intro" en="The table below lists every unique vulnerability identified during the assessment, ordered by severity. Each vulnerability is analysed in detail in the following section." pt="A tabela abaixo lista cada vulnerabilidade única identificada durante a avaliação, ordenada por severidade. Cada vulnerabilidade é analisada em detalhe na seção seguinte." es="La tabla siguiente enumera cada vulnerabilidad única identificada durante la evaluación, ordenada por severidad. Cada vulnerabilidad se analiza en detalle en la sección siguiente."/>
    <s k="th_num" en="\#" pt="\#" es="\#"/>
    <s k="th_vuln" en="Vulnerability" pt="Vulnerabilidade" es="Vulnerabilidad"/>
    <s k="th_inst" en="Inst." pt="Inst." es="Inst."/>
    <s k="th_severity" en="Severity" pt="Severidade" es="Severidad"/>
    <!-- Hosts &amp; ports -->
    <s k="sec_hosts_ports" en="Hosts and Open Ports" pt="Hosts e Portas Abertas" es="Hosts y Puertos Abiertos"/>
    <s k="hp_intro" en="The table below summarises the network services discovered on each assessed host, together with the number of findings and the highest severity observed on each port." pt="A tabela abaixo resume os serviços de rede descobertos em cada host avaliado, junto com o número de achados e a maior severidade observada em cada porta." es="La tabla siguiente resume los servicios de red descubiertos en cada host evaluado, junto con el número de hallazgos y la mayor severidad observada en cada puerto."/>
    <s k="th_port" en="Port" pt="Porta" es="Puerto"/>
    <s k="th_proto" en="Proto" pt="Proto" es="Proto"/>
    <s k="th_findings" en="Findings" pt="Achados" es="Hallazgos"/>
    <s k="th_max_sev" en="Highest severity" pt="Maior severidade" es="Mayor severidad"/>
    <s k="hp_general" en="General" pt="Geral" es="General"/>
    <s k="hp_hostlevel" en="host-level" pt="nível de host" es="nivel de host"/>
    <s k="hp_no_ports" en="No network services with findings were recorded on this host." pt="Nenhum serviço de rede com achados foi registrado neste host." es="No se registraron servicios de red con hallazgos en este host."/>
    <s k="hp_os_unknown" en="Operating system not identified" pt="Sistema operacional não identificado" es="Sistema operativo no identificado"/>
    <s k="hp_open_ports" en="open port(s) with findings" pt="porta(s) com achados" es="puerto(s) con hallazgos"/>
    <!-- Detailed findings -->
    <s k="sec_detailed" en="Detailed Findings" pt="Achados Detalhados" es="Hallazgos Detallados"/>
    <s k="lbl_instances" en="instance(s)" pt="instância(s)" es="instancia(s)"/>
    <s k="lbl_cvss_vector" en="CVSS Vector" pt="Vetor CVSS" es="Vector CVSS"/>
    <s k="f_summary" en="Summary" pt="Resumo" es="Resumen"/>
    <s k="f_impact" en="Impact" pt="Impacto" es="Impacto"/>
    <s k="f_insight" en="Insight" pt="Detalhes Técnicos" es="Detalles Técnicos"/>
    <s k="f_affected_sw" en="Affected Software / OS" pt="Software / SO Afetado" es="Software / SO Afectado"/>
    <s k="f_affected_sys" en="Affected Systems" pt="Sistemas Afetados" es="Sistemas Afectados"/>
    <s k="f_detection" en="Detection Result" pt="Resultado da Detecção" es="Resultado de la Detección"/>
    <s k="f_solution" en="Solution / Remediation" pt="Solução / Remediação" es="Solución / Remediación"/>
    <s k="f_references" en="References" pt="Referências" es="Referencias"/>
    <s k="output_truncated" en="[output truncated]" pt="[saída truncada]" es="[salida truncada]"/>
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

  <!-- Full escape, including backslash. -->
  <xsl:template name="escape_text">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="contains($string, '\')">
        <xsl:for-each select="str:tokenize($string, '\')">
          <xsl:if test="position() != 1">
            <xsl:text>\textbackslash{}</xsl:text>
          </xsl:if>
          <xsl:call-template name="escape_special_chars">
            <xsl:with-param name="string" select="."/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="escape_special_chars">
          <xsl:with-param name="string" select="$string"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Emit a multi-line string, escaping it and converting newlines to forced
       line breaks. NON-RECURSIVE (single str:replace over the escaped text) so it
       scales to very long fields (e.g. multi-thousand-line detection results)
       without hitting xsltMaxDepth — a recursive per-line version blew the 3000
       template-depth limit on real reports. A trailing \mbox{} makes a final
       \newline safe ("no line here to end") and is invisible otherwise. -->
  <xsl:template name="escape_lines">
    <xsl:param name="string"/>
    <xsl:variable name="escaped">
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="$string"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:value-of select="str:replace(string($escaped), '&#10;', '\newline ')"/>
    <xsl:text>\mbox{}</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Severity helpers                                                  -->
  <!-- ================================================================= -->

  <!-- Map a threat level to a brand colour name. -->
  <xsl:template name="threat-color">
    <xsl:param name="threat"/>
    <xsl:choose>
      <xsl:when test="$threat='Critical'">gvm_critical</xsl:when>
      <xsl:when test="$threat='High'">gvm_hole</xsl:when>
      <xsl:when test="$threat='Medium'">gvm_warning</xsl:when>
      <xsl:when test="$threat='Low'">gvm_note</xsl:when>
      <xsl:otherwise>gvm_log</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

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
      <xsl:otherwise>Log</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Localised severity word for a class token (Critical/High/Medium/Low/Log). -->
  <func:function name="gvm:sev-word">
    <xsl:param name="class"/>
    <func:result select="gvm:t(concat('sev_', translate($class, 'CHMLO', 'chmlo')))"/>
  </func:function>

  <!-- A small filled severity pill: localised class word + CVSS score, derived
       from the numeric severity. -->
  <xsl:template name="severity-pill">
    <xsl:param name="severity"/>
    <xsl:variable name="class">
      <xsl:call-template name="sev-class">
        <xsl:with-param name="severity" select="$severity"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="c">
      <xsl:call-template name="threat-color">
        <xsl:with-param name="threat" select="$class"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{</xsl:text>
    <xsl:value-of select="$c"/>
    <xsl:text>}{\color{white}\scriptsize\bfseries~</xsl:text>
    <xsl:value-of select="gvm:sev-word($class)"/>
    <xsl:if test="$class != 'Log'">
      <xsl:text> \textbullet\ CVSS </xsl:text>
      <xsl:value-of select="$severity"/>
    </xsl:if>
    <xsl:text>~}}</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- LaTeX preamble                                                    -->
  <!-- ================================================================= -->

  <xsl:template name="header">
    <xsl:text>\documentclass[11pt]{article}

\usepackage[utf8x]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{textcomp}
\usepackage{helvet}
\renewcommand{\familydefault}{\sfdefault}

\usepackage{geometry}
\usepackage{calc}
\usepackage{array}
\usepackage{tabularx}
\usepackage{longtable}
\usepackage{colortbl}
\usepackage{booktabs}
\usepackage{enumitem}
\usepackage{titlesec}
\usepackage{url}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{tikz}
\usepackage{pgfplots}
\pgfplotsset{compat=1.16}
\usepackage[most,breakable]{tcolorbox}
\usepackage{fancyhdr}
\usepackage{lastpage}

\DeclareUnicodeCharacter{135}{{\textascii ?}}
\DeclareUnicodeCharacter{129}{{\textascii ?}}
\DeclareUnicodeCharacter{128}{{\textascii ?}}

% ---- Suricatoos brand palette ----
\definecolor{surNavy}{rgb}{0.031,0.055,0.090}
\definecolor{surNavyTwo}{rgb}{0.047,0.086,0.133}
\definecolor{surSurface}{rgb}{0.075,0.125,0.180}
\definecolor{surIndigo}{rgb}{0.357,0.486,0.980}
\definecolor{surIndigoLt}{rgb}{0.490,0.592,1.0}
\definecolor{surBorder}{rgb}{0.133,0.204,0.290}
\definecolor{surBorderLt}{rgb}{0.780,0.820,0.870}
\definecolor{surInk}{rgb}{0.059,0.094,0.145}
\definecolor{surMuted}{rgb}{0.361,0.420,0.478}
\definecolor{surCloud}{rgb}{0.937,0.953,0.965}
\definecolor{surMist}{rgb}{0.960,0.972,0.985}

% ---- Severity colours ----
\definecolor{linkblue}{rgb}{0.357,0.486,0.980}
\definecolor{gvm_critical}{rgb}{0.647,0.043,0.098}
\definecolor{gvm_hole}{rgb}{0.847,0.325,0.098}
\definecolor{gvm_warning}{rgb}{0.929,0.667,0.153}
\definecolor{gvm_note}{rgb}{0.204,0.451,0.792}
\definecolor{gvm_log}{rgb}{0.400,0.451,0.510}
\definecolor{gvm_report}{rgb}{0.808,0.851,1.0}

% ---- Page geometry (A4, room for branded header / footer) ----
\geometry{a4paper,top=30mm,bottom=24mm,left=22mm,right=22mm,headheight=13mm,headsep=6mm,footskip=13mm}
\setlength{\parskip}{\smallskipamount}
\setlength{\parindent}{0pt}
% Absorb the occasional overfull line in justified narrative paragraphs
% (long unbreakable tokens like CVE ids / package names) instead of letting
% them poke into the margin.
\setlength{\emergencystretch}{3em}

% ---- Branded running header / footer ----
\fancypagestyle{surfancy}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{0.7pt}%
  \renewcommand{\footrulewidth}{0.4pt}%
  \renewcommand{\headrule}{{\color{surIndigo}\hrule height \headrulewidth}}%
  \renewcommand{\footrule}{{\color{surBorder}\hrule height \footrulewidth}}%
  \fancyhead[L]{\raisebox{-1.8mm}{\includegraphics[height=5mm]{suricatoos-mark-navy}}\hspace{2mm}{\bfseries\color{surInk}Suricatoos}}%
  \fancyhead[R]{{\footnotesize\color{surMuted}</xsl:text>
    <xsl:value-of select="gvm:t('running_header')"/>
    <xsl:text>}}%
  \fancyfoot[L]{{\footnotesize\color{surMuted}\bfseries </xsl:text>
    <xsl:value-of select="gvm:t('confidential_caps')"/>
    <xsl:text>}}%
  \fancyfoot[C]{{\footnotesize\color{surMuted}Suricatoos Security Platform}}%
  \fancyfoot[R]{{\footnotesize\color{surMuted}</xsl:text>
    <xsl:value-of select="gvm:t('page_word')"/>
    <xsl:text> \thepage\ </xsl:text>
    <xsl:value-of select="gvm:t('of_word')"/>
    <xsl:text> \pageref{LastPage}}}%
}

% ---- Brand-coloured section headings ----
\titleformat{\section}{\Large\bfseries\color{surInk}}{\thesection}{0.7em}{}[{\color{surIndigo}\titlerule[1.1pt]}]
\titleformat{\subsection}{\large\bfseries\color{surIndigo}}{\thesubsection}{0.6em}{}
\titleformat{\subsubsection}{\normalsize\bfseries\color{surInk}}{\thesubsubsection}{0.5em}{}
\titlespacing*{\section}{0pt}{3.4ex plus 1ex minus .2ex}{1.8ex plus .2ex}
\titlespacing*{\subsection}{0pt}{2.6ex plus .8ex}{1.2ex}

% ---- Finding-card field label ----
\newcommand{\fieldlabel}[1]{\smallskip\par{\color{surIndigo}\footnotesize\bfseries\MakeUppercase{#1}}\par\nopagebreak\vspace{0.4mm}}

% must come last
\usepackage{hyperref}
\hypersetup{unicode=true,colorlinks=true,linkcolor=surIndigo,urlcolor=surIndigo,citecolor=surIndigo,bookmarks=true,bookmarksopen=true,pdftitle={</xsl:text>
    <xsl:value-of select="gvm:t('pdftitle')"/>
    <xsl:text>},pdfauthor={Suricatoos Security Platform}}
\usepackage[all]{hypcap}
\pagenumbering{arabic}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Cover page                                                        -->
  <!-- ================================================================= -->

  <xsl:template name="cover-page">
    <xsl:variable name="task_escaped">
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="gvm:report()/task/name"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:text>\begin{titlepage}
\thispagestyle{empty}
\begin{tikzpicture}[remember picture,overlay]
  \fill[surNavy] (current page.south west) rectangle (current page.north east);
  \begin{scope}
    \clip (current page.south west) rectangle (current page.north east);
    \draw[surIndigo,line width=1pt,draw opacity=0.10]   ([xshift=8mm,yshift=20mm]current page.south east) circle (42mm);
    \draw[surIndigoLt,line width=1pt,draw opacity=0.13] ([xshift=8mm,yshift=20mm]current page.south east) circle (60mm);
    \draw[surIndigo,line width=1pt,draw opacity=0.08]   ([xshift=8mm,yshift=20mm]current page.south east) circle (84mm);
  \end{scope}
  \fill[surIndigo] (current page.north west) rectangle ([yshift=-3mm]current page.north east);
  \node[anchor=north west,xshift=22mm,yshift=-32mm] at (current page.north west)
    {\includegraphics[width=70mm]{suricatoos-wordmark-white}};
  \node[anchor=north west,xshift=22mm,yshift=-78mm,text=surIndigoLt] at (current page.north west)
    {\sffamily\bfseries\large </xsl:text>
    <xsl:value-of select="gvm:t('cover_kicker')"/>
    <xsl:text>};
  \node[anchor=north west,xshift=22mm,yshift=-83mm] at (current page.north west)
    {\color{surIndigo}\rule{40mm}{1.3pt}};
  \node[anchor=north west,xshift=21mm,yshift=-89mm,text=white,text width=172mm] at (current page.north west)
    {\sffamily\bfseries\fontsize{31}{36}\selectfont </xsl:text>
    <xsl:value-of select="gvm:t('cover_title')"/>
    <xsl:text>};
  \node[anchor=north west,xshift=22mm,yshift=-124mm,text=surCloud,text width=164mm] at (current page.north west)
    {\sffamily\large </xsl:text>
    <xsl:value-of select="gvm:t('cover_prepared')"/>
    <xsl:text>};
  \node[anchor=south west,xshift=22mm,yshift=40mm,fill=surSurface,rounded corners=2mm,
        inner sep=5mm,draw=surBorder,line width=0.5pt] at (current page.south west)
    {\sffamily\renewcommand{\arraystretch}{1.55}%
     \begin{tabular}{@{}m{34mm}@{\hspace{4mm}}m{102mm}@{}}
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_engagement')"/><xsl:text>}&amp;{\color{white}</xsl:text>
       <xsl:value-of select="$task_escaped"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_hosts_assessed')"/><xsl:text>}&amp;{\color{white}</xsl:text>
       <xsl:value-of select="count(gvm:report()/host)"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_scan_started')"/><xsl:text>}&amp;{\color{white}</xsl:text>
       <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_start"/></xsl:call-template>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_scan_completed')"/><xsl:text>}&amp;{\color{white}</xsl:text>
       <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_end"/></xsl:call-template>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_report_date')"/><xsl:text>}&amp;{\color{white}</xsl:text><xsl:call-template name="emit-today"/><xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_classification')"/><xsl:text>}&amp;{\color{white}</xsl:text><xsl:value-of select="gvm:t('val_confidential')"/><xsl:text>}\\
     \end{tabular}};
  \fill[surIndigo] (current page.south west) rectangle ([yshift=14mm]current page.south east);
  \node[anchor=west,xshift=22mm,text=white] at ([yshift=7mm]current page.south west)
    {\sffamily\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('confidential_caps')"/><xsl:text>};
  \node[anchor=east,xshift=-22mm,text=white] at ([yshift=7mm]current page.south east)
    {\sffamily\footnotesize Suricatoos Security Platform};
\end{tikzpicture}
\end{titlepage}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Executive summary                                                 -->
  <!-- ================================================================= -->

  <!-- A single metric tile inside the metrics tikzpicture. -->
  <xsl:template name="metric-tile">
    <xsl:param name="xl"/>
    <xsl:param name="xr"/>
    <xsl:param name="value"/>
    <xsl:param name="label"/>
    <xsl:variable name="xc" select="format-number(($xl + $xr) div 2, '0.###')"/>
    <xsl:text>\begin{scope}
\clip[rounded corners=1.8mm] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,26);
\fill[surMist] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,26);
\fill[surIndigo] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="format-number($xl + 1.4, '0.###')"/><xsl:text>,26);
\end{scope}
\node[anchor=center,text=surInk] at (</xsl:text><xsl:value-of select="$xc"/><xsl:text>,16.5) {\fontsize{21}{21}\selectfont\bfseries </xsl:text><xsl:value-of select="$value"/><xsl:text>};
\node[anchor=center,text=surMuted,text width=</xsl:text><xsl:value-of select="format-number($xr - $xl - 3, '0.###')"/><xsl:text>mm,align=center] at (</xsl:text><xsl:value-of select="$xc"/><xsl:text>,6.5) {\scriptsize\bfseries </xsl:text><xsl:value-of select="$label"/><xsl:text>};
\draw[surBorderLt,rounded corners=1.8mm,line width=0.3pt] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,26);
</xsl:text>
  </xsl:template>

  <xsl:template name="executive-summary">
    <xsl:variable name="crit" select="count(gvm:report()/results/result[number(severity) &gt;= 9.0])"/>
    <xsl:variable name="high" select="count(gvm:report()/results/result[number(severity) &gt;= 7.0 and number(severity) &lt; 9.0])"/>
    <xsl:variable name="med"  select="count(gvm:report()/results/result[number(severity) &gt;= 4.0 and number(severity) &lt; 7.0])"/>
    <xsl:variable name="low"  select="count(gvm:report()/results/result[number(severity) &gt;= 0.1 and number(severity) &lt; 4.0])"/>
    <xsl:variable name="logc" select="count(gvm:report()/results/result[not(number(severity) &gt;= 0.1)])"/>
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
        <xsl:when test="$crit &gt; 0"><xsl:value-of select="gvm:t('risk_critical')"/></xsl:when>
        <xsl:when test="$high &gt; 0"><xsl:value-of select="gvm:t('risk_high')"/></xsl:when>
        <xsl:when test="$med &gt; 0"><xsl:value-of select="gvm:t('risk_medium')"/></xsl:when>
        <xsl:when test="$low &gt; 0"><xsl:value-of select="gvm:t('risk_low')"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="gvm:t('risk_info')"/></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="riskColor">
      <xsl:choose>
        <xsl:when test="$crit &gt; 0">gvm_critical</xsl:when>
        <xsl:when test="$high &gt; 0">gvm_hole</xsl:when>
        <xsl:when test="$med &gt; 0">gvm_warning</xsl:when>
        <xsl:when test="$low &gt; 0">gvm_note</xsl:when>
        <xsl:otherwise>gvm_log</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_exec')"/><xsl:text>}
</xsl:text>

    <!-- Narrative (per-language, with counts interpolated) -->
    <xsl:variable name="taskname">
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="gvm:report()/task/name"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="hicrit" select="$crit + $high"/>
    <xsl:choose>
      <xsl:when test="$L='pt'">
        <xsl:text>Este relatório apresenta os resultados de uma avaliação de vulnerabilidades realizada pela Plataforma de Segurança Suricatoos. O projeto ``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>'' avaliou </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) e produziu </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> resultado(s). Este relatório descreve </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> vulnerabilidade(s) única(s). Destas, \textbf{</xsl:text>
        <xsl:value-of select="$hicrit"/><xsl:text>} achado(s) são de severidade Alta ou Crítica e exigem remediação imediata</xsl:text>
        <xsl:if test="$lowconf-hi &gt; 0">
          <xsl:text> --- </xsl:text><xsl:value-of select="$lowconf-hi"/><xsl:value-of select="gvm:t('of_which_lowconf')"/>
        </xsl:if>
        <xsl:text>. A exposição geral ao risco do ambiente avaliado é classificada como \textbf{</xsl:text>
        <xsl:value-of select="$riskWord"/><xsl:text>}.\par
</xsl:text>
      </xsl:when>
      <xsl:when test="$L='es'">
        <xsl:text>Este informe presenta los resultados de una evaluación de vulnerabilidades realizada por la Plataforma de Seguridad Suricatoos. El proyecto ``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>'' evaluó </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) y produjo </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> resultado(s). Este informe describe </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> vulnerabilidad(es) única(s). De estas, \textbf{</xsl:text>
        <xsl:value-of select="$hicrit"/><xsl:text>} hallazgo(s) son de severidad Alta o Crítica y requieren remediación inmediata</xsl:text>
        <xsl:if test="$lowconf-hi &gt; 0">
          <xsl:text> --- </xsl:text><xsl:value-of select="$lowconf-hi"/><xsl:value-of select="gvm:t('of_which_lowconf')"/>
        </xsl:if>
        <xsl:text>. La exposición general al riesgo del entorno evaluado se clasifica como \textbf{</xsl:text>
        <xsl:value-of select="$riskWord"/><xsl:text>}.\par
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This report presents the findings of a vulnerability assessment performed by the Suricatoos Security Platform. The engagement ``</xsl:text>
        <xsl:value-of select="$taskname"/>
        <xsl:text>'' assessed </xsl:text><xsl:value-of select="$hosts"/><xsl:text> host(s) and produced </xsl:text>
        <xsl:value-of select="$total-full"/><xsl:text> result(s). This report describes </xsl:text>
        <xsl:value-of select="$uniq"/><xsl:text> unique vulnerabilit</xsl:text>
        <xsl:choose><xsl:when test="$uniq = 1">y</xsl:when><xsl:otherwise>ies</xsl:otherwise></xsl:choose>
        <xsl:text>. Of these, \textbf{</xsl:text><xsl:value-of select="$hicrit"/>
        <xsl:text>} finding(s) are of High or Critical severity and warrant prompt remediation</xsl:text>
        <xsl:if test="$lowconf-hi &gt; 0">
          <xsl:text> --- </xsl:text><xsl:value-of select="$lowconf-hi"/><xsl:value-of select="gvm:t('of_which_lowconf')"/>
        </xsl:if>
        <xsl:text>. The overall risk exposure of the assessed environment is rated \textbf{</xsl:text>
        <xsl:value-of select="$riskWord"/><xsl:text>}.\par
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>\vspace{4mm}
</xsl:text>

    <!-- Risk badge + key metrics row -->
    <xsl:text>\begin{center}
\begin{tikzpicture}[x=1mm,y=1mm]
\begin{scope}
\clip[rounded corners=2mm] (0,0) rectangle (66,26);
\fill[</xsl:text><xsl:value-of select="$riskColor"/><xsl:text>] (0,0) rectangle (66,26);
\end{scope}
\node[anchor=north west,text=white] at (5,22.5) {\scriptsize\bfseries </xsl:text><xsl:value-of select="gvm:t('overall_risk')"/><xsl:text>};
\node[anchor=west,text=white] at (5,10) {\fontsize{20}{20}\selectfont\bfseries </xsl:text><xsl:value-of select="$riskWord"/><xsl:text>};
</xsl:text>
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="69"/>
      <xsl:with-param name="xr" select="99"/>
      <xsl:with-param name="value" select="$hosts"/>
      <xsl:with-param name="label" select="gvm:t('m_hosts')"/>
    </xsl:call-template>
    <!-- Total the SCAN produced, not the number of rows this export carries. -->
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="102"/>
      <xsl:with-param name="xr" select="132"/>
      <xsl:with-param name="value" select="$total-full"/>
      <xsl:with-param name="label" select="gvm:t('m_total')"/>
    </xsl:call-template>
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="135"/>
      <xsl:with-param name="xr" select="165"/>
      <xsl:with-param name="value" select="$uniq"/>
      <xsl:with-param name="label" select="gvm:t('m_uniq')"/>
    </xsl:call-template>
    <xsl:text>\end{tikzpicture}
\end{center}
\vspace{5mm}
</xsl:text>

    <!-- Sampling disclosure. Only rendered when the export really is partial,
         so a complete report carries no needless caveat. -->
    <xsl:if test="$truncated">
      <xsl:text>\begin{tcolorbox}[colback=surMist,colframe=gvm_warning,boxrule=0.9pt,arc=1.4mm,left=3mm,right=3mm,top=2mm,bottom=2mm]
{\bfseries\color{surInk}</xsl:text><xsl:value-of select="gvm:t('sample_hdr')"/><xsl:text>}\par\vspace{1mm}
{\small\color{surInk}</xsl:text>
      <xsl:value-of select="gvm:t('sample_a')"/>
      <xsl:text>\textbf{</xsl:text><xsl:value-of select="$total"/><xsl:text>}</xsl:text>
      <xsl:value-of select="gvm:t('sample_b')"/>
      <xsl:text>\textbf{</xsl:text><xsl:value-of select="$total-full"/><xsl:text>}</xsl:text>
      <xsl:value-of select="gvm:t('sample_c')"/>
      <xsl:text>}
\end{tcolorbox}
\vspace{4mm}
</xsl:text>
    </xsl:if>

    <!-- Severity breakdown chart (pgfplots). The symbolic y coords stay as the
         language-neutral class tokens; the DISPLAYED tick labels are localised
         via yticklabels (same order as ytick, bottom-to-top). -->
    <xsl:text>{\color{surInk}\bfseries </xsl:text><xsl:value-of select="gvm:t('findings_by_sev')"/><xsl:text>}\par\vspace{2mm}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$crit + $high + $med + $low = 0">
        <xsl:text>{\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('no_findings')"/><xsl:text>}\par
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\begin{center}
\begin{tikzpicture}
\begin{axis}[
    xbar,
    width=0.82\textwidth, height=54mm,
    bar width=5mm,
    xmin=0,
    enlarge x limits={upper,value=0.18},
    enlarge y limits={abs=10mm},
    axis lines=left,
    x axis line style={draw=surBorderLt},
    y axis line style={draw=none},
    tick style={draw=none},
    xmajorgrids, grid style={surCloud, line width=0.4pt},
    symbolic y coords={Low,Medium,High,Critical},
    ytick={Low,Medium,High,Critical},
    yticklabels={</xsl:text><xsl:value-of select="gvm:t('sev_low')"/><xsl:text>,</xsl:text><xsl:value-of select="gvm:t('sev_medium')"/><xsl:text>,</xsl:text><xsl:value-of select="gvm:t('sev_high')"/><xsl:text>,</xsl:text><xsl:value-of select="gvm:t('sev_critical')"/><xsl:text>},
    yticklabel style={font=\small\bfseries, color=surInk},
    xticklabel style={font=\footnotesize, color=surMuted},
    nodes near coords, nodes near coords style={font=\small\bfseries, color=surInk},
    every axis plot/.append style={bar shift=0pt, draw=none},
]
\addplot[fill=gvm_critical] coordinates {(</xsl:text><xsl:value-of select="$crit"/><xsl:text>,Critical)};
\addplot[fill=gvm_hole] coordinates {(</xsl:text><xsl:value-of select="$high"/><xsl:text>,High)};
\addplot[fill=gvm_warning] coordinates {(</xsl:text><xsl:value-of select="$med"/><xsl:text>,Medium)};
\addplot[fill=gvm_note] coordinates {(</xsl:text><xsl:value-of select="$low"/><xsl:text>,Low)};
\end{axis}
\end{tikzpicture}
\end{center}
\vspace{2mm}
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>

    <!-- Scan timeline -->
    <xsl:text>\vspace{2mm}
{\color{surInk}\bfseries </xsl:text><xsl:value-of select="gvm:t('timeline')"/><xsl:text>}\par\vspace{1.5mm}
\renewcommand{\arraystretch}{1.4}
\begin{tabular}{@{}l@{\hspace{8mm}}l@{}}
{\color{surMuted}\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_scan_started')"/><xsl:text>} &amp; {\color{surInk}</xsl:text>
    <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_start"/></xsl:call-template>
    <xsl:text>} \\
{\color{surMuted}\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('lbl_scan_completed')"/><xsl:text>} &amp; {\color{surInk}</xsl:text>
    <xsl:call-template name="emit-date"><xsl:with-param name="date" select="gvm:report()/scan_end"/></xsl:call-template>
    <xsl:text>} \\
{\color{surMuted}\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('t_generated')"/><xsl:text>} &amp; {\color{surInk}</xsl:text><xsl:call-template name="emit-today"/><xsl:text>} \\
\end{tabular}\par
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Hosts and open ports (per-target service inventory)               -->
  <!-- ================================================================= -->

  <!-- Highest-severity pill among the results on a given host:port, or an em
       dash when the port has no rated finding. -->
  <xsl:template name="port-max-sev">
    <xsl:param name="ip"/>
    <xsl:param name="pstr"/>
    <xsl:variable name="rs" select="gvm:report()/results/result[host/text()=$ip][port=$pstr]"/>
    <xsl:choose>
      <xsl:when test="count($rs) = 0">{\color{surMuted}\scriptsize ---}</xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="$rs">
          <xsl:sort select="severity" data-type="number" order="descending"/>
          <xsl:if test="position() = 1">
            <xsl:call-template name="severity-pill">
              <xsl:with-param name="severity" select="severity"/>
            </xsl:call-template>
          </xsl:if>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- One port row: PORT | PROTO | FINDINGS | HIGHEST SEVERITY. -->
  <xsl:template name="port-row">
    <xsl:param name="ip"/>
    <xsl:param name="pstr"/>
    <xsl:param name="zebra"/>
    <xsl:variable name="isgeneral" select="starts-with($pstr, 'general')"/>
    <xsl:variable name="portnum" select="substring-before($pstr, '/')"/>
    <xsl:variable name="proto" select="substring-after($pstr, '/')"/>
    <xsl:variable name="fcount" select="count(gvm:report()/results/result[host/text()=$ip][port=$pstr])"/>
    <xsl:if test="$zebra">
      <xsl:text>\rowcolor{surMist}</xsl:text>
    </xsl:if>
    <!-- Port column -->
    <xsl:choose>
      <xsl:when test="$isgeneral">
        <xsl:text>{\itshape\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('hp_general')"/><xsl:text>}</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>{\ttfamily </xsl:text>
        <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$portnum"/></xsl:call-template>
        <xsl:text>}</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> &amp; </xsl:text>
    <!-- Proto column -->
    <xsl:choose>
      <xsl:when test="$isgeneral">
        <xsl:text>{\itshape\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('hp_hostlevel')"/><xsl:text>}</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>{\ttfamily </xsl:text>
        <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$proto"/></xsl:call-template>
        <xsl:text>}</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> &amp; </xsl:text>
    <xsl:value-of select="$fcount"/>
    <xsl:text> &amp; </xsl:text>
    <xsl:call-template name="port-max-sev">
      <xsl:with-param name="ip" select="$ip"/>
      <xsl:with-param name="pstr" select="$pstr"/>
    </xsl:call-template>
    <xsl:text> \\[0.4mm]
</xsl:text>
  </xsl:template>

  <!-- Full-width host banner: IP (white mono) + hostname (cloud) + OS (indigo
       italic, right-aligned). A real \colorbox spanning \linewidth, so the fill
       always covers the whole strip regardless of content length — unlike a
       \rowcolor'd \multicolumn, whose panel width tracked only the first column
       and left the hostname/OS floating on white. -->
  <xsl:template name="host-banner">
    <xsl:param name="ip"/>
    <xsl:param name="hostname"/>
    <xsl:param name="os"/>
    <xsl:param name="portcount"/>
    <xsl:text>\noindent\colorbox{surSurface}{\makebox[\dimexpr\linewidth-2\fboxsep\relax][l]{%
\color{white}\bfseries\ttfamily </xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$ip"/></xsl:call-template>
    <xsl:text>\normalfont</xsl:text>
    <xsl:if test="string-length($hostname) &gt; 0">
      <xsl:text>\hspace{4mm}{\color{surCloud}</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$hostname"/></xsl:call-template>
      <xsl:text>}</xsl:text>
    </xsl:if>
    <xsl:text>\hfill{\color{surIndigoLt}\footnotesize\itshape </xsl:text>
    <xsl:choose>
      <xsl:when test="string-length($os) &gt; 0">
        <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$os"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="gvm:t('hp_os_unknown')"/></xsl:otherwise>
    </xsl:choose>
    <xsl:text>}</xsl:text>
    <xsl:if test="$portcount &gt; 0">
      <xsl:text>{\color{surIndigoLt}\footnotesize\hspace{4mm}</xsl:text>
      <xsl:value-of select="$portcount"/><xsl:text> </xsl:text><xsl:value-of select="gvm:t('hp_open_ports')"/>
      <xsl:text>}</xsl:text>
    </xsl:if>
    <xsl:text>}}\par\nopagebreak\vspace{0.6mm}
</xsl:text>
  </xsl:template>

  <xsl:template name="hosts-ports">
    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_hosts_ports')"/><xsl:text>}
</xsl:text>
    <xsl:value-of select="gvm:t('hp_intro')"/>
    <xsl:text>\par
\vspace{3mm}
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
      <!-- Count of real (non host-level) ports, for the banner tally. -->
      <xsl:variable name="realportcount">
        <xsl:choose>
          <xsl:when test="count($fromports) &gt; 0"><xsl:value-of select="count($fromports[not(starts-with(text(), 'general'))])"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="count(gvm:report()/results/result[host/text()=$ip][not(starts-with(port, 'general'))][generate-id() = generate-id(key('by-host-port', concat(host/text(), '|', port))[1])])"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      <xsl:text>\vspace{2mm}
</xsl:text>
      <xsl:call-template name="host-banner">
        <xsl:with-param name="ip" select="$ip"/>
        <xsl:with-param name="hostname" select="$hostname"/>
        <xsl:with-param name="os" select="$os"/>
        <xsl:with-param name="portcount" select="$realportcount"/>
      </xsl:call-template>

      <!-- Per-host port table (own repeating header so it survives page breaks). -->
      <!-- m{} columns vertically centre each cell so the plain port/proto text
           shares a baseline with the taller severity pill (a \colorbox). -->
      <xsl:text>\renewcommand{\arraystretch}{1.2}
\begin{longtable}{@{}m{22mm} m{22mm} m{22mm} m{40mm}@{}}
\rowcolor{surInk}
\textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('th_port')"/><xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('th_proto')"/><xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('th_findings')"/><xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('th_max_sev')"/><xsl:text>} \\
\endhead
</xsl:text>
      <xsl:choose>
        <!-- Primary source: the report's <ports> inventory for this host. -->
        <xsl:when test="count($fromports) &gt; 0">
          <!-- Real ports first, numeric ascending... -->
          <xsl:for-each select="$fromports[not(starts-with(text(), 'general'))]">
            <xsl:sort select="number(substring-before(text(), '/'))" data-type="number" order="ascending"/>
            <xsl:call-template name="port-row">
              <xsl:with-param name="ip" select="$ip"/>
              <xsl:with-param name="pstr" select="text()"/>
              <xsl:with-param name="zebra" select="position() mod 2 = 0"/>
            </xsl:call-template>
          </xsl:for-each>
          <!-- ...then host-level (general/*) pseudo-ports. -->
          <xsl:for-each select="$fromports[starts-with(text(), 'general')]">
            <xsl:sort select="text()"/>
            <xsl:call-template name="port-row">
              <xsl:with-param name="ip" select="$ip"/>
              <xsl:with-param name="pstr" select="text()"/>
              <xsl:with-param name="zebra" select="false()"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:when>
        <!-- Fallback: derive distinct ports from this host's results. -->
        <xsl:when test="count(gvm:report()/results/result[host/text()=$ip]) &gt; 0">
          <xsl:for-each select="gvm:report()/results/result[host/text()=$ip][generate-id() = generate-id(key('by-host-port', concat(host/text(), '|', port))[1])]">
            <xsl:sort select="starts-with(port, 'general')"/>
            <xsl:sort select="number(substring-before(port, '/'))" data-type="number" order="ascending"/>
            <xsl:call-template name="port-row">
              <xsl:with-param name="ip" select="$ip"/>
              <xsl:with-param name="pstr" select="port"/>
              <xsl:with-param name="zebra" select="position() mod 2 = 0"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:when>
        <!-- No ports and no results: clean host. -->
        <xsl:otherwise>
          <xsl:text>\multicolumn{4}{@{}l@{}}{\color{surMuted}\footnotesize </xsl:text>
          <xsl:value-of select="gvm:t('hp_no_ports')"/>
          <xsl:text>} \\[0.2mm]
</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>\end{longtable}
</xsl:text>
    </xsl:for-each>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Findings summary table (grouped by NVT)                           -->
  <!-- ================================================================= -->

  <xsl:template name="findings-summary">
    <xsl:variable name="n-low" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])][qod/value][number(qod/value) &lt; number($qod-min)])"/>
    <xsl:variable name="n-ok" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])][not(qod/value) or number(qod/value) &gt;= number($qod-min)])"/>
    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_findings_summary')"/><xsl:text>}
</xsl:text>
    <xsl:value-of select="gvm:t('fs_intro')"/>
    <xsl:text>\par
\vspace{3mm}
</xsl:text>

    <!-- Confirmed findings. Sub-headed only when low-confidence items exist, so
         a clean report keeps the original single-table layout. -->
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\subsection*{</xsl:text><xsl:value-of select="gvm:t('sub_confirmed')"/><xsl:text>}
{\color{surMuted}\small </xsl:text><xsl:value-of select="gvm:t('conf_intro')"/>
      <xsl:value-of select="$qod-min"/><xsl:text>\%.}\par\vspace{2mm}
</xsl:text>
    </xsl:if>
    <xsl:choose>
      <xsl:when test="$n-ok = 0">
        <xsl:text>{\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('none_confirmed')"/><xsl:text>}\par\vspace{3mm}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="findings-summary-table">
          <xsl:with-param name="low" select="0"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>

    <!-- Indicators to validate: what the scanner is not confident about. -->
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\vspace{4mm}
\subsection*{</xsl:text><xsl:value-of select="gvm:t('sub_indicators')"/><xsl:text>}
{\color{surMuted}\small </xsl:text><xsl:value-of select="gvm:t('ind_intro')"/>
      <xsl:value-of select="$qod-min"/><xsl:text>\%</xsl:text><xsl:value-of select="gvm:t('ind_intro2')"/>
      <xsl:text>}\par\vspace{2mm}
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
    <xsl:text>\renewcommand{\arraystretch}{1.35}
\begin{longtable}{@{}p{9mm} p{92mm} p{15mm} p{35mm}@{}}
\rowcolor{surInk}
\textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_num')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_vuln')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_inst')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_severity')"/><xsl:text>} \\
\endfirsthead
\rowcolor{surInk}
\textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_num')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_vuln')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_inst')"/><xsl:text>} &amp; \textcolor{white}{\bfseries </xsl:text><xsl:value-of select="gvm:t('th_severity')"/><xsl:text>} \\
\endhead
</xsl:text>
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
    <xsl:if test="$low = 0">
      <xsl:for-each select="$groups">
        <xsl:sort select="severity" data-type="number" order="descending"/>
        <xsl:if test="position() mod 2 = 0"><xsl:text>\rowcolor{surMist}</xsl:text></xsl:if>
        <xsl:text>{\bfseries </xsl:text><xsl:value-of select="position()"/><xsl:text>} &amp; </xsl:text>
        <xsl:text>\hyperlink{</xsl:text><xsl:value-of select="concat('grp-', translate(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')), ' ./:,()', '-------'))"/><xsl:text>}{\color{surInk}</xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' '))"/>
        </xsl:call-template>
        <xsl:text> --- </xsl:text><xsl:value-of select="gvm:t('grp_title')"/>
        <xsl:text>} &amp; </xsl:text>
        <xsl:value-of select="count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])])"/>
        <xsl:text> &amp; </xsl:text>
        <xsl:call-template name="severity-pill">
          <xsl:with-param name="severity" select="severity"/>
        </xsl:call-template>
        <xsl:text> \\[0.6mm]
</xsl:text>
      </xsl:for-each>
    </xsl:if>
    <xsl:for-each select="$rows[($low = 1 and qod/value and number(qod/value) &lt; number($qod-min)) or ($low = 0 and (not(qod/value) or number(qod/value) &gt;= number($qod-min)))][not((nvt/solution/@type='VendorFix' and count(key('by-updgrp',concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')))[generate-id() = generate-id(key('by-updgrp-nvt',concat(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')),'||',nvt/@oid))[1])]) &gt;= $group-min))]">
      <xsl:sort select="severity" data-type="number" order="descending"/>
      <xsl:variable name="oid" select="nvt/@oid"/>
      <xsl:variable name="anchor" select="concat('fnd-', translate($oid, '.', '-'))"/>
      <xsl:variable name="instances" select="count(key('by-nvt', $oid))"/>
      <xsl:variable name="cvss">
        <xsl:choose>
          <xsl:when test="string-length(nvt/cvss_base) &gt; 0"><xsl:value-of select="nvt/cvss_base"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="severity"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <!-- alternate zebra shading -->
      <xsl:if test="position() mod 2 = 0">
        <xsl:text>\rowcolor{surMist}</xsl:text>
      </xsl:if>
      <xsl:text>{\bfseries </xsl:text><xsl:value-of select="position() + number($ngroups)"/><xsl:text>} &amp; </xsl:text>
      <xsl:text>\hyperlink{</xsl:text><xsl:value-of select="$anchor"/><xsl:text>}{\color{surInk}</xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="nvt/name"/>
      </xsl:call-template>
      <xsl:text>} &amp; </xsl:text>
      <xsl:value-of select="$instances"/>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="severity-pill">
        <xsl:with-param name="severity" select="severity"/>
      </xsl:call-template>
      <xsl:text> \\[0.6mm]
</xsl:text>
    </xsl:for-each>
    <xsl:text>\end{longtable}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Detailed findings (grouped by NVT)                                -->
  <!-- ================================================================= -->

  <!-- A labelled body field with escaped multi-line text; skipped if empty. -->
  <xsl:template name="finding-field">
    <xsl:param name="label"/>
    <xsl:param name="value"/>
    <xsl:if test="string-length(normalize-space($value)) &gt; 0">
      <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="$label"/><xsl:text>}</xsl:text>
      <xsl:call-template name="escape_lines">
        <xsl:with-param name="string" select="$value"/>
      </xsl:call-template>
      <xsl:text>\par
</xsl:text>
    </xsl:if>
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
    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_detailed')"/><xsl:text>}
</xsl:text>
    <!-- Confirmed first; the low-confidence block is only introduced when there
         is something in it, so a clean report reads exactly as before. -->
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\subsection*{</xsl:text><xsl:value-of select="gvm:t('sub_confirmed')"/><xsl:text>}
</xsl:text>
    </xsl:if>
    <xsl:call-template name="consolidated-update-cards"/>
    <xsl:call-template name="finding-cards">
      <xsl:with-param name="low" select="0"/>
    </xsl:call-template>
    <xsl:if test="$n-low &gt; 0">
      <xsl:text>\subsection*{</xsl:text><xsl:value-of select="gvm:t('sub_indicators')"/><xsl:text>}
{\color{surMuted}\small </xsl:text><xsl:value-of select="gvm:t('ind_intro')"/>
      <xsl:value-of select="$qod-min"/><xsl:text>\%</xsl:text><xsl:value-of select="gvm:t('ind_intro2')"/>
      <xsl:text>}\par\vspace{3mm}
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
      <xsl:variable name="sevclass">
        <xsl:call-template name="sev-class">
          <xsl:with-param name="severity" select="severity"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:variable name="tcolor">
        <xsl:call-template name="threat-color">
          <xsl:with-param name="threat" select="$sevclass"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:variable name="cvss">
        <xsl:choose>
          <xsl:when test="string-length(nvt/cvss_base) &gt; 0"><xsl:value-of select="nvt/cvss_base"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="severity"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="name_escaped">
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="nvt/name"/>
        </xsl:call-template>
      </xsl:variable>

      <!-- Card -->
      <xsl:text>\hypertarget{</xsl:text><xsl:value-of select="$anchor"/><xsl:text>}{}%
\begin{tcolorbox}[breakable, enhanced, sharp corners=uphill, arc=1.2mm,
  colback=white, colframe=surBorderLt, boxrule=0.5pt,
  left=3.5mm, right=3.5mm, top=3mm, bottom=3mm,
  toptitle=1.6mm, bottomtitle=1.6mm, lefttitle=3.5mm,
  colbacktitle=</xsl:text><xsl:value-of select="$tcolor"/><xsl:text>, coltitle=white,
  fonttitle=\bfseries,
  title={\#</xsl:text><xsl:value-of select="position()"/><xsl:text>\hspace{2mm} </xsl:text>
      <xsl:value-of select="$name_escaped"/>
      <xsl:text>}]
</xsl:text>

      <!-- Severity + QoD + CVSS vector line -->
      <xsl:text>\noindent </xsl:text>
      <xsl:call-template name="severity-pill">
        <xsl:with-param name="severity" select="severity"/>
      </xsl:call-template>
      <xsl:text>\hspace{2mm}</xsl:text>
      <xsl:if test="string-length(qod/value) &gt; 0">
        <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{surCloud}{\color{surInk}\scriptsize\bfseries~QoD </xsl:text>
        <xsl:value-of select="qod/value"/>
        <xsl:text>\%~}}\hspace{2mm}</xsl:text>
      </xsl:if>
      <!-- Loud badge so a low-quality detection is never read as a fact, no
           matter how high its CVSS looks next to it. -->
      <xsl:if test="qod/value and number(qod/value) &lt; number($qod-min)">
        <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{gvm_warning}{\color{white}\scriptsize\bfseries~</xsl:text>
        <xsl:value-of select="gvm:t('lbl_lowconf')"/>
        <xsl:text>~}}\hspace{2mm}</xsl:text>
      </xsl:if>
      <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{surCloud}{\color{surInk}\scriptsize\bfseries~</xsl:text>
      <xsl:value-of select="$instances"/>
      <xsl:text> </xsl:text><xsl:value-of select="gvm:t('lbl_instances')"/><xsl:text>~}}</xsl:text>

      <!-- CVE badges -->
      <xsl:if test="count(nvt/refs/ref[@type='cve']) &gt; 0">
        <xsl:for-each select="nvt/refs/ref[@type='cve']">
          <xsl:text>\hspace{2mm}{\setlength{\fboxsep}{2.2pt}\colorbox{gvm_report}{\color{surInk}\scriptsize\bfseries~</xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="@id"/>
          </xsl:call-template>
          <xsl:text>~}}</xsl:text>
        </xsl:for-each>
      </xsl:if>
      <xsl:text>\par
</xsl:text>

      <!-- CVSS vector (from tags) -->
      <xsl:variable name="vector" select="gvm:get-nvt-tag('cvss_base_vector')"/>
      <xsl:if test="string-length($vector) &gt; 0">
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('lbl_cvss_vector')"/><xsl:text>}{\ttfamily\footnotesize </xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="$vector"/>
        </xsl:call-template>
        <xsl:text>}\par
</xsl:text>
      </xsl:if>

      <!-- Summary / Impact / Insight -->
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_summary')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('summary')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_impact')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('impact')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_insight')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('insight')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label" select="gvm:t('f_affected_sw')"/>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('affected')"/>
      </xsl:call-template>

      <!-- Affected systems (UNIQUE host:port instances of this NVT, capped) -->
      <xsl:variable name="uniqhosts" select="key('by-nvt', $oid)[generate-id() = generate-id(key('by-nvt-hostport', concat($oid, '|', host/text(), '|', port))[1])]"/>
      <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('f_affected_sys')"/><xsl:text>}</xsl:text>
      <xsl:for-each select="$uniqhosts">
        <xsl:sort select="host/text()"/>
        <xsl:if test="position() &lt;= 40">
          <xsl:text>{\ttfamily\footnotesize </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="host/text()"/>
          </xsl:call-template>
          <xsl:if test="string-length(port) &gt; 0">
            <xsl:text>:</xsl:text>
            <xsl:call-template name="escape_text">
              <xsl:with-param name="string" select="port"/>
            </xsl:call-template>
          </xsl:if>
          <xsl:text>}</xsl:text>
          <xsl:if test="position() != last() and position() &lt; 40">
            <xsl:text>,\quad </xsl:text>
          </xsl:if>
        </xsl:if>
      </xsl:for-each>
      <xsl:if test="count($uniqhosts) &gt; 40">
        <xsl:text>{\itshape\footnotesize\quad (+</xsl:text>
        <xsl:value-of select="count($uniqhosts) - 40"/>
        <xsl:text> </xsl:text><xsl:value-of select="gvm:t('more_word')"/><xsl:text>)}</xsl:text>
      </xsl:if>
      <xsl:text>\par
</xsl:text>

      <!-- Detection result (representative) -->
      <xsl:if test="string-length(normalize-space(description)) &gt; 0">
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('f_detection')"/><xsl:text>}%
\begin{tcolorbox}[enhanced, colback=surMist, colframe=surBorderLt, boxrule=0.4pt,
  arc=0.8mm, left=2.5mm, right=2.5mm, top=1.6mm, bottom=1.6mm, before skip=1mm, after skip=1mm]
{\ttfamily\footnotesize\color{surInk} </xsl:text>
        <xsl:call-template name="escape_lines">
          <xsl:with-param name="string" select="substring(description, 1, 1500)"/>
        </xsl:call-template>
        <xsl:if test="string-length(description) &gt; 1500">
          <xsl:text> \newline \textmd{\itshape </xsl:text><xsl:value-of select="gvm:t('output_truncated')"/><xsl:text>}</xsl:text>
        </xsl:if>
        <xsl:text>}
\end{tcolorbox}
</xsl:text>
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
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('f_solution')"/><xsl:text>}%
\begin{tcolorbox}[enhanced, colback=gvm_note!8!white, colframe=gvm_note!55!white, boxrule=0.5pt,
  arc=0.8mm, left=2.5mm, right=2.5mm, top=1.6mm, bottom=1.6mm, before skip=1mm, after skip=1mm]
{\color{surInk}</xsl:text>
        <xsl:if test="string-length(nvt/solution/@type) &gt; 0">
          <xsl:text>{\bfseries </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="gvm:solution-type-label(nvt/solution/@type)"/>
          </xsl:call-template>
          <xsl:text>:\ }</xsl:text>
        </xsl:if>
        <xsl:call-template name="escape_lines">
          <xsl:with-param name="string" select="$solution"/>
        </xsl:call-template>
        <xsl:text>}
\end{tcolorbox}
</xsl:text>
      </xsl:if>

      <!-- References (url refs) -->
      <xsl:if test="count(nvt/refs/ref[@type='url']) &gt; 0">
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('f_references')"/><xsl:text>}%
\begin{itemize}[leftmargin=5mm, itemsep=0.2mm, topsep=0.4mm]
</xsl:text>
        <xsl:for-each select="nvt/refs/ref[@type='url']">
          <xsl:text>\item {\footnotesize\url{</xsl:text>
          <xsl:value-of select="@id"/>
          <xsl:text>}}
</xsl:text>
        </xsl:for-each>
        <xsl:text>\end{itemize}
</xsl:text>
      </xsl:if>

      <xsl:text>\end{tcolorbox}
\vspace{3mm}

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
        <xsl:variable name="sevclass">
          <xsl:call-template name="sev-class">
            <xsl:with-param name="severity" select="$maxsev"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:variable name="tcolor">
          <xsl:call-template name="threat-color">
            <xsl:with-param name="threat" select="$sevclass"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:variable name="gname">
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="$g"/>
          </xsl:call-template>
        </xsl:variable>

        <xsl:text>\hypertarget{</xsl:text><xsl:value-of select="concat('grp-', translate(concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')), ' ./:,()', '-------'))"/><xsl:text>}{}%
</xsl:text>
        <xsl:text>\begin{tcolorbox}[breakable, enhanced, sharp corners=uphill, arc=1.2mm,
  colback=white, colframe=surBorderLt, boxrule=0.5pt,
  left=3.5mm, right=3.5mm, top=3mm, bottom=3mm,
  toptitle=1.6mm, bottomtitle=1.6mm, lefttitle=3.5mm,
  colbacktitle=</xsl:text><xsl:value-of select="$tcolor"/><xsl:text>, coltitle=white,
  fonttitle=\bfseries,
  title={</xsl:text><xsl:value-of select="gvm:t('grp_title')"/><xsl:text>:\hspace{2mm} </xsl:text>
        <xsl:value-of select="$gname"/><xsl:text>}]
</xsl:text>
        <xsl:text>\noindent </xsl:text>
        <xsl:call-template name="severity-pill">
          <xsl:with-param name="severity" select="$maxsev"/>
        </xsl:call-template>
        <xsl:text>\hspace{2mm}{\setlength{\fboxsep}{2.2pt}\colorbox{surInk}{\color{white}\scriptsize\bfseries~</xsl:text>
        <xsl:value-of select="gvm:t('grp_badge')"/>
        <xsl:text>~}}\par\vspace{2mm}
</xsl:text>
        <xsl:text>{\small </xsl:text><xsl:value-of select="gvm:t('grp_intro_a')"/>
        <xsl:text>\textbf{</xsl:text><xsl:value-of select="$ndist"/><xsl:text>}</xsl:text>
        <xsl:value-of select="gvm:t('grp_intro_b')"/><xsl:text>}\par\vspace{2mm}
</xsl:text>

        <!-- Affected hosts (each host once, however many advisories hit it). -->
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('grp_host')"/><xsl:text>}
\begingroup\ttfamily\footnotesize\raggedright
</xsl:text>
        <xsl:for-each select="$members">
          <xsl:sort select="host/text()"/>
          <xsl:variable name="h" select="host/text()"/>
          <xsl:if test="not(preceding::result[nvt/solution/@type='VendorFix'][host/text() = $h][concat(substring-before(concat(normalize-space(nvt/name),' '),' '),' ',substring-before(concat(substring-after(normalize-space(nvt/name),' '),' '),' ')) = $g])">
            <xsl:if test="position() &gt; 1"><xsl:text>, </xsl:text></xsl:if>
            <xsl:call-template name="escape_text">
              <xsl:with-param name="string" select="$h"/>
            </xsl:call-template>
          </xsl:if>
        </xsl:for-each>
        <xsl:text>
\par\endgroup\vspace{2mm}
</xsl:text>

        <!-- The advisories rolled up here, most severe first. -->
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('grp_th_adv')"/><xsl:text>}
\renewcommand{\arraystretch}{1.2}
\begin{longtable}{@{}p{112mm} p{28mm}@{}}
</xsl:text>
        <xsl:for-each select="$members[generate-id() = generate-id(key('by-updgrp-nvt',concat($g,'||',nvt/@oid))[1])]">
          <xsl:sort select="severity" data-type="number" order="descending"/>
          <!-- Lista só os mais severos. O restante vira UMA linha que declara
               quantos ficaram de fora e até onde vai a severidade deles: um
               corte silencioso faria o card parecer completo, e este documento
               é material de auditoria. A ação de remediação é a mesma para
               todos, então o que se perde é enumeração, não decisão. -->
          <xsl:if test="position() &lt;= number($adv-max)">
            <xsl:text>{\footnotesize </xsl:text>
            <xsl:call-template name="escape_text">
              <xsl:with-param name="string" select="nvt/name"/>
            </xsl:call-template>
            <xsl:text>} &amp; </xsl:text>
            <xsl:call-template name="severity-pill">
              <xsl:with-param name="severity" select="severity"/>
            </xsl:call-template>
            <xsl:text> \\
</xsl:text>
          </xsl:if>
          <xsl:if test="position() = number($adv-max) + 1">
            <xsl:text>\multicolumn{2}{@{}l@{}}{\footnotesize\itshape\color{surMuted}</xsl:text>
            <xsl:text>+ </xsl:text><xsl:value-of select="$ndist - number($adv-max)"/>
            <xsl:value-of select="gvm:t('grp_more_a')"/>
            <xsl:text>CVSS </xsl:text>
            <xsl:value-of select="format-number(severity, '0.0')"/>
            <xsl:value-of select="gvm:t('grp_more_b')"/>
            <xsl:text>} \\
</xsl:text>
          </xsl:if>
        </xsl:for-each>
        <xsl:text>\end{longtable}
\vspace{1mm}
</xsl:text>

        <!-- Single remediation action: the fix of the most severe advisory. -->
        <xsl:text>\fieldlabel{</xsl:text><xsl:value-of select="gvm:t('grp_action')"/><xsl:text>}
\begin{tcolorbox}[colback=surMist,colframe=surBorderLt,boxrule=0.4pt,arc=1mm,left=2.5mm,right=2.5mm,top=1.5mm,bottom=1.5mm]
</xsl:text>
        <xsl:for-each select="$members">
          <xsl:sort select="severity" data-type="number" order="descending"/>
          <xsl:if test="position() = 1">
            <xsl:call-template name="escape_lines">
              <xsl:with-param name="string" select="nvt/solution"/>
            </xsl:call-template>
          </xsl:if>
        </xsl:for-each>
        <xsl:text>
\end{tcolorbox}
\end{tcolorbox}
\vspace{3mm}
</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="branded-footer">
    <xsl:text>
\vspace{6mm}
\begin{center}
{\color{surBorderLt}\rule{\textwidth}{0.4pt}}\\[2.5mm]
\raisebox{-1.5mm}{\includegraphics[height=6mm]{suricatoos-mark-navy}}\quad{\bfseries\color{surInk}\large Suricatoos Security Platform}\\[1.5mm]
{\footnotesize\color{surMuted}</xsl:text>
    <xsl:value-of select="gvm:t('colophon_1')"/>
    <xsl:text>\\
</xsl:text>
    <xsl:value-of select="gvm:t('colophon_2')"/>
    <xsl:text>}
\end{center}
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Document assembly                                                 -->
  <!-- ================================================================= -->

  <xsl:template name="real-report">
    <xsl:call-template name="header"/>
    <xsl:call-template name="newline"/>
    <xsl:text>\begin{document}
</xsl:text>
    <xsl:call-template name="cover-page"/>
    <xsl:text>\pagestyle{surfancy}
</xsl:text>
    <xsl:call-template name="executive-summary"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="hosts-ports"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="findings-summary"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="detailed-findings"/>
    <xsl:call-template name="branded-footer"/>
    <xsl:text>
\end{document}
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
