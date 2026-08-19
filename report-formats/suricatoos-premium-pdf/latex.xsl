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
    <s k="sev_falsepos" en="False pos." pt="Falso pos." es="Falso pos."/>
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
    <!-- Hexmap (port exposure panel). Same rule as every other value here: no
         LaTeX-special character unless a control sequence is intended, because
         gvm:t() output is emitted WITHOUT escaping. -->
    <s k="sec_hexmap" en="Port Exposure Map" pt="Mapa de Exposição de Portas" es="Mapa de Exposición de Puertos"/>
    <s k="hx_intro" en="Every hexagon is one network port observed in the assessed scope; the cell key is the pair (transport, port number), so a port seen on many hosts is a single hexagon. Colour, outline weight and the marker at the top vertex carry the HIGHEST severity observed on that port across every host that exposes it. The third line inside the hexagon names the exposed host (abbreviated when the address is too long for the cell), or counts them when the port is open on more than one. The table below the board lists every port with its mapped IP addresses, up to 40 per port." pt="Cada hexágono é uma porta de rede observada no escopo avaliado; a chave da célula é o par (transporte, número da porta), então uma porta vista em vários hosts é um único hexágono. Cor, espessura do traço e o marcador no vértice superior carregam a MAIOR severidade observada naquela porta em todos os hosts que a expõem. A terceira linha dentro do hexágono nomeia o host exposto (abreviado quando o endereço não cabe na célula), ou conta quantos são quando a porta está aberta em mais de um. A tabela abaixo do tabuleiro lista todas as portas com os endereços IP mapeados, até 40 por porta." es="Cada hexágono es un puerto de red observado en el alcance evaluado; la clave de la celda es el par (transporte, número de puerto), así que un puerto visto en varios hosts es un único hexágono. Color, grosor del trazo y el marcador en el vértice superior llevan la MAYOR severidad observada en ese puerto en todos los hosts que lo exponen. La tercera línea dentro del hexágono nombra el host expuesto (abreviado cuando la dirección no cabe en la celda), o los cuenta cuando el puerto está abierto en más de uno. La tabla debajo del tablero lista todos los puertos con las direcciones IP mapeadas, hasta 40 por puerto."/>
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
    <!-- When family collapsing merges ports, the header must report BOTH numbers:
         saying only the cell count understates how many ports the scan actually
         observed, and this document has a history of headline numbers that quietly
         meant something narrower than the reader assumed. -->
    <s k="hx_ports_word" en="ports" pt="portas" es="puertos"/>
    <s k="hx_in_word" en="in" pt="em" es="en"/>
    <s k="hx_cells_word" en="cells" pt="células" es="celdas"/>
    <s k="hx_hosts_word" en="host(s)" pt="host(s)" es="host(s)"/>
    <s k="hx_omitted" en=" port(s) did not fit the board and were rolled into the final cell. None was dropped: every one of them is listed in the table below." pt=" porta(s) não couberam no tabuleiro e foram somadas na célula final. Nenhuma foi descartada: todas estão listadas na tabela abaixo." es=" puerto(s) no cupieron en el tablero y se sumaron en la celda final. Ninguno fue descartado: todos están listados en la tabla siguiente."/>
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
      <xsl:when test="$threat='Falsepos'">gvm_falsepos</xsl:when>
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

  <!-- Localised severity word for a class token (Critical/High/Medium/Low/Log). -->
  <func:function name="gvm:sev-word">
    <xsl:param name="class"/>
    <!-- 'F' entra no translate para a classe Falsepos casar com sev_falsepos. -->
    <func:result select="gvm:t(concat('sev_', translate($class, 'CHMLOF', 'chmlof')))"/>
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
    <xsl:if test="$class != 'Log' and $class != 'Falsepos'">
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
\definecolor{gvm_falsepos}{rgb}{0.545,0.404,0.612}
\definecolor{gvm_report}{rgb}{0.808,0.851,1.0}

% ---- Hexmap panel palette (dark board) and its table-safe darkened twins ----
\definecolor{hexBg}{HTML}{0B1426}
\definecolor{hexFg}{HTML}{FFFFFF}
\definecolor{hexMuted}{HTML}{A8B6C8}
\definecolor{hexCrit}{HTML}{E63946}
\definecolor{hexHigh}{HTML}{FF7678}
\definecolor{hexMed}{HTML}{F0A202}
\definecolor{hexLow}{HTML}{4FB477}
\definecolor{hexExp}{HTML}{00D4FF}
\definecolor{hexNeu}{HTML}{E8EDF5}
\definecolor{hexCritT}{HTML}{B0111C}
\definecolor{hexHighT}{HTML}{C4453F}
\definecolor{hexMedT}{HTML}{9A6600}
\definecolor{hexLowT}{HTML}{2C7A52}
\definecolor{hexExpT}{HTML}{00688F}
\definecolor{hexNeuT}{HTML}{5F6B7A}

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

  <!-- Character count weighted for the widest upper-case glyphs of the bold
       sans face: W is 0.944 em and M 0.833 against a 0.69 average, so counting
       characters alone under-measures a label like MSSQLSVR by a fifth and
       WWWWWWWW by a third. Each W M G O Q counts as 1.35 characters, which
       keeps the estimate above the real width for every upper-case label. -->
  <func:function name="gvm:hx-wlen">
    <xsl:param name="s"/>
    <func:result select="string-length($s) + 0.35 * string-length(translate($s, translate($s,'WMGOQ',''), ''))"/>
  </func:function>

  <func:function name="gvm:hx-max2">
    <xsl:param name="a"/>
    <xsl:param name="b"/>
    <xsl:choose>
      <xsl:when test="number($a) &gt;= number($b)"><func:result select="number($a)"/></xsl:when>
      <xsl:otherwise><func:result select="number($b)"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Font size that makes a string of $len characters fit $avail points, given
       a per-character width ratio, clamped between $floor and $base. -->
  <func:function name="gvm:hx-fit">
    <xsl:param name="len"/>
    <xsl:param name="base"/>
    <xsl:param name="avail"/>
    <xsl:param name="ratio"/>
    <xsl:param name="floor"/>
    <xsl:choose>
      <xsl:when test="number($len) &lt;= 0"><func:result select="number($base)"/></xsl:when>
      <xsl:when test="number($avail) div (number($len) * number($ratio)) &gt;= number($base)">
        <func:result select="number($base)"/>
      </xsl:when>
      <xsl:when test="number($avail) div (number($len) * number($ratio)) &lt; number($floor)">
        <func:result select="number($floor)"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="number($avail) div (number($len) * number($ratio))"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- State -> palette entry. The board uses the dark hex* palette; the table in
       the body of the document uses the hex*T variants, which are the same hues
       darkened enough to carry white text on white paper. -->
  <func:function name="gvm:hx-color">
    <xsl:param name="st"/>
    <xsl:choose>
      <xsl:when test="$st='critico'"><func:result select="'hexCrit'"/></xsl:when>
      <xsl:when test="$st='alto'"><func:result select="'hexHigh'"/></xsl:when>
      <xsl:when test="$st='medio'"><func:result select="'hexMed'"/></xsl:when>
      <xsl:when test="$st='baixo'"><func:result select="'hexLow'"/></xsl:when>
      <xsl:when test="$st='exposto'"><func:result select="'hexExp'"/></xsl:when>
      <xsl:otherwise><func:result select="'hexNeu'"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <func:function name="gvm:hx-tcolor">
    <xsl:param name="st"/>
    <xsl:choose>
      <xsl:when test="$st='critico'"><func:result select="'hexCritT'"/></xsl:when>
      <xsl:when test="$st='alto'"><func:result select="'hexHighT'"/></xsl:when>
      <xsl:when test="$st='medio'"><func:result select="'hexMedT'"/></xsl:when>
      <xsl:when test="$st='baixo'"><func:result select="'hexLowT'"/></xsl:when>
      <xsl:when test="$st='exposto'"><func:result select="'hexExpT'"/></xsl:when>
      <xsl:otherwise><func:result select="'hexNeuT'"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

  <func:function name="gvm:hx-fillop">
    <xsl:param name="st"/>
    <xsl:choose>
      <xsl:when test="$st='critico'"><func:result select="'0.22'"/></xsl:when>
      <xsl:when test="$st='alto'"><func:result select="'0.16'"/></xsl:when>
      <xsl:when test="$st='medio'"><func:result select="'0.14'"/></xsl:when>
      <xsl:when test="$st='baixo'"><func:result select="'0.12'"/></xsl:when>
      <xsl:when test="$st='exposto'"><func:result select="'0.12'"/></xsl:when>
      <xsl:otherwise><func:result select="'0'"/></xsl:otherwise>
    </xsl:choose>
  </func:function>

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
  <!-- Hexmap: board geometry and TikZ rendering                         -->
  <!-- ================================================================= -->

  <!-- One hexagon. Pointy-top, circumradius 60 drawn at 57 so neighbours keep a
       gap; TikZ y grows UPWARDS, so the vertex order below is already signed for
       LaTeX and not for SVG. Colour is never the only channel: critical and high
       also carry a filled marker under the top vertex (critical adds a ring), and
       the outline of a critical cell is thicker. -->
  <xsl:template name="hx-hex">
    <xsl:param name="cx"/>
    <xsl:param name="cy"/>
    <xsl:param name="third"/>
    <xsl:variable name="st" select="string(@state)"/>
    <xsl:variable name="col" select="gvm:hx-color($st)"/>
    <xsl:variable name="x" select="format-number($cx, '0.##')"/>
    <xsl:variable name="y" select="format-number($cy, '0.##')"/>
    <xsl:variable name="xl" select="format-number($cx - 49.36, '0.##')"/>
    <xsl:variable name="xr" select="format-number($cx + 49.36, '0.##')"/>
    <!-- outline + fill -->
    <xsl:text>\draw[</xsl:text>
    <xsl:value-of select="$col"/>
    <xsl:choose>
      <xsl:when test="$st = 'critico'"><xsl:text>,line width=4pt</xsl:text></xsl:when>
      <xsl:otherwise><xsl:text>,line width=3pt</xsl:text></xsl:otherwise>
    </xsl:choose>
    <xsl:choose>
      <xsl:when test="$st = 'neutro'"><xsl:text>,draw opacity=0.70</xsl:text></xsl:when>
      <xsl:otherwise>
        <xsl:text>,fill=</xsl:text><xsl:value-of select="$col"/>
        <xsl:text>,fill opacity=</xsl:text><xsl:value-of select="gvm:hx-fillop($st)"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>,line join=round] (</xsl:text>
    <xsl:value-of select="concat($x,',',format-number($cy + 57, '0.##'),') -- (')"/>
    <xsl:value-of select="concat($xl,',',format-number($cy + 28.5, '0.##'),') -- (')"/>
    <xsl:value-of select="concat($xl,',',format-number($cy - 28.5, '0.##'),') -- (')"/>
    <xsl:value-of select="concat($x,',',format-number($cy - 57, '0.##'),') -- (')"/>
    <xsl:value-of select="concat($xr,',',format-number($cy - 28.5, '0.##'),') -- (')"/>
    <xsl:value-of select="concat($xr,',',format-number($cy + 28.5, '0.##'),')')"/>
    <xsl:text> -- cycle;
</xsl:text>
    <!-- accessibility marker -->
    <xsl:if test="$st = 'critico' or $st = 'alto'">
      <xsl:text>\fill[</xsl:text><xsl:value-of select="$col"/><xsl:text>] (</xsl:text>
      <xsl:value-of select="concat($x,',',format-number($cy + 42, '0.##'))"/>
      <xsl:text>) circle (4.5pt);
</xsl:text>
      <xsl:if test="$st = 'critico'">
        <xsl:text>\draw[</xsl:text><xsl:value-of select="$col"/><xsl:text>,line width=1.6pt] (</xsl:text>
        <xsl:value-of select="concat($x,',',format-number($cy + 42, '0.##'))"/>
        <xsl:text>) circle (8.5pt);
</xsl:text>
      </xsl:if>
    </xsl:if>
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
    <!-- 90pt is what the hexagon really offers across the band this baseline
         and its cap height occupy (the widest span is 98.7pt, at the corners
         it is down to 94.5pt); the length is weighted so a run of W or M is
         measured for what it costs. Both were budgets that under-measured
         before: WWWWWWWW came out 21pt wider than the cell. -->
    <xsl:if test="string-length($svcup) &gt; 0">
      <xsl:text>\node[anchor=base,inner sep=0,text=hexFg,font=\fontsize{</xsl:text>
      <xsl:value-of select="format-number(gvm:hx-fit(gvm:hx-wlen($svcup), 19, 90, 0.75, 7), '0.##')"/>
      <xsl:text>}{0}\selectfont\bfseries] at (</xsl:text>
      <xsl:value-of select="concat($x,',',format-number($cy + 16, '0.##'))"/>
      <xsl:text>) {</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($svcup)"/></xsl:call-template>
      <xsl:text>};
</xsl:text>
    </xsl:if>
    <!-- line 2: the port WITH its transport (or the collapsed range, or "+N").
         Without the transport the same number on tcp and on udp draws two
         hexagons whose three lines of text are identical, and the per-host
         board has no table underneath to tell them apart. -->
    <xsl:text>\node[anchor=base,inner sep=0,text=hexFg,font=\fontsize{</xsl:text>
    <xsl:value-of select="format-number(gvm:hx-fit(string-length(@blabel), 28, 84, 0.58, 9), '0.##')"/>
    <xsl:text>}{0}\selectfont\bfseries] at (</xsl:text>
    <xsl:value-of select="concat($x,',',format-number($cy - 11, '0.##'))"/>
    <xsl:text>) {</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@blabel)"/></xsl:call-template>
    <xsl:text>};
</xsl:text>
    <!-- line 3: the mapped host (global board) or the finding tally (per host) -->
    <xsl:variable name="l3">
      <xsl:choose>
        <xsl:when test="@svcsrc = 'over'"></xsl:when>
        <xsl:when test="$third = 'find'">
          <xsl:value-of select="concat(@nfind, ' ', gvm:t('hx_findings_n'))"/>
        </xsl:when>
        <xsl:when test="number(@nips) = 1">
          <!-- The baseline sits 35pt below the centre, where the hexagon is
               only 76pt wide, and the type size bottoms out at 5pt: past 26
               characters no size change can make the address fit, so it is
               elided head and tail rather than printed across the outline (an
               IPv6 in long form ran 22pt past it, into the next cell). The
               integral address is in the Port -> IP table either way. -->
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
    <xsl:if test="string-length($l3) &gt; 0">
      <xsl:text>\node[anchor=base,inner sep=0,text=hexMuted,font=\fontsize{</xsl:text>
      <xsl:value-of select="format-number(gvm:hx-fit(string-length($l3), 12, 72, 0.52, 5), '0.##')"/>
      <xsl:text>}{0}\selectfont] at (</xsl:text>
      <xsl:value-of select="concat($x,',',format-number($cy - 35, '0.##'))"/>
      <xsl:text>) {</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($l3)"/></xsl:call-template>
      <xsl:text>};
</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- The whole dark panel: header, hex-blob board, legend. $cells must already
       be in draw order. -->
  <xsl:template name="hx-board">
    <xsl:param name="cells"/>
    <xsl:param name="title"/>
    <xsl:param name="meta"/>
    <xsl:param name="third" select="'ip'"/>
    <xsl:variable name="N" select="count($cells)"/>

    <!-- k = smallest radius whose centred hexagonal number 1+3k(k+1) holds N. -->
    <xsl:variable name="k">
      <xsl:choose>
        <xsl:when test="$N &lt;= 1">0</xsl:when>
        <xsl:when test="$N &lt;= 7">1</xsl:when>
        <xsl:when test="$N &lt;= 19">2</xsl:when>
        <xsl:when test="$N &lt;= 37">3</xsl:when>
        <xsl:when test="$N &lt;= 61">4</xsl:when>
        <xsl:when test="$N &lt;= 91">5</xsl:when>
        <xsl:when test="$N &lt;= 127">6</xsl:when>
        <xsl:when test="$N &lt;= 169">7</xsl:when>
        <xsl:otherwise>8</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="L" select="2 * number($k) + 1"/>
    <xsl:variable name="E" select="1 + 3 * number($k) * (number($k) + 1) - $N"/>
    <!-- The excess is shaved one cell at a time, LAST row then FIRST row and so
         on, each side stepping inwards when its row is down to a single cell.
         That alternation is equivalent to giving the bottom ceil(E/2) removals
         and the top floor(E/2), each consumed greedily from the outside in,
         which is what the arithmetic below does without simulating the loop. -->
    <xsl:variable name="B" select="ceiling($E div 2)"/>
    <xsl:variable name="T" select="floor($E div 2)"/>

    <xsl:variable name="rowsA-rtf">
      <xsl:for-each select="$hx-ints/i[number(@v) &lt; $L]">
        <row r="{@v}">
          <xsl:attribute name="n">
            <xsl:choose>
              <xsl:when test="number(@v) &lt;= number($k)"><xsl:value-of select="number($k) + 1 + number(@v)"/></xsl:when>
              <xsl:otherwise><xsl:value-of select="3 * number($k) + 1 - number(@v)"/></xsl:otherwise>
            </xsl:choose>
          </xsl:attribute>
        </row>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="rowsB-rtf">
      <xsl:for-each select="exsl:node-set($rowsA-rtf)/row">
        <xsl:variable name="capB" select="sum(following-sibling::row/@n) - count(following-sibling::row)"/>
        <xsl:variable name="capT" select="sum(preceding-sibling::row/@n) - count(preceding-sibling::row)"/>
        <xsl:variable name="want">
          <xsl:choose>
            <xsl:when test="number(@r) &gt; number($k)"><xsl:value-of select="$B - $capB"/></xsl:when>
            <xsl:when test="number(@r) &lt; number($k)"><xsl:value-of select="$T - $capT"/></xsl:when>
            <xsl:otherwise>
              <xsl:variable name="lb"><xsl:choose><xsl:when test="$B - $capB &gt; 0"><xsl:value-of select="$B - $capB"/></xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose></xsl:variable>
              <xsl:variable name="lt"><xsl:choose><xsl:when test="$T - $capT &gt; 0"><xsl:value-of select="$T - $capT"/></xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose></xsl:variable>
              <xsl:value-of select="number($lb) + number($lt)"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:variable name="rem">
          <xsl:choose>
            <xsl:when test="number($want) &lt;= 0">0</xsl:when>
            <xsl:when test="number($want) &gt; number(@n) - 1"><xsl:value-of select="number(@n) - 1"/></xsl:when>
            <xsl:otherwise><xsl:value-of select="number($want)"/></xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <row r="{@r}" n="{number(@n) - number($rem)}"/>
      </xsl:for-each>
    </xsl:variable>
    <!-- Trailing rows with nothing left to hold are dropped (only reachable for
         a board of two cells, where the blob cannot shrink far enough). -->
    <xsl:variable name="rowsC-rtf">
      <xsl:for-each select="exsl:node-set($rowsB-rtf)/row">
        <xsl:variable name="cum" select="sum(preceding-sibling::row/@n)"/>
        <xsl:variable name="neff">
          <xsl:choose>
            <xsl:when test="$N - $cum &lt;= 0">0</xsl:when>
            <xsl:when test="$N - $cum &lt; number(@n)"><xsl:value-of select="$N - $cum"/></xsl:when>
            <xsl:otherwise><xsl:value-of select="@n"/></xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:if test="number($neff) &gt; 0">
          <row n="{$neff}" cum="{$cum}"/>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <!-- Phase correction. Centring each row on its own midpoint leaves two
         neighbouring rows of the SAME parity sitting on the same lattice
         columns, which stacks hexagons 120pt tall on a 90pt vertical pitch and
         makes them overlap. Never happens on an exact blob (sizes step by one),
         but it does as soon as the excess is trimmed. So the expected phase
         alternates 0 / half a step down the board, and any row whose natural
         phase disagrees is shifted half a step to the right. -->
    <xsl:variable name="rowsD-rtf">
      <xsl:for-each select="exsl:node-set($rowsC-rtf)/row">
        <xsl:variable name="idx" select="count(preceding-sibling::row)"/>
        <xsl:variable name="nat" select="number(@n) mod 2 = 0"/>
        <xsl:variable name="exp" select="(number(number(../row[1]/@n) mod 2 = 0) + $idx) mod 2 = 1"/>
        <xsl:variable name="shift">
          <xsl:choose><xsl:when test="$nat != $exp">0.5</xsl:when><xsl:otherwise>0</xsl:otherwise></xsl:choose>
        </xsl:variable>
        <row idx="{$idx}" n="{@n}" cum="{@cum}" x0="{(1 - number(@n)) div 2 + number($shift)}"/>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="rows" select="exsl:node-set($rowsD-rtf)"/>

    <!-- Recentre on the real bounding box, since the shifts break the symmetry. -->
    <xsl:variable name="minx">
      <xsl:for-each select="$rows/row">
        <xsl:sort select="number(@x0)" data-type="number"/>
        <xsl:if test="position() = 1"><xsl:value-of select="@x0"/></xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="maxx">
      <xsl:for-each select="$rows/row">
        <xsl:sort select="number(@x0) + number(@n) - 1" data-type="number" order="descending"/>
        <xsl:if test="position() = 1"><xsl:value-of select="number(@x0) + number(@n) - 1"/></xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="xoff" select="(number($minx) + number($maxx)) div 2"/>
    <xsl:variable name="Leff" select="count($rows/row)"/>
    <xsl:variable name="BW" select="(number($maxx) - number($minx) + 1) * 103.923048"/>
    <xsl:variable name="BH" select="(number($Leff) - 1) * 90 + 120"/>

    <!-- Header / legend type sizes, shrunk so the chrome never widens the panel
         beyond the board itself (a wider panel means a smaller board once the
         whole picture is scaled to the text width). -->
    <!-- Both strings come from the report: the title of a per-host board is the
         host address and the metadata line carries the task name, neither of
         which the scanner bounds. They size the panel, the panel sizes the
         tikzpicture, and TeX refuses any dimension past 16383.99pt: an 8000
         character task name asked for 33585pt and killed the whole PDF. Long
         before that they simply crowd out the board, because the picture is
         scaled to the text width as a whole - a 246 character task name shrank
         a full-page board to 84mm. So they are cut to a length that can never
         drive the panel wider than the legend already does, and what was cut is
         shown as such. The uncut values are on the cover, in the running header
         and in the host banner. -->
    <xsl:variable name="title-c">
      <xsl:value-of select="substring($title, 1, 60)"/>
      <xsl:if test="string-length($title) &gt; 60"><xsl:text>...</xsl:text></xsl:if>
    </xsl:variable>
    <xsl:variable name="meta-c">
      <xsl:value-of select="substring($meta, 1, 110)"/>
      <xsl:if test="string-length($meta) &gt; 110"><xsl:text>...</xsl:text></xsl:if>
    </xsl:variable>
    <xsl:variable name="tlen" select="string-length($title-c)"/>
    <xsl:variable name="mlen" select="string-length($meta-c)"/>
    <xsl:variable name="clen" select="string-length(gvm:t('hx_state_critico')) + string-length(gvm:t('hx_state_alto'))
                                    + string-length(gvm:t('hx_state_medio')) + string-length(gvm:t('hx_state_baixo'))
                                    + string-length(gvm:t('hx_state_exposto')) + string-length(gvm:t('hx_state_neutro'))
                                    + 30"/>
    <xsl:variable name="tf" select="gvm:hx-fit($tlen, 26, $BW, 0.56, 12)"/>
    <xsl:variable name="mf" select="gvm:hx-fit($mlen, 14, $BW, 0.52, 8)"/>
    <xsl:variable name="lf" select="gvm:hx-fit(number($clen) * 0.55 + 17.34, 15, $BW, 1, 9)"/>
    <xsl:variable name="TW" select="$tf * 0.56 * $tlen"/>
    <xsl:variable name="MW" select="$mf * 0.52 * $mlen"/>
    <xsl:variable name="LW" select="$lf * (number($clen) * 0.55 + 17.34)"/>
    <!-- Hard ceiling as well, so no future input can walk the picture past the
         dimension TeX will accept. The widest board the geometry can produce is
         under 1800pt, so this never binds on real data. -->
    <xsl:variable name="PW" select="gvm:hx-min2(gvm:hx-max2(gvm:hx-max2($BW, $TW), gvm:hx-max2($MW, $LW)), 4000)"/>
    <xsl:variable name="PX" select="$PW div 2"/>
    <xsl:variable name="PY1" select="$BH div 2 + 100"/>
    <xsl:variable name="PY0" select="-($BH div 2) - 78"/>
    <xsl:variable name="PWt" select="$PW + 56"/>
    <xsl:variable name="PHt" select="$PY1 - $PY0"/>

    <xsl:text>\begin{center}
</xsl:text>
    <!-- Fit to the text width, unless the board is so tall that doing so would
         push it off the page; then fit to the height instead. -->
    <xsl:choose>
      <xsl:when test="$PHt div $PWt &gt; 1.11">
        <xsl:text>\resizebox{!}{185mm}{%
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\resizebox{\linewidth}{!}{%
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>\begin{tikzpicture}[x=1pt,y=1pt]
\fill[hexBg,rounded corners=10pt] (</xsl:text>
    <xsl:value-of select="concat(format-number(-$PX - 28,'0.##'),',',format-number($PY0,'0.##'),') rectangle (',format-number($PX + 28,'0.##'),',',format-number($PY1,'0.##'))"/>
    <xsl:text>);
</xsl:text>
    <!-- header -->
    <xsl:text>\node[anchor=north west,inner sep=0,text=hexFg,font=\fontsize{</xsl:text>
    <xsl:value-of select="format-number($tf,'0.##')"/>
    <xsl:text>}{0}\selectfont\bfseries] at (</xsl:text>
    <xsl:value-of select="concat(format-number(-$PX,'0.##'),',',format-number($PY1 - 20,'0.##'))"/>
    <xsl:text>) {</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($title-c)"/></xsl:call-template>
    <xsl:text>};
\node[anchor=north west,inner sep=0,text=hexMuted,font=\fontsize{</xsl:text>
    <xsl:value-of select="format-number($mf,'0.##')"/>
    <xsl:text>}{0}\selectfont] at (</xsl:text>
    <xsl:value-of select="concat(format-number(-$PX,'0.##'),',',format-number($PY1 - 26 - $tf * 1.2,'0.##'))"/>
    <xsl:text>) {</xsl:text>
    <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string($meta-c)"/></xsl:call-template>
    <xsl:text>};
</xsl:text>
    <!-- cells, row by row -->
    <xsl:for-each select="$rows/row">
      <xsl:variable name="cy" select="-(number(@idx) - (number($Leff) - 1) div 2) * 90"/>
      <xsl:variable name="rx0" select="number(@x0) - $xoff"/>
      <xsl:variable name="cum" select="number(@cum)"/>
      <xsl:variable name="nn" select="number(@n)"/>
      <xsl:for-each select="$cells[position() &gt; $cum and position() &lt;= $cum + $nn]">
        <xsl:call-template name="hx-hex">
          <xsl:with-param name="cx" select="($rx0 + position() - 1) * 103.923048"/>
          <xsl:with-param name="cy" select="$cy"/>
          <xsl:with-param name="third" select="$third"/>
        </xsl:call-template>
      </xsl:for-each>
    </xsl:for-each>
    <!-- legend: one chip per state, in severity order, carrying its count. The
         six counts add up to the number of hexagons drawn, by construction. -->
    <xsl:variable name="chips-rtf">
      <chip st="critico" n="{count($cells[@state='critico'])}"/>
      <chip st="alto" n="{count($cells[@state='alto'])}"/>
      <chip st="medio" n="{count($cells[@state='medio'])}"/>
      <chip st="baixo" n="{count($cells[@state='baixo'])}"/>
      <chip st="exposto" n="{count($cells[@state='exposto'])}"/>
      <chip st="neutro" n="{count($cells[@state='neutro'])}"/>
    </xsl:variable>
    <xsl:variable name="ly" select="$PY0 + 39"/>
    <xsl:for-each select="exsl:node-set($chips-rtf)/chip">
      <xsl:variable name="lbl" select="concat(gvm:t(concat('hx_state_', @st)), ' (', @n, ')')"/>
      <xsl:variable name="nb" select="count(preceding-sibling::chip)"/>
      <xsl:variable name="prevchars">
        <xsl:call-template name="hx-sum-chip-chars">
          <xsl:with-param name="nodes" select="preceding-sibling::chip"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:variable name="lx" select="-$PX + $lf * (number($prevchars) * 0.55 + $nb * 2.89)"/>
      <xsl:text>\fill[</xsl:text><xsl:value-of select="gvm:hx-color(string(@st))"/>
      <xsl:text>,fill opacity=0.30] (</xsl:text>
      <xsl:value-of select="concat(format-number($lx + $lf * 0.47,'0.##'),',',format-number($ly + $lf * 0.3,'0.##'))"/>
      <xsl:text>) circle (</xsl:text><xsl:value-of select="format-number($lf * 0.47,'0.##')"/><xsl:text>pt);
\draw[</xsl:text><xsl:value-of select="gvm:hx-color(string(@st))"/>
      <xsl:text>,line width=</xsl:text><xsl:value-of select="format-number($lf * 0.14,'0.##')"/><xsl:text>pt] (</xsl:text>
      <xsl:value-of select="concat(format-number($lx + $lf * 0.47,'0.##'),',',format-number($ly + $lf * 0.3,'0.##'))"/>
      <xsl:text>) circle (</xsl:text><xsl:value-of select="format-number($lf * 0.47,'0.##')"/><xsl:text>pt);
\node[anchor=base west,inner sep=0,text=hexMuted,font=\fontsize{</xsl:text>
      <xsl:value-of select="format-number($lf,'0.##')"/>
      <xsl:text>}{0}\selectfont] at (</xsl:text>
      <xsl:value-of select="concat(format-number($lx + $lf * 1.29,'0.##'),',',format-number($ly,'0.##'))"/>
      <xsl:text>) {</xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="$lbl"/></xsl:call-template>
      <xsl:text>};
</xsl:text>
    </xsl:for-each>
    <xsl:text>\end{tikzpicture}}
\end{center}
</xsl:text>
  </xsl:template>

  <!-- Total label length of a set of legend chips (used to lay them out left to
       right without a running accumulator). -->
  <xsl:template name="hx-sum-chip-chars">
    <xsl:param name="nodes"/>
    <xsl:variable name="lens">
      <xsl:for-each select="$nodes">
        <n v="{string-length(concat(gvm:t(concat('hx_state_', @st)), ' (', @n, ')'))}"/>
      </xsl:for-each>
    </xsl:variable>
    <xsl:value-of select="sum(exsl:node-set($lens)/n/@v)"/>
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
    <xsl:if test="string-length($s) &gt; 96"><xsl:text>...</xsl:text></xsl:if>
  </xsl:template>

  <!-- State badge for the light-themed table. Same hues as the board, darkened
       so white text keeps its contrast on paper. -->
  <xsl:template name="hx-state-pill">
    <xsl:param name="st"/>
    <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{</xsl:text>
    <xsl:value-of select="gvm:hx-tcolor($st)"/>
    <xsl:text>}{\color{white}\scriptsize\bfseries~</xsl:text>
    <xsl:value-of select="gvm:t(concat('hx_state_', $st))"/>
    <xsl:text>~}}</xsl:text>
  </xsl:template>

  <!-- Every port in the scope, INCLUDING the ones the board could not hold:
       nothing disappears between the picture and the table. -->
  <xsl:template name="hx-table">
    <xsl:param name="ord"/>
    <xsl:text>\renewcommand{\arraystretch}{1.25}
\begin{longtable}{@{}>{\raggedright\arraybackslash}p{16mm} >{\raggedright\arraybackslash}p{10mm} >{\raggedright\arraybackslash}p{24mm} >{\raggedright\arraybackslash}p{23mm} >{\raggedright\arraybackslash}p{13mm} >{\raggedright\arraybackslash}p{10mm} >{\raggedright\arraybackslash}p{44mm}@{}}
\rowcolor{surInk}
</xsl:text>
    <xsl:call-template name="hx-table-head"/>
    <xsl:text>\endfirsthead
\rowcolor{surInk}
</xsl:text>
    <xsl:call-template name="hx-table-head"/>
    <xsl:text>\endhead
</xsl:text>
    <xsl:for-each select="$ord/c">
      <xsl:sort select="number(@num)" data-type="number"/>
      <xsl:sort select="@proto"/>
      <xsl:if test="position() mod 2 = 0"><xsl:text>\rowcolor{surMist}</xsl:text></xsl:if>
      <!-- port (or collapsed range) -->
      <xsl:text>{\ttfamily </xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@label)"/></xsl:call-template>
      <xsl:text>}</xsl:text>
      <xsl:if test="@qodlow = '1'"><xsl:text>\textsuperscript{\ddag}</xsl:text></xsl:if>
      <xsl:if test="@collapsed = '1'">
        <xsl:text>\newline{\tiny\color{surMuted}</xsl:text>
        <xsl:value-of select="gvm:t('hx_members')"/>
        <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@members)"/></xsl:call-template>
        <xsl:text>}</xsl:text>
      </xsl:if>
      <xsl:text> &amp; {\ttfamily </xsl:text>
      <xsl:call-template name="escape_text"><xsl:with-param name="string" select="string(@proto)"/></xsl:call-template>
      <xsl:text>} &amp; {\footnotesize </xsl:text>
      <xsl:call-template name="hx-brk"><xsl:with-param name="s" select="string(@svc)"/></xsl:call-template>
      <xsl:if test="@svcsrc = 'iana'"><xsl:text>\textsuperscript{\dag}</xsl:text></xsl:if>
      <xsl:if test="@svcsrc = 'fam'"><xsl:text>\textsuperscript{*}</xsl:text></xsl:if>
      <xsl:text>} &amp; </xsl:text>
      <xsl:call-template name="hx-state-pill"><xsl:with-param name="st" select="string(@state)"/></xsl:call-template>
      <xsl:text> &amp; </xsl:text>
      <xsl:choose>
        <xsl:when test="number(@cvss) &gt;= 0">
          <xsl:text>{\footnotesize </xsl:text>
          <xsl:value-of select="format-number(number(@cvss), '0.0')"/>
          <xsl:text>}</xsl:text>
        </xsl:when>
        <xsl:otherwise><xsl:text>{\color{surMuted}\scriptsize ---}</xsl:text></xsl:otherwise>
      </xsl:choose>
      <xsl:text> &amp; {\footnotesize </xsl:text>
      <xsl:value-of select="@nips"/>
      <xsl:text>} &amp; {\tiny\ttfamily </xsl:text>
      <!-- A collapsed family is ONE cell on the board but it is not one port
           here: printing the union of the family's hosts next to the member
           list asserts pairs the scan never saw (137 was on a single host while
           the family spanned two). When the members do not share the same
           addresses, each member gets its own line. -->
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
          <xsl:call-template name="hx-ip-list"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>} \\[0.3mm]
</xsl:text>
    </xsl:for-each>
    <xsl:text>\end{longtable}
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
      <xsl:text>{\rmfamily\itshape\color{surMuted}</xsl:text>
      <xsl:value-of select="gvm:t('hx_ip_more_a')"/>
      <xsl:value-of select="number(@nips) - 40"/>
      <xsl:value-of select="gvm:t('hx_ip_more_b')"/>
      <xsl:text>}</xsl:text>
    </xsl:if>
  </xsl:template>

  <xsl:template name="hx-table-head">
    <xsl:text>\textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_port')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_proto')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_service')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_state')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_cvss')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_hosts')"/>
    <xsl:text>} &amp; \textcolor{white}{\footnotesize\bfseries </xsl:text><xsl:value-of select="gvm:t('hx_th_ips')"/>
    <xsl:text>} \\
</xsl:text>
  </xsl:template>

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
    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_hexmap')"/><xsl:text>}
</xsl:text>
    <xsl:value-of select="gvm:t('hx_intro')"/>
    <xsl:text>\par
</xsl:text>
    <xsl:choose>
      <xsl:when test="$n = 0">
        <xsl:text>\vspace{2mm}
{\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('hx_no_ports')"/><xsl:text>}\par
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="draw-rtf">
          <xsl:call-template name="hx-draw-cells">
            <xsl:with-param name="ord" select="$ord"/>
            <xsl:with-param name="max" select="$hexmap-max"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:variable name="meta">
          <xsl:value-of select="gvm:report()/task/name"/>
          <xsl:text> -- </xsl:text>
          <xsl:value-of select="count(gvm:report()/host)"/>
          <xsl:text> </xsl:text><xsl:value-of select="gvm:t('hx_hosts_word')"/>
          <xsl:text> -- </xsl:text>
          <xsl:call-template name="hx-scope-phrase">
            <xsl:with-param name="cells" select="$n"/>
            <xsl:with-param name="ports" select="$nraw"/>
          </xsl:call-template>
          <xsl:text> -- </xsl:text>
          <xsl:call-template name="emit-date">
            <xsl:with-param name="date" select="gvm:report()/scan_end"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:text>\vspace{2mm}
</xsl:text>
        <xsl:call-template name="hx-board">
          <xsl:with-param name="cells" select="exsl:node-set($draw-rtf)/c"/>
          <xsl:with-param name="title" select="gvm:t('sec_hexmap')"/>
          <xsl:with-param name="meta" select="string($meta)"/>
          <xsl:with-param name="third" select="'ip'"/>
        </xsl:call-template>
        <!-- Everything the board could not show, said out loud. -->
        <xsl:call-template name="hx-notes">
          <xsl:with-param name="omitted" select="$n - count(exsl:node-set($draw-rtf)/c[not(@over)])"/>
          <xsl:with-param name="iana" select="count($ord/c[@svcsrc='iana'])"/>
          <xsl:with-param name="fam" select="count($ord/c[@svcsrc='fam'])"/>
          <xsl:with-param name="qodlow" select="count($ord/c[@qodlow='1'])"/>
        </xsl:call-template>
        <xsl:text>\vspace{2mm}
</xsl:text>
        <xsl:call-template name="hx-table">
          <xsl:with-param name="ord" select="$ord"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="hx-notes">
    <xsl:param name="omitted"/>
    <xsl:param name="iana"/>
    <xsl:param name="fam" select="0"/>
    <xsl:param name="qodlow"/>
    <xsl:variable name="total" select="count(gvm:report()/results/result)"/>
    <xsl:variable name="rc-full" select="normalize-space(gvm:report()/result_count/text())"/>
    <xsl:variable name="partial"
      select="string-length($rc-full) &gt; 0 and floor(number($rc-full)) = number($rc-full) and number($rc-full) &gt; $total"/>
    <xsl:if test="$omitted &gt; 0 or number($hx-genhosts) &gt; 0 or number($hx-malformed) &gt; 0
                  or number($hx-noip) &gt; 0 or $iana &gt; 0 or $fam &gt; 0 or $qodlow &gt; 0 or $partial">
      <xsl:text>\vspace{-2mm}
{\footnotesize\color{surMuted}
</xsl:text>
      <xsl:if test="$omitted &gt; 0">
        <xsl:value-of select="$omitted"/><xsl:value-of select="gvm:t('hx_omitted')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="number($hx-genhosts) &gt; 0">
        <xsl:value-of select="$hx-genhosts"/><xsl:value-of select="gvm:t('hx_hostlevel_note')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="number($hx-malformed) &gt; 0">
        <xsl:value-of select="$hx-malformed"/><xsl:value-of select="gvm:t('hx_malformed_note')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="number($hx-noip) &gt; 0">
        <xsl:value-of select="$hx-noip"/><xsl:value-of select="gvm:t('hx_noip_note')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="$partial">
        <xsl:value-of select="gvm:t('hx_partial')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="$fam &gt; 0">
        <xsl:text>\textsuperscript{*}</xsl:text><xsl:value-of select="gvm:t('hx_fam_note')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="$iana &gt; 0">
        <xsl:text>\textsuperscript{\dag}</xsl:text><xsl:value-of select="gvm:t('hx_iana_note')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:if test="$qodlow &gt; 0">
        <xsl:text>\textsuperscript{\ddag}</xsl:text><xsl:value-of select="gvm:t('hx_low_qod')"/><xsl:text>\par
</xsl:text>
      </xsl:if>
      <xsl:text>}\par
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
    <xsl:text>\section{</xsl:text><xsl:value-of select="gvm:t('sec_hexmap_host')"/><xsl:text>}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$nhosts &gt; number($hexmap-per-host-max)">
        <xsl:value-of select="gvm:t('hx_host_skipped_a')"/>
        <xsl:value-of select="$nhosts"/>
        <xsl:value-of select="gvm:t('hx_host_skipped_b')"/>
        <xsl:value-of select="$hexmap-per-host-max"/>
        <xsl:value-of select="gvm:t('hx_host_skipped_c')"/>
        <xsl:text>\par
</xsl:text>
      </xsl:when>
      <xsl:when test="count($hosts) = 0 or $nglobal = 0">
        <xsl:text>{\color{surMuted}</xsl:text><xsl:value-of select="gvm:t('hx_host_none')"/><xsl:text>}\par
</xsl:text>
        <xsl:call-template name="hx-noip-hosts-note"><xsl:with-param name="n" select="$noiph"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="gvm:t('hx_host_intro')"/>
        <xsl:text>\par
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
          <xsl:text>\vspace{3mm}
</xsl:text>
          <xsl:call-template name="host-banner">
            <xsl:with-param name="ip" select="$ip"/>
            <xsl:with-param name="hostname" select="$hostname"/>
            <xsl:with-param name="os" select="string($os)"/>
            <xsl:with-param name="portcount" select="0"/>
          </xsl:call-template>
          <xsl:choose>
            <xsl:when test="count($hord/c) = 0">
              <xsl:text>{\color{surMuted}\footnotesize </xsl:text>
              <xsl:value-of select="gvm:t('hp_no_ports')"/>
              <xsl:text>}\par
</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="hdraw-rtf">
                <xsl:call-template name="hx-draw-cells">
                  <xsl:with-param name="ord" select="$hord"/>
                  <xsl:with-param name="max" select="$hexmap-per-host-cells"/>
                </xsl:call-template>
              </xsl:variable>
              <xsl:variable name="hmeta">
                <xsl:if test="string-length($hostname) &gt; 0">
                  <xsl:value-of select="$hostname"/><xsl:text> -- </xsl:text>
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
      <xsl:text>{\footnotesize\color{surMuted}</xsl:text>
      <xsl:value-of select="$n"/><xsl:value-of select="gvm:t('hx_host_noip')"/>
      <xsl:text>}\par
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
    <xsl:call-template name="hexmap-section"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="hosts-ports"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="findings-summary"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="detailed-findings"/>
    <xsl:text>\newpage
</xsl:text>
    <xsl:call-template name="hexmap-hosts-section"/>
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
