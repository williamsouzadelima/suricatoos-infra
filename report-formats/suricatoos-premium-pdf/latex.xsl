<?xml version="1.0"?>

<!--
Suricatoos Premium PDF - Vulnerability Assessment Report (v2, redesign).

Transforms a GVM report XML into a premium, pentest-style LaTeX document that
is compiled to PDF with pdflatex. Findings are GROUPED BY NVT (Muenchian
grouping) so each unique vulnerability appears once, with every affected
host:port instance listed together.

Copyright (C) 2010-2019 Greenbone AG
Copyright (C) 2026 Suricatoos
SPDX-License-Identifier: GPL-2.0-or-later
-->

<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func="http://exslt.org/functions"
    xmlns:str="http://exslt.org/strings"
    xmlns:gvm="http://greenbone.net"
    xmlns:date="http://exslt.org/dates-and-times"
    extension-element-prefixes="str func date gvm">
  <xsl:output method="text" encoding="string" indent="no"/>
  <xsl:strip-space elements="*"/>

  <!-- Group all result elements by their NVT oid (Muenchian grouping). -->
  <xsl:key name="by-nvt" match="result" use="nvt/@oid"/>
  <!-- Composite key to de-duplicate a vulnerability's affected systems: the same
       NVT often fires many times on one host:port (e.g. one advisory per package),
       which would otherwise list that host:port repeatedly. -->
  <xsl:key name="by-nvt-hostport" match="result" use="concat(nvt/@oid, '|', host/text(), '|', port)"/>

  <!-- ================================================================= -->
  <!-- Helper functions                                                  -->
  <!-- ================================================================= -->

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
  <!-- Date formatting                                                   -->
  <!-- ================================================================= -->

  <xsl:template match="scan_start" name="format-date">
    <xsl:param name="date" select="."/>
    <xsl:if test="string-length($date)">
      <xsl:value-of select="concat(date:day-abbreviation($date), ' ', date:month-abbreviation($date), ' ', date:day-in-month($date), ', ', date:year($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ' ', gvm:timezone-abbrev())"/>
    </xsl:if>
  </xsl:template>

  <xsl:template match="scan_end">
    <xsl:param name="date" select="."/>
    <xsl:if test="string-length($date)">
      <xsl:value-of select="concat(date:day-abbreviation($date), ' ', date:month-abbreviation($date), ' ', date:day-in-month($date), ', ', date:year($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ' ', gvm:timezone-abbrev())"/>
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
       derived from the numeric severity, matching the GSA severity classes. -->
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

  <!-- A small filled severity pill: class word + CVSS score, derived from the
       numeric severity. -->
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
    <xsl:value-of select="$class"/>
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

% ---- Branded running header / footer ----
\fancypagestyle{surfancy}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{0.7pt}%
  \renewcommand{\footrulewidth}{0.4pt}%
  \renewcommand{\headrule}{{\color{surIndigo}\hrule height \headrulewidth}}%
  \renewcommand{\footrule}{{\color{surBorder}\hrule height \footrulewidth}}%
  \fancyhead[L]{\raisebox{-1.8mm}{\includegraphics[height=5mm]{suricatoos-mark-navy}}\hspace{2mm}{\bfseries\color{surInk}Suricatoos}}%
  \fancyhead[R]{{\footnotesize\color{surMuted}Vulnerability Assessment Report}}%
  \fancyfoot[L]{{\footnotesize\color{surMuted}\bfseries CONFIDENTIAL}}%
  \fancyfoot[C]{{\footnotesize\color{surMuted}Suricatoos Security Platform}}%
  \fancyfoot[R]{{\footnotesize\color{surMuted}Page \thepage\ of \pageref{LastPage}}}%
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
\hypersetup{colorlinks=true,linkcolor=surIndigo,urlcolor=surIndigo,citecolor=surIndigo,bookmarks=true,bookmarksopen=true,pdftitle={Suricatoos Vulnerability Assessment Report},pdfauthor={Suricatoos Security Platform}}
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
    {\sffamily\bfseries\large VULNERABILITY ASSESSMENT};
  \node[anchor=north west,xshift=22mm,yshift=-83mm] at (current page.north west)
    {\color{surIndigo}\rule{40mm}{1.3pt}};
  \node[anchor=north west,xshift=21mm,yshift=-89mm,text=white,text width=172mm] at (current page.north west)
    {\sffamily\bfseries\fontsize{31}{36}\selectfont Vulnerability\\Assessment Report};
  \node[anchor=north west,xshift=22mm,yshift=-124mm,text=surCloud,text width=164mm] at (current page.north west)
    {\sffamily\large Prepared by the Suricatoos Security Platform};
  \node[anchor=south west,xshift=22mm,yshift=40mm,fill=surSurface,rounded corners=2mm,
        inner sep=5mm,draw=surBorder,line width=0.5pt] at (current page.south west)
    {\sffamily\renewcommand{\arraystretch}{1.55}%
     \begin{tabular}{@{}m{34mm}@{\hspace{4mm}}m{102mm}@{}}
     \textcolor{surIndigoLt}{\scriptsize\bfseries ENGAGEMENT}&amp;{\color{white}</xsl:text>
       <xsl:value-of select="$task_escaped"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries HOSTS ASSESSED}&amp;{\color{white}</xsl:text>
       <xsl:value-of select="count(gvm:report()/host)"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries SCAN STARTED}&amp;{\color{white}</xsl:text>
       <xsl:apply-templates select="gvm:report()/scan_start"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries SCAN COMPLETED}&amp;{\color{white}</xsl:text>
       <xsl:apply-templates select="gvm:report()/scan_end"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries REPORT DATE}&amp;{\color{white}\today}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries CLASSIFICATION}&amp;{\color{white}Confidential}\\
     \end{tabular}};
  \fill[surIndigo] (current page.south west) rectangle ([yshift=14mm]current page.south east);
  \node[anchor=west,xshift=22mm,text=white] at ([yshift=7mm]current page.south west)
    {\sffamily\footnotesize\bfseries CONFIDENTIAL};
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
    <xsl:variable name="total" select="count(gvm:report()/results/result)"/>
    <xsl:variable name="rated" select="$crit + $high + $med + $low"/>
    <xsl:variable name="uniq" select="count(gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])])"/>

    <!-- Overall risk rating derivation -->
    <xsl:variable name="riskWord">
      <xsl:choose>
        <xsl:when test="$crit &gt; 0">CRITICAL</xsl:when>
        <xsl:when test="$high &gt; 0">HIGH</xsl:when>
        <xsl:when test="$med &gt; 0">MEDIUM</xsl:when>
        <xsl:when test="$low &gt; 0">LOW</xsl:when>
        <xsl:otherwise>INFORMATIONAL</xsl:otherwise>
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

    <xsl:text>\section{Executive Summary}
</xsl:text>

    <!-- Narrative -->
    <xsl:text>This report presents the findings of a vulnerability assessment performed by the Suricatoos Security Platform. The engagement ``</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="gvm:report()/task/name"/>
    </xsl:call-template>
    <xsl:text>'' assessed </xsl:text>
    <xsl:value-of select="$hosts"/>
    <xsl:text> host(s) and produced </xsl:text>
    <xsl:value-of select="$total"/>
    <xsl:text> result(s), corresponding to </xsl:text>
    <xsl:value-of select="$uniq"/>
    <xsl:text> unique vulnerabilit</xsl:text>
    <xsl:choose><xsl:when test="$uniq = 1">y</xsl:when><xsl:otherwise>ies</xsl:otherwise></xsl:choose>
    <xsl:text>. Of these, \textbf{</xsl:text>
    <xsl:value-of select="$crit + $high"/>
    <xsl:text>} finding(s) are of High or Critical severity and warrant prompt remediation. The overall risk exposure of the assessed environment is rated \textbf{</xsl:text>
    <xsl:value-of select="$riskWord"/>
    <xsl:text>}.\par
\vspace{4mm}
</xsl:text>

    <!-- Risk badge + key metrics row -->
    <xsl:text>\begin{center}
\begin{tikzpicture}[x=1mm,y=1mm]
\begin{scope}
\clip[rounded corners=2mm] (0,0) rectangle (66,26);
\fill[</xsl:text><xsl:value-of select="$riskColor"/><xsl:text>] (0,0) rectangle (66,26);
\end{scope}
\node[anchor=north west,text=white] at (5,22.5) {\scriptsize\bfseries OVERALL RISK RATING};
\node[anchor=west,text=white] at (5,10) {\fontsize{20}{20}\selectfont\bfseries </xsl:text><xsl:value-of select="$riskWord"/><xsl:text>};
</xsl:text>
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="69"/>
      <xsl:with-param name="xr" select="99"/>
      <xsl:with-param name="value" select="$hosts"/>
      <xsl:with-param name="label">HOSTS ASSESSED</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="102"/>
      <xsl:with-param name="xr" select="132"/>
      <xsl:with-param name="value" select="$total"/>
      <xsl:with-param name="label">TOTAL FINDINGS</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="metric-tile">
      <xsl:with-param name="xl" select="135"/>
      <xsl:with-param name="xr" select="165"/>
      <xsl:with-param name="value" select="$uniq"/>
      <xsl:with-param name="label">UNIQUE VULNS</xsl:with-param>
    </xsl:call-template>
    <xsl:text>\end{tikzpicture}
\end{center}
\vspace{5mm}
</xsl:text>

    <!-- Severity breakdown chart (pgfplots) -->
    <xsl:text>{\color{surInk}\bfseries Findings by severity}\par\vspace{2mm}
</xsl:text>
    <xsl:choose>
      <xsl:when test="$crit + $high + $med + $low = 0">
        <xsl:text>{\color{surMuted}No findings above informational severity were recorded for this assessment.}\par
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
{\color{surInk}\bfseries Assessment timeline}\par\vspace{1.5mm}
\renewcommand{\arraystretch}{1.4}
\begin{tabular}{@{}l@{\hspace{8mm}}l@{}}
{\color{surMuted}\footnotesize\bfseries SCAN STARTED} &amp; {\color{surInk}</xsl:text>
    <xsl:apply-templates select="gvm:report()/scan_start"/>
    <xsl:text>} \\
{\color{surMuted}\footnotesize\bfseries SCAN COMPLETED} &amp; {\color{surInk}</xsl:text>
    <xsl:apply-templates select="gvm:report()/scan_end"/>
    <xsl:text>} \\
{\color{surMuted}\footnotesize\bfseries REPORT GENERATED} &amp; {\color{surInk}\today} \\
\end{tabular}\par
</xsl:text>
  </xsl:template>

  <!-- ================================================================= -->
  <!-- Findings summary table (grouped by NVT)                           -->
  <!-- ================================================================= -->

  <xsl:template name="findings-summary">
    <xsl:variable name="rated" select="count(gvm:report()/results/result[number(severity) &gt;= 0.1])"/>
    <xsl:text>\section{Findings Summary}
</xsl:text>
    <xsl:text>The table below lists every unique vulnerability identified during the assessment, ordered by severity. Each vulnerability is analysed in detail in the following section.\par
\vspace{3mm}
</xsl:text>
    <xsl:text>\renewcommand{\arraystretch}{1.35}
\begin{longtable}{@{}p{9mm} p{92mm} p{15mm} p{35mm}@{}}
\rowcolor{surInk}
\textcolor{white}{\bfseries \#} &amp; \textcolor{white}{\bfseries Vulnerability} &amp; \textcolor{white}{\bfseries Inst.} &amp; \textcolor{white}{\bfseries Severity} \\
\endfirsthead
\rowcolor{surInk}
\textcolor{white}{\bfseries \#} &amp; \textcolor{white}{\bfseries Vulnerability} &amp; \textcolor{white}{\bfseries Inst.} &amp; \textcolor{white}{\bfseries Severity} \\
\endhead
</xsl:text>
    <xsl:for-each select="gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])]">
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
      <xsl:text>{\bfseries </xsl:text><xsl:value-of select="position()"/><xsl:text>} &amp; </xsl:text>
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

  <xsl:template name="detailed-findings">
    <xsl:text>\section{Detailed Findings}
</xsl:text>
    <xsl:for-each select="gvm:report()/results/result[generate-id() = generate-id(key('by-nvt', nvt/@oid)[1])]">
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
      <xsl:text>{\setlength{\fboxsep}{2.2pt}\colorbox{surCloud}{\color{surInk}\scriptsize\bfseries~</xsl:text>
      <xsl:value-of select="$instances"/>
      <xsl:text> instance(s)~}}</xsl:text>

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
        <xsl:text>\fieldlabel{CVSS Vector}{\ttfamily\footnotesize </xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="$vector"/>
        </xsl:call-template>
        <xsl:text>}\par
</xsl:text>
      </xsl:if>

      <!-- Summary / Impact / Insight -->
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label">Summary</xsl:with-param>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('summary')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label">Impact</xsl:with-param>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('impact')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label">Insight</xsl:with-param>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('insight')"/>
      </xsl:call-template>
      <xsl:call-template name="finding-field">
        <xsl:with-param name="label">Affected Software / OS</xsl:with-param>
        <xsl:with-param name="value" select="gvm:get-nvt-tag('affected')"/>
      </xsl:call-template>

      <!-- Affected systems (UNIQUE host:port instances of this NVT, capped) -->
      <xsl:variable name="uniqhosts" select="key('by-nvt', $oid)[generate-id() = generate-id(key('by-nvt-hostport', concat($oid, '|', host/text(), '|', port))[1])]"/>
      <xsl:text>\fieldlabel{Affected Systems}</xsl:text>
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
        <xsl:text> more)}</xsl:text>
      </xsl:if>
      <xsl:text>\par
</xsl:text>

      <!-- Detection result (representative) -->
      <xsl:if test="string-length(normalize-space(description)) &gt; 0">
        <xsl:text>\fieldlabel{Detection Result}%
\begin{tcolorbox}[enhanced, colback=surMist, colframe=surBorderLt, boxrule=0.4pt,
  arc=0.8mm, left=2.5mm, right=2.5mm, top=1.6mm, bottom=1.6mm, before skip=1mm, after skip=1mm]
{\ttfamily\footnotesize\color{surInk} </xsl:text>
        <xsl:call-template name="escape_lines">
          <xsl:with-param name="string" select="substring(description, 1, 1500)"/>
        </xsl:call-template>
        <xsl:if test="string-length(description) &gt; 1500">
          <xsl:text> \newline \textmd{\itshape [output truncated]}</xsl:text>
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
        <xsl:text>\fieldlabel{Solution / Remediation}%
\begin{tcolorbox}[enhanced, colback=gvm_note!8!white, colframe=gvm_note!55!white, boxrule=0.5pt,
  arc=0.8mm, left=2.5mm, right=2.5mm, top=1.6mm, bottom=1.6mm, before skip=1mm, after skip=1mm]
{\color{surInk}</xsl:text>
        <xsl:if test="string-length(nvt/solution/@type) &gt; 0">
          <xsl:text>{\bfseries </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="nvt/solution/@type"/>
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
        <xsl:text>\fieldlabel{References}%
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

  <xsl:template name="branded-footer">
    <xsl:text>
\vspace{6mm}
\begin{center}
{\color{surBorderLt}\rule{\textwidth}{0.4pt}}\\[2.5mm]
\raisebox{-1.5mm}{\includegraphics[height=6mm]{suricatoos-mark-navy}}\quad{\bfseries\color{surInk}\large Suricatoos Security Platform}\\[1.5mm]
{\footnotesize\color{surMuted}This report was generated automatically by the Suricatoos vulnerability management platform.\\
CONFIDENTIAL --- distribute on a need-to-know basis.}
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
