<?xml version="1.0"?>

<!--
Copyright (C) 2010-2019 Greenbone AG

SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
-->

<!-- Stylesheet to transform result (report) xml to latex.

TODOS: Solve Whitespace/Indentation problem of this file.
-->

<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func = "http://exslt.org/functions"
    xmlns:str="http://exslt.org/strings"
    xmlns:gvm="http://greenbone.net"
    xmlns:date="http://exslt.org/dates-and-times"
    extension-element-prefixes="str func date gvm">
  <xsl:output method="text" encoding="string" indent="no"/>
  <xsl:strip-space elements="*"/>

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

  <func:function name="gvm:get-nvt-tag">
    <xsl:param name="tags"/>
    <xsl:param name="name"/>
    <xsl:variable name="after">
      <xsl:value-of select="substring-after (nvt/tags, concat ($name, '='))"/>
    </xsl:variable>
    <xsl:choose>
        <xsl:when test="contains ($after, '|')">
          <func:result select="substring-before ($after, '|')"/>
        </xsl:when>
        <xsl:otherwise>
          <func:result select="$after"/>
        </xsl:otherwise>
    </xsl:choose>
  </func:function>

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

  <xsl:template match="scan_start" name="format-date">
    <xsl:param name="date" select="."/>
    <xsl:if test="string-length ($date)">
      <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' ', gvm:timezone-abbrev ())"/>
    </xsl:if>
  </xsl:template>

  <xsl:template match="scan_end">
    <xsl:param name="date" select="."/>
    <xsl:if test="string-length ($date)">
      <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' ', gvm:timezone-abbrev ())"/>
    </xsl:if>
  </xsl:template>

  <!-- A newline, after countless failed tries to define a newline-entity. -->
  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>


<!-- TEMPLATES MATCHING LATEX COMMANDS -->

  <!-- Simple Latex Context. -->
  <xsl:template name="latex-simple-command">
    <xsl:param name="command"/>
    <xsl:param name="content"/>
    <xsl:text>\</xsl:text>
    <xsl:value-of select="command"/>
    <xsl:text>{</xsl:text>
    <xsl:value-of select="$content"/>
    <xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Latex Label. -->
  <xsl:template name="latex-label">
    <xsl:param name="label_string"/>
    <xsl:text>\label{</xsl:text><xsl:value-of select="$label_string"/><xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Latex Section. -->
  <xsl:template name="latex-section">
    <xsl:param name="section_string"/>
    <xsl:text>\section{</xsl:text><xsl:value-of select="$section_string"/><xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Latex Subsection. -->
  <xsl:template name="latex-subsection">
    <xsl:param name="subsection_string"/>
    <xsl:text>\subsection{</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="$subsection_string"/>
    </xsl:call-template>
    <xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Latex Subsubsection. -->
  <xsl:template name="latex-subsubsection">
    <xsl:param name="subsubsection_string"/>
    <xsl:text>\subsubsection{</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="$subsubsection_string"/>
    </xsl:call-template>
    <xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- \\ -->
  <xsl:template name="latex-newline">
    <xsl:text>\\</xsl:text><xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Latex \hline command. -->
  <xsl:template name="latex-hline">
    <xsl:text>\hline</xsl:text><xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Latex \hyperref command. -->
  <xsl:template name="latex-hyperref">
    <xsl:param name="target"/>
    <xsl:param name="text"/>
    <xsl:text>\hyperref[</xsl:text>
    <xsl:value-of select="$target"/>
    <xsl:text>]{</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="$text"/>
    </xsl:call-template>
    <xsl:text>}</xsl:text>
  </xsl:template>

<!-- BUILDING- BLOCK- TEMPLATES -->

  <!-- The longtable block to defined what to print if a page break falls
       within a table. -->
  <xsl:template name="longtable-continue-block">
    <xsl:param name="number-of-columns"/>
    <xsl:param name="header-color"/>
    <xsl:param name="header-text"/>
    <xsl:text>\rowcolor{</xsl:text><xsl:value-of select="$header-color"/><xsl:text>}</xsl:text><xsl:value-of select="$header-text"/>
    <xsl:call-template name="latex-newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\endfirsthead</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>\multicolumn{</xsl:text><xsl:value-of select="$number-of-columns"/><xsl:text>}{l}{\hfill\ldots (continued) \ldots}</xsl:text>
    <xsl:call-template name="latex-newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\rowcolor{</xsl:text><xsl:value-of select="$header-color"/><xsl:text>}</xsl:text><xsl:value-of select="$header-text"/>
    <xsl:call-template name="latex-newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\endhead</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\multicolumn{</xsl:text><xsl:value-of select="$number-of-columns"/><xsl:text>}{l}{\ldots (continues) \ldots}</xsl:text><xsl:call-template name="latex-newline"/>
    <xsl:text>\endfoot</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\endlastfoot</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="latex-hline"/>
  </xsl:template>

  <!-- The latex header (Suricatoos premium preamble). -->
  <xsl:template name="header">
    <xsl:text>\documentclass[11pt]{article}

\usepackage{tabularx}
\usepackage{geometry}
\usepackage{comment}
\usepackage{longtable}
\usepackage{titlesec}
\usepackage{chngpage}
\usepackage{calc}
\usepackage{url}
\usepackage[utf8x]{inputenc}

% Font setup -- clean corporate sans (Helvetica-like)
\usepackage[T1]{fontenc}
\usepackage{textcomp}
\usepackage{helvet}
\renewcommand{\familydefault}{\sfdefault}

\DeclareUnicodeCharacter {135}{{\textascii ?}}
\DeclareUnicodeCharacter {129}{{\textascii ?}}
\DeclareUnicodeCharacter {128}{{\textascii ?}}

\usepackage{colortbl}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{tikz}
\usepackage{fancyhdr}
\usepackage{lastpage}

% ---- Suricatoos brand palette ----
\definecolor{surNavy}{rgb}{0.031,0.055,0.090}
\definecolor{surNavyTwo}{rgb}{0.047,0.086,0.133}
\definecolor{surSurface}{rgb}{0.075,0.125,0.180}
\definecolor{surIndigo}{rgb}{0.357,0.486,0.980}
\definecolor{surIndigoLt}{rgb}{0.490,0.592,1.0}
\definecolor{surBorder}{rgb}{0.133,0.204,0.290}
\definecolor{surInk}{rgb}{0.059,0.094,0.145}
\definecolor{surMuted}{rgb}{0.361,0.420,0.478}
\definecolor{surCloud}{rgb}{0.937,0.953,0.965}

% ---- Severity / GVM machinery colours (names kept for the findings engine) ----
\definecolor{linkblue}{rgb}{0.357,0.486,0.980}
\definecolor{inactive}{rgb}{0.56,0.56,0.56}
\definecolor{gvm_debug}{rgb}{0.78,0.78,0.78}
\definecolor{gvm_false_positive}{rgb}{0.2275,0.2275,0.2275}
\definecolor{gvm_log}{rgb}{0.2275,0.2275,0.2275}
\definecolor{gvm_critical}{rgb}{0.749,0.0,0.0}
\definecolor{gvm_hole}{rgb}{0.796,0.1137,0.0902}
\definecolor{gvm_note}{rgb}{0.247,0.561,0.820}
\definecolor{gvm_report}{rgb}{0.808,0.851,1.0}
\definecolor{gvm_user_note}{rgb}{1.0,0.973,0.733}
\definecolor{gvm_user_override}{rgb}{1.0,0.973,0.733}
\definecolor{gvm_warning}{rgb}{0.9764,0.6235,0.1922}
\definecolor{chunk}{rgb}{0.9412,0.8275,1}
\definecolor{line_new}{rgb}{0.89,1,0.89}
\definecolor{line_gone}{rgb}{1.0,0.89,0.89}

% ---- Page geometry leaving room for the branded header / footer ----
\geometry{a4paper,top=28mm,bottom=24mm,left=22mm,right=22mm,headheight=11mm,headsep=6mm,footskip=13mm}
\setlength{\parskip}{\smallskipamount}
\setlength{\parindent}{0pt}

% ---- Branded running header / footer ----
\fancypagestyle{surfancy}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{0.7pt}%
  \renewcommand{\footrulewidth}{0.4pt}%
  \renewcommand{\headrule}{{\color{surIndigo}\hrule height \headrulewidth}}%
  \renewcommand{\footrule}{{\color{surBorder}\hrule height \footrulewidth}}%
  \fancyhead[L]{\raisebox{-1.6mm}{\includegraphics[height=5mm]{suricatoos-mark-navy}}\hspace{2mm}{\bfseries\color{surInk}Suricatoos}}%
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

% must come last
\usepackage{hyperref}
\hypersetup{colorlinks=true,linkcolor=surIndigo,urlcolor=surIndigo,citecolor=surIndigo,bookmarks=true,bookmarksopen=true,pdftitle={Suricatoos Vulnerability Assessment Report},pdfauthor={Suricatoos Security Platform}}
\usepackage[all]{hypcap}
\pagenumbering{arabic}
</xsl:text>
  </xsl:template>

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
      $string,
      '$', '\$'),
      '_', '\_'),
      '%', '\%'),
      '&amp;','\&amp;'),
      '#', '\#'),
      '}', '\}'),
      '{', '\}'),
      '^', '\^{}')"/>
  </xsl:template>

  <!-- Escape text for normal latex environment. Following characters get a
       prepended backslash: #$%&_^{} -->
  <xsl:template name="escape_text">
    <xsl:param name="string"/>
    <!-- Replace backslashes and $'s .-->
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

  <!-- Create a verbatim indented row. -->
  <xsl:template name="wrap-row-indented">
    <xsl:param name="line"/>
    <xsl:param name="color">white</xsl:param>
    <xsl:text>\rowcolor{</xsl:text>
    <xsl:value-of select="$color"/>
    <xsl:text>}{$\hookrightarrow$\verb=</xsl:text>
    <xsl:value-of select="str:replace($line, '=', '=\verb-=-\verb=')"/>
    <!-- Inline latex-newline for speed. -->
    <xsl:text>=}\\
</xsl:text>
  </xsl:template>

  <!-- Create a verbatim row. -->
  <!-- This is called very often, and is relatively slow. -->
  <xsl:template name="wrap-row">
    <xsl:param name="line"/>
    <xsl:text>\rowcolor{white}{\verb=</xsl:text>
    <xsl:value-of select="str:replace($line, '=', '=\verb-=-\verb=')"/>
    <!-- Inline latex-newline for speed. -->
    <xsl:text>=}\\
</xsl:text>
  </xsl:template>

  <!-- Create a verbatim row. -->
  <!-- This is called very often, and is relatively slow. -->
  <xsl:template name="wrap-row-color">
    <xsl:param name="line"/>
    <xsl:param name="color">white</xsl:param>
    <xsl:text>\rowcolor{</xsl:text>
    <xsl:value-of select="$color"/>
    <xsl:text>}{\verb=</xsl:text>
    <xsl:value-of select="str:replace($line, '=', '=\verb-=-\verb=')"/>
    <!-- Inline latex-newline for speed. -->
    <xsl:text>=}\\
</xsl:text>
  </xsl:template>

  <!-- Takes a string that does not contain a newline char and outputs $max
       characters long lines. -->
  <xsl:template name="break-into-rows-indented">
    <xsl:param name="string"/>
    <xsl:variable name="head" select="substring($string, 1, 78)"/>
    <xsl:variable name="tail" select="substring($string, 79)"/>
    <xsl:if test="string-length($head) &gt; 0">
      <xsl:call-template name="wrap-row-indented">
        <xsl:with-param name="line" select="$head"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:if test="string-length($tail) &gt; 0">
      <xsl:call-template name="break-into-rows-indented">
        <xsl:with-param name="string" select="$tail"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Takes a string that does not contain a newline char and outputs $max
       characters long lines. -->
  <xsl:template name="break-into-rows-indented-color">
    <xsl:param name="string"/>
    <xsl:param name="color">white</xsl:param>
    <xsl:variable name="head" select="substring($string, 1, 78)"/>
    <xsl:variable name="tail" select="substring($string, 79)"/>
    <xsl:if test="string-length($head) &gt; 0">
      <xsl:call-template name="wrap-row-indented">
        <xsl:with-param name="line" select="$head"/>
        <xsl:with-param name="color" select="$color"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:if test="string-length($tail) &gt; 0">
      <xsl:call-template name="break-into-rows-indented-color">
        <xsl:with-param name="string" select="$tail"/>
        <xsl:with-param name="color" select="$color"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Takes a string that does not contain a newline char and outputs $max
       characters long lines. -->
  <xsl:template name="break-into-rows">
    <xsl:param name="string"/>
    <xsl:variable name="head" select="substring($string, 1, 80)"/>
    <xsl:variable name="tail" select="substring($string, 81)"/>
    <xsl:if test="string-length($head) &gt; 0">
      <xsl:call-template name="wrap-row">
        <xsl:with-param name="line" select="$head"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:if test="string-length($tail) &gt; 0">
      <xsl:call-template name="break-into-rows-indented">
        <xsl:with-param name="string" select="$tail"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Takes a string that does not contain a newline char and outputs $max
       characters long lines. -->
  <xsl:template name="break-into-rows-color">
    <xsl:param name="string"/>
    <xsl:param name="color">white</xsl:param>
    <xsl:variable name="head" select="substring($string, 1, 80)"/>
    <xsl:variable name="tail" select="substring($string, 81)"/>
    <xsl:if test="string-length($head) &gt; 0">
      <xsl:call-template name="wrap-row-color">
        <xsl:with-param name="line" select="$head"/>
        <xsl:with-param name="color" select="$color"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:if test="string-length($tail) &gt; 0">
      <xsl:call-template name="break-into-rows-indented-color">
        <xsl:with-param name="string" select="$tail"/>
        <xsl:with-param name="color" select="$color"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Currently only a very simple formatting method to produce
       nice LaTeX from a structured text:
       - create paragraphs for each text block separated with a empty line
  -->
  <xsl:template name="structured-text">
    <xsl:param name="string"/>
  
    <xsl:for-each select="str:split($string, '&#10;&#10;')">
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="."/>
      </xsl:call-template>
      <xsl:call-template name="latex-newline"/>
    </xsl:for-each>
  </xsl:template>

  <!-- -->
  <xsl:template name="text-to-escaped-row">
    <xsl:param name="string"/>
    <xsl:for-each select="str:tokenize($string, '&#10;')">
      <xsl:call-template name="break-into-rows">
        <xsl:with-param name="string" select="."/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- -->
  <xsl:template name="text-to-escaped-row-color">
    <xsl:param name="string"/>
    <xsl:param name="color">white</xsl:param>
    <xsl:for-each select="str:tokenize($string, '&#10;')">
      <xsl:call-template name="break-into-rows-color">
        <xsl:with-param name="string" select="."/>
        <xsl:with-param name="color" select="$color"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- -->
  <xsl:template name="text-to-escaped-diff-row">
    <xsl:param name="string"/>
    <xsl:for-each select="str:tokenize($string, '&#10;')">
      <xsl:call-template name="break-into-rows-color">
        <xsl:with-param name="string" select="."/>
        <xsl:with-param name="color">
          <xsl:choose>
            <xsl:when test="substring(., 1, 2) = '@@'">chunk</xsl:when>
            <xsl:when test="substring(., 1, 1) = '-'">line_gone</xsl:when>
            <xsl:when test="substring(., 1, 1) = '+'">line_new</xsl:when>
            <xsl:otherwise>white</xsl:otherwise>
          </xsl:choose>
        </xsl:with-param>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- The Abstract. -->
  <xsl:template name="abstract">
    <xsl:choose>
      <xsl:when test="gvm:report()/delta and gvm:report()/report_format/param[name='summary']">
        <xsl:text>
\renewcommand{\abstractname}{Delta Report Summary}
\begin{abstract}
</xsl:text>
        <xsl:value-of select="gvm:report()/report_format/param[name='summary']/value"/>
        <xsl:text>
\end{abstract}
</xsl:text>
      </xsl:when>
      <xsl:when test="gvm:report()/report_format/param[name='summary']">
        <xsl:text>
\renewcommand{\abstractname}{Summary}
\begin{abstract}
</xsl:text>
        <xsl:value-of select="gvm:report()/report_format/param[name='summary']/value"/>
        <xsl:text>
\end{abstract}
</xsl:text>
      </xsl:when>
      <xsl:when test="gvm:report()/delta">
        <xsl:text>
\renewcommand{\abstractname}{Delta Report Summary}
\begin{abstract}
This document compares the results of two security scans.
All dates are displayed using the timezone ``</xsl:text>
        <xsl:value-of select="timezone"/>
        <xsl:text>'', which is abbreviated ``</xsl:text>
        <xsl:value-of select="timezone_abbrev"/>
        <xsl:text>''.
The task was ``</xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="/report/task/name"/>
        </xsl:call-template>
        <xsl:text>''.  The first scan started at </xsl:text>
        <xsl:apply-templates select="scan_start"/>
<xsl:text> and ended at </xsl:text>
          <xsl:value-of select="scan_end"/>
<xsl:text>.
The second scan started at </xsl:text>
        <xsl:apply-templates select="delta/report/scan_start"/>
<xsl:text> and ended at </xsl:text>
        <xsl:apply-templates select="delta/report/scan_end"/>
<xsl:text>.
The report first summarises the hosts found.  Then, for each host,
the report describes the changes that occurred between the two scans.
\end{abstract}
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>
\renewcommand{\abstractname}{Summary}
\begin{abstract}
This document reports on the results of an automatic security scan.
All dates are displayed using the timezone ``</xsl:text>
        <xsl:value-of select="timezone"/>
        <xsl:text>'', which is abbreviated ``</xsl:text>
        <xsl:value-of select="timezone_abbrev"/>
        <xsl:text>''.
The task was ``</xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="/report/task/name"/>
        </xsl:call-template>
        <xsl:text>''.  The scan started at </xsl:text>
        <xsl:apply-templates select="scan_start"/>
<xsl:text> and ended at </xsl:text>
        <xsl:apply-templates select="scan_end"/>
<xsl:text>.  The
report first summarises the results found.  Then, for each host,
the report describes every issue found.  Please consider the
advice given in each description, in order to rectify the issue.
\end{abstract}
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- The Table of Contents. -->
  <xsl:template name="toc">
    <xsl:text>\tableofcontents</xsl:text><xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Row in table with count of issues for a single host. -->
  <xsl:template name="results-overview-table-single-host-row">
    <xsl:variable name="host" select="ip"/>
    <xsl:variable name="hostname" select="detail[name/text() = 'hostname']/value"/>
    <xsl:call-template name="latex-hyperref">
      <xsl:with-param name="target" select="concat('host:',$host)"/>
      <xsl:with-param name="text" select="$host"/>
    </xsl:call-template>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='Critical'])"/>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='High'])"/>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='Medium'])"/>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='Low'])"/>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='Log'])"/>
    <xsl:text>&amp;</xsl:text>
    <xsl:value-of select="count(../results/result[host/text()=$host][threat/text()='False P.'])"/>
    <xsl:call-template name="latex-newline"/>
    <xsl:choose>
      <xsl:when test="$hostname">
        <xsl:call-template name="latex-hyperref">
          <xsl:with-param name="target" select="concat('host:',$host)"/>
          <xsl:with-param name="text" select="$hostname"/>
        </xsl:call-template>
        <xsl:text>&amp;&amp;&amp;&amp;&amp;&amp;</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="latex-hline"/>
  </xsl:template>

  <xsl:template name="auth-success-row">
    <xsl:variable name="host" select="./ip"/>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SSH-Success']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SSH</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Success</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SSH-Failure']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SSH</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Failure</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SMB-Success']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SMB</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Success</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SMB-Failure']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SMB</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Failure</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-ESXi-Success']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>ESXi</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Success</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-ESXi-Failure']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>ESXi</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Failure</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SNMP-Success']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SNMP</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Success</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SNMP-Failure']">
      <xsl:value-of select="$host"/>
      <xsl:choose>
        <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
          <xsl:text> - </xsl:text>
          <xsl:call-template name="escape_text">
            <xsl:with-param name="string" select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
          </xsl:call-template>
        </xsl:when>
      </xsl:choose>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>SNMP</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:text>Failure</xsl:text>
      <xsl:text> &amp; </xsl:text>
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="value/text()"/>
      </xsl:call-template>
      <xsl:text>\\ \hline</xsl:text>
    </xsl:for-each>
  </xsl:template>

  <!-- The Results Overview section. -->
  <xsl:template name="results-overview">
    <xsl:call-template name="latex-section">
      <xsl:with-param name="section_string">Result Overview</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <xsl:text>\begin{longtable}{|l|l|l|l|l|l|l|}</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:call-template name="longtable-continue-block">
      <xsl:with-param name="number-of-columns">7</xsl:with-param>
      <xsl:with-param name="header-color">gvm_report</xsl:with-param>
      <xsl:with-param name="header-text">Host&amp;Critical&amp;High&amp;Medium&amp;Low&amp;Log&amp;False P.</xsl:with-param>
    </xsl:call-template>
    <xsl:for-each select="host"><xsl:call-template name="results-overview-table-single-host-row"/></xsl:for-each>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>Total: </xsl:text>
    <xsl:value-of select="count(gvm:report()/host)"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'Critical'])"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'High'])"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'Medium'])"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'Low'])"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'Log'])"/>&amp;<xsl:value-of select="count(gvm:report()/results/result[threat = 'False Positive'])"/><xsl:call-template name="latex-newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:text>\end{longtable}</xsl:text><xsl:call-template name="newline"/>

    <xsl:choose>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='autofp']/value='1'">
        <xsl:text>Vendor security updates are trusted, using full CVE matching.</xsl:text>
      </xsl:when>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='autofp']/value='2'">
        <xsl:text>Vendor security updates are trusted, using partial CVE matching.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Vendor security updates are not trusted.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="latex-newline"/>
    <xsl:choose>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='apply_overrides']/value='1'">
        <xsl:text>Overrides are on.  When a result has an override, this report uses the threat of the override.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Overrides are off.  Even when a result has an override, this report uses the actual threat of the result.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:choose>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='overrides']/value = 0">
        <xsl:text>Information on overrides is excluded from the report.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Information on overrides is included in the report.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:choose>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='notes']/value = 0">
        <xsl:text>Notes are excluded from the report.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Notes are included in the report.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:text>This report might not show details of all issues that were found.</xsl:text><xsl:call-template name="latex-newline"/>
    <xsl:if test="gvm:report()/filters/keywords/keyword[column='result_hosts_only']/value = 1">
      <xsl:text>It only lists hosts that produced issues.</xsl:text><xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="string-length(gvm:report()/filters/phrase) &gt; 0">
      <xsl:text>It shows issues that contain the search phrase "</xsl:text><xsl:value-of select="gvm:report()/filters/phrase"/><xsl:text>".</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'c') = false">
      <xsl:text>Issues with the threat level ``Critical'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'h') = false">
      <xsl:text>Issues with the threat level ``High'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'm') = false">
      <xsl:text>Issues with the threat level ``Medium'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'l') = false">
      <xsl:text>Issues with the threat level ``Low'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'g') = false">
      <xsl:text>Issues with the threat level ``Log'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'd') = false">
      <xsl:text>Issues with the threat level ``Debug'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:if test="contains(gvm:report()/filters/keywords/keyword[column='levels']/value, 'f') = false">
      <xsl:text>Issues with the threat level ``False Positive'' are not shown.</xsl:text>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:choose>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='min_qod']/value = 0">
      </xsl:when>
      <xsl:when test="string-length (gvm:report()/filters/keywords/keyword[column='min_qod']/value) > 0">
        <xsl:text>Only results with a minimum QoD of </xsl:text>
        <xsl:value-of select="gvm:report()/filters/keywords/keyword[column='min_qod']/value"/>
        <xsl:text> are shown.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Only results with a minimum QoD of 70 are shown.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="latex-newline"/>

    <xsl:variable name="last" select="gvm:report()/results/@start + count(gvm:report()/results/result) - 1"/>
    <xsl:choose>
      <xsl:when test="$last = 0">
        <xsl:text>This report contains 0 results.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = gvm:report()/results/@start">
        <xsl:text>This report contains result </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="gvm:report()/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:text> filtering above.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = gvm:report()/result_count/filtered">
        <xsl:text>This report contains all </xsl:text>
        <xsl:value-of select="gvm:report()/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:text> filtering described above.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This report contains results </xsl:text>
        <xsl:value-of select="gvm:report()/results/@start"/>
        <xsl:text> to </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="gvm:report()/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:text> filtering described above.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:choose>
      <xsl:when test="gvm:report()/delta">
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>  Before filtering there were </xsl:text>
        <xsl:value-of select="gvm:report()/result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:choose>
      <xsl:when test="string-length(/report/host/detail[name='Auth-SSH-Success']/value) &gt; 0 or
        string-length(/report/host/detail[name='Auth-SSH-Failure']/value) &gt; 0 or
        string-length(/report/host/detail[name='Auth-SMB-Success']/value) &gt; 0 or
        string-length(/report/host/detail[name='Auth-SMB-Failure']/value) &gt; 0 or
        string-length(/report/host/detail[name='Auth-ESXi-Success']/value) &gt; 0 or
        string-length(/report/host/detail[name='Auth-ESXi-Failure']/value) &gt; 0">
        <xsl:call-template name="latex-subsection"><xsl:with-param name="subsection_string">Host Authentications</xsl:with-param></xsl:call-template>
        <xsl:text>\begin{longtable}{|p{6cm}|l|l|p{6cm}|}</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:call-template name="longtable-continue-block">
          <xsl:with-param name="number-of-columns">4</xsl:with-param>
          <xsl:with-param name="header-color">gvm_report</xsl:with-param>
          <xsl:with-param name="header-text">Host&amp;Protocol&amp;Result&amp;Port/User</xsl:with-param>
        </xsl:call-template>
        <xsl:for-each select="host">
          <xsl:sort select="key('host-by-ip', host)/detail[name='hostname']/value/text()"/>
          <xsl:call-template name="auth-success-row"/>
        </xsl:for-each>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\end{longtable}</xsl:text><xsl:call-template name="newline"/>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- In Host-wise overview row in table. -->
  <xsl:template name="single-host-overview-table-row">
    <xsl:param name="threat"/>
    <xsl:param name="host"/>
    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
        <!--
          port_service must be selected with variable and xsl:value-of element
          to handle empty ports correctly.
        -->
        <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
        <xsl:variable name="port_text">
          <xsl:choose>
            <xsl:when test="$port_service=''">
              <xsl:text>N/A</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$port_service"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:if test="gvm:report()/results/result[host/text()=$host][threat/text()=$threat][port=$port_service]">
          <xsl:call-template name="latex-hyperref">
            <xsl:with-param name="target" select="concat('port:', $host, ' ', $port_service, ' ', $threat)"/>
            <xsl:with-param name="text" select="$port_text"/>
          </xsl:call-template>
          <xsl:text>&amp;</xsl:text><xsl:value-of select="$threat"/><xsl:call-template name="latex-newline"/>
          <xsl:call-template name="latex-hline"/>
        </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- Overview table for subsect. of details of findings for a single host. -->
  <xsl:template name="results-per-host-single-host-port-findings">
    <xsl:variable name="host" select="ip"/>
    <xsl:text>\begin{longtable}{|l|l|}</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="latex-hline"/>
    <xsl:call-template name="longtable-continue-block">
      <xsl:with-param name="number-of-columns">2</xsl:with-param>
      <xsl:with-param name="header-color">gvm_report</xsl:with-param>
      <xsl:with-param name="header-text">Service (Port)&amp;Threat Level</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">Critical</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">High</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">Medium</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">Low</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">Log</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="single-host-overview-table-row">
      <xsl:with-param name="threat">False Positive</xsl:with-param>
      <xsl:with-param name="host" select="$host"/>
    </xsl:call-template>
    <xsl:text>\end{longtable}</xsl:text><xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Table of Closed CVEs for a single host. -->
  <xsl:template name="results-per-host-single-host-closed-cves">
    <xsl:variable name="cves" select="str:split(detail[name = 'Closed CVEs']/value, ',')"/>
    <xsl:choose>
      <xsl:when test="gvm:report()/@type = 'delta'">
      </xsl:when>
      <xsl:when test="gvm:report()/filters/keywords/keyword[column='show_closed_cves']/value = 1">
        <xsl:text>\begin{longtable}{|l|l|}</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:call-template name="longtable-continue-block">
          <xsl:with-param name="number-of-columns">2</xsl:with-param>
          <xsl:with-param name="header-color">gvm_report</xsl:with-param>
          <xsl:with-param name="header-text">Closed CVE&amp;NVT</xsl:with-param>
        </xsl:call-template>
        <xsl:variable name="host" select="."/>
        <xsl:for-each select="$cves">
          <xsl:value-of select="."/>
          <xsl:text>&amp;</xsl:text>
          <xsl:variable name="cve" select="normalize-space(.)"/>
          <xsl:variable name="closed_cve"
                        select="$host/detail[name = 'Closed CVE' and contains(value, $cve)]"/>
          <xsl:value-of select="$closed_cve/source/description"/>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="latex-hline"/>
        </xsl:for-each>
        <xsl:text>\end{longtable}</xsl:text><xsl:call-template name="newline"/>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- Colors for threats. -->
  <xsl:template name="threat-to-color">
    <xsl:param name="threat"/>
    <xsl:choose>
      <xsl:when test="threat='Critical'">gvm_critical</xsl:when>
      <xsl:when test="threat='High'">gvm_hole</xsl:when>
      <xsl:when test="threat='Medium'">gvm_warning</xsl:when>
      <xsl:when test="threat='Low'">gvm_note</xsl:when>
      <xsl:when test="threat='Log'">gvm_log</xsl:when>
      <xsl:when test="threat='False Positive'">gvm_log</xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- Text of threat, Log to empty string. -->
  <xsl:template name="threat-to-severity">
    <xsl:param name="threat"/>
    <xsl:choose>
      <xsl:when test="threat='Low'">Low</xsl:when>
      <xsl:when test="threat='Medium'">Medium</xsl:when>
      <xsl:when test="threat='High'">High</xsl:when>
      <xsl:when test="threat='Critical'">Critical</xsl:when>
      <xsl:when test="threat='Log'"></xsl:when>
      <!-- TODO False Positive -->
    </xsl:choose>
  </xsl:template>

  <!-- References box. -->
  <xsl:template name="references">
    <xsl:if test="count(nvt/refs/ref) &gt; 0">
      \hline
      <xsl:call-template name="latex-newline"/>
      <xsl:text>\textbf{References}</xsl:text>
      <xsl:call-template name="latex-newline"/>

      <xsl:for-each select="nvt/refs/ref">
        <xsl:call-template name="text-to-escaped-row">
          <xsl:with-param name="string" select="concat(@type, ': ', @id)"/>
        </xsl:call-template>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>

  <!-- Text of a note. -->
  <xsl:template name="notes">
    <xsl:param name="delta">0</xsl:param>
    <xsl:if test="count(notes/note [not (active='0')]) &gt; 0">
      <xsl:call-template name="latex-hline"/>
      <xsl:call-template name="latex-newline"/>
    </xsl:if>
    <xsl:for-each select="notes/note [not (active='0')]">
      <xsl:call-template name="latex-newline"/>
      <xsl:text>\rowcolor{gvm_user_note}{\textbf{Note}</xsl:text>
      <xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if>
      <xsl:text>}</xsl:text>\\<xsl:call-template name="latex-newline"/>
      <xsl:call-template name="text-to-escaped-row-color">
        <xsl:with-param name="color" select="'gvm_user_note'"/>
        <xsl:with-param name="string" select="text"/>
      </xsl:call-template>
      <xsl:text>\rowcolor{gvm_user_note}{}</xsl:text><xsl:call-template name="latex-newline"/>
      <xsl:choose>
        <xsl:when test="active='0'">
        </xsl:when>
        <xsl:when test="active='1' and string-length (end_time) &gt; 0">
          <xsl:text>\rowcolor{gvm_user_note}{Active until: </xsl:text>
          <xsl:call-template name="format-date">
            <xsl:with-param name="date" select="end_time"/>
          </xsl:call-template>
          <xsl:text>}</xsl:text><xsl:call-template name="latex-newline"/>
        </xsl:when>
        <xsl:otherwise>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>\rowcolor{gvm_user_note}{Last modified: </xsl:text>
      <xsl:call-template name="format-date">
        <xsl:with-param name="date" select="modification_time"/>
      </xsl:call-template>
      <xsl:text>}</xsl:text><xsl:call-template name="latex-newline"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Text of an override. -->
  <xsl:template name="overrides">
    <xsl:param name="delta">0</xsl:param>
    <xsl:if test="gvm:report()/filters/apply_overrides/text()='1'">
      <xsl:if test="count(overrides/override [not (active='0')]) &gt; 0">
        <xsl:call-template name="latex-hline"/>
        <xsl:call-template name="latex-newline"/>
      </xsl:if>
      <xsl:for-each select="overrides/override [not (active='0')]">
        <xsl:call-template name="latex-newline"/>
        <xsl:text>\rowcolor{gvm_user_override}{\textbf{Override from </xsl:text>
        <xsl:choose>
          <xsl:when test="string-length(threat) = 0">
            <xsl:text>Any</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="threat"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text> to </xsl:text>
        <xsl:value-of select="new_threat"/><xsl:text>}</xsl:text>
        <xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if>
        <xsl:text>}</xsl:text>\\<xsl:call-template name="latex-newline"/>
        <xsl:call-template name="text-to-escaped-row-color">
          <xsl:with-param name="color" select="'gvm_user_override'"/>
          <xsl:with-param name="string" select="text"/>
        </xsl:call-template>
        <xsl:text>\rowcolor{gvm_user_override}{}</xsl:text><xsl:call-template name="latex-newline"/>
        <xsl:choose>
          <xsl:when test="active='0'">
          </xsl:when>
          <xsl:when test="active='1' and string-length (end_time) &gt; 0">
            <xsl:text>\rowcolor{gvm_user_override}{Active until: </xsl:text>
            <xsl:call-template name="format-date">
              <xsl:with-param name="date" select="end_time"/>
            </xsl:call-template>
            <xsl:text>}</xsl:text><xsl:call-template name="latex-newline"/>
          </xsl:when>
          <xsl:otherwise>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>\rowcolor{gvm_user_override}{Last modified: </xsl:text>
        <xsl:call-template name="format-date">
          <xsl:with-param name="date" select="modification_time"/>
        </xsl:call-template>
        <xsl:text>}</xsl:text><xsl:call-template name="latex-newline"/>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>

<!-- SUBSECTION: Results for a single host. -->

  <!-- Overview table for a single host -->
  <xsl:template name="result-details-host-port-threat">
    <xsl:param name="host"/>
    <xsl:param name="port_service"/>
    <xsl:param name="threat"/>
    <xsl:if test="gvm:report()/results/result[host/text()=$host][threat/text()=$threat][port=$port_service]">
      <xsl:call-template name="latex-subsubsection"><xsl:with-param name="subsubsection_string" select="concat ($threat, ' ', $port_service)"/></xsl:call-template>
      <xsl:call-template name="latex-label"><xsl:with-param name="label_string" select="concat('port:', $host, ' ', $port_service, ' ', $threat)"/></xsl:call-template>
      <xsl:call-template name="newline"/>
      <xsl:for-each select="gvm:report()/results/result[host/text()=$host][threat/text()=$threat][port=$port_service]">
        <xsl:text>\begin{longtable}{|p{\textwidth * 1}|}</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\rowcolor{</xsl:text>
        <xsl:call-template name="threat-to-color">
          <xsl:with-param name="threat" select="$threat" />
        </xsl:call-template>
        <xsl:text>}{\color{white}{</xsl:text>
        <xsl:if test="delta/text()">
          <xsl:text>\vspace{3pt}</xsl:text>
          <xsl:text>\hspace{3pt}</xsl:text>
          <xsl:choose>
            <xsl:when test="delta/text() = 'changed'">\begin{LARGE}\sim\end{LARGE}</xsl:when>
            <xsl:when test="delta/text() = 'gone'">\begin{LARGE}&#8722;\end{LARGE}</xsl:when>
            <xsl:when test="delta/text() = 'new'">\begin{LARGE}+\end{LARGE}</xsl:when>
            <xsl:when test="delta/text() = 'same'">\begin{LARGE}=\end{LARGE}</xsl:when>
          </xsl:choose>
          <xsl:text>\hspace{3pt}</xsl:text>
        </xsl:if>
        <xsl:value-of select="$threat"/>
        <xsl:choose>
          <xsl:when test="original_threat">
            <xsl:choose>
              <xsl:when test="threat = original_threat">
                <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
                  <xsl:text> (CVSS: </xsl:text>
                  <xsl:value-of select="nvt/cvss_base"/>
                  <xsl:text>) </xsl:text>
                </xsl:if>
              </xsl:when>
              <xsl:otherwise>
                <xsl:text> (Overridden from </xsl:text>
                <xsl:value-of select="original_threat"/>
                <xsl:text>) </xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:otherwise>
            <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
              <xsl:text> (CVSS: </xsl:text>
              <xsl:value-of select="nvt/cvss_base"/>
              <xsl:text>) </xsl:text>
            </xsl:if>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>}}</xsl:text>
        <xsl:call-template name="latex-newline"/>
        <xsl:text>\rowcolor{</xsl:text>
        <xsl:call-template name="threat-to-color">
          <xsl:with-param name="threat" select="$threat"/>
        </xsl:call-template>
        <xsl:text>}{\color{white}{NVT: </xsl:text>
        <xsl:variable name="name_escaped"><xsl:call-template name="escape_text"><xsl:with-param name="string" select="nvt/name"/></xsl:call-template></xsl:variable>
        <xsl:value-of select="$name_escaped"/>
        <xsl:text>}}</xsl:text>
        <xsl:call-template name="latex-newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\endfirsthead</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>\hfill\ldots continued from previous page \ldots </xsl:text><xsl:call-template name="latex-newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\endhead</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\ldots continues on next page \ldots </xsl:text><xsl:call-template name="latex-newline"/>
        <xsl:text>\endfoot</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:text>\endlastfoot</xsl:text><xsl:call-template name="newline"/>

        <xsl:if test="count (detection)">
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Product detection result}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="text-to-escaped-row">
            <xsl:with-param name="string" select="detection/result/details/detail[name = 'product']/value/text()"/>
          </xsl:call-template>
          <xsl:call-template name="text-to-escaped-row">
            <xsl:with-param name="string" select="concat('Detected by ', detection/result/details/detail[name = 'source_name']/value/text(), ' (OID: ', detection/result/details/detail[name = 'source_oid']/value/text(), ')')"/>
          </xsl:call-template>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="latex-hline"/>
        </xsl:if>

        <!-- Summary -->
        <xsl:if test="string-length (gvm:get-nvt-tag (nvt/tags, 'summary')) &gt; 0">
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Summary}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="gvm:get-nvt-tag (nvt/tags, 'summary')"/>
          </xsl:call-template>
        </xsl:if>

        <!-- QoD -->
        <xsl:if test="qod/value/text() != ''">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Quality of Detection (QoD):} </xsl:text>
          <xsl:value-of select="qod/value/text()"/>
          <xsl:text>\%</xsl:text>
          <xsl:call-template name="latex-newline"/>
        </xsl:if>

        <!-- EPSS -->
        <xsl:if test="nvt/epss">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{EPSS (Maximum severity CVE)} </xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Score:} </xsl:text>
          <xsl:value-of select="nvt/epss/max_severity/score/text()"/>
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Percentile:} </xsl:text>
          <xsl:value-of select="nvt/epss/max_severity/percentile/text()"/>
          <xsl:call-template name="latex-newline"/>
        </xsl:if>

        <!-- Result -->
        <xsl:choose>
          <xsl:when test="delta/text() = 'changed'">
            <xsl:call-template name="latex-newline"/>
            <xsl:text>\textbf{Result 1}</xsl:text>
            <xsl:call-template name="latex-newline"/>
          </xsl:when>
        </xsl:choose>
        \hline
        <xsl:call-template name="latex-newline"/>
        <xsl:text>\textbf{Vulnerability Detection Result}</xsl:text>
        <xsl:call-template name="latex-newline"/>
        <xsl:choose>
          <xsl:when test="string-length(description) &lt; 2">
            <xsl:text>Vulnerability was detected according to the Vulnerability Detection Method.</xsl:text>
            <xsl:call-template name="latex-newline"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="text-to-escaped-row">
              <xsl:with-param name="string" select="description"/>
            </xsl:call-template>
          </xsl:otherwise>
        </xsl:choose>

        <xsl:if test="string-length (gvm:get-nvt-tag (nvt/tags, 'impact')) &gt; 0 and gvm:get-nvt-tag (nvt/tags, 'impact') != 'N/A'">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Impact}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="gvm:get-nvt-tag (nvt/tags, 'impact')"/>
          </xsl:call-template>
        </xsl:if>

        <xsl:if test="(string-length (gvm:get-nvt-tag (nvt/tags, 'solution')) &gt; 0 and gvm:get-nvt-tag (nvt/tags, 'solution') != 'N/A') or (string-length (gvm:get-nvt-tag (nvt/tags, 'solution_type')) &gt; 0) or (count(nvt/solution) &gt; 0)">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Solution:}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:variable name="solution_type">
            <xsl:choose>
              <xsl:when test="count(nvt/solution) &gt; 0">
                <!-- new solution element -->
                <xsl:value-of select="nvt/solution/@type"/>
              </xsl:when>
              <xsl:otherwise>
                <!-- old NVT tag -->
                <xsl:value-of select="gvm:get-nvt-tag (nvt/tags, 'solution_type')"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:variable name="solution">
            <xsl:choose>
              <xsl:when test="count(nvt/solution) &gt; 0">
                <!-- new solution element -->
                <xsl:value-of select="nvt/solution/text()"/>
              </xsl:when>
              <xsl:otherwise>
                <!-- old NVT tag -->
                <xsl:value-of select="gvm:get-nvt-tag (nvt/tags, 'solution')"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:if test="string-length ($solution_type) &gt; 0">
            <xsl:text>\textbf{Solution type:} </xsl:text>
            <xsl:value-of select="$solution_type"/>
            <xsl:call-template name="latex-newline"/>
          </xsl:if>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="$solution"/>
          </xsl:call-template>
          <xsl:call-template name="latex-newline"/>
        </xsl:if>

        <xsl:if test="string-length (gvm:get-nvt-tag (nvt/tags, 'affected')) &gt; 0 and gvm:get-nvt-tag (nvt/tags, 'affected') != 'N/A'">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Affected Software/OS}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="gvm:get-nvt-tag (nvt/tags, 'affected')"/>
          </xsl:call-template>
        </xsl:if>

        <xsl:if test="string-length (gvm:get-nvt-tag (nvt/tags, 'insight')) &gt; 0 and gvm:get-nvt-tag (nvt/tags, 'insight') != 'N/A'">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Vulnerability Insight}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="gvm:get-nvt-tag (nvt/tags, 'insight')"/>
          </xsl:call-template>
        </xsl:if>

        \hline
        <xsl:call-template name="latex-newline"/>
        <xsl:choose>
          <xsl:when test="(nvt/cvss_base &gt; 0) or (cve/cvss_base &gt; 0)">
            <xsl:text>\textbf{Vulnerability Detection Method}</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>\textbf{Log Method}</xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:call-template name="latex-newline"/>
        <xsl:call-template name="structured-text">
          <xsl:with-param name="string" select="gvm:get-nvt-tag (nvt/tags, 'vuldetect')"/>
        </xsl:call-template>

        <xsl:text>Details:</xsl:text><xsl:call-template name="newline"/>
        <xsl:choose>
          <xsl:when test="nvt/@oid = 0">
            <xsl:if test="delta/text()">
              <xsl:call-template name="latex-newline"/>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:variable name="max" select="80"/>
            <xsl:choose>
              <xsl:when test="string-length(nvt/name) &gt; $max">
                <xsl:call-template name="text-to-escaped-row">
                  <xsl:with-param name="string" select="concat (substring(nvt/name, 0, $max), '...')"/>
                </xsl:call-template>
              </xsl:when>
              <xsl:otherwise>
                <xsl:call-template name="text-to-escaped-row">
                  <xsl:with-param name="string" select="nvt/name"/>
                </xsl:call-template>
              </xsl:otherwise>
            </xsl:choose>
            <xsl:text>OID:</xsl:text>
            <xsl:value-of select="nvt/@oid"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:if test="scan_nvt_version != ''">
          <xsl:call-template name="latex-newline"/>
          <xsl:text>Version used:</xsl:text><xsl:call-template name="newline"/>
          <xsl:call-template name="text-to-escaped-row">
            <xsl:with-param name="string" select="scan_nvt_version"/>
          </xsl:call-template>
        </xsl:if>

        <xsl:if test="count (detection)">
          \hline
          <xsl:call-template name="latex-newline"/>
          <xsl:text>\textbf{Product Detection Result}</xsl:text>
          <xsl:call-template name="latex-newline"/>
          <xsl:text>Product:</xsl:text><xsl:call-template name="newline"/>
          <xsl:call-template name="text-to-escaped-row">
            <xsl:with-param name="string" select="detection/result/details/detail[name = 'product']/value/text()"/>
          </xsl:call-template>
          <xsl:text>Method:</xsl:text><xsl:call-template name="newline"/>
          <xsl:call-template name="text-to-escaped-row">
            <xsl:with-param name="string" select="detection/result/details/detail[name = 'source_name']/value/text()"/>
          </xsl:call-template>
          OID:
          <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>)
        </xsl:if>

        <xsl:if test="delta">
          <xsl:choose>
            <xsl:when test="delta/text() = 'changed'">

              <xsl:call-template name="latex-hline"/>
              <xsl:call-template name="latex-newline"/>
              <xsl:text>\textbf{Result 2}</xsl:text>
              <xsl:call-template name="latex-newline"/>
              <xsl:call-template name="latex-newline"/>
              <xsl:call-template name="text-to-escaped-row">
                <xsl:with-param name="string" select="delta/result/description"/>
              </xsl:call-template>
              <xsl:text>\rowcolor{white}{\verb==}</xsl:text><xsl:call-template name="latex-newline"/>
              <xsl:text>\rowcolor{white}{\verb==}</xsl:text><xsl:call-template name="latex-newline"/>
              <xsl:call-template name="latex-newline"/>
              <xsl:text>OID of test routine: </xsl:text><xsl:value-of select="delta/result/nvt/@oid"/>
              <xsl:call-template name="latex-newline"/>

              <xsl:call-template name="latex-hline"/>
              <xsl:call-template name="latex-newline"/>
              <xsl:text>\textbf{Different Lines}</xsl:text>
              <xsl:call-template name="latex-newline"/>
              <xsl:call-template name="latex-newline"/>
              <xsl:call-template name="text-to-escaped-diff-row">
                <xsl:with-param name="string" select="delta/diff"/>
              </xsl:call-template>
              <!-- Delta Severity -->
              <xsl:if test="delta/result/severity/text() != severity/text()">
                \hline
                <xsl:call-template name="latex-newline"/>
                <xsl:text>\textbf{Severity Change}</xsl:text>
                <xsl:call-template name="latex-newline"/>
                <xsl:call-template name="latex-newline"/>
                <xsl:text>Severity changed from </xsl:text>
                <xsl:value-of select="delta/result/severity/text()"/>
                <xsl:text> to </xsl:text>
                <xsl:value-of select="severity/text()"/>
                <xsl:text>.</xsl:text>
                <xsl:call-template name="latex-newline"/>
              </xsl:if>
              <!-- Delta QoD -->
              <xsl:if test="delta/result/qod/value/text() != qod/value/text()">
                \hline
                <xsl:call-template name="latex-newline"/>
                <xsl:text>\textbf{QoD Change}</xsl:text>
                <xsl:call-template name="latex-newline"/>
                <xsl:call-template name="latex-newline"/>
                <xsl:text>Quality of Detection (QoD) changed from </xsl:text>
                <xsl:value-of select="delta/result/qod/value/text()"/>
                <xsl:text> to </xsl:text>
                <xsl:value-of select="qod/value/text()"/>
                <xsl:text>.</xsl:text>
                <xsl:call-template name="latex-newline"/>
              </xsl:if>
              <xsl:call-template name="latex-newline"/>
            </xsl:when>
          </xsl:choose>
        </xsl:if>
        <xsl:call-template name="references"/>
        <xsl:variable name="delta">
          <xsl:choose>
            <xsl:when test="delta">1</xsl:when>
            <xsl:otherwise>0</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:call-template name="notes">
          <xsl:with-param name="delta" select="$delta"/>
        </xsl:call-template>
        <xsl:for-each select="delta">
          <xsl:call-template name="notes">
            <xsl:with-param name="delta" select="2"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:call-template name="overrides">
          <xsl:with-param name="delta" select="$delta"/>
        </xsl:call-template>
        <xsl:for-each select="delta">
          <xsl:call-template name="overrides">
            <xsl:with-param name="delta" select="2"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>\end{longtable}</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:call-template name="newline"/>
      </xsl:for-each>

      <xsl:text>\begin{footnotesize}</xsl:text>
      <xsl:call-template name="latex-hyperref">
        <xsl:with-param name="target" select="concat('host:', $host)"/>
        <xsl:with-param name="text" select="concat('[ return to ', $host, ' ]')"/>
      </xsl:call-template>

      <xsl:text>\end{footnotesize}</xsl:text><xsl:call-template name="newline"/>
    </xsl:if>
  </xsl:template>

  <!-- Findings for a single host -->
  <xsl:template name="results-per-host-single-host-findings">
    <xsl:param name="host"/>

    <!-- TODO Solve other sorting possibilities. -->
    <!--
      port_service must be selected with variable and xsl:value-of element
      to handle empty ports correctly.
    -->
    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">Critical</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">High</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">Medium</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">Low</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">Log</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:variable name="port_service"><xsl:value-of select="text()"/></xsl:variable>
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">Debug</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="$port_service"/>
      </xsl:call-template>
    </xsl:for-each>

    <xsl:for-each select="gvm:report()/ports/port[host/text()=$host]">
      <xsl:call-template name="result-details-host-port-threat">
        <xsl:with-param name="threat">False Positive</xsl:with-param>
        <xsl:with-param name="host" select="$host"/>
        <xsl:with-param name="port_service" select="text()"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- Subsection for a single host, with all details. -->
  <xsl:template name="results-per-host-single-host">
    <xsl:variable name="host" select="ip"/>
    <xsl:call-template name="latex-subsection">
      <xsl:with-param name="subsection_string" select="$host"/>
    </xsl:call-template>
    <xsl:call-template name="latex-label">
      <xsl:with-param name="label_string" select="concat('host:', $host)"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <xsl:text>\begin{tabular}{ll}</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>Host scan start&amp;</xsl:text>
    <xsl:call-template name="format-date">
      <xsl:with-param name="date" select="start"/>
    </xsl:call-template>
    <xsl:call-template name="latex-newline"/>
    <xsl:text>Host scan end&amp;</xsl:text>
    <xsl:call-template name="format-date">
      <xsl:with-param name="date" select="end"/>
    </xsl:call-template>
    <xsl:call-template name="latex-newline"/>
    <xsl:text>\end{tabular}</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="results-per-host-single-host-port-findings"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="results-per-host-single-host-closed-cves"/>
    <xsl:call-template name="newline"/>

    <xsl:text>%\subsection*{Security Issues and Fixes -- </xsl:text><xsl:value-of select="$host"/><xsl:text>}</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="results-per-host-single-host-findings"><xsl:with-param name="host" select="$host"/></xsl:call-template>
  </xsl:template>

  <!-- Section with Results per Host. -->
  <xsl:template name="results-per-host">
    <xsl:text>\section{Results per Host}</xsl:text>
    <xsl:call-template name="newline"/><xsl:call-template name="newline"/>
    <xsl:for-each select="host">
      <xsl:call-template name="results-per-host-single-host"/>
    </xsl:for-each>
  </xsl:template>

  <!-- ============================================================== -->
  <!-- SURICATOOS PREMIUM: cover page, executive summary, helpers     -->
  <!-- ============================================================== -->

  <!-- A single statistic "card" drawn inside an existing tikzpicture
       (units x=1mm, y=1mm).  Header band in the accent colour, big
       number below in ink. -->
  <xsl:template name="stat-card">
    <xsl:param name="xl"/>
    <xsl:param name="count"/>
    <xsl:param name="label"/>
    <xsl:param name="accent"/>
    <xsl:variable name="xr" select="format-number($xl + 26.5, '0.###')"/>
    <xsl:variable name="xc" select="format-number($xl + 13.25, '0.###')"/>
    <xsl:text>\begin{scope}
\clip[rounded corners=1.8mm] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,22);
\fill[</xsl:text><xsl:value-of select="$accent"/><xsl:text>!13!white] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,22);
\fill[</xsl:text><xsl:value-of select="$accent"/><xsl:text>] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,16.3) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,22);
\node[anchor=center,text=white] at (</xsl:text><xsl:value-of select="$xc"/><xsl:text>,19.1) {\scriptsize\bfseries </xsl:text><xsl:value-of select="$label"/><xsl:text>};
\node[anchor=center,text=surInk] at (</xsl:text><xsl:value-of select="$xc"/><xsl:text>,8) {\fontsize{20}{20}\selectfont\bfseries </xsl:text><xsl:value-of select="$count"/><xsl:text>};
\end{scope}
\draw[</xsl:text><xsl:value-of select="$accent"/><xsl:text>!45!white,rounded corners=1.8mm,line width=0.3pt] (</xsl:text><xsl:value-of select="$xl"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xr"/><xsl:text>,22);
</xsl:text>
  </xsl:template>

  <!-- Rows of the "Top Findings" table for a single threat level. -->
  <xsl:template name="top-risk-rows">
    <xsl:param name="threat"/>
    <xsl:param name="color"/>
    <xsl:for-each select="gvm:report()/results/result[threat=$threat]">
      <xsl:if test="position() &lt;= 8">
        <xsl:text>\cellcolor{white}\colorbox{</xsl:text>
        <xsl:value-of select="$color"/>
        <xsl:text>}{\color{white}\scriptsize\bfseries\,</xsl:text>
        <xsl:value-of select="$threat"/>
        <xsl:text>\,}&amp;</xsl:text>
        <xsl:variable name="nm">
          <xsl:choose>
            <xsl:when test="string-length(nvt/name) &gt; 66">
              <xsl:value-of select="concat(substring(nvt/name,1,66),'...')"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="nvt/name"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="$nm"/>
        </xsl:call-template>
        <xsl:text>&amp;</xsl:text>
        <xsl:call-template name="escape_text">
          <xsl:with-param name="string" select="host/text()"/>
        </xsl:call-template>
        <xsl:text>&amp;</xsl:text>
        <xsl:choose>
          <xsl:when test="string-length(nvt/cvss_base) &gt; 0">
            <xsl:value-of select="nvt/cvss_base"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="severity"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:call-template name="latex-newline"/>
        <xsl:call-template name="latex-hline"/>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <!-- The branded cover / title page. -->
  <xsl:template name="cover-page">
    <xsl:variable name="title">
      <xsl:choose>
        <xsl:when test="gvm:report()/delta">Delta Scan Report</xsl:when>
        <xsl:otherwise>Vulnerability Scan Report</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="task_escaped">
      <xsl:call-template name="escape_text">
        <xsl:with-param name="string" select="/report/task/name"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:text>\begin{titlepage}
\thispagestyle{empty}
\begin{tikzpicture}[remember picture,overlay]
  % Deep-navy full-bleed canvas
  \fill[surNavy] (current page.south west) rectangle (current page.north east);
  % Decorative concentric rings, lower-right
  \begin{scope}
    \clip (current page.south west) rectangle (current page.north east);
    \draw[surIndigo,line width=1pt,draw opacity=0.10]   ([xshift=8mm,yshift=20mm]current page.south east) circle (42mm);
    \draw[surIndigoLt,line width=1pt,draw opacity=0.13] ([xshift=8mm,yshift=20mm]current page.south east) circle (60mm);
    \draw[surIndigo,line width=1pt,draw opacity=0.08]   ([xshift=8mm,yshift=20mm]current page.south east) circle (84mm);
  \end{scope}
  % Thin indigo accent at the very top
  \fill[surIndigo] (current page.north west) rectangle ([yshift=-3mm]current page.north east);
  % Wordmark
  \node[anchor=north west,xshift=22mm,yshift=-32mm] at (current page.north west)
    {\includegraphics[width=70mm]{suricatoos-wordmark-white}};
  % Kicker
  \node[anchor=north west,xshift=22mm,yshift=-76mm,text=surIndigoLt] at (current page.north west)
    {\sffamily\bfseries\large SECURITY ASSESSMENT};
  \node[anchor=north west,xshift=22mm,yshift=-81mm] at (current page.north west)
    {\color{surIndigo}\rule{40mm}{1.3pt}};
  % Title
  \node[anchor=north west,xshift=21mm,yshift=-87mm,text=white,text width=170mm] at (current page.north west)
    {\sffamily\bfseries\fontsize{33}{37}\selectfont </xsl:text>
    <xsl:value-of select="$title"/>
    <xsl:text>};
  % Standfirst
  \node[anchor=north west,xshift=22mm,yshift=-120mm,text=surCloud,text width=164mm] at (current page.north west)
    {\sffamily\large Prepared by the Suricatoos Security Platform};
  % Metadata card
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
       <xsl:apply-templates select="scan_start"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries SCAN COMPLETED}&amp;{\color{white}</xsl:text>
       <xsl:apply-templates select="scan_end"/>
       <xsl:text>}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries REPORT DATE}&amp;{\color{white}\today}\\
     \textcolor{surIndigoLt}{\scriptsize\bfseries CLASSIFICATION}&amp;{\color{white}Confidential}\\
     \end{tabular}};
  % Bottom band
  \fill[surIndigo] (current page.south west) rectangle ([yshift=14mm]current page.south east);
  \node[anchor=west,xshift=22mm,text=white] at ([yshift=7mm]current page.south west)
    {\sffamily\footnotesize\bfseries CONFIDENTIAL};
  \node[anchor=east,xshift=-22mm,text=white] at ([yshift=7mm]current page.south east)
    {\sffamily\footnotesize Suricatoos Security Platform};
\end{tikzpicture}
\end{titlepage}
</xsl:text>
  </xsl:template>

  <!-- The executive summary: risk dashboard, severity bar, top findings. -->
  <xsl:template name="executive-summary">
    <xsl:variable name="crit" select="count(gvm:report()/results/result[threat='Critical'])"/>
    <xsl:variable name="high" select="count(gvm:report()/results/result[threat='High'])"/>
    <xsl:variable name="med"  select="count(gvm:report()/results/result[threat='Medium'])"/>
    <xsl:variable name="low"  select="count(gvm:report()/results/result[threat='Low'])"/>
    <xsl:variable name="logc" select="count(gvm:report()/results/result[threat='Log'])"/>
    <xsl:variable name="hosts" select="count(gvm:report()/host)"/>
    <xsl:variable name="risk" select="$crit + $high + $med + $low"/>

    <xsl:call-template name="latex-section">
      <xsl:with-param name="section_string">Executive Summary</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <!-- Narrative -->
    <xsl:text>This report presents the results of an automated security assessment performed by the Suricatoos Security Platform. The task ``</xsl:text>
    <xsl:call-template name="escape_text">
      <xsl:with-param name="string" select="/report/task/name"/>
    </xsl:call-template>
    <xsl:text>'' assessed </xsl:text>
    <xsl:value-of select="$hosts"/>
    <xsl:text> host(s) and identified </xsl:text>
    <xsl:value-of select="$risk"/>
    <xsl:text> security finding(s) carrying a severity rating, of which \textbf{</xsl:text>
    <xsl:value-of select="$crit + $high"/>
    <xsl:text>} are of High or Critical severity and warrant prompt remediation.</xsl:text>
    <xsl:call-template name="latex-newline"/>
    <xsl:call-template name="newline"/>

    <!-- Statistic cards -->
    <xsl:text>\vspace{2mm}
{\color{surInk}\bfseries Findings by severity}\par\vspace{2mm}
\begin{center}
\begin{tikzpicture}[x=1mm,y=1mm]
</xsl:text>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="0"/>
      <xsl:with-param name="count" select="$crit"/>
      <xsl:with-param name="label">CRITICAL</xsl:with-param>
      <xsl:with-param name="accent">gvm_critical</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="28.1"/>
      <xsl:with-param name="count" select="$high"/>
      <xsl:with-param name="label">HIGH</xsl:with-param>
      <xsl:with-param name="accent">gvm_hole</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="56.2"/>
      <xsl:with-param name="count" select="$med"/>
      <xsl:with-param name="label">MEDIUM</xsl:with-param>
      <xsl:with-param name="accent">gvm_warning</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="84.3"/>
      <xsl:with-param name="count" select="$low"/>
      <xsl:with-param name="label">LOW</xsl:with-param>
      <xsl:with-param name="accent">gvm_note</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="112.4"/>
      <xsl:with-param name="count" select="$logc"/>
      <xsl:with-param name="label">LOG</xsl:with-param>
      <xsl:with-param name="accent">gvm_log</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="stat-card">
      <xsl:with-param name="xl" select="140.5"/>
      <xsl:with-param name="count" select="$hosts"/>
      <xsl:with-param name="label">HOSTS</xsl:with-param>
      <xsl:with-param name="accent">surIndigo</xsl:with-param>
    </xsl:call-template>
    <xsl:text>\end{tikzpicture}
\end{center}
\vspace{3mm}
</xsl:text>

    <!-- Severity distribution bar -->
    <xsl:text>{\color{surInk}\bfseries Severity distribution}\par\vspace{1.5mm}
\begin{center}
\begin{tikzpicture}[x=1mm,y=1mm]
</xsl:text>
    <xsl:choose>
      <xsl:when test="$risk = 0">
        <xsl:text>\fill[gvm_report,rounded corners=1.6mm] (0,0) rectangle (167,7);
\node[anchor=center,text=surMuted] at (83.5,3.5) {\footnotesize No rated findings were identified.};
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="barW" select="167"/>
        <xsl:variable name="xHf" select="format-number($crit div $risk * $barW, '0.###')"/>
        <xsl:variable name="xMf" select="format-number(($crit + $high) div $risk * $barW, '0.###')"/>
        <xsl:variable name="xLf" select="format-number(($crit + $high + $med) div $risk * $barW, '0.###')"/>
        <xsl:text>\begin{scope}
\clip[rounded corners=1.6mm] (0,0) rectangle (167,7);
\fill[gvm_critical] (0,0) rectangle (</xsl:text><xsl:value-of select="$xHf"/><xsl:text>,7);
\fill[gvm_hole] (</xsl:text><xsl:value-of select="$xHf"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xMf"/><xsl:text>,7);
\fill[gvm_warning] (</xsl:text><xsl:value-of select="$xMf"/><xsl:text>,0) rectangle (</xsl:text><xsl:value-of select="$xLf"/><xsl:text>,7);
\fill[gvm_note] (</xsl:text><xsl:value-of select="$xLf"/><xsl:text>,0) rectangle (167,7);
\end{scope}
\draw[surBorder,rounded corners=1.6mm,line width=0.4pt] (0,0) rectangle (167,7);
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>\end{tikzpicture}
\end{center}
\vspace{1mm}
\begin{center}{\footnotesize\color{surInk}%
\textcolor{gvm_critical}{\rule{2.4mm}{2.4mm}}~Critical~\textbf{</xsl:text><xsl:value-of select="$crit"/><xsl:text>}\hspace{4mm}%
\textcolor{gvm_hole}{\rule{2.4mm}{2.4mm}}~High~\textbf{</xsl:text><xsl:value-of select="$high"/><xsl:text>}\hspace{4mm}%
\textcolor{gvm_warning}{\rule{2.4mm}{2.4mm}}~Medium~\textbf{</xsl:text><xsl:value-of select="$med"/><xsl:text>}\hspace{4mm}%
\textcolor{gvm_note}{\rule{2.4mm}{2.4mm}}~Low~\textbf{</xsl:text><xsl:value-of select="$low"/><xsl:text>}\hspace{4mm}%
\textcolor{gvm_log}{\rule{2.4mm}{2.4mm}}~Log~\textbf{</xsl:text><xsl:value-of select="$logc"/><xsl:text>}}\end{center}
\vspace{4mm}
</xsl:text>

    <!-- Top findings table -->
    <xsl:call-template name="latex-subsection">
      <xsl:with-param name="subsection_string">Top Findings</xsl:with-param>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="$crit + $high = 0">
        <xsl:text>No Critical or High severity findings were identified during this assessment.</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>\begin{longtable}{|p{18mm}|p{74mm}|p{34mm}|p{12mm}|}</xsl:text><xsl:call-template name="newline"/>
        <xsl:call-template name="latex-hline"/>
        <xsl:call-template name="longtable-continue-block">
          <xsl:with-param name="number-of-columns">4</xsl:with-param>
          <xsl:with-param name="header-color">gvm_report</xsl:with-param>
          <xsl:with-param name="header-text">\textbf{Severity}&amp;\textbf{Finding (NVT)}&amp;\textbf{Affected Host}&amp;\textbf{CVSS}</xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="top-risk-rows">
          <xsl:with-param name="threat">Critical</xsl:with-param>
          <xsl:with-param name="color">gvm_critical</xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="top-risk-rows">
          <xsl:with-param name="threat">High</xsl:with-param>
          <xsl:with-param name="color">gvm_hole</xsl:with-param>
        </xsl:call-template>
        <xsl:text>\end{longtable}</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>{\footnotesize\color{surMuted}Up to eight findings are listed per severity level. The complete set of results follows in the detailed sections below.}</xsl:text>
        <xsl:call-template name="latex-newline"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- The closing branded colophon. -->
  <xsl:template name="branded-footer">
    <xsl:text>
\vspace{8mm}
\begin{center}
{\color{surBorder}\rule{\textwidth}{0.4pt}}\\[2.5mm]
\raisebox{-1.5mm}{\includegraphics[height=6mm]{suricatoos-mark-navy}}\quad{\bfseries\color{surInk}\large Suricatoos Security Platform}\\[1.5mm]
{\footnotesize\color{surMuted}This report was generated automatically by the Suricatoos vulnerability management platform.\\
CONFIDENTIAL --- distribute on a need-to-know basis.}
\end{center}
</xsl:text>
  </xsl:template>

  <!-- The actual report. -->
  <xsl:template name="real-report">
    <xsl:call-template name="header"/>
    <xsl:call-template name="newline"/>
    <xsl:text>\begin{document}</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="cover-page"/>
    <xsl:text>\pagestyle{surfancy}</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="toc"/>
    <xsl:text>\newpage</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="executive-summary"/>
    <xsl:text>\newpage</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="results-overview"/>
    <xsl:call-template name="results-per-host"/>
    <xsl:call-template name="branded-footer"/>
    <xsl:text>
\end{document}
</xsl:text>
  </xsl:template>

  <!-- The first report element. -->
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

  <!-- Match the root. -->
  <xsl:template match="/">
    <xsl:apply-templates/>
  </xsl:template>

</xsl:stylesheet>
