#!/usr/bin/env python3
"""Build the combined Greenbone feed XML for the Suricatoos Premium PDF report
format from the files in the suricatoos-premium-pdf/ bundle directory.

The output XML mirrors the structure of the stock Greenbone
``pdf-c402cc3e-b531-11e1-9163-406186ea4fc5.xml`` feed object: a single
``<report_format>`` element whose ``<file>`` children carry the bundle files
base64-encoded.  Dropping this file into the report-formats feed source makes
gvmd install the format as predefined + trusted (no GPG signing, no GSA change).

Usage:  python3 build-feed-xml.py
"""
import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "suricatoos-premium-pdf")

REPORT_FORMAT_ID = "c6482c1b-57bb-406b-a501-c97eed86ad05"
NAME = "Suricatoos Premium PDF"
SUMMARY = "Premium branded Portable Document Format report. Version 20260701."
DESCRIPTION = (
    "A premium, corporate vulnerability assessment report in Portable Document "
    "Format (PDF): branded cover, executive risk summary with a severity "
    "dashboard, a findings summary table, and detailed findings grouped by "
    "vulnerability (each with CVSS, CVEs, affected systems and remediation). "
    "Version 20260701."
)

# Order mirrors the stock bundle: scripts first, then embedded assets.
FILES = [
    "generate",
    "latex.xsl",
    "report_format.xml",
    "suricatoos-wordmark-white.pdf",
    "suricatoos-mark-navy.pdf",
    "suricatoos-mark-white.pdf",
]


def b64(path):
    with open(path, "rb") as fh:
        return base64.b64encode(fh.read()).decode("ascii")


def main():
    lines = [
        "<!-- Copyright (C) 2026 Suricatoos -->",
        f'<report_format id="{REPORT_FORMAT_ID}">',
        f"  <name>{NAME}</name>",
        f"  <summary>{SUMMARY}</summary>",
        f"  <description>{DESCRIPTION}</description>",
        "  <extension>pdf</extension>",
        "  <content_type>application/pdf</content_type>",
        "  <report_type>all</report_type>",
    ]
    for name in FILES:
        lines.append(f'  <file name="{name}">{b64(os.path.join(BUNDLE, name))}</file>')
    lines.append("</report_format>")
    lines.append("")

    out = os.path.join(HERE, f"pdf-suricatoos-{REPORT_FORMAT_ID}.xml")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
