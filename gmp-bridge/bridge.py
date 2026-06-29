#!/usr/bin/env python3
"""
Suricatoos Agent — GMP bridge (Fase 2)

Reads a FindingReport (schema/finding.schema.json), enriches findings with
CVE/severity from the gvmd VT feed via OID lookup, then imports the result
into gvmd as a container-task report so findings appear in the GSA.

Mechanism (verified against gvmd 26.31.1 / GMP v22.x / python-gvm 27.x):
  1. Nvts.get_nvt(oid) → cvss_base + CVE list (from VT feed)
  2. Tasks.create_container_task(name, comment) → task_id
  3. Reports.import_report(report_xml, task_id, in_assets=True)

Verified behavior (2026-06-28, live stack):
  - gvmd enriches nvt.name + nvt.cvss_base after import, BUT result.severity
    stays at the value we supply. We must therefore supply the correct severity
    by looking up the OID in the VT feed BEFORE building the XML.
  - CVEs appear in the get_nvt response; deduplicated before use.

Usage:
  bridge.py FINDING_REPORT_JSON [OPTIONS]

  FINDING_REPORT_JSON  Path to a FindingReport JSON file (- for stdin).

Environment:
  GVM_PASSWORD  GMP password (alternative to --password flag).
"""

import argparse
import json
import os
import sys
import uuid
from xml.etree import ElementTree as ET

from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmp.requests.v226 import Authentication, Nvts, Reports, Tasks


# --------------------------------------------------------------------------- #
# Severity mapping
# --------------------------------------------------------------------------- #

def severity_to_threat(severity: float) -> str:
    """Map a CVSS base score to a GMP threat string."""
    if severity >= 9.0:
        return "Critical"
    if severity >= 7.0:
        return "High"
    if severity >= 4.0:
        return "Medium"
    if severity > 0.0:
        return "Low"
    return "Log"


# --------------------------------------------------------------------------- #
# NVT metadata lookup (pre-enrichment from gvmd VT feed)
# --------------------------------------------------------------------------- #

class NVTMeta:
    """Cached CVE + severity metadata for a single NVT OID."""
    __slots__ = ("cvss_base", "cves")

    def __init__(self, cvss_base: float, cves: list[str]):
        self.cvss_base = cvss_base
        self.cves = cves


def fetch_nvt_meta(gmp: Gmp, oid: str) -> NVTMeta | None:
    """Look up CVE list and CVSS base score for an OID from the gvmd VT feed.

    Returns None when there is NO feed evidence for the OID — i.e. the GMP
    request errored (non-2xx status: auth expired, OID rejected, ...) or the OID
    is not present in the feed. None is distinct from a found-but-unscored VT,
    which legitimately returns NVTMeta(cvss_base=0.0, cves=[...]): an OID can
    exist in the feed with a real CVE list yet a 0.0 base score.

    Callers MUST treat None as "no evidence" and never substitute a
    caller-supplied severity in its place (that would fabricate severity).
    """
    req = Nvts.get_nvt(oid)
    resp = gmp.send_command(str(req))
    root = ET.fromstring(resp)

    status = root.get("status", "")
    if not status.startswith("2"):
        # Feed lookup failed — signal "no evidence" loudly instead of silently
        # collapsing to severity 0 (which the old code did, masking feed outages).
        print(
            f"WARN: get_nvt {oid} failed: {status} {root.get('status_text', '')}",
            file=sys.stderr,
        )
        return None

    nvt = root.find(".//nvt")
    if nvt is None:
        return None  # OID not in feed → no evidence

    cvss_text = nvt.findtext("cvss_base") or "0.0"
    try:
        cvss = float(cvss_text)
    except ValueError:
        cvss = 0.0

    # CVEs may appear duplicated across multiple <refs> blocks; deduplicate.
    seen: set[str] = set()
    cves: list[str] = []
    for ref in nvt.findall(".//refs/ref"):
        if ref.get("type") == "cve":
            cve_id = ref.get("id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                cves.append(cve_id)

    return NVTMeta(cvss_base=cvss, cves=cves)


# --------------------------------------------------------------------------- #
# Report XML builder
# --------------------------------------------------------------------------- #

def finding_report_to_xml(report: dict, nvt_meta: dict[str, NVTMeta | None] | None = None) -> str:
    """Convert a FindingReport dict to a GMP report XML string.

    The report carries a report-level <host> block (+ <scan_start>/<scan_end>) so
    gvmd registers the host on import (host_count, and a host asset with in_assets=1).

    Each finding becomes a <result> with:
    - <host> → host IP as text content (gvmd's result-host format).
    - <nvt oid=...> → links to the VT; gvmd enriches name after import.
    - <severity> → the VT-feed cvss_base for the OID (nvt_meta), else 0.0 (Log).
      Never the caller-supplied value — feed evidence only.
    - <refs><ref type="cve">…> → the VT-feed CVEs for the OID (nvt_meta), else none.
    - <description> → evidence trail (package, advisory, agent).
    - <qod><type>package</type> → QoD 70 (same as Notus scanner results).

    nvt_meta: dict {oid → NVTMeta} pre-fetched from the gvmd VT feed; an OID maps
    to None when there is no feed evidence (absent / lookup failed). When the map
    is empty (e.g. --dry-run without a live connection) every result is emitted
    unenriched at severity 0.0/Log — severity requires the feed.
    """
    if nvt_meta is None:
        nvt_meta = {}

    root = ET.Element("report", id=str(uuid.uuid4()))
    host_ip = report.get("host", "0.0.0.0")
    # collected_at is RFC3339/ISO-8601 (e.g. "2026-06-29T00:00:00Z"), which gvmd's
    # parse_iso_time_tz accepts. A bad/empty value parses to 0 but still registers
    # the host, so this is safe either way.
    scan_time = report.get("collected_at") or ""

    # scan_start precedes <results> (mirrors gvmd's own report export order).
    ET.SubElement(root, "scan_start").text = scan_time

    results_el = ET.SubElement(root, "results", max="-1", start="1")

    for finding in report.get("findings", []):
        r = ET.SubElement(results_el, "result", id=str(uuid.uuid4()))

        pkg_obs = finding.get("package_observed", "")
        pkg_fix = finding.get("package_fixed", "")
        product = finding.get("product", "")
        evidence = finding.get("evidence", {})
        advisory = evidence.get("matched_advisory", "")
        source = evidence.get("source", "")
        desc = (
            f"Package {pkg_obs!r} is installed and vulnerable.\n"
            f"Fixed version: {pkg_fix}\n"
            f"Product: {product}\n"
            f"Advisory: {advisory} (source: {source})\n"
            f"Agent: {report.get('agent_id', '')}"
        )
        ET.SubElement(r, "description").text = desc

        # GMP result host: the IP is the TEXT content of <host> (optionally with
        # <hostname>/<asset> children). gvmd ignores a <host><ip> child, which
        # left every imported result with a blank host.
        host_el = ET.SubElement(r, "host")
        host_el.text = host_ip
        ET.SubElement(r, "port").text = "general/tcp"

        oid = finding.get("oid", "")
        meta = nvt_meta.get(oid)

        # Severity and CVEs come from FEED EVIDENCE ONLY (non-fabrication). When
        # the OID has feed metadata we use its score — even 0.0, since an
        # unscored VT is genuinely "Log" — and its CVEs. Without feed evidence
        # (meta is None: OID absent or lookup failed) we emit 0.0/Log and no CVE
        # refs; we never substitute the caller-supplied finding.severity/finding.cve,
        # which would present unverified, client-controlled values as feed-attested.
        if meta is not None:
            severity = meta.cvss_base
            cves = meta.cves
        else:
            severity = 0.0
            cves = []

        nvt_el = ET.SubElement(r, "nvt", oid=oid)
        ET.SubElement(nvt_el, "type").text = "nvt"
        ET.SubElement(nvt_el, "name").text = f"Package vulnerability: {pkg_obs}"
        ET.SubElement(nvt_el, "family").text = "General"
        ET.SubElement(nvt_el, "cvss_base").text = str(severity)
        ET.SubElement(nvt_el, "tags").text = ""
        refs_el = ET.SubElement(nvt_el, "refs")
        for cve in cves:
            ET.SubElement(refs_el, "ref", type="cve", id=cve)

        ET.SubElement(r, "severity").text = str(severity)
        ET.SubElement(r, "threat").text = severity_to_threat(severity)

        qod = ET.SubElement(r, "qod")
        ET.SubElement(qod, "value").text = "70"
        ET.SubElement(qod, "type").text = "package"

    # Report-level host block — registers the host so the imported report is
    # host-attributed (report_hosts row → host_count) and, with in_assets=1,
    # creates a host asset. Without it gvmd shows the report with 0 hosts. This
    # is the modern <host> form gvmd itself exports (verified against gvmd 26.31.1:
    # creates both the report_host and the asset). All findings in a FindingReport
    # belong to the single agent host, so one block suffices.
    report_host_el = ET.SubElement(root, "host")
    ET.SubElement(report_host_el, "ip").text = host_ip
    ET.SubElement(report_host_el, "start").text = scan_time
    ET.SubElement(report_host_el, "end").text = scan_time
    ET.SubElement(root, "scan_end").text = scan_time

    return ET.tostring(root, encoding="unicode")


# --------------------------------------------------------------------------- #
# Main import logic
# --------------------------------------------------------------------------- #

def run_import(
    report_dict: dict,
    *,
    socket_path: str | None,
    host: str | None,
    port: int,
    username: str,
    password: str,
    task_name: str | None,
    dry_run: bool,
) -> None:
    """Enrich + import the FindingReport into gvmd, or dry-run print the XML."""
    if dry_run:
        report_xml = finding_report_to_xml(report_dict)
        print(report_xml)
        return

    if not password:
        sys.exit("GMP password required (--password or GVM_PASSWORD env var)")
    if socket_path is None and host is None:
        sys.exit("Provide --socket or --host to connect to gvmd")

    conn = (
        UnixSocketConnection(path=socket_path)
        if socket_path
        else TLSConnection(hostname=host, port=port)
    )

    if not task_name:
        agent_host = report_dict.get("host", "unknown")
        task_name = f"suricatoos-agent-{agent_host}"

    with Gmp(connection=conn) as gmp:
        auth_req = Authentication.authenticate(username=username, password=password)
        _assert_ok(gmp.send_command(str(auth_req)), "authenticate")

        # Enrich findings with CVE/severity from the VT feed.
        unique_oids = {f.get("oid", "") for f in report_dict.get("findings", []) if f.get("oid")}
        nvt_meta: dict[str, NVTMeta | None] = {}
        for oid in unique_oids:
            meta = fetch_nvt_meta(gmp, oid)
            nvt_meta[oid] = meta
            if meta is None:
                print(f"VT {oid}: no feed evidence (severity 0/Log)", file=sys.stderr)
            else:
                print(f"VT {oid}: cvss={meta.cvss_base} cves={len(meta.cves)}", file=sys.stderr)

        report_xml = finding_report_to_xml(report_dict, nvt_meta=nvt_meta)

        task_req = Tasks.create_container_task(
            name=task_name,
            comment=f"Suricatoos Agent findings for host {report_dict.get('host', '')}",
        )
        task_resp = gmp.send_command(str(task_req))
        _assert_ok(task_resp, "create_container_task")
        task_id = _extract_id(task_resp)
        print(f"Container task: {task_id} ({task_name})", file=sys.stderr)

        import_req = Reports.import_report(report_xml, task_id=task_id, in_assets=True)
        import_resp = gmp.send_command(str(import_req))
        _assert_ok(import_resp, "import_report")
        report_id = _extract_id(import_resp)
        print(f"Imported report: {report_id}", file=sys.stderr)

    findings_count = len(report_dict.get("findings", []))
    print(f"ok: {findings_count} finding(s) imported — task={task_id} report={report_id}")


def _assert_ok(xml_str: str, cmd: str) -> None:
    root = ET.fromstring(xml_str)
    status = root.get("status", "")
    if not status.startswith("2"):
        status_text = root.get("status_text", "")
        sys.exit(f"GMP error on {cmd}: {status} {status_text}\n{xml_str}")


def _extract_id(xml_str: str) -> str:
    return ET.fromstring(xml_str).get("id", "")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "report",
        metavar="FINDING_REPORT_JSON",
        help="Path to FindingReport JSON file; use - for stdin",
    )
    p.add_argument(
        "--socket",
        metavar="PATH",
        default="/run/gvmd/gvmd.sock",
        help="gvmd Unix socket path (default: /run/gvmd/gvmd.sock)",
    )
    p.add_argument("--host", metavar="HOST", help="gvmd TCP host (overrides --socket)")
    p.add_argument("--port", metavar="PORT", type=int, default=9390, help="gvmd TCP port")
    p.add_argument("--username", metavar="USER", default="admin", help="GMP username")
    p.add_argument(
        "--password",
        metavar="PASS",
        default=os.environ.get("GVM_PASSWORD", ""),
        help="GMP password (or set GVM_PASSWORD env var)",
    )
    p.add_argument(
        "--task-name",
        metavar="NAME",
        help="Container task name (default: suricatoos-agent-{host})",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the report XML without connecting to gvmd",
    )
    args = p.parse_args()

    if args.report == "-":
        report_dict = json.load(sys.stdin)
    else:
        with open(args.report) as f:
            report_dict = json.load(f)

    run_import(
        report_dict,
        socket_path=args.socket if not args.host else None,
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        task_name=args.task_name,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
