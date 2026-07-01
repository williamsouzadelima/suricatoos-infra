#!/usr/bin/env python3
"""
Suricatoos — reNgine→OpenVAS scan bridge (ADR-0006)

Launches and tracks REAL OpenVAS scans in gvmd on behalf of the ingest
`scanlaunch` reconciler. Sibling to bridge.py (which only imports findings);
this one drives create_target → create_task → start_task and reads results back.

Invoked ONLY by the serialized reconciler (never concurrently for the same job),
so its find-or-create steps are race-free. All GVM XML is built via python-gvm
request objects (never string-formatted), and hosts are re-validated as IP
literals here as defense in depth — a hostname must never reach a GVM target.

Subcommands (each takes a request JSON file = the ingest Job) print ONE JSON
object on stdout:

  launch  → {"target_id","task_id","report_id","status"}
  status  → {"status","progress","report_id"}
  fetch   → {"findings":[...]}
  stop    → {"stopped":true}

Environment:
  GVM_PASSWORD  GMP password (or --password).
"""

import argparse
import ipaddress
import json
import os
import sys
from xml.etree import ElementTree as ET

from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmp.requests.v226 import (
    Authentication,
    Targets,
    Tasks,
    Reports,
    AliveTest,
)

# Reuse the audited helpers from the import bridge (same directory at runtime).
from bridge import _assert_ok, _extract_id, _esc_filter, _find_task_id

CONFIG_FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_OPENVAS_DEFAULT = "08b69003-5fc2-4037-a479-93b440211c73"

# GVM task statuses that mean "safe to (re)start" — idle. Running/Requested/
# Queued/Done are left untouched so a retried launch never double-starts.
_STARTABLE = {"New", "Stopped", "Interrupted", ""}


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested without a live gvmd)
# --------------------------------------------------------------------------- #

def sanitize_ips(hosts) -> list[str]:
    """Return the canonical IP-literal string for each host, raising if ANY host
    is not a valid IP literal. This is the last line of defense against a
    hostname reaching a GVM target (gvmd would re-resolve it at scan time)."""
    out = []
    for h in hosts or []:
        ip = ipaddress.ip_address(str(h["ip"]).strip())  # raises ValueError on a name
        out.append(str(ip))
    if not out:
        raise ValueError("no hosts")
    return out


def build_port_range(hosts) -> str:
    """Build a GVM TCP port_range from the union of discovered open ports, e.g.
    'T:22,80,443'. Ports are ints only — no ranges/commas can be injected."""
    ports = set()
    for h in hosts or []:
        for p in h.get("ports", []):
            pi = int(p)
            if 1 <= pi <= 65535:
                ports.add(pi)
    if not ports:
        raise ValueError("no ports")
    return "T:" + ",".join(str(p) for p in sorted(ports))


def _tag_value(tags: str, key: str) -> str:
    """Extract key=value from a GVM pipe-delimited nvt/tags string."""
    for part in (tags or "").split("|"):
        if part.startswith(key + "="):
            return part[len(key) + 1:]
    return ""


def parse_report_results(xml_str: str) -> list[dict]:
    """Parse a get_report response into normalized finding dicts (the shape the
    reNgine importer consumes). Robust to the outer/inner <report> nesting."""
    root = ET.fromstring(xml_str)
    findings = []
    for res in root.findall(".//results/result"):
        nvt = res.find("nvt")
        oid = nvt.get("oid", "") if nvt is not None else ""
        tags = (nvt.findtext("tags") if nvt is not None else "") or ""
        sev_txt = res.findtext("severity") or (nvt.findtext("cvss_base") if nvt is not None else "") or "0"
        try:
            cvss = max(0.0, float(sev_txt))
        except ValueError:
            cvss = 0.0
        cves, refs = [], []
        if nvt is not None:
            for ref in nvt.findall("refs/ref"):
                rid = ref.get("id", "")
                if ref.get("type") == "cve" and rid and rid not in cves:
                    cves.append(rid)
                elif ref.get("type") == "url" and rid:
                    refs.append(rid)
        findings.append({
            "host": (res.findtext("host") or "").strip(),
            "port": res.findtext("port") or "",
            "oid": oid,
            "name": (nvt.findtext("name") if nvt is not None else "") or res.findtext("name") or "",
            "cvss_base": cvss,
            "cvss_vector": _tag_value(tags, "cvss_base_vector"),
            "threat": res.findtext("threat") or "",
            "cves": cves,
            "references": refs,
            "summary": _tag_value(tags, "summary"),
            "impact": _tag_value(tags, "impact"),
            "solution": _tag_value(tags, "solution"),
            "qod": int(res.findtext("qod/value") or 0),
        })
    return findings


# --------------------------------------------------------------------------- #
# GVM interaction
# --------------------------------------------------------------------------- #

def _connect(args):
    return (
        UnixSocketConnection(path=args.socket)
        if not args.host
        else TLSConnection(hostname=args.host, port=args.port)
    )


def _find_target_id(gmp: Gmp, name: str) -> str | None:
    resp = gmp.get_targets(filter_string=f'name="{_esc_filter(name)}" rows=50 first=1')
    for tgt in ET.fromstring(resp).findall(".//target[@id]"):
        if (tgt.findtext("name") or "") == name:
            return tgt.get("id")
    return None


def _task_info(gmp: Gmp, name: str):
    """Return (task_id, status, progress, last_report_id) for the named task, or
    (None, '', 0, '') if it does not exist."""
    resp = gmp.get_tasks(filter_string=f'name="{_esc_filter(name)}" rows=50 first=1')
    for task in ET.fromstring(resp).findall(".//task[@id]"):
        if (task.findtext("name") or "") != name:
            continue
        status = task.findtext("status") or ""
        try:
            progress = max(0, int(float(task.findtext("progress") or 0)))
        except ValueError:
            progress = 0
        lr = task.find("last_report/report")
        report_id = lr.get("id") if lr is not None else ""
        return task.get("id"), status, progress, report_id
    return None, "", 0, ""


def _alive_test(value: str):
    # python-gvm's AliveTest overrides _missing_ to call from_string, which raises
    # gvm.errors.InvalidArgument (not ValueError) on an unknown value — catch broadly
    # and fall back to the scan config default rather than failing the launch.
    try:
        return AliveTest(value)
    except Exception:
        return None


def cmd_launch(gmp: Gmp, req: dict, args) -> dict:
    sid = int(req["rengine_scan_history_id"])
    name = f"suricatoos-rengine-{sid}"
    comment = json.dumps({
        "rengine_scan_history_id": sid,
        "target": req.get("target", ""),
        "engagement": req.get("engagement", ""),
    })
    hosts = sanitize_ips(req.get("hosts"))
    port_range = build_port_range(req.get("hosts"))

    # (a) target — find-or-create by exact name (idempotent).
    target_id = _find_target_id(gmp, name)
    if not target_id:
        resp = gmp.send_command(str(Targets.create_target(
            name=name, hosts=hosts, port_range=port_range,
            alive_test=_alive_test(args.alive_test), comment=comment)))
        _assert_ok(resp, "create_target")
        target_id = _extract_id(resp)

    # (b) task — reuse if present.
    task_id, status, _, report_id = _task_info(gmp, name)
    if not task_id:
        resp = gmp.send_command(str(Tasks.create_task(
            name=name, config_id=args.config_id, target_id=target_id,
            scanner_id=args.scanner_id, comment=comment)))
        _assert_ok(resp, "create_task")
        task_id = _extract_id(resp)
        status = "New"

    # (c) start ONLY if idle — never restart a live or finished task.
    if status in _STARTABLE:
        resp = gmp.send_command(str(Tasks.start_task(task_id)))
        _assert_ok(resp, "start_task")
        # start_task_response carries the report id in a CHILD <report_id>, not a
        # root @id attribute — _extract_id would return "" here.
        rid = ET.fromstring(resp).findtext("report_id") or ""
        if rid:
            report_id = rid
        status = "Requested"

    return {"target_id": target_id, "task_id": task_id, "report_id": report_id or "", "status": status}


def cmd_status(gmp: Gmp, req: dict, _args) -> dict:
    name = f"suricatoos-rengine-{int(req['rengine_scan_history_id'])}"
    task_id, status, progress, report_id = _task_info(gmp, name)
    if not task_id:
        # NÃO emitir 'error' aqui: um campo error faz o exec.go do ingest tratar como
        # falha transitória (retry), então a transição terminal 'Interrupted' nunca
        # dispararia e o job ficaria preso em RUNNING até o SCAN_MAX_DURATION.
        return {"status": "Interrupted", "progress": 0, "report_id": ""}
    return {"status": status, "progress": progress, "report_id": report_id or ""}


def cmd_fetch(gmp: Gmp, req: dict, _args) -> dict:
    name = f"suricatoos-rengine-{int(req['rengine_scan_history_id'])}"
    _tid, _status, _progress, report_id = _task_info(gmp, name)
    if not report_id:
        return {"findings": []}
    resp = gmp.send_command(str(Reports.get_report(
        report_id, details=True,
        filter_string="apply_overrides=1 levels=hmlg rows=-1 min_qod=0")))
    _assert_ok(resp, "get_report")
    return {"findings": parse_report_results(resp)}


def cmd_stop(gmp: Gmp, req: dict, _args) -> dict:
    name = f"suricatoos-rengine-{int(req['rengine_scan_history_id'])}"
    task_id, _status, _progress, _report_id = _task_info(gmp, name)
    if task_id:
        gmp.send_command(str(Tasks.stop_task(task_id)))  # best effort
    return {"stopped": True}


_COMMANDS = {"launch": cmd_launch, "status": cmd_status, "fetch": cmd_fetch, "stop": cmd_stop}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=sorted(_COMMANDS))
    p.add_argument("request", help="Path to the scan-request/job JSON (- for stdin)")
    p.add_argument("--socket", default="/run/gvmd/gvmd.sock")
    p.add_argument("--host")
    p.add_argument("--port", type=int, default=9390)
    p.add_argument("--username", default="suricatoos-scan")
    p.add_argument("--password", default=os.environ.get("GVM_PASSWORD", ""))
    p.add_argument("--config-id", default=CONFIG_FULL_AND_FAST)
    p.add_argument("--scanner-id", default=SCANNER_OPENVAS_DEFAULT)
    p.add_argument("--alive-test", default="Consider Alive")
    args = p.parse_args()

    req = json.load(sys.stdin) if args.request == "-" else json.load(open(args.request))
    if not args.password:
        _emit_error("GMP password required (--password or GVM_PASSWORD)")
    if not args.socket and not args.host:
        _emit_error("provide --socket or --host")

    try:
        with Gmp(connection=_connect(args)) as gmp:
            _assert_ok(gmp.send_command(str(Authentication.authenticate(
                username=args.username, password=args.password))), "authenticate")
            result = _COMMANDS[args.command](gmp, req, args)
        print(json.dumps(result))
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — surface any failure as JSON for the Go caller
        _emit_error(f"{type(e).__name__}: {e}")


def _emit_error(msg: str) -> None:
    print(json.dumps({"error": msg}))
    sys.exit(1)


if __name__ == "__main__":
    main()
