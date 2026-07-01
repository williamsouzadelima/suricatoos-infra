#!/usr/bin/env python3
# Read-only gvmd query that powers the Suricatoos "Agents" page. Lists every
# endpoint-agent container task (`suricatoos-agent-<id>`) with its posture from
# the LAST report: severity, threat class, finding counts, timestamp, report id.
#
# The agent's precise Notus findings live in a gvmd container task, which the GSA
# Tasks page can't render with a severity column (gvmd doesn't compute task-level
# severity for container tasks). This query reads the report/host severity — the
# accurate value — so the Agents page can show it like a normal scan.
#
# Reads GMP_SOCKET / GMP_USERNAME / GVM_PASSWORD from the environment (the ingest
# container already carries them); the password never appears on the CLI. Prints
# a JSON array to stdout; exits non-zero on error (the caller returns 500).
import json
import os
import sys
import xml.etree.ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

TASK_PREFIX = "suricatoos-agent-"


def el(resp):
    return resp if ET.iselement(resp) else ET.fromstring(resp)


def txt(node, path, default=""):
    if node is None:
        return default
    f = node.find(path)
    return (f.text or "").strip() if f is not None and f.text else default


def threat_class(sev: float) -> str:
    # GVM/NVD default severity classes.
    if sev >= 9.0:
        return "Critical"
    if sev >= 7.0:
        return "High"
    if sev >= 4.0:
        return "Medium"
    if sev > 0.0:
        return "Low"
    return "Log"


def main() -> None:
    sock = os.environ.get("GMP_SOCKET", "/run/gvmd/gvmd.sock")
    user = os.environ.get("GMP_USERNAME", "admin")
    password = os.environ.get("GVM_PASSWORD", "")

    conn = UnixSocketConnection(path=sock)
    agents = []
    with Gmp(connection=conn) as gmp:
        gmp.authenticate(username=user, password=password)
        tasks = el(gmp.get_tasks(filter_string=f"name~{TASK_PREFIX} rows=200 sort=name"))
        for t in tasks.findall("task"):
            name = txt(t, "name")
            if not name.startswith(TASK_PREFIX):
                continue  # substring filter can over-match; anchor on the prefix
            host = name[len(TASK_PREFIX):]
            lr = t.find("last_report/report")
            sev = 0.0
            try:
                sev = float(txt(lr, "severity", "0") or "0")
            except ValueError:
                sev = 0.0
            rc = lr.find("result_count") if lr is not None else None

            def count(tag):
                v = txt(rc, tag, "0") if rc is not None else "0"
                try:
                    return int(v or "0")
                except ValueError:
                    return 0

            crit, high, med, low = count("critical"), count("high"), count("medium"), count("low")
            findings = crit + high + med + low
            agents.append({
                "host": host,
                "task": name,
                "task_id": t.get("id", ""),
                "severity": round(sev, 1),
                "threat": threat_class(sev),
                "findings": findings,
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "last_report": txt(lr, "timestamp") if lr is not None else "",
                "report_id": lr.get("id") if lr is not None else "",
                "reports": int(txt(t, "report_count/full", txt(t, "report_count", "0")) or "0"),
            })

    json.dump(agents, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001 - surface any failure as a non-zero exit
        print(f"agents_query error: {e}", file=sys.stderr)
        sys.exit(1)
