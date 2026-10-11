"""Tests for fleet_ops.py (ADR-0011, slice F2.3) — no live gvmd.

FakeGvmd answers the GMP commands fleet_ops sends with gvmd 26.31.1-shaped XML and
reproduces the gvmd behaviours the implementation depends on (verified in the gvmd
v26.31.1 sources): alive tests are a bitfield of methods — <alive_test> sub-elements
parsed like alive_test_from_array, a text value like alive_test_from_string (which
refuses the combined 'ICMP, TCP-SYN Service & ARP Ping'), read back as gvmd's legacy
string plus one sub-element per method; rows=-1 is capped at "Max Rows Per Page"
unless ignore_pagination=1 (tasks, reports, results) and targets/schedules page with
first=N; modify_task applies name/comment BEFORE refusing a target change on a non-New
task; modify_target needs HOSTS and EXCLUDE_HOSTS together and refuses host changes on
a target in use; modify_schedule requires ICALENDAR; lean=1 trims result fields.

Every output is validated OFFLINE against schema/fleet-*.schema.json (local registry,
no network): the $defs entry AND the full result / state body the connector will send.
The request validation is also run against every command example of the contract
(schema/examples/fleet), so fleet_ops and the example validator give the same verdict.
"""

import base64
import datetime
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from gvm.errors import GvmError
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

import fleet_ops

HERE = Path(__file__).resolve().parent
SCHEMA_DIR = HERE.parent / "schema"
EXAMPLES_DIR = SCHEMA_DIR / "examples" / "fleet"
BASE = "https://suricatoos.dev/schema/"

SENTINEL = "Sentinela-S3nh4-9f2c-only-in-env"   # the gvmd password: ONLY in the environment
TENANT_USER = "acme-gmp"                          # tenant 'acme' gvmd user (owner of its objects)
OTHER_USER = "globex-gmp"                         # another tenant's gvmd user
READER = "fleet-reader"                           # the node's "current" gvmd user (D6)
CID = "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18"
NOW = datetime.datetime(2026, 10, 11, 12, 0, 0, tzinfo=datetime.timezone.utc)

ENV_TENANT = {"GMP_USERNAME": TENANT_USER, "GMP_PASSWORD": SENTINEL, "GVMD_SOCKET": "/run/gvmd/gvmd.sock"}
ENV_READER = {"GMP_USERNAME": READER, "GMP_PASSWORD": SENTINEL, "GVMD_SOCKET": "/run/gvmd/gvmd.sock"}


def U(n):
    return f"00000000-0000-4000-8000-{n:012x}"


TASK, TASK2, TARGET, TARGET2, SCHED, REPORT, REPORT_OLD, REPORT_OTHER = (U(i) for i in range(1, 9))
MISSING = U(0xdead)
CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER = fleet_ops.SCANNER_OPENVAS_DEFAULT
PORT_LIST = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
ICAL = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20261012T020000Z\r\n"
        "RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
ICAL2 = ICAL.replace("WEEKLY", "DAILY")
PDF_BYTES = b"%PDF-1.7\n" + bytes(range(256)) * 900 + b"\n%%EOF\n"   # > one gvmd base64 chunk
CSV_BYTES = "IP,Hostname,Port\n192.0.2.10,,443\n".encode("utf-8")
TECHNICAL_IDS = set(fleet_ops.REPORT_FORMAT_IDS.values())
# gvmd 26.31.1 alive tests: a bitfield of methods, or 'default' (Scan Config Default, 0)
# or 'consider' (Consider Alive).
ICMP, ACK, SYN, ARP = "ICMP", "TCP-ACK Service", "TCP-SYN Service", "ARP"
STR_ORDER = (ICMP, ACK, SYN, ARP)        # send_alive_tests_str order
SUB_ORDER = (ARP, ICMP, ACK, SYN)        # send_alive_tests_subelems order
ARRAY_ITEMS = {"arp": ARP, "arp ping": ARP, "icmp": ICMP, "icmp ping": ICMP,          # alive_test_from_array
               "tcp-ack service": ACK, "tcp-ack service ping": ACK,
               "tcp-syn service": SYN, "tcp-syn service ping": SYN}
LEGACY_STRINGS = {  # alive_test_from_string: NO 'ICMP, TCP-SYN Service & ARP Ping'
    "": "default", "Scan Config Default": "default", "Consider Alive": "consider",
    "ICMP, TCP-ACK Service & ARP Ping": frozenset({ICMP, ACK, ARP}),
    "TCP-ACK Service & ARP Ping": frozenset({ACK, ARP}), "ICMP & ARP Ping": frozenset({ICMP, ARP}),
    "ICMP & TCP-ACK Service Ping": frozenset({ICMP, ACK}), "ARP Ping": frozenset({ARP}),
    "TCP-ACK Service Ping": frozenset({ACK}), "TCP-SYN Service Ping": frozenset({SYN}),
    "ICMP Ping": frozenset({ICMP}),
}
# The ADR-0011 table, transcribed here independently of fleet_ops.ALIVE_TEST_METHODS.
ADR_ALIVE_TABLE = {
    "ICMP, TCP-SYN Service & ARP Ping": ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"],
    "ICMP, TCP-ACK Service & ARP Ping": ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"],
    "ICMP & TCP-ACK Service Ping": ["ICMP Ping", "TCP-ACK Service Ping"],
    "ICMP & ARP Ping": ["ICMP Ping", "ARP Ping"],
    "TCP-ACK Service & ARP Ping": ["TCP-ACK Service Ping", "ARP Ping"],
    "ICMP Ping": ["ICMP Ping"], "TCP-ACK Service Ping": ["TCP-ACK Service Ping"],
    "TCP-SYN Service Ping": ["TCP-SYN Service Ping"], "ARP Ping": ["ARP Ping"],
    "Consider Alive": ["Consider Alive"], "Scan Config Default": ["Scan Config Default"],
}


def alive_strings(alive):
    """gvmd's rendering of an alive-test value: (legacy string, sub-element texts)."""
    if alive == "default":
        return "Scan Config Default", ["Scan Config Default"]
    if alive == "consider":
        return "Consider Alive", ["Consider Alive"]
    names = [m for m in STR_ORDER if m in alive]
    text = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " & " + names[-1]
    return text + " Ping", [f"{m} Ping" for m in SUB_ORDER if m in alive]
LEVEL_OF = {"c": lambda s: s >= 9.0, "h": lambda s: 7.0 <= s < 9.0, "m": lambda s: 4.0 <= s < 7.0,
            "l": lambda s: 0.0 < s < 4.0, "g": lambda s: s == 0.0, "f": lambda s: s == -1.0}


# --------------------------------------------------------------------------- #
# Offline schema validation
# --------------------------------------------------------------------------- #

def _registry():
    resources = []
    for path in sorted(SCHEMA_DIR.glob("fleet-*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)   # no retrieve(): an unknown $ref raises


REGISTRY = _registry()
MESSAGE_MAX = json.loads((SCHEMA_DIR / "fleet-result.schema.json").read_text(encoding="utf-8"))[
    "$defs"]["error"]["properties"]["message"]["maxLength"]


def validate(ref, instance):
    validator = Draft202012Validator({"$ref": BASE + ref}, registry=REGISTRY,
                                     format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors]


OUTPUT_DEF = {
    "task.start": "output_task_action", "task.stop": "output_task_action",
    "task.resume": "output_task_action", "task.create": "output_task_create",
    "task.modify": "output_task_modify", "task.clone": "output_task_clone",
    "task.delete": "output_trash", "target.create": "output_target_create",
    "target.modify": "output_target_modify", "target.delete": "output_trash",
    "schedule.create": "output_schedule_create", "schedule.modify": "output_schedule_modify",
    "schedule.delete": "output_trash", "report.export": "output_report_export",
    "report.summary": "output_report_summary",
}


def result_body(op, response):
    body = {"schema_version": "1.0.0", "command_id": CID, "node_id": "node-lab-0001", "type": op,
            "started_at": "2026-10-11T12:00:00Z", "finished_at": "2026-10-11T12:00:05Z",
            "contains_secret": False}
    if response["ok"]:
        body.update(status="succeeded", output=response["output"])
        if op == "report.export":
            art = response["artifact"]
            gz = gzip.compress(b"x")          # the connector's gzip: only its shape matters here
            body["artifacts"] = [{"name": response["output"]["artifact_name"], "content_encoding": "gzip",
                                  "size": len(gz), "sha256": hashlib.sha256(gz).hexdigest(), **art}]
    else:
        body.update(status="failed", error=response["error"])
    return body


def assert_ok(op, response, code):
    assert code == 0, response
    assert response.get("ok") is True, response
    allowed = {"ok", "output", "artifact"} if op == "report.export" else {"ok", "output"}
    assert set(response) == allowed
    validate(f"fleet-result.schema.json#/$defs/{OUTPUT_DEF[op]}", response["output"])
    validate("fleet-result.schema.json", result_body(op, response))
    return response["output"]


def assert_error(response, code, expected, op="task.start"):
    assert code == 0, response
    assert response["ok"] is False, response
    assert set(response) == {"ok", "error"}
    assert response["error"]["code"] == expected, response
    validate("fleet-result.schema.json#/$defs/error", response["error"])
    validate("fleet-result.schema.json", result_body(op, response))
    return response["error"]["message"]


def assert_state(kind, response, code):
    assert code == 0 and response["ok"] is True, response
    data = response["output"]
    validate(f"fleet-state.schema.json#/$defs/data_{kind}", data)
    raw = fleet_ops.dumps(data)
    validate("fleet-state.schema.json", {
        "schema_version": "1.0.0", "node_id": "node-lab-0001", "kind": kind,
        "collected_at": "2026-10-11T12:00:00Z", "content_sha256": hashlib.sha256(raw).hexdigest(),
        "data": data})
    return data


# --------------------------------------------------------------------------- #
# Fake gvmd
# --------------------------------------------------------------------------- #

def E(tag, text=None, **attrs):
    el = ET.Element(tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        el.text = str(text)
    return el


def sub(parent, tag, text=None, **attrs):
    el = E(tag, text, **attrs)
    parent.append(el)
    return el


def xml(el):
    return ET.tostring(el, encoding="unicode")


def refusal(tag, status, text):
    return xml(E(f"{tag}_response", status=status, status_text=text))


def _filter_terms(term):
    return dict(part.split("=", 1) for part in (term or "").split() if "=" in part)


class FakeGvmd:
    """A tiny gvmd: in-memory objects, gvmd-shaped XML, every command recorded."""

    def __init__(self):
        self.calls = []
        self.raw = []
        self.user = None
        self.auth_ok = True
        self.refuse_methods = set()          # LAB switch: refuse a set holding these methods
        self.honor_lean = True               # lean=1 trims result fields, like gvmd
        self.max_rows = 1000                 # "Max Rows Per Page"
        self.connect_error = None
        self.timeouts = []
        self.refuse = {}                     # command tag -> (status, status_text)
        self.raise_on = {}                   # command tag -> exception
        self.tasks, self.targets, self.schedules, self.reports = {}, {}, {}, {}
        self.trash = []
        self.report_formats = {rf: {"active": "1", "trust": "yes"} for rf in TECHNICAL_IDS}
        self.feeds = [("NVT", "202610110600", False, False), ("SCAP", "202610100000", False, False),
                      ("CERT", "202610090000", False, False), ("GVMD_DATA", "202610010000", False, False)]
        self._next = 0x900

    # -- connection ---------------------------------------------------------- #
    def connect(self, env, timeout):
        self.timeouts.append(timeout)
        fake = self

        class _Context:
            def __enter__(self):
                if fake.connect_error is not None:
                    raise fake.connect_error
                return fake

            def __exit__(self, *exc):
                return False
        return _Context()

    def send_command(self, command):
        el = ET.fromstring(command)
        self.raw.append(command)
        self.calls.append(el)
        if el.tag in self.raise_on:
            raise self.raise_on[el.tag]
        if el.tag in self.refuse:
            return refusal(el.tag, *self.refuse[el.tag])
        return getattr(self, "_" + el.tag)(el)

    def sent(self, tag):
        return [c for c in self.calls if c.tag == tag]

    def writes(self):
        return [c.tag for c in self.calls if not c.tag.startswith(("get_", "authenticate"))]

    def tags(self):
        return [c.tag for c in self.calls]

    def new_id(self):
        self._next += 1
        return U(self._next)

    # -- model --------------------------------------------------------------- #
    def add_task(self, task_id, owner=TENANT_USER, **kw):
        task = dict(id=task_id, owner=owner, name="Varredura semanal", comment="", status="New",
                    progress=-1, alterable="0", target=TARGET, target_trash="0", config=CONFIG,
                    scanner=SCANNER, schedule="", schedule_trash="0", report_count=0, last_report=None)
        task.update(kw)
        self.tasks[task_id] = task
        return task

    def add_target(self, target_id, owner=TENANT_USER, **kw):
        target = dict(id=target_id, owner=owner, name=f"alvo-{target_id[-4:]}", comment="",
                      hosts="192.0.2.0/24", exclude_hosts="", port_list=PORT_LIST,
                      alive=frozenset({ICMP, ACK, ARP}), in_use="0", port_range="T:1-65535")
        target.update(kw)
        self.targets[target_id] = target
        return target

    def add_schedule(self, schedule_id, owner=TENANT_USER, **kw):
        schedule = dict(id=schedule_id, owner=owner, name="semanal", comment="", icalendar=ICAL,
                        timezone="America/Sao_Paulo", tasks=[])
        schedule.update(kw)
        self.schedules[schedule_id] = schedule
        return schedule

    def add_report(self, report_id, owner=TENANT_USER, task=TASK, **kw):
        report = dict(id=report_id, owner=owner, task=task, status="Done",
                      creation_time="2026-10-10T02:00:00Z", scan_start="2026-10-10T02:00:05Z",
                      scan_end="2026-10-10T03:10:00Z", hosts_count=3,
                      counts=dict(critical=1, high=2, medium=0, low=1, log=4, false_positive=1),
                      results=[], content={})
        report.update(kw)
        self.reports[report_id] = report
        return report

    # -- element builders ---------------------------------------------------- #
    def _common(self, el, obj, in_use="0"):
        owner = sub(el, "owner")
        sub(owner, "name", obj["owner"])
        sub(el, "name", obj["name"])
        sub(el, "comment", obj["comment"])
        sub(el, "creation_time", "2026-10-01T10:00:00Z")
        sub(el, "modification_time", "2026-10-02T10:00:00-03:00")
        sub(el, "writable", "1")
        sub(el, "in_use", in_use)
        sub(el, "permissions")

    def _task_el(self, t):
        el = E("task", id=t["id"])
        self._common(el, t)
        sub(el, "alterable", t["alterable"])
        sub(el, "usage_type", "scan")
        cfg = sub(el, "config", id=t["config"])
        sub(cfg, "name", "Full and fast")
        sub(cfg, "trash", "0")
        tgt = sub(el, "target", id=t["target"])
        sub(tgt, "name", "alvo")
        sub(tgt, "trash", t["target_trash"])
        scn = sub(el, "scanner", id=t["scanner"])
        sub(scn, "name", "OpenVAS Default")
        sub(scn, "type", "2")
        sub(scn, "trash", "0")
        sub(el, "status", t["status"])
        sub(el, "progress", t["progress"])
        rc = sub(el, "report_count", t["report_count"])
        sub(rc, "finished", t["report_count"])
        sub(el, "trend")
        sch = sub(el, "schedule", id=t["schedule"])
        sub(sch, "name", "semanal" if t["schedule"] else "")
        sub(sch, "trash", t["schedule_trash"])
        sub(el, "schedule_periods", "0")
        if t["last_report"]:
            lr = sub(sub(el, "last_report"), "report", id=t["last_report"])
            sub(lr, "timestamp", "2026-10-10T23:00:00-03:00")
            sub(lr, "scan_start", "2026-10-10T23:00:05-03:00")
            sub(lr, "scan_end", "")
        sub(el, "observers")
        return el

    def _target_el(self, t, details):
        el = E("target", id=t["id"])
        self._common(el, t, in_use=t["in_use"])
        sub(el, "hosts", t["hosts"])
        sub(el, "exclude_hosts", t["exclude_hosts"])
        sub(el, "max_hosts", "256")
        pl = sub(el, "port_list", id=t["port_list"])
        sub(pl, "name", "All IANA assigned TCP")
        sub(pl, "trash", "0")
        for cred in ("ssh_credential", "smb_credential", "esxi_credential", "snmp_credential"):
            c = sub(el, cred, id="")
            sub(c, "name", "")
            sub(c, "trash", "0")
        sub(el, "reverse_lookup_only", "0")
        sub(el, "reverse_lookup_unify", "0")
        sub(el, "allow_simultaneous_ips", "1")
        legacy, methods = alive_strings(t["alive"])
        alive = sub(el, "alive_tests", legacy)
        for method in methods:
            sub(alive, "alive_test", method)
        if details:
            sub(el, "port_range", t["port_range"])
        return el

    def _schedule_el(self, s, with_tasks):
        el = E("schedule", id=s["id"])
        self._common(el, s)
        sub(el, "icalendar", s["icalendar"])
        sub(el, "timezone", s["timezone"])
        if with_tasks:
            tasks = sub(el, "tasks")
            for task_id in s["tasks"]:
                t = sub(tasks, "task", id=task_id)
                sub(t, "name", "tarefa")
        return el

    def _result_el(self, r, lean=False):
        el = E("result", id=r.get("id", self.new_id()))
        sub(el, "name", r.get("name", "OpenSSL Heartbleed"))
        if not lean:                                   # gvmd: lean drops owner and times
            sub(sub(el, "owner"), "name", TENANT_USER)
            sub(el, "modification_time", "2026-10-10T03:00:00Z")
        host = sub(el, "host", r["host"])
        if not lean:                                   # ...and the empty asset placeholder
            sub(host, "asset", asset_id="")
        sub(host, "hostname", r.get("hostname", "web01.example.com"))
        sub(el, "port", r.get("port", "443/tcp"))
        nvt = sub(el, "nvt", oid=r.get("oid", "1.3.6.1.4.1.25623.1.0.103936"))
        sub(nvt, "name", r.get("name", "OpenSSL Heartbleed"))
        refs = sub(nvt, "refs")
        sub(refs, "ref", type="cve", id=r.get("cve", "CVE-2014-0160"))
        if not lean:                                   # ...and scan_nvt_version / threat
            sub(el, "scan_nvt_version", "2026-10-01T00:00:00Z")
            sub(el, "threat", "High")
        sub(el, "severity", f"{r['severity']:.1f}")
        qod = sub(el, "qod")
        sub(qod, "value", r.get("qod", 80))
        sub(qod, "type", "remote_banner")
        sub(el, "description", r.get("description", "evidence: TLS heartbeat leaked memory"))
        return el

    def _inner_report(self, r, results, lean=False):
        el = E("report", id=r["id"])
        sub(sub(el, "gmp"), "version", "22.7")
        sub(el, "scan_run_status", r["status"])
        sub(sub(el, "hosts"), "count", r["hosts_count"])
        sub(sub(el, "vulns"), "count", "5")
        task = sub(el, "task", id=r["task"])
        sub(task, "name", "Varredura semanal")
        sub(el, "timestamp", r["creation_time"])
        sub(el, "scan_start", r["scan_start"])
        sub(el, "timezone", "UTC")
        if results is not None:
            res = sub(el, "results", start="1", max="-1")
            for item in results:
                res.append(self._result_el(item, lean))
        rc = sub(el, "result_count", sum(r["counts"].values()))
        sub(rc, "full", sum(r["counts"].values()))
        sub(rc, "filtered", sum(r["counts"].values()))
        for level in ("critical", "high", "medium", "low", "log", "false_positive"):
            node = sub(rc, level)
            sub(node, "full", r["counts"][level])
            sub(node, "filtered", 0 if level == "false_positive" else r["counts"][level])
        sev = sub(el, "severity")
        sub(sev, "full", "10.0")
        sub(sev, "filtered", "10.0")
        sub(el, "scan_end", r["scan_end"])
        return el

    def _outer_report(self, r, inner=None, format_id=""):
        el = E("report", id=r["id"], format_id=format_id, config_id="", extension="",
               content_type="application/xml")
        owner = sub(el, "owner")
        sub(owner, "name", r["owner"])
        sub(el, "name", r["creation_time"])
        sub(el, "comment", "")
        sub(el, "creation_time", r["creation_time"])
        sub(el, "modification_time", r["creation_time"])
        sub(el, "writable", "0")
        sub(el, "in_use", "0")
        task = sub(el, "task", id=r["task"])
        sub(task, "name", "Varredura semanal")
        if format_id:
            fmt = sub(el, "report_format", id=format_id)
            sub(fmt, "name", "format")
        if inner is not None:
            el.append(inner)
        return el

    def _response(self, tag, children=(), status="200", text="OK", count=None):
        el = E(f"{tag}_response", status=status, status_text=text)
        for child in children:
            el.append(child)
        if count is not None:
            kind, full, page = count
            c = sub(el, f"{kind}_count", full)
            sub(c, "filtered", full)
            sub(c, "page", page)
        return xml(el)

    def _page(self, el, objects, kind):
        terms = _filter_terms(el.get("filter"))
        first = max(int(terms.get("first", "1")), 1)
        ordered = sorted(objects, key=lambda o: o["id"])
        page = ordered[first - 1:first - 1 + self.max_rows]
        return page, (kind, len(ordered), len(page))

    # -- commands ------------------------------------------------------------ #
    def _authenticate(self, el):
        self.user = el.findtext("credentials/username")
        if not self.auth_ok:
            return refusal("authenticate", "400", "Authentication failed")
        return self._response("authenticate", [E("role", "User"), E("timezone", "UTC")])

    def _get_version(self, el):
        return self._response("get_version", [E("version", "22.7")])

    def _get_feeds(self, el):
        feeds = []
        for ftype, version, syncing, unavailable in self.feeds:
            f = E("feed")
            sub(f, "type", ftype)
            sub(f, "name", f"Greenbone {ftype} Feed")
            sub(f, "version", version)
            sub(f, "description", "feed")
            if unavailable:
                sub(sub(f, "sync_not_available"), "error", "Could not connect to scanner")
            if syncing:
                sub(sub(f, "currently_syncing"), "timestamp", "")
            feeds.append(f)
        return self._response("get_feeds", feeds)

    def _get_report_formats(self, el):
        out = []
        for rf_id, info in sorted(self.report_formats.items()):
            node = E("report_format", id=rf_id)
            sub(node, "name", "fmt")
            trust = sub(node, "trust", info["trust"])
            sub(trust, "time", "2026-10-01T00:00:00Z")
            sub(node, "active", info["active"])
            out.append(node)
        return self._response("get_report_formats", out, count=("report_format", len(out), len(out)))

    def _get_tasks(self, el):
        task_id = el.get("task_id")
        if task_id:
            if task_id not in self.tasks:
                return refusal("get_tasks", "404", f"Failed to find task '{task_id}'")
            return self._response("get_tasks", [self._task_el(self.tasks[task_id])])
        ordered = sorted(self.tasks.values(), key=lambda t: t["id"])
        if el.get("ignore_pagination") != "1":
            ordered = ordered[:self.max_rows]
        return self._response("get_tasks", [self._task_el(t) for t in ordered],
                              count=("task", len(self.tasks), len(ordered)))

    def _task_action(self, el, tag):
        task = self.tasks.get(el.get("task_id"))
        if task is None:
            return refusal(tag, "404", f"Failed to find task '{el.get('task_id')}'")
        active = task["status"] in ("Requested", "Queued", "Running")
        if tag == "start_task" and active:
            return refusal(tag, "400", "Task is active already")
        if tag == "resume_task" and task["status"] not in ("Stopped", "Interrupted"):
            return refusal(tag, "400", "Task must be in Stopped or Interrupted state")
        if tag == "stop_task":
            task["status"] = "Stop Requested" if active else "Stopped"
            return self._response(tag, status="202", text="OK, request submitted")
        task["status"] = "Requested"
        report_id = self.new_id()
        return self._response(tag, [E("report_id", report_id)], status="202", text="OK, request submitted")

    def _start_task(self, el):
        return self._task_action(el, "start_task")

    def _stop_task(self, el):
        return self._task_action(el, "stop_task")

    def _resume_task(self, el):
        return self._task_action(el, "resume_task")

    def _create_task(self, el):
        copy = el.findtext("copy")
        if copy:
            src = self.tasks.get(copy)
            if src is None:
                return refusal("create_task", "404", f"Failed to find task '{copy}'")
            name = el.findtext("name") or src["name"] + " Clone"
            if el.findtext("name") and any(t["name"] == name for t in self.tasks.values()):
                return refusal("create_task", "400", "Task exists already")
            new = dict(src, id=self.new_id(), owner=self.user, name=name, status="New",
                       comment=el.findtext("comment") or src["comment"], report_count=0, last_report=None)
        else:
            target_id = el.find("target").get("id")
            if target_id not in self.targets:
                return refusal("create_task", "404", f"Failed to find target '{target_id}'")
            sched = el.find("schedule")
            new = dict(id=self.new_id(), owner=self.user, name=el.findtext("name"),
                       comment=el.findtext("comment") or "", status="New", progress=-1, alterable="0",
                       target=target_id, target_trash="0", config=el.find("config").get("id"),
                       scanner=el.find("scanner").get("id"),
                       schedule=sched.get("id") if sched is not None else "", schedule_trash="0",
                       report_count=0, last_report=None)
        self.tasks[new["id"]] = new
        return self._response("create_task", status="201", text="OK, resource created").replace(
            "<create_task_response ", f'<create_task_response id="{new["id"]}" ', 1)

    def _modify_task(self, el):
        task = self.tasks.get(el.get("task_id"))
        if task is None:
            return refusal("modify_task", "404", "Failed to find task")
        # gvmd 26.31.1: name and comment land first, the target check comes later.
        if el.find("name") is not None:
            task["name"] = el.findtext("name")
        if el.find("comment") is not None:
            task["comment"] = el.findtext("comment") or ""
        sched = el.find("schedule")
        if sched is not None:
            task["schedule"] = "" if sched.get("id") == "0" else sched.get("id")
        for tag, field in (("config", "config"), ("target", "target")):
            node = el.find(tag)
            if node is not None:
                if task["status"] != "New" and task["alterable"] != "1":
                    return refusal("modify_task", "400", f"Status must be New to edit {tag.title()}")
                task[field] = node.get("id")
        return self._response("modify_task")

    def _delete_task(self, el):
        task = self.tasks.pop(el.get("task_id"), None)
        if task is None:
            return refusal("delete_task", "404", "Failed to find task")
        self.trash.append(("task", task["id"], el.get("ultimate")))
        return self._response("delete_task")

    def _get_targets(self, el):
        target_id = el.get("target_id")
        if target_id:
            if target_id not in self.targets:
                return refusal("get_targets", "404", f"Failed to find target '{target_id}'")
            return self._response("get_targets", [self._target_el(self.targets[target_id], el.get("details") == "1")])
        page, count = self._page(el, self.targets.values(), "target")
        return self._response("get_targets", [self._target_el(t, False) for t in page], count=count)

    def _parse_alive(self, el):
        """(alive value or None if absent, gvmd refusal text or None)."""
        node = el.find("alive_tests")
        if node is None:
            return None, None
        subs = [(sub.text or "").strip() for sub in node.findall("alive_test")]
        text = (node.text or "").strip()
        if subs and text:
            return None, "ALIVE_TESTS can contain either a string or sub-elements, but not both."
        if not subs:
            value = LEGACY_STRINGS.get(text)
            return (value, None) if value is not None else (None, "Error in alive test")
        if self.refuse_methods & set(subs):
            return None, "Error in alive test"
        flags = set()
        for item in subs:
            low = item.lower()
            if low == "scan config default":
                return "default", None
            if low == "consider alive":
                return "consider", None
            if low not in ARRAY_ITEMS:
                return None, "Error in alive test"
            flags.add(ARRAY_ITEMS[low])
        return frozenset(flags), None

    def _create_target(self, el):
        alive, refused = self._parse_alive(el)
        if refused:
            return refusal("create_target", "400", refused)
        has_list, has_range = el.find("port_list") is not None, el.find("port_range") is not None
        if not has_list and not has_range:
            return refusal("create_target", "400", "One of PORT_LIST and PORT_RANGE are required")
        if has_range and not re.fullmatch(r"[TU]:[0-9,\-]+", el.findtext("port_range") or ""):
            return refusal("create_target", "400", "Error in port range")
        if any(t["name"] == el.findtext("name") for t in self.targets.values()):
            return refusal("create_target", "400", "Target exists already")
        new = dict(id=self.new_id(), owner=self.user, name=el.findtext("name"),
                   comment=el.findtext("comment") or "",
                   hosts=", ".join(h.strip() for h in el.findtext("hosts").split(",")),
                   exclude_hosts=", ".join(h.strip() for h in (el.findtext("exclude_hosts") or "").split(",") if h.strip()),
                   port_list=el.find("port_list").get("id") if has_list else self.new_id(),
                   alive=alive if alive is not None else "default",
                   in_use="0", port_range=el.findtext("port_range") or "T:1-65535")
        self.targets[new["id"]] = new
        return self._response("create_target", status="201", text="OK, resource created").replace(
            "<create_target_response ", f'<create_target_response id="{new["id"]}" ', 1)

    def _modify_target(self, el):
        target = self.targets.get(el.get("target_id"))
        if target is None:
            return refusal("modify_target", "404", "Failed to find target")
        hosts, exclude = el.find("hosts"), el.find("exclude_hosts")
        if hosts is not None and exclude is None:
            return refusal("modify_target", "400", "HOSTS requires an EXCLUDE_HOSTS")
        if exclude is not None and hosts is None:
            return refusal("modify_target", "400", "EXCLUDE_HOSTS requires a HOSTS")
        if el.find("port_range") is not None:
            return refusal("modify_target", "400", "Unexpected element PORT_RANGE")
        if target["in_use"] == "1" and (hosts is not None or el.find("port_list") is not None):
            return refusal("modify_target", "400", "Target is in use")
        alive, refused = self._parse_alive(el)
        if refused:
            return refusal("modify_target", "400", refused)
        # gvmd runs modify_target in one transaction: all or nothing.
        if el.find("name") is not None:
            target["name"] = el.findtext("name")
        if el.find("comment") is not None:
            target["comment"] = el.findtext("comment") or ""
        if hosts is not None:
            target["hosts"] = ", ".join(h.strip() for h in (hosts.text or "").split(","))
            target["exclude_hosts"] = ", ".join(h.strip() for h in (exclude.text or "").split(",") if h.strip())
        if el.find("port_list") is not None:
            target["port_list"] = el.find("port_list").get("id")
        if alive is not None:
            target["alive"] = alive
        return self._response("modify_target")

    def _delete_target(self, el):
        target = self.targets.get(el.get("target_id"))
        if target is None:
            return refusal("delete_target", "404", "Failed to find target")
        if target["in_use"] == "1":
            return refusal("delete_target", "400", "Target is in use")
        del self.targets[target["id"]]
        self.trash.append(("target", target["id"], el.get("ultimate")))
        return self._response("delete_target")

    def _get_schedules(self, el):
        schedule_id = el.get("schedule_id")
        with_tasks = el.get("tasks") == "1"
        if schedule_id:
            if schedule_id not in self.schedules:
                return refusal("get_schedules", "404", f"Failed to find schedule '{schedule_id}'")
            return self._response("get_schedules", [self._schedule_el(self.schedules[schedule_id], with_tasks)])
        page, count = self._page(el, self.schedules.values(), "schedule")
        return self._response("get_schedules", [self._schedule_el(s, with_tasks) for s in page], count=count)

    def _create_schedule(self, el):
        new = dict(id=self.new_id(), owner=self.user, name=el.findtext("name"),
                   comment=el.findtext("comment") or "", icalendar=el.findtext("icalendar"),
                   timezone=el.findtext("timezone"), tasks=[])
        self.schedules[new["id"]] = new
        return self._response("create_schedule", status="201", text="OK, resource created").replace(
            "<create_schedule_response ", f'<create_schedule_response id="{new["id"]}" ', 1)

    def _modify_schedule(self, el):
        schedule = self.schedules.get(el.get("schedule_id"))
        if schedule is None:
            return refusal("modify_schedule", "404", "Failed to find schedule")
        if not (el.findtext("icalendar") or "").strip():
            return refusal("modify_schedule", "400", "ICALENDAR element is required")
        for field in ("name", "comment", "icalendar", "timezone"):
            if el.find(field) is not None:
                schedule[field] = el.findtext(field) or ""
        return self._response("modify_schedule", [E("status_details", "")])

    def _delete_schedule(self, el):
        schedule = self.schedules.pop(el.get("schedule_id"), None)
        if schedule is None:
            return refusal("delete_schedule", "404", "Failed to find schedule")
        self.trash.append(("schedule", schedule["id"], el.get("ultimate")))
        return self._response("delete_schedule")

    def _filtered_results(self, r, el):
        terms = _filter_terms(el.get("filter"))
        levels = terms.get("levels", "chmlgdf")
        min_qod = int(terms.get("min_qod", "70"))       # gvmd's hidden default
        keep = [x for x in r["results"]
                if x.get("qod", 80) >= min_qod and any(LEVEL_OF[c](x["severity"]) for c in levels if c in LEVEL_OF)]
        if el.get("ignore_pagination") != "1":
            keep = keep[:self.max_rows]
        return keep

    def _get_reports(self, el):
        report_id = el.get("report_id")
        if not report_id:
            ordered = sorted(self.reports.values(), key=lambda r: r["id"])
            if el.get("ignore_pagination") != "1":
                ordered = ordered[:self.max_rows]
            outers = [self._outer_report(r, self._inner_report(r, None)) for r in ordered]
            return self._response("get_reports", outers, count=("report", len(self.reports), len(ordered)))
        r = self.reports.get(report_id)
        if r is None:
            return refusal("get_reports", "404", f"Failed to find report '{report_id}'")
        delta = el.get("delta_report_id")
        if delta and delta not in self.reports:
            return refusal("get_reports", "404", f"Failed to find report '{delta}'")
        format_id = el.get("format_id", "")
        if format_id and format_id not in self.report_formats:
            return refusal("get_reports", "404", f"Failed to find report format '{format_id}'")
        results = self._filtered_results(r, el) if el.get("details") == "1" else None
        lean = self.honor_lean and el.get("lean") == "1"
        if not format_id:
            return self._response("get_reports", [self._outer_report(r, self._inner_report(r, results, lean))])
        if format_id == fleet_ops.REPORT_FORMAT_IDS[("gvm-xml", "en", "technical")]:
            outer = self._outer_report(r, self._inner_report(r, results), format_id)
            return self._response("get_reports", [outer])
        outer = self._outer_report(r, None, format_id)
        content = r["content"].get(format_id, b"")
        chunk = 196608   # gvmd's MANAGE_SEND_REPORT_CHUNK_SIZE: base64 per chunk
        outer[-1].tail = "".join(base64.b64encode(content[i:i + chunk]).decode()
                                 for i in range(0, len(content), chunk))
        return self._response("get_reports", [outer])


def cmd(op, payload, **extra):
    req = {"op": op, "command_id": CID, "tenant": "acme", "tenant_gmp_user": TENANT_USER, "payload": payload}
    req.update(extra)
    return req


def state_req(kind, payload=None, owners=None):
    req = {"op": f"state.{kind}", "command_id": "", "payload": {} if payload is None else payload}
    if kind != "node":
        req["owners"] = {TENANT_USER: "acme"} if owners is None else owners
    return req


def run(gvmd, request, env=None, raw=None):
    if env is None:
        spec = fleet_ops._OPS.get(request.get("op")) if isinstance(request, dict) else None
        env = ENV_TENANT if spec and spec["user"] == "tenant" else ENV_READER
    data = raw if raw is not None else json.dumps(request, ensure_ascii=False).encode("utf-8")
    response, code = fleet_ops.handle(data, env, connect=gvmd.connect, now=lambda: NOW)
    out = fleet_ops.dumps(response)
    # Never the password, and never a piece of it either: no prefix of >= 4 characters
    # (a truncation done before the redaction would leave exactly that).
    assert SENTINEL[:4].encode() not in out
    assert json.loads(out.decode("utf-8")) == response
    if not response.get("ok"):
        assert 1 <= len(response["error"]["message"]) <= MESSAGE_MAX
    return response, code


@pytest.fixture
def gvmd():
    g = FakeGvmd()
    g.add_target(TARGET)
    g.add_task(TASK)
    return g


# --------------------------------------------------------------------------- #
# Interface: strict request, allowlist, JSON encoding, credentials
# --------------------------------------------------------------------------- #

class TestInterface:
    def test_unknown_top_level_key_is_refused(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}, filter="rows=-1"))
        assert "unknown key" in assert_error(resp, code, "internal_error")
        assert gvmd.calls == []                                # nothing reached gvmd

    def test_key_of_another_op_shape_is_refused(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}, artifact_path="/tmp/x"))
        assert_error(resp, code, "internal_error")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}, owners={}))
        assert_error(resp, code, "internal_error")

    def test_missing_key_is_refused(self, gvmd):
        req = cmd("task.start", {"task_id": TASK})
        del req["tenant_gmp_user"]
        resp, code = run(gvmd, req)
        assert "missing key" in assert_error(resp, code, "internal_error")

    def test_unknown_payload_key_is_refused(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK, "force": True}))
        assert_error(resp, code, "internal_error")
        assert gvmd.calls == []

    @pytest.mark.parametrize("op", ["state.resync", "feed.sync_now", "agent.revoke", "enroll_token.create",
                                    "sensor_job.enqueue", "gmp.raw", "get_tasks", "task.START", ""])
    def test_op_outside_the_allowlist_is_refused(self, gvmd, op):
        resp, code = run(gvmd, cmd(op, {}))
        assert "allowlist" in assert_error(resp, code, "internal_error")
        assert gvmd.calls == []

    def test_allowlist_is_exactly_the_catalog_gvm_rows_plus_reads(self):
        assert set(fleet_ops._OPS) == {
            "task.start", "task.stop", "task.resume", "task.create", "task.modify", "task.clone",
            "task.delete", "target.create", "target.modify", "target.delete", "schedule.create",
            "schedule.modify", "schedule.delete", "report.export", "report.summary",
            "inspect.task", "inspect.target", "inspect.schedule",
            "state.node", "state.tasks", "state.targets", "state.schedules", "state.reports"}

    @pytest.mark.parametrize("raw", [
        b'{"op":"task.start","op":"task.stop","command_id":"x","tenant":"acme","tenant_gmp_user":"u","payload":{}}',
        b'{"op":"task.start"} {}',
        b'[1]',
        b'\xef\xbb\xbf{}',
        b'{"op": "task.start", "x": NaN}',
        b'\xff\xfe',
        b'',
    ])
    def test_malformed_json_is_refused(self, gvmd, raw):
        resp, code = run(gvmd, None, raw=raw)
        assert_error(resp, code, "internal_error")
        assert gvmd.calls == []

    def test_duplicate_key_inside_payload_is_refused(self, gvmd):
        raw = (b'{"op":"task.start","command_id":"' + CID.encode() + b'","tenant":"acme",'
               b'"tenant_gmp_user":"acme-gmp","payload":{"task_id":"' + TASK.encode() +
               b'","task_id":"' + TASK2.encode() + b'"}}')
        resp, code = run(gvmd, None, raw=raw)
        assert "duplicate key" in assert_error(resp, code, "internal_error")

    def test_integer_with_fraction_is_refused(self, gvmd):
        gvmd.add_report(REPORT)
        req = cmd("report.summary", {"report_id": REPORT, "min_qod": 70.0, "apply_overrides": True, "levels": "chml"})
        resp, code = run(gvmd, req)
        assert_error(resp, code, "internal_error", "report.summary")
        req["payload"]["min_qod"] = True
        resp, code = run(gvmd, req)
        assert_error(resp, code, "internal_error", "report.summary")

    def test_command_id_must_be_a_uuid_and_empty_for_state(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}, command_id=""))
        assert_error(resp, code, "internal_error")
        req = state_req("tasks")
        req["command_id"] = CID
        resp, code = run(gvmd, req)
        assert_error(resp, code, "internal_error")

    def test_state_read_refuses_command_keys(self, gvmd):
        req = state_req("tasks")
        req["tenant"] = "acme"
        resp, code = run(gvmd, req)
        assert_error(resp, code, "internal_error")
        resp, code = run(gvmd, state_req("tasks", payload={"filter": "rows=-1"}))
        assert_error(resp, code, "internal_error")

    def test_missing_credentials_in_environment(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}), env={"GMP_USERNAME": READER})
        assert "GMP_PASSWORD" in assert_error(resp, code, "internal_error")
        assert gvmd.calls == []

    def test_tenant_op_must_run_as_the_tenant_user(self, gvmd):
        resp, code = run(gvmd, cmd("task.delete", {"task_id": TASK}), env=ENV_READER)
        assert "tenant" in assert_error(resp, code, "internal_error", "task.delete")
        assert gvmd.calls == []

    def test_socket_unavailable(self, gvmd):
        gvmd.connect_error = GvmError("Socket /run/gvmd/gvmd.sock does not exist")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert_error(resp, code, "unavailable")

    def test_timeout_while_reading(self, gvmd):
        gvmd.raise_on["start_task"] = TimeoutError("timed out")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert_error(resp, code, "timeout")

    def test_connection_drop_mid_operation_is_gvm_error(self, gvmd):
        gvmd.raise_on["start_task"] = GvmError("Remote closed the connection")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert_error(resp, code, "gvm_error")

    def test_authentication_failure(self, gvmd):
        gvmd.auth_ok = False
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert assert_error(resp, code, "gvm_error") == "gvmd authentication failed"
        assert gvmd.writes() == []

    def test_unexpected_exception_exits_1_with_one_json_error(self, gvmd):
        gvmd.raise_on["start_task"] = RuntimeError("boom " + SENTINEL)
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert code == 1
        assert resp == {"ok": False, "error": {"code": "internal_error",
                                               "message": "unexpected failure (RuntimeError)"}}

    def test_socket_timeouts_follow_the_connector_budget(self, gvmd):
        gvmd.add_report(REPORT, content={fleet_ops.REPORT_FORMAT_IDS[("gvm-csv-results", "en", "technical")]: CSV_BYTES})
        run(gvmd, cmd("task.start", {"task_id": TASK}))
        run(gvmd, cmd("report.summary", {"report_id": REPORT, "min_qod": 70, "apply_overrides": True, "levels": "chml"}))
        assert gvmd.timeouts == [110, 290]
        assert fleet_ops.TIMEOUT_EXPORT == 890 < 900

    def test_output_encoding_is_compact_utf8_without_escapes(self):
        out = fleet_ops.dumps({"ok": True, "output": {"name": "Varredura São Paulo <&>  "}})
        assert out == '{"ok":true,"output":{"name":"Varredura São Paulo <&>  "}}'.encode("utf-8")


# --------------------------------------------------------------------------- #
# The gvmd password never leaves the process
# --------------------------------------------------------------------------- #

class TestSentinelPassword:
    def test_password_reaches_gvmd_only_in_authenticate(self, gvmd):
        run(gvmd, cmd("task.start", {"task_id": TASK}))
        carrying = [c.tag for c, raw in zip(gvmd.calls, gvmd.raw) if SENTINEL in raw]
        assert carrying == ["authenticate"]

    def test_gvm_error_carrying_the_password_is_not_echoed(self, gvmd):
        gvmd.raise_on["authenticate"] = GvmError(f"Cannot parse XML response. Response data read {SENTINEL!r}")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert_error(resp, code, "gvm_error")

    def test_gvmd_status_text_echoing_the_password_is_redacted(self, gvmd):
        gvmd.refuse["start_task"] = ("400", f"Task is active already {SENTINEL}")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert "[redacted]" in assert_error(resp, code, "gvm_error")   # not the exact gvmd text

    # "gvmd refused start_task (400): " is 31 characters: pads 170-195 put the password
    # across a 200-character cut of the text, pads 455-478 across the 512 cut of the message.
    @pytest.mark.parametrize("pad", [170, 185, 195, 455, 470, 478])
    def test_password_across_any_cut_never_leaves_a_piece(self, gvmd, pad):
        gvmd.refuse["start_task"] = ("400", "A" * pad + SENTINEL + " tail")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))   # run() checks the prefix
        assert len(assert_error(resp, code, "gvm_error")) <= MESSAGE_MAX

    @pytest.mark.parametrize("pad", [490, 500, 505])
    def test_error_itself_redacts_before_it_cuts(self, monkeypatch, pad):
        # Second layer: every source redacts already, but a future message carrying an
        # unredacted secret must still come out clean whatever the cut.
        monkeypatch.setattr(fleet_ops, "_SECRETS", [SENTINEL])
        message = fleet_ops._error("gvm_error", "x" * pad + SENTINEL + " tail")["error"]["message"]
        assert len(message) <= MESSAGE_MAX and SENTINEL[:4] not in message

    def test_password_in_a_request_key_is_redacted_before_the_key_is_cut(self, gvmd):
        req = cmd("task.start", {"task_id": TASK})
        req["x" * 58 + SENTINEL] = 1
        resp, code = run(gvmd, req)
        assert "unknown key" in assert_error(resp, code, "internal_error")

    def test_auth_refusal_text_is_never_used(self, gvmd):
        gvmd.refuse["authenticate"] = ("400", f"Authentication failed for {SENTINEL}")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert assert_error(resp, code, "gvm_error") == "gvmd authentication failed"

    RUNNER = textwrap.dedent("""
        import sys
        sys.path.insert(0, {bridge!r})
        import fleet_ops
        from gvm.errors import GvmError

        MODE = sys.argv[1]

        class Gmp:
            def send_command(self, xml):
                if MODE == "op-error" and "<authenticate" in xml:
                    raise GvmError("auth exchange failed: " + xml)
                if MODE == "unexpected":
                    raise RuntimeError("unexpected: " + xml)
                return '<x_response status="200" status_text="OK"/>'

        class Connect:
            def __init__(self, env, timeout):
                self.password = env["GMP_PASSWORD"]
            def __enter__(self):
                if MODE == "connect-error":
                    raise GvmError("could not connect, password was " + self.password)
                return Gmp()
            def __exit__(self, *exc):
                return False

        if MODE != "real-socket":
            fleet_ops._connect = Connect
        sys.exit(fleet_ops.main())
    """)

    @pytest.mark.parametrize("mode", ["connect-error", "op-error", "unexpected", "real-socket", "bad-request"])
    def test_real_process_stdout_and_stderr_never_carry_the_password(self, tmp_path, mode):
        runner = tmp_path / "runner.py"
        runner.write_text(self.RUNNER.format(bridge=str(HERE)), encoding="utf-8")
        request = cmd("task.start", {"task_id": TASK})
        if mode == "bad-request":
            request["password"] = "x"
        env = dict(os.environ, GMP_USERNAME=READER, GMP_PASSWORD=SENTINEL,
                   GVMD_SOCKET=str(tmp_path / "no-gvmd.sock"))
        proc = subprocess.run([sys.executable, str(runner), mode], input=json.dumps(request).encode(),
                              capture_output=True, env=env, timeout=60)
        assert SENTINEL.encode() not in proc.stdout
        assert SENTINEL.encode() not in proc.stderr
        assert proc.stderr == b""                                       # no traceback, no log
        assert proc.stdout.endswith(b"\n") and proc.stdout.count(b"\n") == 1
        response = json.loads(proc.stdout)
        assert response["ok"] is False
        validate("fleet-result.schema.json#/$defs/error", response["error"])
        if mode == "unexpected":
            assert proc.returncode == 1 and response["error"]["code"] == "internal_error"
        elif mode == "real-socket":
            # Linux: no socket -> unavailable (exit 0); a platform without AF_UNIX
            # ends as an unexpected failure (exit 1). Neither leaks the password.
            assert (proc.returncode, response["error"]["code"]) in {(0, "unavailable"), (1, "internal_error")}
        else:
            assert proc.returncode == 0


# --------------------------------------------------------------------------- #
# task.start / task.stop / task.resume
# --------------------------------------------------------------------------- #

class TestTaskActions:
    def test_start_happy_path(self, gvmd):
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        out = assert_ok("task.start", resp, code)
        assert [c.tag for c in gvmd.calls] == ["authenticate", "get_tasks", "start_task", "get_tasks"]
        assert gvmd.calls[0].findtext("credentials/username") == READER
        get = gvmd.calls[1]
        assert get.get("task_id") == TASK and get.get("filter") == fleet_ops.TASKS_FILTER
        assert get.get("filter") == "apply_overrides=1 min_qod=0 rows=-1 first=1 sort=uuid"
        assert gvmd.calls[2].get("task_id") == TASK
        assert out["task_id"] == TASK and out["status"] == "Requested"
        assert re.fullmatch(r"[0-9a-f-]{36}", out["report_id"])

    def test_owner_mismatch_is_not_found_like_a_missing_task(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER)
        foreign, code1 = run(gvmd, cmd("task.start", {"task_id": TASK2}))
        missing, code2 = run(gvmd, cmd("task.start", {"task_id": MISSING}))
        assert assert_error(foreign, code1, "not_found") == assert_error(missing, code2, "not_found")
        assert foreign == missing
        assert gvmd.sent("start_task") == []

    def test_start_of_active_task_is_conflict(self, gvmd):
        gvmd.tasks[TASK]["status"] = "Running"
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert "active" in assert_error(resp, code, "conflict")

    def test_stop(self, gvmd):
        gvmd.tasks[TASK]["status"] = "Running"
        resp, code = run(gvmd, cmd("task.stop", {"task_id": TASK}))
        out = assert_ok("task.stop", resp, code)
        assert gvmd.tags() == ["authenticate", "get_tasks", "stop_task", "get_tasks"]
        assert out == {"task_id": TASK, "status": "Stop Requested"}
        assert len(gvmd.sent("stop_task")) == 1

    def test_stop_foreign_task(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER, status="Running")
        resp, code = run(gvmd, cmd("task.stop", {"task_id": TASK2}))
        assert_error(resp, code, "not_found", "task.stop")
        assert gvmd.sent("stop_task") == []

    def test_resume(self, gvmd):
        gvmd.tasks[TASK]["status"] = "Stopped"
        resp, code = run(gvmd, cmd("task.resume", {"task_id": TASK}))
        out = assert_ok("task.resume", resp, code)
        assert gvmd.tags() == ["authenticate", "get_tasks", "resume_task", "get_tasks"]
        assert out["status"] == "Requested" and "report_id" in out
        assert len(gvmd.sent("resume_task")) == 1

    def test_resume_of_new_task_is_conflict(self, gvmd):
        resp, code = run(gvmd, cmd("task.resume", {"task_id": TASK}))
        assert_error(resp, code, "conflict", "task.resume")

    def test_failed_reread_still_reports_the_action(self, gvmd):
        original = gvmd._get_tasks
        calls = []

        def flaky(el):
            calls.append(el)
            return original(el) if len(calls) == 1 else refusal("get_tasks", "500", "Internal error")
        gvmd._get_tasks = flaky
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert assert_ok("task.start", resp, code)["status"] == "Requested"


# --------------------------------------------------------------------------- #
# task.create / modify / clone / delete
# --------------------------------------------------------------------------- #

class TestTaskWrites:
    def test_create_happy_path(self, gvmd):
        gvmd.add_schedule(SCHED)
        payload = {"name": "Varredura LAN", "comment": "pedido do NOC", "target_id": TARGET,
                   "scan_config_id": CONFIG, "schedule_id": SCHED}
        resp, code = run(gvmd, cmd("task.create", payload))
        out = assert_ok("task.create", resp, code)
        assert [c.tag for c in gvmd.calls] == ["authenticate", "get_targets", "get_schedules", "create_task"]
        assert gvmd.calls[0].findtext("credentials/username") == TENANT_USER
        assert gvmd.calls[1].get("filter") == "rows=-1 first=1 sort=uuid"
        assert gvmd.calls[2].get("filter") == "rows=-1 first=1 sort=uuid"
        create = gvmd.calls[3]
        assert create.findtext("comment") == f"fleet:{CID} pedido do NOC"
        assert create.find("scanner").get("id") == SCANNER                 # OpenVAS Default
        assert create.find("target").get("id") == TARGET
        assert create.find("config").get("id") == CONFIG
        assert create.find("schedule").get("id") == SCHED
        assert gvmd.tasks[out["task_id"]]["owner"] == TENANT_USER

    def test_create_without_comment_still_carries_the_prefix(self, gvmd):
        resp, code = run(gvmd, cmd("task.create", {"name": "n", "target_id": TARGET, "scan_config_id": CONFIG,
                                                   "scanner_id": U(77)}))
        assert_ok("task.create", resp, code)
        create = gvmd.sent("create_task")[0]
        assert create.findtext("comment") == f"fleet:{CID} "
        assert create.find("scanner").get("id") == U(77)

    def test_create_with_foreign_target_is_not_found(self, gvmd):
        gvmd.add_target(TARGET2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.create", {"name": "n", "target_id": TARGET2, "scan_config_id": CONFIG}))
        assert_error(resp, code, "not_found", "task.create")
        assert gvmd.writes() == []

    def test_create_with_foreign_schedule_is_not_found(self, gvmd):
        gvmd.add_schedule(SCHED, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.create", {"name": "n", "target_id": TARGET, "scan_config_id": CONFIG,
                                                   "schedule_id": SCHED}))
        assert_error(resp, code, "not_found", "task.create")
        assert gvmd.writes() == []

    def test_modify_links_schedule_and_renames(self, gvmd):
        gvmd.add_schedule(SCHED)
        gvmd.tasks[TASK]["comment"] = "fleet:11111111-2222-4333-8444-555555555555 texto local"
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "name": "Novo nome", "schedule_id": SCHED}))
        out = assert_ok("task.modify", resp, code)
        assert gvmd.tags() == ["authenticate", "get_tasks", "get_schedules", "modify_task"]
        assert out == {"task_id": TASK, "changed": ["name", "schedule_id"],
                       "before": {"name": "Varredura semanal", "schedule_id": ""}}
        modify = gvmd.sent("modify_task")[0]
        assert modify.findtext("name") == "Novo nome"
        assert modify.find("schedule").get("id") == SCHED
        # the comment is re-prefixed with THIS command (the old fleet prefix is replaced)
        assert modify.findtext("comment") == f"fleet:{CID} texto local"

    def test_only_a_leading_fleet_prefix_is_replaced(self, gvmd):
        old = "fleet:11111111-2222-4333-8444-555555555555 "
        inner = "fleet:22222222-2222-4333-8444-555555555555 "
        gvmd.tasks[TASK]["comment"] = f"{old}{old}ver {inner}ok"
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "name": "n"}))
        assert_ok("task.modify", resp, code)
        assert gvmd.tasks[TASK]["comment"] == f"fleet:{CID} ver {inner}ok"
        # no leading prefix: an embedded 'fleet:<uuid> ' is user text and stays
        gvmd.tasks[TASK]["comment"] = f"ver {inner}ok"
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "name": "m"}))
        assert_ok("task.modify", resp, code)
        assert gvmd.tasks[TASK]["comment"] == f"fleet:{CID} ver {inner}ok"

    def test_modify_unlinks_schedule_with_id_zero(self, gvmd):
        gvmd.add_schedule(SCHED)
        gvmd.tasks[TASK]["schedule"] = SCHED
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "schedule_id": ""}))
        out = assert_ok("task.modify", resp, code)
        assert gvmd.sent("modify_task")[0].find("schedule").get("id") == "0"
        assert out["before"] == {"schedule_id": SCHED}
        assert gvmd.tasks[TASK]["schedule"] == ""

    def test_modify_target_of_a_task_that_already_ran_is_refused_before_gvmd(self, gvmd):
        gvmd.add_target(TARGET2)
        gvmd.tasks[TASK]["status"] = "Done"
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "name": "x", "target_id": TARGET2}))
        assert_error(resp, code, "conflict", "task.modify")
        # gvmd would have renamed the task and only then refused the target
        assert gvmd.sent("modify_task") == [] and gvmd.tasks[TASK]["name"] == "Varredura semanal"

    def test_modify_target_of_new_task(self, gvmd):
        gvmd.add_target(TARGET2)
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "target_id": TARGET2, "comment": "c"}))
        out = assert_ok("task.modify", resp, code)
        assert out["changed"] == ["comment", "target_id"] and out["before"] == {"target_id": TARGET}
        assert gvmd.tasks[TASK]["target"] == TARGET2
        assert gvmd.sent("modify_task")[0].findtext("comment") == f"fleet:{CID} c"

    def test_modify_with_foreign_target_or_task_is_not_found(self, gvmd):
        gvmd.add_target(TARGET2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK, "target_id": TARGET2}))
        assert_error(resp, code, "not_found", "task.modify")
        gvmd.add_task(TASK2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK2, "name": "x"}))
        assert_error(resp, code, "not_found", "task.modify")
        assert gvmd.sent("modify_task") == []

    def test_modify_needs_a_change(self, gvmd):
        resp, code = run(gvmd, cmd("task.modify", {"task_id": TASK}))
        assert_error(resp, code, "internal_error", "task.modify")

    def test_clone_in_one_create_task(self, gvmd):
        gvmd.tasks[TASK]["comment"] = "fleet:11111111-2222-4333-8444-555555555555 base"
        resp, code = run(gvmd, cmd("task.clone", {"task_id": TASK, "name": "Copia"}))
        out = assert_ok("task.clone", resp, code)
        assert gvmd.tags() == ["authenticate", "get_tasks", "create_task"]
        create = gvmd.sent("create_task")
        assert len(create) == 1 and gvmd.sent("modify_task") == []
        assert create[0].findtext("copy") == TASK
        assert create[0].findtext("name") == "Copia"
        assert create[0].findtext("comment") == f"fleet:{CID} base"
        assert out["source_task_id"] == TASK and gvmd.tasks[out["task_id"]]["name"] == "Copia"

    def test_clone_without_name_keeps_gvmd_naming(self, gvmd):
        resp, code = run(gvmd, cmd("task.clone", {"task_id": TASK}))
        assert_ok("task.clone", resp, code)
        assert gvmd.sent("create_task")[0].find("name") is None

    def test_clone_foreign_task(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.clone", {"task_id": TASK2}))
        assert_error(resp, code, "not_found", "task.clone")
        assert gvmd.writes() == []

    def test_delete_goes_to_trash(self, gvmd):
        resp, code = run(gvmd, cmd("task.delete", {"task_id": TASK}))
        assert assert_ok("task.delete", resp, code) == {"object_id": TASK, "trash": True}
        assert gvmd.tags() == ["authenticate", "get_tasks", "delete_task"]
        assert gvmd.calls[1].get("filter") == "apply_overrides=1 min_qod=0 rows=-1 first=1 sort=uuid"
        delete = gvmd.sent("delete_task")[0]
        assert delete.get("ultimate") == "0"
        assert gvmd.trash == [("task", TASK, "0")]

    def test_delete_foreign_task(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("task.delete", {"task_id": TASK2}))
        assert_error(resp, code, "not_found", "task.delete")
        assert gvmd.sent("delete_task") == [] and TASK2 in gvmd.tasks


# --------------------------------------------------------------------------- #
# target.*
# --------------------------------------------------------------------------- #

def target_payload(**kw):
    payload = {"name": "LAN acme", "comment": "escopo aprovado", "hosts": ["192.0.2.0/24", "198.51.100.7"],
               "exclude_hosts": ["192.0.2.1"], "port_range": "T:1-65535"}
    payload.update(kw)
    return payload


def alive_sent(command_el):
    """The <alive_test> sub-elements of a create/modify_target; its <alive_tests> carries
    no text of its own (the contract set NAME never goes to gvmd)."""
    node = command_el.find("alive_tests")
    assert node is not None and not (node.text or "").strip()
    return [m.text for m in node.findall("alive_test")]


class TestTargets:
    def test_create_default_alive_set_goes_as_sub_elements(self, gvmd):
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        out = assert_ok("target.create", resp, code)
        assert gvmd.tags() == ["authenticate", "create_target"]
        create = gvmd.sent("create_target")[0]
        assert alive_sent(create) == ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"]
        assert "<alive_tests><alive_test>ICMP Ping</alive_test><alive_test>TCP-SYN Service Ping" in gvmd.raw[1]
        assert "ICMP, TCP-SYN" not in gvmd.raw[1]                 # the contract name never reaches gvmd
        assert out["alive_test_effective"] == "ICMP, TCP-SYN Service & ARP Ping"
        assert gvmd.targets[out["target_id"]]["alive"] == frozenset({ICMP, SYN, ARP})

    def test_create_default_refused_falls_back_to_the_ack_set(self, gvmd):
        gvmd.refuse_methods = {"TCP-SYN Service Ping"}            # what LAB must rule out
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        out = assert_ok("target.create", resp, code)
        first, second = gvmd.sent("create_target")
        assert gvmd.tags() == ["authenticate", "create_target", "create_target"]
        assert alive_sent(first) == ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"]
        assert alive_sent(second) == ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"]
        assert out["alive_test_effective"] == "ICMP, TCP-ACK Service & ARP Ping"
        assert gvmd.targets[out["target_id"]]["alive"] == frozenset({ICMP, ACK, ARP})

    @pytest.mark.parametrize("name", list(ADR_ALIVE_TABLE))
    def test_every_contract_set_goes_as_its_adr_methods_and_reads_back_by_name(self, gvmd, name):
        resp, code = run(gvmd, cmd("target.create", target_payload(alive_test=name)))
        out = assert_ok("target.create", resp, code)
        assert alive_sent(gvmd.sent("create_target")[0]) == ADR_ALIVE_TABLE[name]
        assert list(fleet_ops.ALIVE_TEST_METHODS[name]) == ADR_ALIVE_TABLE[name]
        assert out["alive_test_effective"] == name
        resp, code = run(gvmd, state_req("targets"))
        item = next(i for i in assert_state("targets", resp, code)["items"] if i["target_id"] == out["target_id"])
        assert item["alive_test"] == name

    def test_contract_table_covers_exactly_the_schema_enum(self):
        schema = json.loads((SCHEMA_DIR / "fleet-command.schema.json").read_text(encoding="utf-8"))
        assert set(schema["$defs"]["alive_test"]["enum"]) == set(ADR_ALIVE_TABLE) == set(fleet_ops.ALIVE_TESTS)

    def test_create_sends_only_literal_hosts_and_nothing_else(self, gvmd):
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        assert_ok("target.create", resp, code)
        create = gvmd.sent("create_target")[0]
        assert create.findtext("hosts") == "192.0.2.0/24,198.51.100.7"
        assert create.findtext("exclude_hosts") == "192.0.2.1"
        assert create.findtext("comment") == f"fleet:{CID} escopo aprovado"
        assert create.findtext("reverse_lookup_only") == "0"
        assert create.findtext("reverse_lookup_unify") == "0"
        assert create.findtext("port_range") == "T:1-65535" and create.find("port_list") is None
        tags = {child.tag for child in create}
        assert tags == {"name", "hosts", "exclude_hosts", "comment", "reverse_lookup_only",
                        "reverse_lookup_unify", "port_range", "alive_tests"}
        assert not tags & {"asset_hosts", "ssh_credential", "smb_credential", "esxi_credential",
                           "snmp_credential", "krb5_credential"}

    def test_create_with_port_list(self, gvmd):
        payload = target_payload(port_list_id=PORT_LIST)
        del payload["port_range"]
        resp, code = run(gvmd, cmd("target.create", payload))
        assert_ok("target.create", resp, code)
        create = gvmd.sent("create_target")[-1]
        assert create.find("port_list").get("id") == PORT_LIST and create.find("port_range") is None

    @pytest.mark.parametrize("changes", [
        {"port_list_id": PORT_LIST},                       # both
        {"port_range": None},                              # neither (filtered below)
    ])
    def test_create_needs_exactly_one_port_source(self, gvmd, changes):
        payload = target_payload(**changes)
        payload = {k: v for k, v in payload.items() if v is not None}
        resp, code = run(gvmd, cmd("target.create", payload))
        assert_error(resp, code, "internal_error", "target.create")
        assert gvmd.calls == []

    @pytest.mark.parametrize("host", ["bad.cafe", "dead.beef", "192.0.2.5/24", "192.0.2.1-20", "fe80::1%eth0",
                                      "scanme.example.com", "192.168.001.001", " 192.0.2.1"])
    def test_create_refuses_non_literal_hosts(self, gvmd, host):
        resp, code = run(gvmd, cmd("target.create", target_payload(hosts=["192.0.2.0/24", host])))
        assert_error(resp, code, "internal_error", "target.create")
        assert gvmd.calls == []

    def test_create_refuses_non_literal_exclude(self, gvmd):
        resp, code = run(gvmd, cmd("target.create", target_payload(exclude_hosts=["printer.lan"])))
        assert_error(resp, code, "internal_error", "target.create")

    def test_explicit_set_is_never_replaced(self, gvmd):
        gvmd.refuse_methods = {"ARP Ping"}
        resp, code = run(gvmd, cmd("target.create", target_payload(name="b", alive_test="ICMP & ARP Ping")))
        assert_error(resp, code, "gvm_error", "target.create")
        assert [alive_sent(c) for c in gvmd.sent("create_target")] == [["ICMP Ping", "ARP Ping"]]

    def test_fallback_never_goes_to_consider_alive_or_scan_config_default(self, gvmd):
        gvmd.refuse["create_target"] = ("400", "Error in alive test")
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        assert_error(resp, code, "gvm_error", "target.create")
        assert [alive_sent(c) for c in gvmd.sent("create_target")] == [
            ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"], ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"]]

    @pytest.mark.parametrize("text", ["Error in port range",
                                      "ALIVE_TESTS can contain either a string or sub-elements, but not both.",
                                      "Error in alive tests", "error in alive test"])
    def test_only_gvmds_exact_alive_refusal_triggers_the_fallback(self, gvmd, text):
        gvmd.refuse["create_target"] = ("400", text)
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        assert_error(resp, code, "gvm_error", "target.create")
        assert len(gvmd.sent("create_target")) == 1

    def test_reading_reports_a_set_outside_the_table_as_its_methods(self, gvmd):
        gvmd.add_target(TARGET2, alive=frozenset({ICMP, SYN}))
        gvmd.add_target(U(40), alive=frozenset({ICMP, ACK, SYN, ARP}))
        gvmd.add_target(U(41), alive="default")
        resp, code = run(gvmd, state_req("targets"))
        alive = {i["target_id"]: i["alive_test"] for i in assert_state("targets", resp, code)["items"]}
        assert alive[TARGET2] == "ICMP Ping, TCP-SYN Service Ping"
        assert alive[U(40)] == "ARP Ping, ICMP Ping, TCP-ACK Service Ping, TCP-SYN Service Ping"
        assert alive[U(41)] == "Scan Config Default"
        assert alive[TARGET] == "ICMP, TCP-ACK Service & ARP Ping"

    def test_name_collision_is_conflict(self, gvmd):
        gvmd.targets[TARGET]["name"] = "LAN acme"
        resp, code = run(gvmd, cmd("target.create", target_payload()))
        assert_error(resp, code, "conflict", "target.create")

    def test_modify_hosts_keeps_current_exclusions(self, gvmd):
        gvmd.targets[TARGET].update(exclude_hosts="192.0.2.1, 192.0.2.2", alive=frozenset({ICMP}))
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "hosts": ["198.51.100.0/24"]}))
        out = assert_ok("target.modify", resp, code)
        assert gvmd.tags() == ["authenticate", "get_targets", "modify_target"]
        assert gvmd.calls[1].get("filter") == "rows=-1 first=1 sort=uuid" and gvmd.calls[1].get("details") == "1"
        modify = gvmd.sent("modify_target")[0]
        assert modify.findtext("hosts") == "198.51.100.0/24"
        assert modify.findtext("exclude_hosts") == "192.0.2.1,192.0.2.2"
        assert modify.findtext("comment") == f"fleet:{CID} "
        assert out == {"target_id": TARGET, "changed": ["hosts"],
                       "before": {"hosts": ["192.0.2.0/24"], "hosts_non_literal_entries": 0}}

    def test_modify_exclusions_resends_current_literal_hosts(self, gvmd):
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "exclude_hosts": []}))
        out = assert_ok("target.modify", resp, code)
        modify = gvmd.sent("modify_target")[0]
        assert modify.findtext("hosts") == "192.0.2.0/24"
        assert modify.find("exclude_hosts") is not None and not modify.findtext("exclude_hosts")
        assert out["before"] == {"exclude_hosts": []}

    def test_modify_exclusions_of_target_with_hostnames_is_refused(self, gvmd):
        gvmd.targets[TARGET]["hosts"] = "192.0.2.0/24, intranet.acme.example"
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "exclude_hosts": ["192.0.2.9"]}))
        assert_error(resp, code, "conflict", "target.modify")
        assert gvmd.sent("modify_target") == []

    def test_modify_before_lists_only_literal_hosts(self, gvmd):
        gvmd.targets[TARGET]["hosts"] = "192.0.2.0/24, intranet.acme.example, 198.51.100.1-10"
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "hosts": ["203.0.113.0/24"],
                                                     "name": "renomeado"}))
        out = assert_ok("target.modify", resp, code)
        assert out["before"]["hosts"] == ["192.0.2.0/24"]
        assert out["before"]["hosts_non_literal_entries"] == 2
        assert "intranet" not in json.dumps(out)

    def test_modify_alive_test(self, gvmd):
        gvmd.targets[TARGET]["alive"] = frozenset({ICMP, SYN})        # not a contract set
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET,
                                                     "alive_test": "ICMP, TCP-SYN Service & ARP Ping"}))
        out = assert_ok("target.modify", resp, code)
        assert [alive_sent(c) for c in gvmd.sent("modify_target")] == [
            ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"]]
        assert out["alive_test_effective"] == "ICMP, TCP-SYN Service & ARP Ping"
        assert out["before"] == {"alive_test": "ICMP Ping, TCP-SYN Service Ping"}
        assert gvmd.targets[TARGET]["alive"] == frozenset({ICMP, SYN, ARP})

    def test_modify_alive_test_with_fallback(self, gvmd):
        gvmd.refuse_methods = {"TCP-SYN Service Ping"}
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET,
                                                     "alive_test": "ICMP, TCP-SYN Service & ARP Ping"}))
        out = assert_ok("target.modify", resp, code)
        assert [alive_sent(c) for c in gvmd.sent("modify_target")] == [
            ["ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"], ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"]]
        assert out["alive_test_effective"] == "ICMP, TCP-ACK Service & ARP Ping"
        assert out["before"] == {"alive_test": "ICMP, TCP-ACK Service & ARP Ping"}

    def test_modify_target_in_use_is_conflict(self, gvmd):
        gvmd.targets[TARGET]["in_use"] = "1"
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "hosts": ["192.0.2.0/25"]}))
        assert "in use" in assert_error(resp, code, "conflict", "target.modify")
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "name": "ok em uso"}))
        assert_ok("target.modify", resp, code)

    def test_modify_has_no_port_range(self, gvmd):
        # ports change only by port_list_id: gvmd's modify_target has no port_range
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "port_range": "T:22"}))
        assert "port_range" in assert_error(resp, code, "internal_error", "target.modify")
        assert gvmd.calls == []
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "port_list_id": U(55),
                                                     "port_range": "T:22"}))
        assert_error(resp, code, "internal_error", "target.modify")
        assert gvmd.calls == []

    def test_modify_port_list(self, gvmd):
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "port_list_id": U(55)}))
        out = assert_ok("target.modify", resp, code)
        assert gvmd.sent("modify_target")[0].find("port_list").get("id") == U(55)
        assert out["before"] == {"port_list_id": PORT_LIST}

    def test_modify_foreign_target(self, gvmd):
        gvmd.add_target(TARGET2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET2, "name": "x"}))
        assert_error(resp, code, "not_found", "target.modify")
        assert gvmd.sent("modify_target") == []

    def test_modify_refuses_non_literal_hosts(self, gvmd):
        resp, code = run(gvmd, cmd("target.modify", {"target_id": TARGET, "hosts": ["intranet.acme.example"]}))
        assert_error(resp, code, "internal_error", "target.modify")
        assert gvmd.calls == []

    def test_delete_goes_to_trash(self, gvmd):
        resp, code = run(gvmd, cmd("target.delete", {"target_id": TARGET}))
        assert assert_ok("target.delete", resp, code) == {"object_id": TARGET, "trash": True}
        assert gvmd.tags() == ["authenticate", "get_targets", "delete_target"]
        assert gvmd.sent("delete_target")[0].get("ultimate") == "0"

    def test_delete_in_use_is_conflict(self, gvmd):
        gvmd.targets[TARGET]["in_use"] = "1"
        resp, code = run(gvmd, cmd("target.delete", {"target_id": TARGET}))
        assert_error(resp, code, "conflict", "target.delete")

    def test_delete_foreign_target(self, gvmd):
        gvmd.add_target(TARGET2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("target.delete", {"target_id": TARGET2}))
        assert_error(resp, code, "not_found", "target.delete")
        assert gvmd.sent("delete_target") == []


# --------------------------------------------------------------------------- #
# schedule.*
# --------------------------------------------------------------------------- #

class TestSchedules:
    def test_create_and_link_tasks(self, gvmd):
        gvmd.add_task(TASK2, comment="local")
        payload = {"name": "Semanal", "comment": "janela", "icalendar": ICAL, "timezone": "America/Sao_Paulo",
                   "task_ids": [TASK, TASK2]}
        resp, code = run(gvmd, cmd("schedule.create", payload))
        out = assert_ok("schedule.create", resp, code)
        assert gvmd.writes() == ["create_schedule", "modify_task", "modify_task"]
        assert gvmd.tags() == ["authenticate", "get_tasks", "get_tasks", "create_schedule", "modify_task", "modify_task"]
        create = gvmd.sent("create_schedule")[0]
        assert create.findtext("comment") == f"fleet:{CID} janela"
        assert create.findtext("timezone") == "America/Sao_Paulo"
        assert out["linked_task_ids"] == [TASK, TASK2]
        for modify in gvmd.sent("modify_task"):
            assert modify.find("schedule").get("id") == out["schedule_id"]
            assert modify.findtext("comment").startswith(f"fleet:{CID} ")
        assert gvmd.tasks[TASK2]["comment"] == f"fleet:{CID} local"

    def test_create_with_foreign_task_creates_nothing(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER)
        payload = {"name": "s", "icalendar": ICAL, "timezone": "UTC", "task_ids": [TASK, TASK2]}
        resp, code = run(gvmd, cmd("schedule.create", payload))
        assert_error(resp, code, "not_found", "schedule.create")
        assert gvmd.writes() == [] and gvmd.schedules == {}

    def test_create_without_tasks(self, gvmd):
        resp, code = run(gvmd, cmd("schedule.create", {"name": "s", "icalendar": ICAL, "timezone": "UTC"}))
        out = assert_ok("schedule.create", resp, code)
        assert out["linked_task_ids"] == [] and gvmd.writes() == ["create_schedule"]

    def test_partial_link_failure_names_the_created_schedule(self, gvmd):
        gvmd.add_task(TASK2)
        original = gvmd._modify_task

        def second_fails(el):
            if el.get("task_id") == TASK2:
                return refusal("modify_task", "400", "Permission denied")
            return original(el)
        gvmd._modify_task = second_fails
        payload = {"name": "s", "icalendar": ICAL, "timezone": "UTC", "task_ids": [TASK, TASK2]}
        resp, code = run(gvmd, cmd("schedule.create", payload))
        message = assert_error(resp, code, "gvm_error", "schedule.create")
        created = next(iter(gvmd.schedules))
        assert created in message and "1 of 2" in message

    def test_modify_name_resends_the_current_icalendar(self, gvmd):
        gvmd.add_schedule(SCHED)
        resp, code = run(gvmd, cmd("schedule.modify", {"schedule_id": SCHED, "name": "Diaria"}))
        out = assert_ok("schedule.modify", resp, code)
        assert gvmd.tags() == ["authenticate", "get_schedules", "modify_schedule"]
        modify = gvmd.sent("modify_schedule")[0]
        assert modify.findtext("icalendar").startswith("BEGIN:VCALENDAR")       # gvmd requires it
        assert modify.find("timezone") is None
        assert modify.findtext("comment") == f"fleet:{CID} "
        assert out == {"schedule_id": SCHED, "changed": ["name"], "before": {"name": "semanal"}}
        assert gvmd.sent("get_schedules")[0].get("filter") == "rows=-1 first=1 sort=uuid"

    def test_modify_icalendar_and_timezone(self, gvmd):
        gvmd.add_schedule(SCHED)
        resp, code = run(gvmd, cmd("schedule.modify", {"schedule_id": SCHED, "icalendar": ICAL2, "timezone": "UTC"}))
        out = assert_ok("schedule.modify", resp, code)
        assert out["changed"] == ["icalendar", "timezone"]
        assert out["before"]["timezone"] == "America/Sao_Paulo"
        assert out["before"]["icalendar"].startswith("BEGIN:VCALENDAR") and "WEEKLY" in out["before"]["icalendar"]
        assert "DAILY" in gvmd.schedules[SCHED]["icalendar"]

    def test_modify_foreign_schedule(self, gvmd):
        gvmd.add_schedule(SCHED, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("schedule.modify", {"schedule_id": SCHED, "name": "x"}))
        assert_error(resp, code, "not_found", "schedule.modify")
        assert gvmd.sent("modify_schedule") == []

    def test_delete_goes_to_trash(self, gvmd):
        gvmd.add_schedule(SCHED)
        resp, code = run(gvmd, cmd("schedule.delete", {"schedule_id": SCHED}))
        assert assert_ok("schedule.delete", resp, code) == {"object_id": SCHED, "trash": True}
        assert gvmd.tags() == ["authenticate", "get_schedules", "delete_schedule"]
        assert gvmd.sent("delete_schedule")[0].get("ultimate") == "0"

    def test_delete_foreign_schedule(self, gvmd):
        gvmd.add_schedule(SCHED, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("schedule.delete", {"schedule_id": SCHED}))
        assert_error(resp, code, "not_found", "schedule.delete")
        assert gvmd.sent("delete_schedule") == []


# --------------------------------------------------------------------------- #
# report.export
# --------------------------------------------------------------------------- #

PDF_EN = fleet_ops.REPORT_FORMAT_IDS[("suricatoos-pdf", "en", "technical")]
PDF_PT = fleet_ops.REPORT_FORMAT_IDS[("suricatoos-pdf", "pt_BR", "technical")]
XML_ID = fleet_ops.REPORT_FORMAT_IDS[("gvm-xml", "en", "technical")]
CSV_ID = fleet_ops.REPORT_FORMAT_IDS[("gvm-csv-results", "en", "technical")]
EXPORT_FILTER = "apply_overrides=0 levels=chmlgf rows=-1 min_qod=1 first=1 sort-reverse=severity"


def export_req(tmp_path, **kw):
    payload = {"report_id": REPORT, "format": "suricatoos-pdf", "lang": "pt_BR", "variant": "technical",
               "filter": EXPORT_FILTER}
    payload.update(kw)
    return cmd("report.export", payload, artifact_path=str(tmp_path / "artefato.bin"))


class TestReportExport:
    @pytest.fixture
    def g(self, gvmd):
        gvmd.add_report(REPORT, content={PDF_PT: PDF_BYTES, PDF_EN: PDF_BYTES, CSV_ID: CSV_BYTES},
                        results=[{"host": "192.0.2.10", "severity": 7.5}])
        return gvmd

    def test_pdf_happy_path(self, g, tmp_path):
        resp, code = run(g, export_req(tmp_path))
        out = assert_ok("report.export", resp, code)
        meta, export = g.sent("get_reports")
        assert g.tags() == ["authenticate", "get_reports", "get_reports"]
        assert meta.get("report_id") == REPORT and meta.get("details") == "0"
        assert meta.get("filter") == fleet_ops.REPORT_META_FILTER
        assert meta.get("filter") == "apply_overrides=1 min_qod=0 levels=chmlg rows=-1 first=1"
        assert export.get("format_id") == "e43a4f20-d845-4916-83f0-851ac6dc5e57"
        assert export.get("filter") == EXPORT_FILTER                 # the explicit filter, verbatim
        assert export.get("ignore_pagination") == "1" and export.get("details") == "1"
        assert export.get("delta_report_id") is None
        assert out == {"report_id": REPORT, "report_format_id": PDF_PT, "format": "suricatoos-pdf",
                       "lang": "pt_BR", "variant": "technical", "artifact_name": "report.pdf.gz"}
        written = (tmp_path / "artefato.bin").read_bytes()
        assert written == PDF_BYTES
        assert resp["artifact"] == {"original_content_type": "application/pdf",
                                    "original_size": len(PDF_BYTES),
                                    "original_sha256": hashlib.sha256(PDF_BYTES).hexdigest()}
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(tmp_path / "artefato.bin").st_mode) == 0o600
        assert g.writes() == []

    def test_csv(self, g, tmp_path):
        resp, code = run(g, export_req(tmp_path, format="gvm-csv-results", lang="en"))
        out = assert_ok("report.export", resp, code)
        assert out["artifact_name"] == "report.csv.gz" and out["report_format_id"] == CSV_ID
        assert (tmp_path / "artefato.bin").read_bytes() == CSV_BYTES
        assert resp["artifact"]["original_content_type"] == "text/csv"

    def test_xml_is_inline(self, g, tmp_path):
        resp, code = run(g, export_req(tmp_path, format="gvm-xml", lang="en"))
        out = assert_ok("report.export", resp, code)
        assert out["artifact_name"] == "report.xml.gz"
        written = (tmp_path / "artefato.bin").read_bytes()
        root = ET.fromstring(written)
        assert root.tag == "report" and root.get("id") == REPORT
        assert resp["artifact"]["original_content_type"] == "application/xml"
        assert resp["artifact"]["original_sha256"] == hashlib.sha256(written).hexdigest()

    def test_delta_of_the_same_task(self, g, tmp_path):
        g.add_report(REPORT_OLD, creation_time="2026-10-03T02:00:00Z")
        resp, code = run(g, export_req(tmp_path, delta_report_id=REPORT_OLD))
        out = assert_ok("report.export", resp, code)
        assert g.tags() == ["authenticate", "get_reports", "get_reports", "get_reports"]
        assert g.calls[2].get("report_id") == REPORT_OLD and g.calls[2].get("details") == "0"
        assert out["delta_report_id"] == REPORT_OLD
        assert g.sent("get_reports")[-1].get("delta_report_id") == REPORT_OLD

    def test_delta_of_another_task_is_not_found(self, g, tmp_path):
        g.add_task(TASK2)
        g.add_report(REPORT_OLD, task=TASK2)
        resp, code = run(g, export_req(tmp_path, delta_report_id=REPORT_OLD))
        assert_error(resp, code, "not_found", "report.export")
        assert len(g.sent("get_reports")) == 2 and not (tmp_path / "artefato.bin").exists()

    def test_delta_of_another_owner_is_not_found(self, g, tmp_path):
        g.add_report(REPORT_OTHER, owner=OTHER_USER)
        resp, code = run(g, export_req(tmp_path, delta_report_id=REPORT_OTHER))
        missing, code2 = run(g, export_req(tmp_path, delta_report_id=MISSING))
        assert assert_error(resp, code, "not_found", "report.export") == assert_error(missing, code2, "not_found")

    def test_foreign_report_is_not_found(self, g, tmp_path):
        g.add_report(REPORT_OTHER, owner=OTHER_USER, content={PDF_PT: PDF_BYTES})
        resp, code = run(g, export_req(tmp_path, report_id=REPORT_OTHER))
        assert_error(resp, code, "not_found", "report.export")
        assert len(g.sent("get_reports")) == 1 and not (tmp_path / "artefato.bin").exists()

    @pytest.mark.parametrize("variant", ["client", "executive"])
    def test_combination_outside_the_table_is_refused(self, g, tmp_path, variant):
        resp, code = run(g, export_req(tmp_path, variant=variant))
        assert_error(resp, code, "internal_error", "report.export")
        assert g.sent("get_reports") == []

    def test_gvm_format_in_portuguese_is_refused(self, g, tmp_path):
        resp, code = run(g, export_req(tmp_path, format="gvm-pdf", lang="pt_BR"))
        assert_error(resp, code, "internal_error", "report.export")

    def test_missing_report_format_is_gvm_error(self, g, tmp_path):
        del g.report_formats[PDF_PT]
        resp, code = run(g, export_req(tmp_path))
        assert_error(resp, code, "gvm_error", "report.export")

    def test_existing_artifact_path_is_never_overwritten(self, g, tmp_path):
        (tmp_path / "artefato.bin").write_bytes(b"keep")
        resp, code = run(g, export_req(tmp_path))
        assert_error(resp, code, "internal_error", "report.export")
        assert (tmp_path / "artefato.bin").read_bytes() == b"keep"

    def test_relative_artifact_path_is_refused(self, g, tmp_path):
        req = export_req(tmp_path)
        req["artifact_path"] = "artefato.bin"
        resp, code = run(g, req)
        assert_error(resp, code, "internal_error", "report.export")

    def test_too_large(self, g, tmp_path, monkeypatch):
        monkeypatch.setattr(fleet_ops, "MAX_ARTIFACT_BYTES", 1024)
        resp, code = run(g, export_req(tmp_path))
        assert_error(resp, code, "artifact_too_large", "report.export")
        assert not (tmp_path / "artefato.bin").exists()

    def test_empty_or_non_pdf_content_is_refused(self, g, tmp_path):
        g.reports[REPORT]["content"][PDF_PT] = b""
        resp, code = run(g, export_req(tmp_path))
        assert_error(resp, code, "gvm_error", "report.export")
        g.reports[REPORT]["content"][PDF_PT] = b"<html>error</html>"
        resp, code = run(g, export_req(tmp_path))
        assert_error(resp, code, "gvm_error", "report.export")
        assert not (tmp_path / "artefato.bin").exists()


# --------------------------------------------------------------------------- #
# report.summary
# --------------------------------------------------------------------------- #

def summary_req(**kw):
    payload = {"report_id": REPORT, "min_qod": 70, "apply_overrides": True, "levels": "chml"}
    payload.update(kw)
    return cmd("report.summary", payload)


RESULTS = [
    {"host": "192.0.2.10", "severity": 10.0, "qod": 99},
    {"host": "192.0.2.10", "severity": 7.5, "qod": 80},
    {"host": "192.0.2.10", "severity": 5.0, "qod": 70},
    {"host": "198.51.100.20", "severity": 7.8, "qod": 95},
    {"host": "198.51.100.20", "severity": 2.1, "qod": 30},      # below min_qod 70
    {"host": "198.51.100.20", "severity": 0.0, "qod": 80},      # log: not in levels chml
    {"host": "2001:db8::5", "severity": 4.3, "qod": 75},
    {"host": "intranet.acme.example", "severity": 9.1, "qod": 98, "name": "Hostname finding"},
    {"host": "203.0.113.9", "severity": -1.0, "qod": 80},       # false positive: never in levels
]


class TestReportSummary:
    @pytest.fixture
    def g(self, gvmd):
        gvmd.add_report(REPORT, results=RESULTS)
        return gvmd

    def test_counts_only_from_the_node_built_filter(self, g):
        resp, code = run(g, summary_req())
        out = assert_ok("report.summary", resp, code)
        meta, summary = g.sent("get_reports")
        assert g.tags() == ["authenticate", "get_reports", "get_reports"]
        assert meta.get("details") == "0" and meta.get("filter") == fleet_ops.REPORT_META_FILTER
        assert summary.get("filter") == "apply_overrides=1 min_qod=70 levels=chml rows=-1"
        assert summary.get("ignore_pagination") == "1" and summary.get("details") == "1"
        assert summary.get("format_id") is None
        assert out["filter_applied"] == "apply_overrides=1 min_qod=70 levels=chml rows=-1"
        assert out["counts"] == {"critical": 2, "high": 2, "medium": 2, "low": 0, "log": 0, "false_positive": 0}
        assert out["qod_histogram"] == {"q0_29": 0, "q30_69": 0, "q70_100": 6}
        assert out["hosts_count"] == 4
        assert out["hosts"] == [
            {"ip": "192.0.2.10", "critical": 1, "high": 1, "medium": 1, "low": 0, "log": 0},
            {"ip": "198.51.100.20", "critical": 0, "high": 1, "medium": 0, "low": 0, "log": 0},
            {"ip": "2001:db8::5", "critical": 0, "high": 0, "medium": 1, "low": 0, "log": 0}]
        assert out["hosts_truncated"] is False
        assert out["task_id"] == TASK and out["scan_status"] == "Done"
        assert out["scan_start"] == "2026-10-10T02:00:05Z" and out["scan_end"] == "2026-10-10T03:10:00Z"

    def test_no_finding_data_ever_leaves(self, g):
        resp, code = run(g, summary_req(min_qod=0, apply_overrides=False, levels="chmlg"))
        out = assert_ok("report.summary", resp, code)
        text = fleet_ops.dumps(resp).decode("utf-8")
        for leaked in ("1.3.6.1.4.1.25623", "CVE-", "Heartbleed", "Hostname finding", "443/tcp",
                       "web01.example.com", "intranet.acme.example", "evidence"):
            assert leaked not in text
        assert out["filter_applied"] == "apply_overrides=0 min_qod=0 levels=chmlg rows=-1"
        assert out["counts"]["log"] == 1 and out["counts"]["low"] == 1
        assert out["qod_histogram"] == {"q0_29": 0, "q30_69": 1, "q70_100": 7}
        assert out["hosts_count"] == 4

    def test_all_results_not_the_max_rows_page(self, g):
        g.max_rows = 2
        resp, code = run(g, summary_req())
        assert sum(assert_ok("report.summary", resp, code)["counts"].values()) == 6

    def test_free_filter_or_other_narrowing_is_refused(self, g):
        for extra in ({"filter": "host=192.0.2.10"}, {"host": "192.0.2.10"}, {"nvt": "1.3.6"},
                      {"top_findings": True}):
            resp, code = run(g, cmd("report.summary", {"report_id": REPORT, "min_qod": 70,
                                                       "apply_overrides": True, "levels": "chml", **extra}))
            assert_error(resp, code, "internal_error", "report.summary")
        assert g.calls == []

    @pytest.mark.parametrize("levels", ["", "hc", "chmlgf", "x", "cc", "c h"])
    def test_levels_must_be_an_ordered_subset_of_chmlg(self, g, levels):
        resp, code = run(g, summary_req(levels=levels))
        assert_error(resp, code, "internal_error", "report.summary")

    def test_hosts_list_is_capped(self, g, monkeypatch):
        monkeypatch.setattr(fleet_ops, "MAX_SUMMARY_HOSTS", 2)
        resp, code = run(g, summary_req())
        out = assert_ok("report.summary", resp, code)
        assert [h["ip"] for h in out["hosts"]] == ["192.0.2.10", "198.51.100.20"]
        assert out["hosts_truncated"] is True and out["hosts_count"] == 4

    def test_foreign_report(self, g):
        g.add_report(REPORT_OTHER, owner=OTHER_USER, results=RESULTS)
        resp, code = run(g, summary_req(report_id=REPORT_OTHER))
        assert_error(resp, code, "not_found", "report.summary")
        assert len(g.sent("get_reports")) == 1


# --------------------------------------------------------------------------- #
# inspect.* (inputs of the connector's scope gate)
# --------------------------------------------------------------------------- #

def assert_target_view(view):
    assert set(view) == {"target_id", "hosts", "exclude_hosts", "non_literal_hosts", "non_literal_exclude_hosts"}
    for host in view["hosts"] + view["exclude_hosts"]:
        validate("fleet-command.schema.json#/$defs/ip_or_cidr", host)


class TestInspect:
    def test_task_lists_literal_hosts_and_flags_the_rest(self, gvmd):
        gvmd.add_schedule(SCHED)
        gvmd.tasks[TASK]["schedule"] = SCHED
        gvmd.targets[TARGET].update(hosts="192.0.2.0/24, 198.51.100.7, intranet.acme.example, 203.0.113.1-9",
                                    exclude_hosts="192.0.2.1, printer.acme.example")
        resp, code = run(gvmd, cmd("inspect.task", {"task_id": TASK}))
        assert code == 0 and resp["ok"] is True
        assert gvmd.tags() == ["authenticate", "get_tasks", "get_targets"]
        out = resp["output"]
        assert out["task_id"] == TASK and out["schedule_id"] == SCHED
        assert_target_view(out["target"])
        assert out["target"] == {"target_id": TARGET, "hosts": ["192.0.2.0/24", "198.51.100.7"],
                                 "exclude_hosts": ["192.0.2.1"], "non_literal_hosts": 2,
                                 "non_literal_exclude_hosts": 1}
        assert gvmd.writes() == []

    def test_task_without_live_target(self, gvmd):
        gvmd.tasks[TASK].update(target="", schedule="")
        resp, code = run(gvmd, cmd("inspect.task", {"task_id": TASK}))
        assert resp["output"] == {"task_id": TASK, "schedule_id": "", "target": None}
        gvmd.tasks[TASK].update(target=TARGET, target_trash="1")
        resp, code = run(gvmd, cmd("inspect.task", {"task_id": TASK}))
        assert resp["output"]["target"] is None

    def test_unreadable_target_is_unavailable(self, gvmd):
        gvmd.tasks[TASK]["target"] = MISSING
        resp, code = run(gvmd, cmd("inspect.task", {"task_id": TASK}))
        assert_error(resp, code, "unavailable")

    def test_task_owner_check(self, gvmd):
        gvmd.add_task(TASK2, owner=OTHER_USER)
        foreign, c1 = run(gvmd, cmd("inspect.task", {"task_id": TASK2}))
        missing, c2 = run(gvmd, cmd("inspect.task", {"task_id": MISSING}))
        assert assert_error(foreign, c1, "not_found") == assert_error(missing, c2, "not_found")

    def test_target(self, gvmd):
        resp, code = run(gvmd, cmd("inspect.target", {"target_id": TARGET}))
        assert gvmd.tags() == ["authenticate", "get_targets"]
        assert_target_view(resp["output"])
        assert resp["output"]["hosts"] == ["192.0.2.0/24"]
        gvmd.add_target(TARGET2, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("inspect.target", {"target_id": TARGET2}))
        assert_error(resp, code, "not_found")

    def test_schedule_reads_every_linked_task_target(self, gvmd):
        gvmd.add_target(TARGET2, owner=OTHER_USER, hosts="203.0.113.0/24")
        gvmd.add_task(TASK2, owner=OTHER_USER, target=TARGET2)
        gvmd.add_schedule(SCHED, tasks=[TASK, TASK2])
        resp, code = run(gvmd, cmd("inspect.schedule", {"schedule_id": SCHED}))
        out = resp["output"]
        assert gvmd.tags() == ["authenticate", "get_schedules", "get_tasks", "get_targets", "get_tasks", "get_targets"]
        assert out["schedule_id"] == SCHED
        assert [(t["task_id"], t["target"]["hosts"]) for t in out["tasks"]] == [
            (TASK, ["192.0.2.0/24"]), (TASK2, ["203.0.113.0/24"])]
        assert gvmd.sent("get_schedules")[0].get("tasks") == "1"

    def test_schedule_with_unreadable_task_is_unavailable(self, gvmd):
        gvmd.add_schedule(SCHED, tasks=[TASK, MISSING])
        resp, code = run(gvmd, cmd("inspect.schedule", {"schedule_id": SCHED}))
        assert_error(resp, code, "unavailable")

    def test_schedule_owner_check(self, gvmd):
        gvmd.add_schedule(SCHED, owner=OTHER_USER)
        resp, code = run(gvmd, cmd("inspect.schedule", {"schedule_id": SCHED}))
        assert_error(resp, code, "not_found")


# --------------------------------------------------------------------------- #
# state.*
# --------------------------------------------------------------------------- #

NODE_PAYLOAD = {
    "node_kind": "central",
    "connector_version": "0.1.0",
    "policy": {"allow": ["report.export", "state.resync", "task.start"], "sensitive_per_hour": 30,
               "total_per_hour": 120},
    "policy_sha256": "0" * 64,
    "replay_floor": "2026-10-11T11:50:00Z",
    "supported_types": list(fleet_ops.COMMAND_TYPES),
    "state_kinds": list(fleet_ops.STATE_KINDS),
}


class TestStateNode:
    def test_snapshot(self, gvmd):
        gvmd.feeds[2] = ("CERT", "202610090000", True, False)
        payload = dict(NODE_PAYLOAD, versions={"gvmd": "26.31.1", "gsa": "27.4.1"},
                       health={"scanner_up": True, "disk_free_pct": 41.5})
        resp, code = run(gvmd, state_req("node", payload))
        data = assert_state("node", resp, code)
        assert data["versions"] == {"gvmd": "26.31.1", "gmp_protocol": "22.7",
                                    "python_gvm": fleet_ops.gvm.__version__, "gsa": "27.4.1"}
        assert data["health"] == {"status": "ok", "gvmd_up": True, "scanner_up": True, "disk_free_pct": 41.5}
        assert data["feeds"][0] == {"feed": "nvt", "version": "202610110600", "age_hours": 6, "syncing": False}
        assert data["feeds"][2]["syncing"] is True
        assert [c.tag for c in gvmd.calls] == ["authenticate", "get_version", "get_feeds", "get_report_formats"]
        assert gvmd.sent("get_report_formats")[0].get("filter") == "rows=-1 first=1 sort=uuid"
        assert data["capabilities"]["report_formats"] == [
            {"format": "suricatoos-pdf", "lang": "en", "variants": ["technical"]},
            {"format": "suricatoos-pdf", "lang": "pt_BR", "variants": ["technical"]},
            {"format": "suricatoos-pdf", "lang": "es", "variants": ["technical"]},
            {"format": "gvm-xml", "lang": "en", "variants": ["technical"]},
            {"format": "gvm-csv-results", "lang": "en", "variants": ["technical"]},
            {"format": "gvm-pdf", "lang": "en", "variants": ["technical"]}]
        assert data["policy"] == NODE_PAYLOAD["policy"]
        assert data["replay_floor"] == NODE_PAYLOAD["replay_floor"]

    def test_only_present_trusted_active_formats(self, gvmd):
        del gvmd.report_formats[PDF_EN]
        gvmd.report_formats[PDF_PT]["active"] = "0"
        gvmd.report_formats[XML_ID]["trust"] = "unknown"
        gvmd.report_formats[U(99)] = {"active": "1", "trust": "yes"}     # an unmapped format: ignored
        resp, code = run(gvmd, state_req("node", NODE_PAYLOAD))
        formats = assert_state("node", resp, code)["capabilities"]["report_formats"]
        assert formats == [
            {"format": "suricatoos-pdf", "lang": "es", "variants": ["technical"]},
            {"format": "gvm-csv-results", "lang": "en", "variants": ["technical"]},
            {"format": "gvm-pdf", "lang": "en", "variants": ["technical"]}]
        assert all(v == ["technical"] for v in (f["variants"] for f in formats))

    def test_gvmd_down_is_a_valid_down_snapshot(self, gvmd):
        gvmd.connect_error = GvmError("Socket /run/gvmd/gvmd.sock does not exist")
        resp, code = run(gvmd, state_req("node", NODE_PAYLOAD))
        data = assert_state("node", resp, code)
        assert data["health"] == {"status": "down", "gvmd_up": False}
        assert data["feeds"] == [] and data["capabilities"]["report_formats"] == []
        assert data["versions"] == {"python_gvm": fleet_ops.gvm.__version__}

    def test_auth_failure_or_scanner_down_is_degraded(self, gvmd):
        gvmd.auth_ok = False
        resp, code = run(gvmd, state_req("node", NODE_PAYLOAD))
        assert assert_state("node", resp, code)["health"] == {"status": "degraded", "gvmd_up": True}
        gvmd.auth_ok = True
        gvmd.feeds[0] = ("NVT", "202610110600", False, True)
        resp, code = run(gvmd, state_req("node", NODE_PAYLOAD))
        assert assert_state("node", resp, code)["health"]["status"] == "degraded"

    @pytest.mark.parametrize("floor", ["2026-02-30T00:00:00Z", "2026-10-11T24:00:00Z", "2026-10-11T12:00:60Z",
                                       "2026-10-11T12:00:00.5Z", "2026-10-11T12:00:00+00:00"])
    def test_replay_floor_must_be_a_real_utc_instant(self, gvmd, floor):
        resp, code = run(gvmd, state_req("node", dict(NODE_PAYLOAD, replay_floor=floor)))
        assert_error(resp, code, "internal_error")
        assert gvmd.calls == []

    def test_connector_cannot_supply_gvmd_owned_fields(self, gvmd):
        for payload in (dict(NODE_PAYLOAD, versions={"gmp_protocol": "22.7"}),
                        dict(NODE_PAYLOAD, health={"status": "ok"}),
                        dict(NODE_PAYLOAD, feeds=[]),
                        {k: v for k, v in NODE_PAYLOAD.items() if k != "policy"}):
            resp, code = run(gvmd, state_req("node", payload))
            assert_error(resp, code, "internal_error")


OWNERS = {TENANT_USER: "acme", "globex-gmp": "globex", "weird-gmp": "-bad tenant-"}


class TestStateLists:
    def test_tasks(self, gvmd):
        gvmd.tasks[TASK].update(comment="segredo do cliente", status="Done", progress=-1, report_count=3,
                                last_report=REPORT, schedule=SCHED)
        gvmd.add_task(TASK2, owner="globex-gmp", status="Running", progress=42)
        gvmd.add_task(U(50), owner="suricatoos-scan")                     # the reNgine loop user
        gvmd.add_task(U(51), owner="weird-gmp")                           # invalid tenant name
        resp, code = run(gvmd, state_req("tasks", owners=OWNERS))
        data = assert_state("tasks", resp, code)
        assert gvmd.tags() == ["authenticate", "get_tasks"]
        assert data["unattributed_count"] == 2 and data["truncated"] is False
        first, second = data["items"]
        assert first == {"task_id": TASK, "tenant": "acme", "name": "Varredura semanal", "status": "Done",
                         "progress": -1, "target_id": TARGET, "scan_config_id": CONFIG, "scanner_id": SCANNER,
                         "schedule_id": SCHED, "last_report_id": REPORT,
                         "last_report_at": "2026-10-11T02:00:00Z", "report_count": 3}
        assert second["tenant"] == "globex" and second["progress"] == 42
        assert "segredo" not in fleet_ops.dumps(data).decode()
        get = gvmd.sent("get_tasks")[0]
        assert get.get("filter") == "apply_overrides=1 min_qod=0 rows=-1 first=1 sort=uuid"
        assert get.get("ignore_pagination") == "1" and get.get("details") == "0"

    def test_tasks_beyond_max_rows_and_cap(self, gvmd, monkeypatch):
        gvmd.max_rows = 2
        for n in range(60, 65):
            gvmd.add_task(U(n))
        monkeypatch.setattr(fleet_ops, "MAX_TASKS", 4)
        resp, code = run(gvmd, state_req("tasks"))
        data = assert_state("tasks", resp, code)
        assert len(data["items"]) == 4 and data["truncated"] is True    # 6 tasks seen, not 2

    def test_targets(self, gvmd):
        gvmd.targets[TARGET].update(hosts="192.0.2.0/24, intranet.acme.example, 198.51.100.3",
                                    exclude_hosts="192.0.2.1, printer.acme.example", comment="nao sai",
                                    in_use="1")
        gvmd.add_target(TARGET2, owner="nobody-gmp")
        resp, code = run(gvmd, state_req("targets", owners=OWNERS))
        data = assert_state("targets", resp, code)
        assert data["unattributed_count"] == 1
        assert data["items"] == [{
            "target_id": TARGET, "tenant": "acme", "name": f"alvo-{TARGET[-4:]}",
            "hosts": ["192.0.2.0/24", "198.51.100.3"], "literal_entries": 2, "non_literal_entries": 1,
            "exclude_entries": 2, "port_list_id": PORT_LIST, "alive_test": "ICMP, TCP-ACK Service & ARP Ping",
            "in_use": True}]
        text = fleet_ops.dumps(data).decode()
        assert "acme.example" not in text and "nao sai" not in text and "ssh" not in text
        assert gvmd.sent("get_targets")[0].get("filter") == "rows=-1 first=1 sort=uuid"

    def test_targets_page_past_max_rows(self, gvmd):
        gvmd.max_rows = 2
        for n in range(70, 75):
            gvmd.add_target(U(n))
        resp, code = run(gvmd, state_req("targets"))
        data = assert_state("targets", resp, code)
        assert len(data["items"]) == 6
        assert [c.get("filter") for c in gvmd.sent("get_targets")] == [
            "rows=-1 first=1 sort=uuid", "rows=-1 first=3 sort=uuid", "rows=-1 first=5 sort=uuid"]

    def test_target_hosts_listing_is_capped_but_counted(self, gvmd):
        gvmd.targets[TARGET]["hosts"] = ", ".join(f"192.0.2.{i}" for i in range(1, 255)) + ", " + \
            ", ".join(f"198.51.100.{i}" for i in range(1, 11))
        resp, code = run(gvmd, state_req("targets"))
        item = assert_state("targets", resp, code)["items"][0]
        assert len(item["hosts"]) == 256 and item["literal_entries"] == 264

    def test_schedules(self, gvmd):
        gvmd.add_schedule(SCHED, tasks=[TASK2, TASK], comment="nao sai")
        gvmd.add_schedule(U(80), owner="globex-gmp", timezone="UTC")
        gvmd.add_schedule(U(81), owner="nobody-gmp")
        resp, code = run(gvmd, state_req("schedules", owners=OWNERS))
        data = assert_state("schedules", resp, code)
        assert gvmd.tags() == ["authenticate", "get_schedules"]
        assert data["unattributed_count"] == 1 and len(data["items"]) == 2
        mine = data["items"][0]
        assert mine["schedule_id"] == SCHED and mine["tenant"] == "acme"
        assert mine["task_ids"] == sorted([TASK, TASK2]) and mine["timezone"] == "America/Sao_Paulo"
        assert mine["icalendar"].startswith("BEGIN:VCALENDAR")
        assert "nao sai" not in fleet_ops.dumps(data).decode()
        get = gvmd.sent("get_schedules")[0]
        assert get.get("filter") == "rows=-1 first=1 sort=uuid" and get.get("tasks") == "1"

    def test_unrepresentable_schedule_is_only_counted(self, gvmd):
        gvmd.add_schedule(SCHED, icalendar="not a calendar at all")
        resp, code = run(gvmd, state_req("schedules"))
        data = assert_state("schedules", resp, code)
        assert data["items"] == [] and data["unattributed_count"] == 1

    def test_reports(self, gvmd):
        gvmd.add_report(REPORT_OLD, creation_time="2026-10-03T02:00:00Z")
        gvmd.add_report(REPORT, creation_time="2026-10-10T02:00:00-03:00")
        gvmd.add_report(REPORT_OTHER, owner="suricatoos-scan")
        resp, code = run(gvmd, state_req("reports", owners=OWNERS))
        data = assert_state("reports", resp, code)
        assert gvmd.tags() == ["authenticate", "get_reports"]
        assert data["unattributed_count"] == 1
        assert [i["report_id"] for i in data["items"]] == [REPORT, REPORT_OLD]     # most recent first
        assert data["items"][0] == {
            "report_id": REPORT, "task_id": TASK, "tenant": "acme", "scan_status": "Done",
            "scan_start": "2026-10-10T02:00:05Z", "scan_end": "2026-10-10T03:10:00Z",
            "counts": {"critical": 1, "high": 2, "medium": 0, "low": 1, "log": 4, "false_positive": 1},
            "hosts_count": 3}
        get = gvmd.sent("get_reports")[0]
        assert get.get("report_filter") == fleet_ops.REPORTS_FILTER
        assert get.get("report_filter") == "apply_overrides=1 min_qod=0 levels=chmlg rows=-1 first=1 sort-reverse=date"
        assert get.get("ignore_pagination") == "1" and get.get("details") == "0"

    def test_reports_cap(self, gvmd, monkeypatch):
        gvmd.max_rows = 1
        for n, day in ((90, "01"), (91, "02"), (92, "03")):
            gvmd.add_report(U(n), creation_time=f"2026-10-{day}T00:00:00Z")
        monkeypatch.setattr(fleet_ops, "MAX_REPORTS", 2)
        resp, code = run(gvmd, state_req("reports"))
        data = assert_state("reports", resp, code)
        assert [i["report_id"] for i in data["items"]] == [U(92), U(91)] and data["truncated"] is True

    def test_empty_owners_counts_everything(self, gvmd):
        resp, code = run(gvmd, state_req("tasks", owners={}))
        data = assert_state("tasks", resp, code)
        assert data == {"items": [], "truncated": False, "unattributed_count": 1}


# --------------------------------------------------------------------------- #
# Fix round 1: owner check of a linked schedule, refusal classifier, fixed
# not_found texts, XML 1.0 text, export filter, lean summary, contract parity
# --------------------------------------------------------------------------- #

class TestOwnerChecksAndNotFoundTexts:
    def test_task_modify_linked_schedule_is_owner_checked(self, gvmd):
        gvmd.add_schedule(SCHED, owner=OTHER_USER)
        foreign, c1 = run(gvmd, cmd("task.modify", {"task_id": TASK, "schedule_id": SCHED}))
        missing, c2 = run(gvmd, cmd("task.modify", {"task_id": TASK, "schedule_id": MISSING}))
        assert assert_error(foreign, c1, "not_found", "task.modify") == "schedule not found"
        assert foreign == missing and c1 == c2 == 0
        assert gvmd.sent("modify_task") == []

    @pytest.mark.parametrize("op,payload,kind", [
        ("task.start", {"task_id": "X"}, "task"),
        ("task.delete", {"task_id": "X"}, "task"),
        ("target.delete", {"target_id": "X"}, "target"),
        ("schedule.delete", {"schedule_id": "X"}, "schedule"),
        ("report.summary", {"report_id": "X", "min_qod": 70, "apply_overrides": True, "levels": "chml"}, "report"),
    ])
    def test_owner_check_text_is_fixed_and_identical(self, gvmd, op, payload, kind):
        getattr(gvmd, f"add_{kind}")(U(77), owner=OTHER_USER)
        answers = []
        for obj in (U(77), MISSING):
            body = {k: (obj if v == "X" else v) for k, v in payload.items()}
            resp, code = run(gvmd, cmd(op, body))
            answers.append(resp)
            assert assert_error(resp, code, "not_found", op) == f"{kind} not found"
        assert answers[0] == answers[1]
        assert U(77) not in json.dumps(answers) and MISSING not in json.dumps(answers)

    def test_gvmd_404_text_is_fixed(self, gvmd):
        gvmd.refuse["start_task"] = ("404", f"Failed to find task '{TASK}'")
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert assert_error(resp, code, "not_found") == "object not found"


class TestRefusalClassifier:
    @pytest.mark.parametrize("text", sorted(fleet_ops.CONFLICT_TEXTS))
    def test_exact_gvmd_conflict_texts(self, gvmd, text):
        gvmd.refuse["start_task"] = ("400", text)
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert assert_error(resp, code, "conflict") == f"gvmd refused start_task: {text}"

    @pytest.mark.parametrize("status,text,expected", [
        ("400", "Report format must be trusted", "gvm_error"),
        ("400", "Report format must be active", "gvm_error"),
        ("400", "Report format is not compatible with the report type", "gvm_error"),
        ("400", "Permission denied", "gvm_error"),
        ("400", "Error in alive test", "gvm_error"),
        ("400", "Error in port range", "gvm_error"),
        ("400", "Attempt to delete a hidden task", "gvm_error"),
        ("400", "Task is active already, and more", "gvm_error"),       # not the exact text
        ("400", "target is in use", "gvm_error"),                       # case matters
        ("500", "Internal error", "gvm_error"),
        ("409", "Reports database is busy. Please try again later.", "unavailable"),
        ("503", "Service temporarily down", "unavailable"),
        ("404", "Failed to find task 'x'", "not_found"),
    ])
    def test_everything_else(self, gvmd, status, text, expected):
        gvmd.refuse["start_task"] = (status, text)
        resp, code = run(gvmd, cmd("task.start", {"task_id": TASK}))
        assert_error(resp, code, expected)

    def test_untrusted_report_format_on_export_is_gvm_error(self, gvmd, tmp_path):
        gvmd.add_report(REPORT, content={PDF_PT: PDF_BYTES})
        original = gvmd._get_reports

        def untrusted(el):
            if el.get("format_id"):
                return refusal("get_reports", "400", "Report format must be trusted")
            return original(el)
        gvmd._get_reports = untrusted
        resp, code = run(gvmd, export_req(tmp_path))
        assert "must be trusted" in assert_error(resp, code, "gvm_error", "report.export")
        assert not (tmp_path / "artefato.bin").exists()


class TestXmlText:
    @pytest.mark.parametrize("op,payload", [
        ("task.create", {"name": "Varredura\ufffe", "target_id": TARGET, "scan_config_id": CONFIG}),
        ("task.create", {"name": "n", "comment": "fim\uffff", "target_id": TARGET, "scan_config_id": CONFIG}),
        ("task.modify", {"task_id": TASK, "name": "\ufffe"}),
        ("task.clone", {"task_id": TASK, "name": "c\uffff"}),
        ("schedule.create", {"name": "s", "icalendar": ICAL + "X-NOTE:\ufffe\r\n", "timezone": "UTC"}),
        ("schedule.modify", {"schedule_id": SCHED, "comment": "c\x0b"}),
        ("target.create", {"name": "t\x00", "hosts": ["192.0.2.0/24"], "port_range": "T:1-10"}),
    ])
    def test_non_xml_text_is_refused_before_gvmd(self, gvmd, op, payload):
        resp, code = run(gvmd, cmd(op, payload))
        assert_error(resp, code, "internal_error", op)                  # exit 0: no crash
        assert gvmd.calls == []

    def test_export_filter_with_a_noncharacter(self, gvmd, tmp_path):
        resp, code = run(gvmd, export_req(tmp_path, filter=EXPORT_FILTER + " \ufffe"))
        assert_error(resp, code, "internal_error", "report.export")
        assert gvmd.calls == []

    @pytest.mark.parametrize("raw_name", [b'"\\ud800"', b'"a\\udfffb"', b'"\\ud83d"'])
    def test_unpaired_surrogate_escape_is_refused(self, gvmd, raw_name):
        raw = (b'{"op":"task.create","command_id":"' + CID.encode() + b'","tenant":"acme",'
               b'"tenant_gmp_user":"acme-gmp","payload":{"name":' + raw_name +
               b',"target_id":"' + TARGET.encode() + b'","scan_config_id":"' + CONFIG.encode() + b'"}}')
        resp, code = run(gvmd, None, raw=raw)
        assert_error(resp, code, "internal_error", "task.create")
        assert gvmd.calls == []

    def test_surrogate_in_a_key_is_refused(self, gvmd):
        raw = (b'{"op":"task.start","command_id":"' + CID.encode() + b'","tenant":"acme",'
               b'"tenant_gmp_user":"acme-gmp","payload":{"task_id":"' + TASK.encode() + b'"},"\\ud800":1}')
        resp, code = run(gvmd, None, raw=raw)
        assert_error(resp, code, "internal_error")

    def test_paired_surrogates_and_astral_text_are_fine(self, gvmd):
        raw = (b'{"op":"task.create","command_id":"' + CID.encode() + b'","tenant":"acme",'
               b'"tenant_gmp_user":"acme-gmp","payload":{"name":"Varredura \\ud83d\\udee1 S\xc3\xa3o Paulo",'
               b'"target_id":"' + TARGET.encode() + b'","scan_config_id":"' + CONFIG.encode() + b'"}}')
        resp, code = run(gvmd, None, raw=raw, env=ENV_TENANT)
        out = assert_ok("task.create", resp, code)
        assert gvmd.tasks[out["task_id"]]["name"] == "Varredura \U0001F6E1 São Paulo"

    def test_field_checks_match_the_schema_patterns_character_by_character(self):
        # fleet_ops' no_control and iCalendar checks are the schema's, not a lookalike.
        defs = json.loads((SCHEMA_DIR / "fleet-command.schema.json").read_text(encoding="utf-8"))["$defs"]
        no_control = re.compile(defs["no_control"]["not"]["pattern"])
        ical_bad = re.compile(defs["icalendar"]["not"]["pattern"])
        points = list(range(0x00, 0x21)) + [0x7e, 0x7f, 0x80, 0x9f, 0xa0, 0xd7ff, 0xe000, 0xfffd, 0xfffe,
                                            0xffff, 0x10000, 0x10ffff]
        for point in points:
            ch = chr(point)
            assert bool(fleet_ops._CTRL_RE.search(ch)) == bool(no_control.search(ch)), hex(point)
            assert bool(fleet_ops._ICAL_BAD_RE.search(ch)) == bool(ical_bad.search(ch)), hex(point)

    def test_nesting_deeper_than_32_levels_is_refused(self, gvmd):
        deep = "1"
        for _ in range(32):
            deep = '{"a":' + deep + "}"
        raw = (b'{"op":"task.start","command_id":"' + CID.encode() + b'","tenant":"acme",'
               b'"tenant_gmp_user":"acme-gmp","payload":' + deep.encode() + b"}")
        resp, code = run(gvmd, None, raw=raw)
        assert "nesting" in assert_error(resp, code, "internal_error")


class TestExportFilter:
    @pytest.mark.parametrize("flt", [
        "apply_overrides=1 min_qod=70 levels=chmlg",
        "levels=hmlf min_qod=0 apply_overrides=0 rows=100 first=1",
        "min_qod=100 levels=f apply_overrides=1 sort-reverse=severity",
        "rows=-1  apply_overrides=0   levels=gc min_qod=9",            # empty tokens are ignored
        "apply_overrides=1 min_qod=70 levels=chmlgf levelsx=1 x_levels=c",  # other keys
    ])
    def test_explicit_filters_are_accepted_and_sent_verbatim(self, gvmd, tmp_path, flt):
        gvmd.add_report(REPORT, content={PDF_PT: PDF_BYTES})
        resp, code = run(gvmd, export_req(tmp_path, filter=flt))
        assert_ok("report.export", resp, code)
        assert gvmd.sent("get_reports")[-1].get("filter") == flt

    @pytest.mark.parametrize("flt", [
        " ",                                                    # blank
        "levels=chmlg rows=-1",                                 # no apply_overrides, no min_qod
        "apply_overrides=1 levels=chmlg",                       # no min_qod (gvmd would use 70)
        "min_qod=70 levels=chmlg",                              # no apply_overrides (gvmd: 0)
        "apply_overrides=1 min_qod=70",                         # no levels
        "apply_overrides=1 min_qod=101 levels=chmlg",
        "apply_overrides=1 min_qod=070 levels=chmlg",           # leading zero
        "apply_overrides=1 min_qod=-1 levels=chmlg",
        "apply_overrides=2 min_qod=70 levels=chmlg",
        "apply_overrides=1 min_qod=70 levels=cc",               # letter repeated
        "apply_overrides=1 min_qod=70 levels=chmlgx",
        "apply_overrides=1 min_qod=70 levels=",
        "apply_overrides=1 min_qod>50 levels=chmlg",            # relation other than '='
        "apply_overrides=1 min_qod~70 levels=chmlg",
        "apply_overrides:1 min_qod=70 levels=chmlg",
        "apply_overrides=1 min_qod=70 levels=chmlg levels=f",   # key twice
        "apply_overrides=1 apply_overrides=1 min_qod=70 levels=c",
        "apply_overrides=1 min_qod=70 levels",                  # bare key, as the validator reads it
        '"apply_overrides=1 min_qod=70 levels=chmlg"',          # quotes do not group
    ])
    def test_implicit_filters_are_refused_before_gvmd(self, gvmd, tmp_path, flt):
        gvmd.add_report(REPORT, content={PDF_PT: PDF_BYTES})
        resp, code = run(gvmd, export_req(tmp_path, filter=flt))
        assert "must pin" in assert_error(resp, code, "internal_error", "report.export")
        assert gvmd.calls == [] and not (tmp_path / "artefato.bin").exists()


class TestSummaryLean:
    def test_lean_is_asked_and_counts_are_identical_without_it(self, gvmd):
        gvmd.add_report(REPORT, results=RESULTS)
        lean, code = run(gvmd, summary_req(min_qod=0, levels="chmlg"))
        assert gvmd.sent("get_reports")[-1].get("lean") == "1"
        gvmd.honor_lean = False                                  # the same report, full results
        full, code2 = run(gvmd, summary_req(min_qod=0, levels="chmlg"))
        assert assert_ok("report.summary", lean, code) == assert_ok("report.summary", full, code2)


def _contract_command_cases():
    index = json.loads((EXAMPLES_DIR / "index.json").read_text(encoding="utf-8"))
    return [case for case in index["cases"]
            if case["file"].startswith(("valid/command/", "invalid/command/"))
            and "--" not in case["file"].rsplit("/", 1)[1]]       # '<def>--' cases target $defs


# Root-level JSON rules of the contract that live INSIDE the payload.
PAYLOAD_JSON_CASES = {"duplicate-key-in-payload.json", "task-create-name-unpaired-surrogate.json",
                      "payload-nesting-depth-33.json"}
GVM_TYPES = {op for op in fleet_ops._OPS if op in fleet_ops.COMMAND_TYPES}


def _request_around(case):
    """A fleet_ops request around the example's payload, its bytes exactly as in the file."""
    text = (EXAMPLES_DIR / case["file"]).read_text(encoding="utf-8")
    start = text.index('"payload":') + len('"payload":')
    _, end = json.JSONDecoder().raw_decode(text, start)
    op = re.search(r'"type":"([^"]*)"', text).group(1)
    extra = ',"artifact_path":"/var/lib/suricatoos-fleet/artifacts/x.bin"' if op == "report.export" else ""
    return op, ('{"op":' + json.dumps(op) + ',"command_id":"' + CID + '","tenant":"acme",'
                '"tenant_gmp_user":"acme-gmp","payload":' + text[start:end] + extra + "}").encode("utf-8")


@pytest.mark.parametrize("case", _contract_command_cases(), ids=lambda c: c["file"])
def test_request_validation_agrees_with_the_contract_examples(case):
    op, raw = _request_around(case)
    name = case["file"].rsplit("/", 1)[1]
    if op not in GVM_TYPES:
        with pytest.raises(fleet_ops.OpError) as refused:             # never executed here
            fleet_ops.parse_request(raw)
        assert refused.value.code == "internal_error" and "allowlist" in refused.value.message
        return
    if case["file"].startswith("valid/"):
        fleet_ops.parse_request(raw)                                  # must not raise
        return
    path = case["expect"].get("path", "")
    if not (path.startswith("/payload") or name in PAYLOAD_JSON_CASES):
        pytest.skip("envelope-level rule (the connector's verification lines 0-2)")
    with pytest.raises(fleet_ops.OpError) as refused:
        fleet_ops.parse_request(raw)
    assert refused.value.code == "internal_error"


def test_contract_examples_cover_the_new_rules():
    names = {c["file"].rsplit("/", 1)[1] for c in _contract_command_cases()}
    assert {"report-export-filter-blank.json", "report-export-filter-levels-repeated.json",
            "report-export-filter-min-qod-101.json", "report-export-filter-without-overrides-and-qod.json",
            "report-export-filter-any-order.json", "target-modify-port-range.json",
            "target-modify-unknown-alive-test.json", "task-create-name-noncharacter.json",
            "task-create-name-unpaired-surrogate.json", "target-modify-port-list.json"} <= names
