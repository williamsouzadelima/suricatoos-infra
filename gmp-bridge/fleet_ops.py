#!/usr/bin/env python3
"""
Suricatoos — fleet_ops (ADR-0011, slice F2.3): the GVM half of the fleet command
catalog plus the GVM state reads, against the LOCAL gvmd socket.

The node's fleet connector (Go, slice F2.6) execs this file ONCE per operation:

    python3 fleet_ops.py  < request.json  > response.json

stdin   ONE JSON object (UTF-8, no BOM, no duplicate key, no unpaired surrogate, nothing
        after it) with EXACTLY the keys its op takes — an unknown or extra key is an
        error (the connector must use one struct per shape, not one with every key):
          catalog ops  op, command_id (uuid), tenant, tenant_gmp_user, payload
                       (+ artifact_path for report.export only)
          inspect.*    op, command_id (uuid of the command being verified), tenant,
                       tenant_gmp_user, payload
          state.node   op, command_id (""), payload (connector-owned data_node members)
          state.<list> op, command_id (""), owners ({gvmd user: tenant}), payload ({})
stdout  ONE compact JSON object (UTF-8, ensure_ascii off, no HTML escaping) + "\\n":
          {"ok": true, "output": {...}}       report.export adds "artifact": {
                                              original_content_type, original_size,
                                              original_sha256}
          {"ok": false, "error": {"code": ..., "message": ...}}
        output validates against fleet-result.schema.json#/$defs/output_<op> or
        fleet-state.schema.json#/$defs/data_<kind> (inspect.* outputs are internal to
        the connector, see their handlers); error.code is one of
        fleet-result.schema.json#/$defs/error_code.
exit    0 for every handled outcome, ok or not; 1 only for an unexpected failure (the
        connector reports it as failed) — still one JSON error on stdout.

Environment (credentials only here: never argv, stdout, stderr or a log). The connector
must exec this with a MINIMAL, explicit environment — never the inherited one (the
ingest container, for one, exports GMP_USERNAME=admin):
  GMP_USERNAME, GMP_PASSWORD  the gvmd user the connector chose (ADR-0011 D6): the
                              node's current user (with Super over the tenants' users)
                              for reads, inspect.*, task.start/stop/resume and report.*;
                              the tenant's user (== tenant_gmp_user) for every
                              create/modify/clone/delete
  GVMD_SOCKET                 gvmd Unix socket (default /run/gvmd/gvmd.sock)

Rules (ADR-0011 "Catálogo de comandos v1" + F2.3 brief):
  * closed allowlist (_OPS): exactly the GVM rows of the catalog, the read-only
    inspect.* used by the connector's scope gate, and the state.* reads; no GMP
    passthrough;
  * every get_* carries an EXPLICIT filter (constants below): gvmd's hidden defaults
    (min_qod=70, apply_overrides=0, the 1000-row "Max Rows Per Page" cap behind
    rows=-1) never decide a result — lists use ignore_pagination=1 (tasks, reports,
    report results) or page through the count (targets, schedules);
  * an existing object must be owned by tenant_gmp_user, else not_found — the same
    answer as a missing one (no cross-tenant enumeration);
  * deletes go to the trash: ultimate=0, always;
  * every object created or altered carries the comment prefix 'fleet:<command_id> ';
  * every text that reaches gvmd's XML holds only XML 1.0 characters (no C0 control
    beyond what the field allows, no U+FFFE/U+FFFF, no unpaired surrogate) — refused
    as an invalid request, never a crash inside the XML builder;
  * targets: IP/CIDR literal hosts only (re-checked here), no credentials, no
    asset_hosts_filter, reverse lookup off; target.create takes exactly one of
    port_list_id | port_range, target.modify changes ports only by port_list_id;
  * alive test: the contract value is the NAME of a set of gvmd methods and is never
    sent to gvmd; each method goes as one <alive_test> sub-element of <alive_tests>,
    built with python-gvm's XmlCommand (ALIVE_TEST_METHODS). Default set
    'ICMP, TCP-SYN Service & ARP Ping'; ONLY if gvmd refuses it, one retry with the
    'ICMP, TCP-ACK Service & ARP Ping' set; alive_test_effective = the set applied,
    by name; never 'Consider Alive' nor 'Scan Config Default' by fallback. Read back,
    a set is reported by its contract name, else as the methods joined with ', ';
  * report.export: the hub's filter must pin apply_overrides=, min_qod= and levels=
    and hold no double quote (ADR export_filter rule); report.summary: counts only,
    from the filter the node builds out of min_qod, apply_overrides and levels — no
    free filter, no OID/name/CVE ever leaves;
  * state.*: metadata and counts only; comments and hostnames never leave; an object
    whose owner is not in `owners` (or maps to an invalid tenant name), or that cannot
    be represented within the schema, is only counted (unattributed_count).
"""

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import warnings
from xml.etree import ElementTree as ET

import gvm
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmp.requests.v226 import (
    Authentication,
    Feed,
    ReportFormats,
    Reports,
    Schedules,
    Targets,
    Tasks,
    Version,
)

# --------------------------------------------------------------------------- #
# Contract constants
# --------------------------------------------------------------------------- #

DEFAULT_GVMD_SOCKET = "/run/gvmd/gvmd.sock"
SCANNER_OPENVAS_DEFAULT = "08b69003-5fc2-4037-a479-93b440211c73"

ALIVE_TEST_DEFAULT = "ICMP, TCP-SYN Service & ARP Ping"
ALIVE_TEST_FALLBACK = "ICMP, TCP-ACK Service & ARP Ping"

# Contract alive_test value = NAME of a set of gvmd methods (ADR-0011 table). The name
# never goes to gvmd: gvmd 26 refuses a combined literal as one <alive_tests> value
# (alive_test_from_string) and accepts the methods as <alive_test> sub-elements
# (alive_test_from_array).
ALIVE_TEST_METHODS = {
    "ICMP, TCP-SYN Service & ARP Ping": ("ICMP Ping", "TCP-SYN Service Ping", "ARP Ping"),
    "ICMP, TCP-ACK Service & ARP Ping": ("ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"),
    "ICMP & TCP-ACK Service Ping": ("ICMP Ping", "TCP-ACK Service Ping"),
    "ICMP & ARP Ping": ("ICMP Ping", "ARP Ping"),
    "TCP-ACK Service & ARP Ping": ("TCP-ACK Service Ping", "ARP Ping"),
    "ICMP Ping": ("ICMP Ping",),
    "TCP-ACK Service Ping": ("TCP-ACK Service Ping",),
    "TCP-SYN Service Ping": ("TCP-SYN Service Ping",),
    "ARP Ping": ("ARP Ping",),
    "Consider Alive": ("Consider Alive",),
    "Scan Config Default": ("Scan Config Default",),
}
_ALIVE_TEST_BY_SET = {frozenset(methods): name for name, methods in ALIVE_TEST_METHODS.items()}
# gvmd 26.31.1's exact status_text when it refuses an alive test (create_target 7,
# modify_target 10): the only refusal that triggers the documented fallback.
ALIVE_TEST_REFUSED = "Error in alive test"

# gvmd 26.31.1 status_texts that mean "the object's state or a name collision
# prevents this" (status 400): conflict. Every other 4xx/5xx text is gvm_error, except
# 404 (not_found, fixed text) and 409/503 (busy / service down: unavailable).
CONFLICT_TEXTS = frozenset({
    "Task is active already",                                   # start_task, resume_task
    "Task must be in Stopped or Interrupted state",             # resume_task
    "Task must have a target",                                  # start_task (container task)
    "Status must be New to edit Target",                        # modify_task
    "Status must be New to edit config",
    "Status must be New to edit scanner",
    "For import tasks only name, comment and observers can be modified",
    "Target is in use",                                         # modify_target, delete_target
    "Schedule is in use",                                       # delete_schedule
    "Resource is in use",                                       # generic delete
    "Target exists already",                                    # create/modify_target name
    "Task exists already",                                      # create_task copy + name
    "Schedule exists already",                                  # create_schedule name
    "Schedule with new name exists already",                    # modify_schedule name
})

# Explicit filters (asserted verbatim by the tests). By-id gets reuse the list
# filter of their kind: gvmd ignores rows/first/sort when an id is given, and the
# result-bearing keywords pin what any embedded count means.
TASKS_FILTER = "apply_overrides=1 min_qod=0 rows=-1 first=1 sort=uuid"
TARGETS_FILTER = "rows=-1 first={first} sort=uuid"
SCHEDULES_FILTER = "rows=-1 first={first} sort=uuid"
REPORTS_FILTER = "apply_overrides=1 min_qod=0 levels=chmlg rows=-1 first=1 sort-reverse=date"
REPORT_META_FILTER = "apply_overrides=1 min_qod=0 levels=chmlg rows=-1 first=1"
REPORT_FORMATS_FILTER = "rows=-1 first=1 sort=uuid"
# report.summary: built by the node, exactly the ADR's form.
SUMMARY_FILTER = "apply_overrides={apply_overrides} min_qod={min_qod} levels={levels} rows=-1"

# (format, lang, variant) -> report_format_id (ADR-0011 table). client/executive
# are slice R5 objects that do not exist yet: no row, so they are refused.
REPORT_FORMAT_IDS = {
    ("suricatoos-pdf", "en", "technical"): "c6482c1b-57bb-406b-a501-c97eed86ad05",
    ("suricatoos-pdf", "pt_BR", "technical"): "e43a4f20-d845-4916-83f0-851ac6dc5e57",
    ("suricatoos-pdf", "es", "technical"): "91afce49-21fd-4ea0-ba16-7ba2bc51a03a",
    ("gvm-xml", "en", "technical"): "a994b278-1f62-11e1-96ac-406186ea4fc5",
    ("gvm-csv-results", "en", "technical"): "c1645568-627a-11e3-a660-406186ea4fc5",
    ("gvm-pdf", "en", "technical"): "c402cc3e-b531-11e1-9163-406186ea4fc5",
}
ARTIFACT_NAMES = {
    "suricatoos-pdf": "report.pdf.gz",
    "gvm-pdf": "report.pdf.gz",
    "gvm-xml": "report.xml.gz",
    "gvm-csv-results": "report.csv.gz",
}
CONTENT_TYPES = {
    "suricatoos-pdf": "application/pdf",
    "gvm-pdf": "application/pdf",
    "gvm-xml": "application/xml",
    "gvm-csv-results": "text/csv",
}

MAX_REQUEST_BYTES = 1 << 20
MAX_ARTIFACT_BYTES = 1073741824          # artifact original_size cap (fleet-result schema)
MAX_TASKS = 5000                         # data_tasks / data_targets items caps
MAX_TARGETS = 5000
MAX_SCHEDULES = 2000                     # data_schedules / data_reports items caps
MAX_REPORTS = 2000
MAX_LISTED_HOSTS = 256                   # data_targets item hosts, before.hosts
MAX_SCHEDULE_TASKS = 256                 # data_schedules item task_ids
MAX_SUMMARY_HOSTS = 1000                 # output_report_summary hosts
MAX_PAGES = 1000

# Socket read timeouts (s): below the connector's per-type timeout (ADR: 120 s;
# report.summary 5 min; report.export 15 min) so gvmd slowness is reported here as
# `timeout` instead of the exec being killed.
TIMEOUT_DEFAULT = 110
TIMEOUT_SUMMARY = 290
TIMEOUT_EXPORT = 890

COMMAND_TYPES = (
    "state.resync",
    "task.start", "task.stop", "task.resume", "task.create", "task.modify", "task.clone", "task.delete",
    "target.create", "target.modify", "target.delete",
    "schedule.create", "schedule.modify", "schedule.delete",
    "report.export", "report.summary",
    "agent.scan_now", "agent.revoke",
    "enroll_token.create", "enroll_token.revoke",
    "sensor_job.enqueue",
    "feed.sync_now",
)
STATE_KINDS = ("node", "tasks", "targets", "schedules", "reports", "agents", "tokens",
               "sensors", "scan_requests", "remediation", "scope", "audit_tail")
ALIVE_TESTS = tuple(ALIVE_TEST_METHODS)
FEED_TYPES = {"NVT": "nvt", "SCAP": "scap", "CERT": "cert", "GVMD_DATA": "gvmd_data"}

# report.export filter (ADR-0011 normative rule; the example validator's export_filter
# check): tokens = the filter split on ' ' (quotes do not group); a token belongs to one
# of these keys when it starts with the key followed by = < > ~ or :; each key exactly
# once, with '=' and a valid value (levels: no letter repeated).
EXPORT_FILTER_KEYS = {
    "apply_overrides": re.compile(r"[01]"),
    "min_qod": re.compile(r"0|[1-9][0-9]?|100"),
    "levels": re.compile(r"[chmlgf]{1,6}"),
}

# no_control of the schemas: C0, DEL and the noncharacters U+FFFE/U+FFFF (not XML 1.0).
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\ufffe\uffff]")
# iCalendar: TAB, LF and CR allowed; nothing else outside XML 1.0.
_ICAL_BAD_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffe\uffff]")
# Never valid in an XML 1.0 document, whatever the field: refused in every string of a
# request before anything is built (a lone surrogate also fails UTF-8 encoding).
_NOT_XML_RE = re.compile(r"[\ud800-\udfff\ufffe\uffff]")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_IP_OR_CIDR_RE = re.compile(r"[0-9A-Fa-f:.]+(?:/[0-9]{1,3})?")
_IP_RE = re.compile(r"[0-9A-Fa-f:.]+")
_PORT_RANGE_RE = re.compile(r"[TU]:[0-9,-]+")
_TZ_RE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)*")
_LEVELS_RE = re.compile(r"c?h?m?l?g?")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]*")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# utc_time of the schema: years 0001-9999 and the field ranges (the calendar is checked apart).
_UTC_RE = re.compile(r"(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})-(?:0[1-9]|1[0-2])"
                     r"-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z")
_STATUS_CODE_RE = re.compile(r"[0-9]{3}")
_STATUS_RE = re.compile(r"[A-Za-z][A-Za-z ]*")
_FLEET_PREFIX_RE = re.compile(
    r"(?:fleet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} )+")
_FEED_VERSION_RE = re.compile(r"[0-9]{8}(?:[0-9]{4}(?:[0-9]{2})?)?")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class OpError(Exception):
    """A handled failure: becomes {"ok": false, "error": {code, message}}, exit 0."""

    def __init__(self, code: str, message: str):
        super().__init__(code)
        self.code = code
        self.message = message


class _GmpStatus(Exception):
    """gvmd answered a command with a non-2xx status."""

    def __init__(self, command: str, status: str, text: str):
        super().__init__(command)
        self.command = command
        self.status = status
        self.text = text


MAX_MESSAGE = 512            # fleet-result error.message maxLength
NOT_FOUND_GVMD = "object not found"

# Secrets of the request being handled (handle() sets them): redacted from any external
# text (gvmd status_text, request key names) BEFORE it is cleaned or truncated, so no
# truncation can ever leave a piece of a secret behind.
_SECRETS = []


def _redact(text: str) -> str:
    for secret in _SECRETS:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def _bad(message: str) -> OpError:
    # A request the connector should never send (it validates first): a contract bug.
    return OpError("internal_error", f"invalid request: {message}")


def _clean(text: str) -> str:
    """Control characters (and U+FFFE/U+FFFF) out. No truncation: that is the last step."""
    return _CTRL_RE.sub(" ", text or "").strip()


def _from_status(e: _GmpStatus) -> OpError:
    """Map a gvmd refusal precisely. 404 is not_found with a FIXED text (it may be another
    tenant's object); 409/503 (busy, service down) are unavailable; a 400 is conflict only
    for the exact gvmd texts of CONFLICT_TEXTS; anything else is gvm_error."""
    if e.status == "404":
        return OpError("not_found", NOT_FOUND_GVMD)
    if e.status in ("409", "503"):
        return OpError("unavailable", f"gvmd busy or unavailable ({e.command})")
    text = _clean(_redact(e.text)) or "no detail"
    if e.status == "400" and text in CONFLICT_TEXTS:
        return OpError("conflict", f"gvmd refused {e.command}: {text}")
    # The status is printed only when it is a 3-digit code: any other value is external
    # text that must not be cut (or shown) outside the redaction path.
    status = e.status if _STATUS_CODE_RE.fullmatch(e.status) else "???"
    return OpError("gvm_error", f"gvmd refused {e.command} ({status}): {text}")


def _is_timeout(e: BaseException) -> bool:
    if isinstance(e, TimeoutError):
        return True
    return isinstance(e, GvmError) and "timeout" in str(e).lower()


# --------------------------------------------------------------------------- #
# Request parsing and validation
# --------------------------------------------------------------------------- #

def _reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise _bad(f"duplicate key {_show(key)}")
        out[key] = value
    return out


def _reject_constant(name):
    raise _bad(f"non-finite number {name}")


def _show(key) -> str:
    text = "".join(c if " " <= c <= "~" else "?" for c in _redact(str(key)))[:64]
    return repr(text)


MAX_DEPTH = 32               # ADR-0011 "Codificação JSON": nesting, top-level value = level 1


def _check_strings(value, path="request", depth=1):
    """Every string of the request holds only characters XML 1.0 can carry (no unpaired
    surrogate from a \\u escape, no U+FFFE/U+FFFF) — what gvmd's XML builder would choke
    on; C0 controls are refused per field. Nesting deeper than 32 levels is refused."""
    if isinstance(value, str):
        if _NOT_XML_RE.search(value):
            raise _bad(f"{path} holds a character XML 1.0 cannot carry")
    elif isinstance(value, (dict, list)):
        if depth > MAX_DEPTH:
            raise _bad(f"nesting deeper than {MAX_DEPTH} levels")
        if isinstance(value, dict):
            for k, v in value.items():
                _check_strings(k, path, depth)
                _check_strings(v, f"{path}.{_show(k)}", depth + 1)
        else:
            for v in value:
                _check_strings(v, path, depth + 1)


def parse_request(raw: bytes) -> dict:
    if len(raw) > MAX_REQUEST_BYTES:
        raise _bad("request too large")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _bad("BOM not allowed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _bad("request is not UTF-8") from None
    try:
        req = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except OpError:
        raise
    except (ValueError, RecursionError):
        raise _bad("request is not exactly one JSON value") from None
    if not isinstance(req, dict):
        raise _bad("request must be a JSON object")
    _check_strings(req)

    op = req.get("op")
    if not isinstance(op, str) or op not in _OPS:
        raise _bad(f"op {_show(op)} is not in the allowlist")
    spec = _OPS[op]
    expected = _REQUEST_KEYS[spec["shape"]]
    for key in req:
        if key not in expected:
            raise _bad(f"unknown key {_show(key)} for {op}")
    for key in expected:
        if key not in req:
            raise _bad(f"missing key {_show(key)} for {op}")

    if spec["shape"] in ("state_node", "state_list"):
        if req["command_id"] != "":
            raise _bad("command_id must be empty for state reads")
    else:
        _c_uuid(req["command_id"], "command_id")
        if not isinstance(req["tenant"], str) or not _TENANT_RE.fullmatch(req["tenant"]):
            raise _bad("tenant has an invalid name")
        _c_text(256, 1)(req["tenant_gmp_user"], "tenant_gmp_user")
    if spec["shape"] == "state_list":
        owners = req["owners"]
        if not isinstance(owners, dict):
            raise _bad("owners must be an object")
        for user, tenant in owners.items():
            _c_text(256, 1)(user, "owners key")
            if not isinstance(tenant, str):
                raise _bad("owners values must be strings")
    if spec["shape"] == "export":
        path = req["artifact_path"]
        if (not isinstance(path, str) or not path or len(path) > 4096
                or _CTRL_RE.search(path) or not os.path.isabs(path)):
            raise _bad("artifact_path must be an absolute path")

    req["payload"] = _check_payload(op, req["payload"])
    return req


# ---- field checkers (mirror fleet-command.schema.json#/$defs) -------------- #

def _c_uuid(value, path):
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise _bad(f"{path} must be a lowercase UUID")
    return value


def _c_text(max_len, min_len=0):
    def check(value, path):
        if (not isinstance(value, str) or not min_len <= len(value) <= max_len
                or _CTRL_RE.search(value)):
            raise _bad(f"{path} must be a string of {min_len}..{max_len} characters without control characters")
        return value
    return check


def _c_pattern(regex, max_len, min_len=1):
    def check(value, path):
        if (not isinstance(value, str) or not min_len <= len(value) <= max_len
                or not regex.fullmatch(value)):
            raise _bad(f"{path} has an invalid format")
        return value
    return check


def _c_enum(values):
    def check(value, path):
        if not isinstance(value, str) or value not in values:
            raise _bad(f"{path} is not an allowed value")
        return value
    return check


def _c_int(lo=None, hi=None):
    def check(value, path):
        if type(value) is not int or (lo is not None and value < lo) or (hi is not None and value > hi):
            raise _bad(f"{path} must be an integer in range")
        return value
    return check


def _c_bool(value, path):
    if type(value) is not bool:
        raise _bad(f"{path} must be a boolean")
    return value


def _c_number(lo, hi):
    def check(value, path):
        if type(value) not in (int, float) or not lo <= value <= hi:
            raise _bad(f"{path} must be a number in range")
        return value
    return check


def _c_list(item, min_items=0, max_items=None, unique=True):
    def check(value, path):
        if not isinstance(value, list) or len(value) < min_items or (
                max_items is not None and len(value) > max_items):
            raise _bad(f"{path} must be a list of {min_items}..{max_items} items")
        out = [item(v, f"{path}[]") for v in value]
        if unique and len(set(out)) != len(out):
            raise _bad(f"{path} has repeated items")
        return out
    return check


def _c_host_literal(value, path):
    """IP or CIDR LITERAL in canonical form (defense in depth: the connector's scope
    gate already checked it). A hostname, a range, host bits set or a zone id fail."""
    if (not isinstance(value, str) or not 2 <= len(value) <= 43
            or not _IP_OR_CIDR_RE.fullmatch(value)):
        raise _bad(f"{path}: host is not an IP/CIDR literal")
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=True)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        raise _bad(f"{path}: host is not an IP/CIDR literal") from None
    return value


def _c_icalendar(value, path):
    if (not isinstance(value, str) or not 15 <= len(value) <= 8192
            or not value.startswith("BEGIN:VCALENDAR") or _ICAL_BAD_RE.search(value)):
        raise _bad(f"{path} is not an accepted iCalendar text")
    return value


def _c_object(required, optional=None):
    optional = optional or {}

    def check(value, path):
        if not isinstance(value, dict):
            raise _bad(f"{path} must be an object")
        for key in value:
            if key not in required and key not in optional:
                raise _bad(f"unknown key {_show(key)} in {path}")
        out = {}
        for key, checker in required.items():
            if key not in value:
                raise _bad(f"missing key {_show(key)} in {path}")
            out[key] = checker(value[key], f"{path}.{key}")
        for key, checker in optional.items():
            if key in value:
                out[key] = checker(value[key], f"{path}.{key}")
        return out
    return check


_name = _c_text(128, 1)
_comment = _c_text(400)
_hosts = _c_list(_c_host_literal, 1, 256)
_exclude_hosts = _c_list(_c_host_literal, 0, 256)
_port_range = _c_pattern(_PORT_RANGE_RE, 1024, 3)
_timezone = _c_pattern(_TZ_RE, 64)
_version = _c_pattern(_VERSION_RE, 64)


def _c_schedule_link(value, path):
    if value == "":
        return value
    return _c_uuid(value, path)


def _post_min_properties(payload, path):
    if len(payload) < 2:
        raise _bad(f"{path} must change at least one field")


def _post_target_create(payload, path):
    if ("port_list_id" in payload) == ("port_range" in payload):
        raise _bad(f"{path} needs exactly one of port_list_id and port_range")


def export_filter_problem(flt: str):
    """None when a report.export filter pins apply_overrides, min_qod and levels
    explicitly (ADR-0011 normative rule, the example validator's export_filter check),
    else why not. No double quote at all: gvmd's split_filter groups a part that starts
    with one (also after = or ~) into a single term, hiding the keywords. Tokens = the
    filter split on single spaces (never str.split(): other whitespace stays inside a
    token, as in gvmd); a token belongs to a key when it IS the key or starts with the
    key followed by a relation (= < > ~ :); each key exactly once, with '=' and a valid
    value."""
    if '"' in flt:
        return "contains a double quote"
    seen = {}
    for token in flt.split(" "):
        key = re.split(r"[=<>~:]", token, maxsplit=1)[0]
        if key not in EXPORT_FILTER_KEYS:
            continue
        value = token[len(key) + 1:]
        if key in seen:
            return f"{key} more than once"
        if (not token.startswith(key + "=") or not EXPORT_FILTER_KEYS[key].fullmatch(value)
                or (key == "levels" and len(set(value)) != len(value))):
            return f"{key} is not {key}=<valid value>"
        seen[key] = value
    missing = [key for key in EXPORT_FILTER_KEYS if key not in seen]
    return f"missing {', '.join(missing)}" if missing else None


def _post_report_export(payload, path):
    if payload["format"] != "suricatoos-pdf" and (
            payload["lang"] != "en" or payload["variant"] != "technical"):
        raise _bad(f"{path}: gvm-* formats only exist as lang en + variant technical")
    problem = export_filter_problem(payload["filter"])
    if problem:
        # Never gvmd's hidden defaults (min_qod=70, apply_overrides=0) in an export.
        raise _bad(f"{path}.filter must pin apply_overrides=, min_qod= and levels= ({problem})")


def _c_utc(value, path):
    """utc_time: the exact 20-character form AND a real calendar instant."""
    _c_pattern(_UTC_RE, 20, 20)(value, path)
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _bad(f"{path} is not a real instant") from None
    return value


def _post_levels(payload, path):
    if not _LEVELS_RE.fullmatch(payload["levels"]):
        raise _bad(f"{path}.levels must be a subset of chmlg in that order")


_TASK_REF = ({"task_id": _c_uuid}, {}, None)
_POLICY = _c_object({
    "allow": _c_list(_c_enum(COMMAND_TYPES)),
    "sensitive_per_hour": _c_int(0, 1000),
    "total_per_hour": _c_int(0, 3600),
})

# op -> (required checkers, optional checkers, cross-field check)
_PAYLOADS = {
    "task.start": _TASK_REF,
    "task.stop": _TASK_REF,
    "task.resume": _TASK_REF,
    "task.delete": _TASK_REF,
    "task.create": ({"name": _name, "target_id": _c_uuid, "scan_config_id": _c_uuid},
                    {"comment": _comment, "scanner_id": _c_uuid, "schedule_id": _c_uuid}, None),
    "task.modify": ({"task_id": _c_uuid},
                    {"name": _name, "comment": _comment, "target_id": _c_uuid,
                     "scan_config_id": _c_uuid, "schedule_id": _c_schedule_link},
                    _post_min_properties),
    "task.clone": ({"task_id": _c_uuid}, {"name": _name}, None),
    "target.create": ({"name": _name, "hosts": _hosts},
                      {"comment": _comment, "exclude_hosts": _exclude_hosts,
                       "port_list_id": _c_uuid, "port_range": _port_range,
                       "alive_test": _c_enum(ALIVE_TESTS)},
                      _post_target_create),
    # Ports change only through port_list_id: gvmd's modify_target has no port_range.
    "target.modify": ({"target_id": _c_uuid},
                      {"name": _name, "comment": _comment, "hosts": _hosts,
                       "exclude_hosts": _exclude_hosts, "port_list_id": _c_uuid,
                       "alive_test": _c_enum(ALIVE_TESTS)},
                      _post_min_properties),
    "target.delete": ({"target_id": _c_uuid}, {}, None),
    "schedule.create": ({"name": _name, "icalendar": _c_icalendar, "timezone": _timezone},
                        {"comment": _comment, "task_ids": _c_list(_c_uuid, 0, 16)}, None),
    "schedule.modify": ({"schedule_id": _c_uuid},
                        {"name": _name, "comment": _comment, "icalendar": _c_icalendar,
                         "timezone": _timezone},
                        _post_min_properties),
    "schedule.delete": ({"schedule_id": _c_uuid}, {}, None),
    "report.export": ({"report_id": _c_uuid,
                       "format": _c_enum(("suricatoos-pdf", "gvm-xml", "gvm-csv-results", "gvm-pdf")),
                       "lang": _c_enum(("en", "pt_BR", "es")),
                       "variant": _c_enum(("technical", "client", "executive")),
                       "filter": _c_text(1024, 1)},
                      {"delta_report_id": _c_uuid}, _post_report_export),
    "report.summary": ({"report_id": _c_uuid, "min_qod": _c_int(0, 100),
                        "apply_overrides": _c_bool, "levels": _c_text(5, 1)},
                       {}, _post_levels),
    "inspect.task": _TASK_REF,
    "inspect.target": ({"target_id": _c_uuid}, {}, None),
    "inspect.schedule": ({"schedule_id": _c_uuid}, {}, None),
    # The connector-owned members of data_node; fleet_ops adds the gvmd-owned ones
    # (versions.gmp_protocol/python_gvm, feeds, health.status/gvmd_up,
    # capabilities.report_formats).
    "state.node": ({"node_kind": _c_enum(("central", "standalone", "sensor")),
                    "connector_version": _version,
                    "policy": _POLICY,
                    "policy_sha256": _c_pattern(_SHA256_RE, 64, 64),
                    "replay_floor": _c_utc,
                    "supported_types": _c_list(_c_enum(COMMAND_TYPES)),
                    "state_kinds": _c_list(_c_enum(STATE_KINDS))},
                   {"versions": _c_object({}, {"gvmd": _version, "openvas_scanner": _version,
                                               "gsa": _version, "control_plane": _version}),
                    "health": _c_object({}, {"scanner_up": _c_bool,
                                             "disk_free_pct": _c_number(0, 100),
                                             "active_tasks": _c_int(0),
                                             "clock_offset_s": _c_int()})},
                   None),
    "state.tasks": ({}, {}, None),
    "state.targets": ({}, {}, None),
    "state.schedules": ({}, {}, None),
    "state.reports": ({}, {}, None),
}


def _check_payload(op, payload):
    required, optional, post = _PAYLOADS[op]
    out = _c_object(required, optional)(payload, "payload")
    if post:
        post(out, "payload")
    return out


_REQUEST_KEYS = {
    "command": ("op", "command_id", "tenant", "tenant_gmp_user", "payload"),
    "export": ("op", "command_id", "tenant", "tenant_gmp_user", "payload", "artifact_path"),
    "state_node": ("op", "command_id", "payload"),
    "state_list": ("op", "command_id", "owners", "payload"),
}


# --------------------------------------------------------------------------- #
# GMP session
# --------------------------------------------------------------------------- #

class _Session:
    """python-gvm Gmp + strict response parsing. Every command is a python-gvm
    request object (XmlCommand underneath) — never a hand-formatted XML string."""

    def __init__(self, gmp):
        self._gmp = gmp

    def call(self, request, command: str) -> ET.Element:
        raw = self._gmp.send_command(str(request))
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise OpError("gvm_error", f"unparseable gvmd response to {command}") from None
        status = root.get("status", "")
        if len(status) != 3 or not status.startswith("2"):
            raise _GmpStatus(command, status, root.get("status_text", ""))
        return root


def _connect(env, timeout):
    path = env.get("GVMD_SOCKET") or DEFAULT_GVMD_SOCKET
    return Gmp(connection=UnixSocketConnection(path=path, timeout=timeout))


def _authenticate(s: _Session, user: str, password: str) -> None:
    try:
        s.call(Authentication.authenticate(username=user, password=password), "authenticate")
    except _GmpStatus:
        # Never echo gvmd's text here: nothing derived from the credential exchange
        # leaves the process.
        raise OpError("gvm_error", "gvmd authentication failed") from None


def _get_command(kind: str, obj_id: str):
    if kind == "task":
        cmd = Tasks.get_task(obj_id)
        cmd.add_filter(TASKS_FILTER, None)
    elif kind == "target":
        cmd = Targets.get_target(obj_id)
        cmd.add_filter(TARGETS_FILTER.format(first=1), None)
        cmd.set_attribute("details", "1")   # brings <port_range>
    elif kind == "schedule":
        cmd = Schedules.get_schedule(obj_id, tasks=True)
        cmd.add_filter(SCHEDULES_FILTER.format(first=1), None)
    elif kind == "report":
        cmd = Reports.get_report(obj_id, filter_string=REPORT_META_FILTER, details=False)
    else:  # pragma: no cover - programming error
        raise ValueError(kind)
    return cmd


def _get_one(s: _Session, kind: str, obj_id: str):
    """The object's element, or None when gvmd does not show it to this user."""
    try:
        root = s.call(_get_command(kind, obj_id), f"get_{kind}s")
    except _GmpStatus as e:
        if e.status == "404":
            return None
        raise
    for el in root.findall(kind):
        if el.get("id") == obj_id:
            return el
    return None


def _owned(s: _Session, kind: str, obj_id: str, owner: str) -> ET.Element:
    """Owner check: missing and owned-by-someone-else give the SAME not_found."""
    el = _get_one(s, kind, obj_id)
    if el is None or (el.findtext("owner/name") or "") != owner:
        raise OpError("not_found", f"{kind} not found")
    return el


def _created_id(root: ET.Element, command: str) -> str:
    new_id = root.get("id", "")
    if not _UUID_RE.fullmatch(new_id):
        raise OpError("gvm_error", f"gvmd did not return the id of the {command} object")
    return new_id


def _count_filtered(root: ET.Element, kind: str):
    text = root.findtext(f"{kind}_count/filtered")
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _list_paged(s: _Session, kind: str, make_command) -> list:
    """List every object of a kind whose listing gvmd caps at "Max Rows Per Page"
    (rows=-1 is capped too, and ignore_pagination does not apply to targets or
    schedules): page through first=N until the filtered count is covered."""
    items, seen, first = [], set(), 1
    for _ in range(MAX_PAGES):
        root = s.call(make_command(first), f"get_{kind}s")
        page = [el for el in root.findall(kind) if el.get("id")]
        for el in page:
            if el.get("id") not in seen:
                seen.add(el.get("id"))
                items.append(el)
        total = _count_filtered(root, kind)
        if total is None:
            raise OpError("gvm_error", f"gvmd {kind} listing without a count")
        if not page or first - 1 + len(page) >= total:
            return items
        first += len(page)
    raise OpError("gvm_error", f"gvmd {kind} listing did not end")


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

def _fleet_comment(command_id: str, comment: str) -> str:
    return f"fleet:{command_id} {comment}"


def _strip_fleet_prefix(comment: str) -> str:
    """The user part of a comment: drop the LEADING 'fleet:<uuid> ' prefix(es) only."""
    comment = comment or ""
    match = _FLEET_PREFIX_RE.match(comment)
    return comment[match.end():] if match else comment


def _host_entries(text: str) -> list:
    return [h.strip() for h in (text or "").replace("\n", ",").split(",") if h.strip()]


def _literal(entry: str):
    """Canonical IP/CIDR literal, or None for anything else (hostname, range...)."""
    if not 2 <= len(entry) <= 43 or not _IP_OR_CIDR_RE.fullmatch(entry):
        return None
    try:
        if "/" in entry:
            return str(ipaddress.ip_network(entry, strict=False))
        return str(ipaddress.ip_address(entry))
    except ValueError:
        return None


def _literal_ip(entry: str):
    if not 2 <= len(entry) <= 39 or not _IP_RE.fullmatch(entry):
        return None
    try:
        text = str(ipaddress.ip_address(entry))
    except ValueError:
        return None
    return text if len(text) <= 39 else None


def _split_literals(text: str):
    entries = _host_entries(text)
    literals = [lit for lit in (_literal(e) for e in entries) if lit]
    return literals, len(entries) - len(literals), len(entries)


def _utc(text: str):
    """gvmd ISO time (UTC 'Z' or the user's offset) -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    t = (text or "").strip()
    if not t:
        return None
    try:
        dt = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    dt = dt.astimezone(datetime.timezone.utc)
    if not 1970 <= dt.year <= 9999:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(text: str) -> float:
    t = _utc(text)
    if not t:
        return 0.0
    return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def _gvm_name(text: str) -> str:
    """Object name for a state snapshot: control characters out, <= 128 characters."""
    name = _CTRL_RE.sub(" ", text or "").strip()[:128]
    return name or "-"


def _valid_name(text):
    return text if isinstance(text, str) and 1 <= len(text) <= 128 and not _CTRL_RE.search(text) else None


def _gvm_status(text: str):
    t = (text or "").strip()
    return t if 1 <= len(t) <= 32 and _STATUS_RE.fullmatch(t) else None


def _uuid_attr(el, path: str):
    node = el.find(path) if el is not None else None
    value = node.get("id", "") if node is not None else ""
    return value if _UUID_RE.fullmatch(value) else None


def _int_text(text, lo=None, hi=None):
    try:
        value = int((text or "").strip())
    except ValueError:
        return None
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        return None
    return value


def _tenant_of(owner: str, owners: dict):
    tenant = owners.get(owner)
    if isinstance(tenant, str) and _TENANT_RE.fullmatch(tenant):
        return tenant
    return None


def _add_alive_tests(cmd, name: str) -> None:
    """<alive_tests> with one <alive_test> sub-element per method of the contract set
    `name`, through python-gvm's XmlCommand (never a formatted string; the contract name
    itself never goes to gvmd)."""
    node = cmd.add_element("alive_tests")
    for method in ALIVE_TEST_METHODS[name]:
        node.add_element("alive_test", method)


def _alive_read(target_el):
    """The alive test of a target as the contract reports it: the set's contract name
    when the <alive_test> methods gvmd lists match one, else those methods joined with
    ', ' (gvmd without sub-elements: its own string). None if not representable."""
    node = target_el.find("alive_tests")
    if node is None:
        return None
    methods = [m for m in ((sub.text or "").strip() for sub in node.findall("alive_test")) if m]
    if methods:
        name = _ALIVE_TEST_BY_SET.get(frozenset(methods)) if len(set(methods)) == len(methods) else None
        text = name or ", ".join(methods)
    else:
        text = (node.text or "").strip()
    return text if text and len(text) <= 64 and not _CTRL_RE.search(text) else None


def _send_with_alive(s: _Session, build, requested: str, command: str):
    """Send a create/modify_target carrying the `requested` set as sub-elements; when it is
    the ADR default and gvmd refuses exactly the alive test, retry ONCE with the documented
    fallback set. Returns (response root, contract name of the set applied)."""
    try:
        return s.call(build(requested), command), requested
    except _GmpStatus as e:
        if not (requested == ALIVE_TEST_DEFAULT and e.status == "400"
                and e.text.strip() == ALIVE_TEST_REFUSED):
            raise
    return s.call(build(ALIVE_TEST_FALLBACK), command), ALIVE_TEST_FALLBACK


# --------------------------------------------------------------------------- #
# task.*
# --------------------------------------------------------------------------- #

_TASK_ACTIONS = {
    "task.start": (Tasks.start_task, "start_task", "Requested"),
    "task.stop": (Tasks.stop_task, "stop_task", "Stop Requested"),
    "task.resume": (Tasks.resume_task, "resume_task", "Requested"),
}


def op_task_action(s: _Session, req: dict, now) -> dict:
    task_id = req["payload"]["task_id"]
    _owned(s, "task", task_id, req["tenant_gmp_user"])
    action, command, expected = _TASK_ACTIONS[req["op"]]
    root = s.call(action(task_id), command)
    report_id = (root.findtext("report_id") or "").strip()
    # The action already happened: a failed re-read must not turn it into an error.
    status = None
    try:
        status = _gvm_status(_get_one(s, "task", task_id).findtext("status"))
    except Exception:  # noqa: BLE001 - deliberate: report the action, not the re-read
        status = None
    out = {"task_id": task_id, "status": status or expected}
    if req["op"] != "task.stop" and _UUID_RE.fullmatch(report_id):
        out["report_id"] = report_id
    return {"output": out}


def op_task_create(s: _Session, req: dict, now) -> dict:
    p, owner = req["payload"], req["tenant_gmp_user"]
    _owned(s, "target", p["target_id"], owner)
    if "schedule_id" in p:
        _owned(s, "schedule", p["schedule_id"], owner)
    root = s.call(Tasks.create_task(
        name=p["name"],
        config_id=p["scan_config_id"],
        target_id=p["target_id"],
        scanner_id=p.get("scanner_id", SCANNER_OPENVAS_DEFAULT),
        schedule_id=p.get("schedule_id"),
        comment=_fleet_comment(req["command_id"], p.get("comment", "")),
    ), "create_task")
    return {"output": {"task_id": _created_id(root, "create_task")}}


def op_task_modify(s: _Session, req: dict, now) -> dict:
    p, owner = req["payload"], req["tenant_gmp_user"]
    task_id = p["task_id"]
    task = _owned(s, "task", task_id, owner)
    if "target_id" in p:
        _owned(s, "target", p["target_id"], owner)
    if p.get("schedule_id"):
        _owned(s, "schedule", p["schedule_id"], owner)
    current_target = _uuid_attr(task, "target")
    # gvmd's modify_task is not atomic (name/comment land before the target/config
    # checks): refuse here what gvmd would refuse half-way.
    if ("target_id" in p or "scan_config_id" in p) and (
            (task.findtext("status") or "") != "New" and (task.findtext("alterable") or "0") != "1"):
        raise OpError("conflict", "the task must be New (or alterable) to change its target or scan config")
    if p.get("schedule_id") and not current_target:
        raise OpError("conflict", "a task without a target cannot be scheduled")

    comment = p["comment"] if "comment" in p else _strip_fleet_prefix(task.findtext("comment") or "")
    schedule = None
    if "schedule_id" in p:
        schedule = p["schedule_id"] or "0"          # gvmd: schedule id 0 unlinks
    s.call(Tasks.modify_task(
        task_id,
        name=p.get("name"),
        comment=_fleet_comment(req["command_id"], comment),
        target_id=p.get("target_id"),
        config_id=p.get("scan_config_id"),
        schedule_id=schedule,
    ), "modify_task")

    changed = [f for f in ("name", "comment", "target_id", "scan_config_id", "schedule_id") if f in p]
    before = {}
    if "name" in p and _valid_name(task.findtext("name")):
        before["name"] = task.findtext("name")
    if "target_id" in p and current_target:
        before["target_id"] = current_target
    if "scan_config_id" in p and _uuid_attr(task, "config"):
        before["scan_config_id"] = _uuid_attr(task, "config")
    if "schedule_id" in p:
        before["schedule_id"] = _uuid_attr(task, "schedule") or ""
    return {"output": {"task_id": task_id, "changed": changed, "before": before}}


def op_task_clone(s: _Session, req: dict, now) -> dict:
    p = req["payload"]
    source = _owned(s, "task", p["task_id"], req["tenant_gmp_user"])
    # One create_task: gvmd's copy takes the given name and comment atomically.
    cmd = Tasks.clone_task(p["task_id"])
    if "name" in p:
        cmd.add_element("name", p["name"])
    cmd.add_element("comment", _fleet_comment(
        req["command_id"], _strip_fleet_prefix(source.findtext("comment") or "")))
    root = s.call(cmd, "create_task")
    return {"output": {"source_task_id": p["task_id"], "task_id": _created_id(root, "create_task")}}


def op_task_delete(s: _Session, req: dict, now) -> dict:
    task_id = req["payload"]["task_id"]
    _owned(s, "task", task_id, req["tenant_gmp_user"])
    s.call(Tasks.delete_task(task_id, ultimate=False), "delete_task")
    return {"output": {"object_id": task_id, "trash": True}}


# --------------------------------------------------------------------------- #
# target.*
# --------------------------------------------------------------------------- #

def op_target_create(s: _Session, req: dict, now) -> dict:
    p = req["payload"]

    def build(alive_test):
        cmd = Targets.create_target(
            name=p["name"],
            hosts=p["hosts"],
            exclude_hosts=p.get("exclude_hosts") or None,
            comment=_fleet_comment(req["command_id"], p.get("comment", "")),
            port_range=p.get("port_range"),
            port_list_id=p.get("port_list_id"),
            reverse_lookup_only=False,
            reverse_lookup_unify=False,
        )
        # python-gvm's alive_test parameter takes ONE AliveTest value: the set goes as
        # sub-elements added through the same XmlCommand instead.
        _add_alive_tests(cmd, alive_test)
        return cmd

    root, applied = _send_with_alive(s, build, p.get("alive_test", ALIVE_TEST_DEFAULT), "create_target")
    return {"output": {"target_id": _created_id(root, "create_target"), "alive_test_effective": applied}}


def op_target_modify(s: _Session, req: dict, now) -> dict:
    p = req["payload"]
    target_id = p["target_id"]
    target = _owned(s, "target", target_id, req["tenant_gmp_user"])
    cur_hosts = _host_entries(target.findtext("hosts"))
    cur_exclude = _host_entries(target.findtext("exclude_hosts"))

    hosts = exclude = None
    if "hosts" in p or "exclude_hosts" in p:
        # gvmd requires HOSTS and EXCLUDE_HOSTS together: the side the payload does
        # not change is re-sent as it is now.
        hosts = p.get("hosts")
        if hosts is None:
            if any(_literal(h) is None for h in cur_hosts) or not cur_hosts:
                raise OpError("conflict", "the target's current hosts are not all IP/CIDR literals")
            hosts = cur_hosts
        exclude = p["exclude_hosts"] if "exclude_hosts" in p else cur_exclude
        exclude = exclude or [""]           # empty <exclude_hosts/> = no exclusion

    comment = p["comment"] if "comment" in p else _strip_fleet_prefix(target.findtext("comment") or "")

    def build(alive_test):
        cmd = Targets.modify_target(
            target_id,
            name=p.get("name"),
            comment=_fleet_comment(req["command_id"], comment),
            hosts=hosts,
            exclude_hosts=exclude,
            port_list_id=p.get("port_list_id"),
        )
        if alive_test is not None:
            _add_alive_tests(cmd, alive_test)
        return cmd

    if "alive_test" in p:
        _, applied = _send_with_alive(s, build, p["alive_test"], "modify_target")
    else:
        s.call(build(None), "modify_target")
        applied = None

    changed = [f for f in ("name", "comment", "hosts", "exclude_hosts", "port_list_id", "alive_test") if f in p]
    before = {}
    if "name" in p and _valid_name(target.findtext("name")):
        before["name"] = target.findtext("name")
    if "hosts" in p:
        literals = [lit for lit in (_literal(h) for h in cur_hosts) if lit]
        before["hosts"] = literals[:MAX_LISTED_HOSTS]
        before["hosts_non_literal_entries"] = len(cur_hosts) - len(literals)
    if "exclude_hosts" in p:
        before["exclude_hosts"] = [lit for lit in (_literal(h) for h in cur_exclude) if lit][:MAX_LISTED_HOSTS]
    if "port_list_id" in p and _uuid_attr(target, "port_list"):
        before["port_list_id"] = _uuid_attr(target, "port_list")
    if "alive_test" in p and _alive_read(target):
        before["alive_test"] = _alive_read(target)
    out = {"target_id": target_id, "changed": changed, "before": before}
    if applied is not None:
        out["alive_test_effective"] = applied
    return {"output": out}


def op_target_delete(s: _Session, req: dict, now) -> dict:
    target_id = req["payload"]["target_id"]
    _owned(s, "target", target_id, req["tenant_gmp_user"])
    s.call(Targets.delete_target(target_id, ultimate=False), "delete_target")
    return {"output": {"object_id": target_id, "trash": True}}


# --------------------------------------------------------------------------- #
# schedule.*
# --------------------------------------------------------------------------- #

def op_schedule_create(s: _Session, req: dict, now) -> dict:
    p, owner, cid = req["payload"], req["tenant_gmp_user"], req["command_id"]
    task_ids = p.get("task_ids", [])
    # Every task is checked BEFORE anything is created.
    tasks = [_owned(s, "task", task_id, owner) for task_id in task_ids]
    if any(_uuid_attr(t, "target") is None for t in tasks):
        raise OpError("conflict", "a task without a target cannot be scheduled")
    root = s.call(Schedules.create_schedule(
        name=p["name"], icalendar=p["icalendar"], timezone=p["timezone"],
        comment=_fleet_comment(cid, p.get("comment", "")),
    ), "create_schedule")
    schedule_id = _created_id(root, "create_schedule")
    linked = []
    for task_id, task in zip(task_ids, tasks):
        try:
            s.call(Tasks.modify_task(
                task_id, schedule_id=schedule_id,
                comment=_fleet_comment(cid, _strip_fleet_prefix(task.findtext("comment") or "")),
            ), "modify_task")
        except _GmpStatus as e:
            err = _from_status(e)
            raise OpError(err.code, f"schedule {schedule_id} created but only {len(linked)} of "
                                    f"{len(task_ids)} tasks linked: {err.message}") from None
        linked.append(task_id)
    return {"output": {"schedule_id": schedule_id, "linked_task_ids": linked}}


def op_schedule_modify(s: _Session, req: dict, now) -> dict:
    p = req["payload"]
    schedule_id = p["schedule_id"]
    schedule = _owned(s, "schedule", schedule_id, req["tenant_gmp_user"])
    current_ical = schedule.findtext("icalendar") or ""
    # gvmd's modify_schedule requires ICALENDAR: unchanged => the current one again.
    icalendar = p.get("icalendar", current_ical)
    if not icalendar.strip():
        raise OpError("gvm_error", "the schedule's current iCalendar could not be read")
    comment = p["comment"] if "comment" in p else _strip_fleet_prefix(schedule.findtext("comment") or "")
    s.call(Schedules.modify_schedule(
        schedule_id, name=p.get("name"), icalendar=icalendar, timezone=p.get("timezone"),
        comment=_fleet_comment(req["command_id"], comment),
    ), "modify_schedule")
    changed = [f for f in ("name", "comment", "icalendar", "timezone") if f in p]
    before = {}
    if "name" in p and _valid_name(schedule.findtext("name")):
        before["name"] = schedule.findtext("name")
    if "icalendar" in p:
        try:
            before["icalendar"] = _c_icalendar(current_ical, "icalendar")
        except OpError:
            pass
    if "timezone" in p:
        tz = (schedule.findtext("timezone") or "").strip()
        if 1 <= len(tz) <= 64 and _TZ_RE.fullmatch(tz):
            before["timezone"] = tz
    return {"output": {"schedule_id": schedule_id, "changed": changed, "before": before}}


def op_schedule_delete(s: _Session, req: dict, now) -> dict:
    schedule_id = req["payload"]["schedule_id"]
    _owned(s, "schedule", schedule_id, req["tenant_gmp_user"])
    s.call(Schedules.delete_schedule(schedule_id, ultimate=False), "delete_schedule")
    return {"output": {"object_id": schedule_id, "trash": True}}


# --------------------------------------------------------------------------- #
# report.*
# --------------------------------------------------------------------------- #

def _report_task_id(report_el) -> str:
    task_id = _uuid_attr(report_el, "task")
    if not task_id:
        raise OpError("gvm_error", "gvmd report without a task")
    return task_id


def _find_report(root: ET.Element, report_id: str) -> ET.Element:
    for el in root.findall("report"):
        if el.get("id") == report_id:
            return el
    raise OpError("gvm_error", "gvmd response without the requested report")


def _report_bytes(outer: ET.Element, fmt: str) -> bytes:
    if fmt == "gvm-xml":
        # gvmd sends the XML report format inline (not base64).
        inner = outer.find("report")
        if inner is None:
            raise OpError("gvm_error", "gvmd response without the XML report")
        return ET.tostring(inner, encoding="utf-8")
    # Any other format: base64 text after the prefix elements (gvmd encodes in
    # 196608-byte chunks, a multiple of 3, so the concatenation is one base64 run).
    text = (outer.text or "") + "".join(child.tail or "" for child in outer)
    compact = "".join(text.split())
    if len(compact) // 4 * 3 > MAX_ARTIFACT_BYTES + 2:
        raise OpError("artifact_too_large", "the report exceeds the artifact size limit")
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        raise OpError("gvm_error", "gvmd sent report content that is not base64") from None


def _write_artifact(path: str, data: bytes) -> None:
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise OpError("internal_error", "artifact_path already exists") from None
    except OSError:
        raise OpError("internal_error", "artifact_path cannot be created") from None
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise OpError("internal_error", "the artifact could not be written") from None


def op_report_export(s: _Session, req: dict, now) -> dict:
    p, owner = req["payload"], req["tenant_gmp_user"]
    key = (p["format"], p["lang"], p["variant"])
    report_format_id = REPORT_FORMAT_IDS.get(key)
    if report_format_id is None:
        # The connector rejects these first (unsupported_report_variant).
        raise _bad("format/lang/variant combination not in the mapping table")
    meta = _owned(s, "report", p["report_id"], owner)
    task_id = _report_task_id(meta)
    delta_id = p.get("delta_report_id")
    if delta_id:
        delta = _get_one(s, "report", delta_id)
        # Same owner AND same task, else the same not_found as a missing report.
        if (delta is None or (delta.findtext("owner/name") or "") != owner
                or _uuid_attr(delta, "task") != task_id):
            raise OpError("not_found", "report not found")
    try:
        root = s.call(Reports.get_report(
            p["report_id"],
            filter_string=p["filter"],
            delta_report_id=delta_id,
            report_format_id=report_format_id,
            ignore_pagination=True,        # every matching result, not gvmd's row cap
            details=True,
        ), "get_reports")
    except _GmpStatus as e:
        if e.status == "404":   # report and delta were just found: the format is missing
            raise OpError("gvm_error", "the report format is not available in gvmd") from None
        raise
    content = _report_bytes(_find_report(root, p["report_id"]), p["format"])
    if not content:
        raise OpError("gvm_error", "gvmd returned an empty report")
    if len(content) > MAX_ARTIFACT_BYTES:
        raise OpError("artifact_too_large", "the report exceeds the artifact size limit")
    if CONTENT_TYPES[p["format"]] == "application/pdf" and not content.startswith(b"%PDF-"):
        raise OpError("gvm_error", "gvmd returned content that is not a PDF")
    _write_artifact(req["artifact_path"], content)
    out = {"report_id": p["report_id"], "report_format_id": report_format_id,
           "format": p["format"], "lang": p["lang"], "variant": p["variant"]}
    if delta_id:
        out["delta_report_id"] = delta_id
    out["artifact_name"] = ARTIFACT_NAMES[p["format"]]
    return {"output": out, "artifact": {
        "original_content_type": CONTENT_TYPES[p["format"]],
        "original_size": len(content),
        "original_sha256": hashlib.sha256(content).hexdigest(),
    }}


def _severity_class(severity: float):
    if severity >= 9.0:
        return "critical"
    if severity >= 7.0:
        return "high"
    if severity >= 4.0:
        return "medium"
    if severity > 0.0:
        return "low"
    if severity == 0.0:
        return "log"
    if severity == -1.0:
        return "false_positive"
    return None


def op_report_summary(s: _Session, req: dict, now) -> dict:
    p = req["payload"]
    report_id = p["report_id"]
    _owned(s, "report", report_id, req["tenant_gmp_user"])
    filter_applied = SUMMARY_FILTER.format(
        apply_overrides=1 if p["apply_overrides"] else 0, min_qod=p["min_qod"], levels=p["levels"])
    # details=1 is required: gvmd only lists results (host, severity, QoD — the per-IP
    # counts and the QoD histogram) with details. lean=1 drops what the counts never read
    # (owners, timestamps, threat, empty placeholders); the NVT block and description stay —
    # gvmd 26 has no switch for them (size to measure in LAB).
    cmd = Reports.get_report(report_id, filter_string=filter_applied, ignore_pagination=True, details=True)
    cmd.set_attribute("lean", "1")
    root = s.call(cmd, "get_reports")
    outer = _find_report(root, report_id)
    inner = outer.find("report")
    if inner is None:
        raise OpError("gvm_error", "gvmd response without the report body")
    task_id = _report_task_id(outer)

    counts = dict.fromkeys(("critical", "high", "medium", "low", "log", "false_positive"), 0)
    qod = {"q0_29": 0, "q30_69": 0, "q70_100": 0}
    hosts_seen = set()
    per_ip = {}
    for result in inner.findall("results/result"):
        try:
            severity = float((result.findtext("severity") or "").strip())
        except ValueError:
            continue
        level = _severity_class(severity)
        if level is None:
            continue
        counts[level] += 1
        value = _int_text(result.findtext("qod/value"), 0, 100)
        if value is not None and value >= 70:
            qod["q70_100"] += 1
        elif value is not None and value >= 30:
            qod["q30_69"] += 1
        else:
            qod["q0_29"] += 1      # unknown QoD counts as the lowest band
        host_el = result.find("host")
        host = ((host_el.text or "") if host_el is not None else "").strip()
        if not host:
            continue
        ip = _literal_ip(host)
        hosts_seen.add(ip or ("name:" + host))
        if ip is None or level == "false_positive":
            continue        # hostnames are counted, never listed
        row = per_ip.setdefault(ip, dict.fromkeys(("critical", "high", "medium", "low", "log"), 0))
        row[level] += 1

    ordered = sorted(per_ip, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a))))
    hosts = [{"ip": ip, **per_ip[ip]} for ip in ordered[:MAX_SUMMARY_HOSTS]]
    out = {"report_id": report_id, "task_id": task_id,
           "scan_status": _gvm_status(inner.findtext("scan_run_status")) or "Unknown"}
    for field in ("scan_start", "scan_end"):
        value = _utc(inner.findtext(field))
        if value:
            out[field] = value
    out.update({
        "filter_applied": filter_applied,
        "counts": counts,
        "qod_histogram": qod,
        "hosts_count": len(hosts_seen),
        "hosts": hosts,
        "hosts_truncated": len(ordered) > MAX_SUMMARY_HOSTS,
    })
    return {"output": out}


# --------------------------------------------------------------------------- #
# inspect.* — read-only inputs for the connector's scope gate (ADR line 9)
# --------------------------------------------------------------------------- #

def _target_view(target_el) -> dict:
    """Every LITERAL host/exclude entry (canonical), plus how many are not literal
    (hostnames, ranges): the connector denies a target with any non-literal host."""
    hosts, non_literal, _ = _split_literals(target_el.findtext("hosts"))
    exclude, non_literal_exclude, _ = _split_literals(target_el.findtext("exclude_hosts"))
    return {"target_id": target_el.get("id"), "hosts": hosts, "exclude_hosts": exclude,
            "non_literal_hosts": non_literal, "non_literal_exclude_hosts": non_literal_exclude}


def _live_schedule_id(task_el) -> str:
    node = task_el.find("schedule")
    if node is None or (node.findtext("trash") or "0") != "0":
        return ""
    return _uuid_attr(task_el, "schedule") or ""


def _task_target_view(s: _Session, task_el):
    """None = the task has no live target (container task, or target in the trash).
    A live target this user cannot read is `unavailable` (fail-closed)."""
    node = task_el.find("target")
    target_id = _uuid_attr(task_el, "target")
    if not target_id or (node.findtext("trash") or "0") != "0":
        return None
    target = _get_one(s, "target", target_id)
    if target is None:
        raise OpError("unavailable", "the task's target could not be read")
    return _target_view(target)


def op_inspect_task(s: _Session, req: dict, now) -> dict:
    task_id = req["payload"]["task_id"]
    task = _owned(s, "task", task_id, req["tenant_gmp_user"])
    return {"output": {"task_id": task_id, "schedule_id": _live_schedule_id(task),
                       "target": _task_target_view(s, task)}}


def op_inspect_target(s: _Session, req: dict, now) -> dict:
    target = _owned(s, "target", req["payload"]["target_id"], req["tenant_gmp_user"])
    return {"output": _target_view(target)}


def op_inspect_schedule(s: _Session, req: dict, now) -> dict:
    schedule_id = req["payload"]["schedule_id"]
    schedule = _owned(s, "schedule", schedule_id, req["tenant_gmp_user"])
    tasks = []
    for node in schedule.findall("tasks/task"):
        task_id = node.get("id", "")
        if not _UUID_RE.fullmatch(task_id):
            raise OpError("unavailable", "a task linked to the schedule could not be read")
        # Linked tasks are read whoever owns them: the scope gate needs every host
        # the schedule will scan.
        task = _get_one(s, "task", task_id)
        if task is None:
            raise OpError("unavailable", "a task linked to the schedule could not be read")
        tasks.append({"task_id": task_id, "target": _task_target_view(s, task)})
    return {"output": {"schedule_id": schedule_id, "tasks": tasks}}


# --------------------------------------------------------------------------- #
# state.*
# --------------------------------------------------------------------------- #

def _list_snapshot(elements, owners, build, cap, sort_key=None):
    items, unattributed = [], 0
    for el in elements:
        tenant = _tenant_of(el.findtext("owner/name") or "", owners)
        item = build(el, tenant) if tenant else None
        if item is None:
            unattributed += 1
        else:
            items.append(item)
    items.sort(key=sort_key or (lambda item: next(iter(item.values()))))
    return {"items": items[:cap], "truncated": len(items) > cap, "unattributed_count": unattributed}


def _task_item(el, tenant):
    task_id, status = el.get("id", ""), _gvm_status(el.findtext("status"))
    report_count = _int_text(el.findtext("report_count"), 0)
    if not _UUID_RE.fullmatch(task_id) or status is None or report_count is None:
        return None
    item = {"task_id": task_id, "tenant": tenant, "name": _gvm_name(el.findtext("name")), "status": status}
    progress = _int_text(el.findtext("progress"), -1, 100)
    if progress is not None:
        item["progress"] = progress
    for field, path in (("target_id", "target"), ("scan_config_id", "config"),
                        ("scanner_id", "scanner"), ("schedule_id", "schedule")):
        value = _uuid_attr(el, path)
        if value:
            item[field] = value
    last = _uuid_attr(el, "last_report/report")
    if last:
        item["last_report_id"] = last
        at = _utc(el.findtext("last_report/report/timestamp"))
        if at:
            item["last_report_at"] = at
    item["report_count"] = report_count
    return item


def _target_item(el, tenant):
    target_id = el.get("id", "")
    if not _UUID_RE.fullmatch(target_id):
        return None
    literals, non_literal, _ = _split_literals(el.findtext("hosts"))
    item = {"target_id": target_id, "tenant": tenant, "name": _gvm_name(el.findtext("name")),
            "hosts": literals[:MAX_LISTED_HOSTS], "literal_entries": len(literals),
            "non_literal_entries": non_literal,
            "exclude_entries": len(_host_entries(el.findtext("exclude_hosts")))}
    port_list = _uuid_attr(el, "port_list")
    if port_list:
        item["port_list_id"] = port_list
    alive = _alive_read(el)
    if alive:
        item["alive_test"] = alive
    item["in_use"] = (el.findtext("in_use") or "0").strip() == "1"
    return item


def _schedule_item(el, tenant):
    schedule_id = el.get("id", "")
    tz = (el.findtext("timezone") or "").strip()
    ical = el.findtext("icalendar") or ""
    if (not _UUID_RE.fullmatch(schedule_id) or not (1 <= len(tz) <= 64 and _TZ_RE.fullmatch(tz))
            or not 15 <= len(ical) <= 8192 or not ical.startswith("BEGIN:VCALENDAR")
            or _ICAL_BAD_RE.search(ical)):
        return None
    task_ids = []
    for node in el.findall("tasks/task"):
        task_id = node.get("id", "")
        if _UUID_RE.fullmatch(task_id) and task_id not in task_ids:
            task_ids.append(task_id)
    # next_run only when gvmd provides it (ADR-0011): gvmd 26's get_schedules does not,
    # so it is omitted — never computed here from the iCalendar.
    return {"schedule_id": schedule_id, "tenant": tenant, "name": _gvm_name(el.findtext("name")),
            "timezone": tz, "icalendar": ical, "task_ids": sorted(task_ids)[:MAX_SCHEDULE_TASKS]}


def _report_item(el, tenant):
    report_id, task_id, inner = el.get("id", ""), _uuid_attr(el, "task"), el.find("report")
    if not _UUID_RE.fullmatch(report_id) or not task_id or inner is None:
        return None
    status = _gvm_status(inner.findtext("scan_run_status"))
    hosts_count = _int_text(inner.findtext("hosts/count"), 0)
    counts = {}
    for level in ("critical", "high", "medium", "low", "log", "false_positive"):
        # `full` = every result under apply_overrides (gvmd computes it with min_qod 0
        # and without levels), so false positives are counted too.
        value = _int_text(inner.findtext(f"result_count/{level}/full"), 0)
        if value is None:
            return None
        counts[level] = value
    if status is None or hosts_count is None:
        return None
    item = {"report_id": report_id, "task_id": task_id, "tenant": tenant, "scan_status": status}
    for field in ("scan_start", "scan_end"):
        value = _utc(inner.findtext(field))
        if value:
            item[field] = value
    item["counts"] = counts
    item["hosts_count"] = hosts_count
    item["_order"] = (-_epoch(el.findtext("creation_time")), report_id)
    return item


def op_state_tasks(s: _Session, req: dict, now) -> dict:
    root = s.call(Tasks.get_tasks(filter_string=TASKS_FILTER, details=False, ignore_pagination=True),
                  "get_tasks")
    return {"output": _list_snapshot(root.findall("task"), req["owners"], _task_item, MAX_TASKS)}


def op_state_targets(s: _Session, req: dict, now) -> dict:
    targets = _list_paged(s, "target", lambda first: Targets.get_targets(
        filter_string=TARGETS_FILTER.format(first=first)))
    return {"output": _list_snapshot(targets, req["owners"], _target_item, MAX_TARGETS)}


def op_state_schedules(s: _Session, req: dict, now) -> dict:
    schedules = _list_paged(s, "schedule", lambda first: Schedules.get_schedules(
        filter_string=SCHEDULES_FILTER.format(first=first), tasks=True))
    return {"output": _list_snapshot(schedules, req["owners"], _schedule_item, MAX_SCHEDULES)}


def op_state_reports(s: _Session, req: dict, now) -> dict:
    root = s.call(Reports.get_reports(filter_string=REPORTS_FILTER, details=False, ignore_pagination=True),
                  "get_reports")
    snapshot = _list_snapshot(root.findall("report"), req["owners"], _report_item, MAX_REPORTS,
                              sort_key=lambda item: item["_order"])
    for item in snapshot["items"]:
        del item["_order"]
    return {"output": snapshot}


def _feed_age_hours(version: str, now) -> int | None:
    if not _FEED_VERSION_RE.fullmatch(version):
        return None
    digits = (version + "000000")[:14]
    try:
        stamp = datetime.datetime.strptime(digits, "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return max(0, int((now() - stamp).total_seconds() // 3600))


def _read_feeds(s: _Session, now):
    """(feeds, nvt_ok): every parseable feed; nvt_ok = the NVT feed is readable."""
    root = s.call(Feed.get_feeds(), "get_feeds")
    feeds, nvt_ok = [], False
    for node in root.findall("feed"):
        feed = FEED_TYPES.get((node.findtext("type") or "").strip())
        version = (node.findtext("version") or "").strip()
        unavailable = node.find("sync_not_available") is not None
        age = _feed_age_hours(version, now) if _VERSION_RE.fullmatch(version) else None
        if feed is None or age is None or len(version) > 64:
            continue
        if feed == "nvt" and not unavailable:
            nvt_ok = True
        feeds.append({"feed": feed, "version": version, "age_hours": age,
                      "syncing": node.find("currently_syncing") is not None})
    return feeds[:8], nvt_ok


def _read_report_formats(s: _Session):
    """capabilities.report_formats: the mapped combinations whose report-format
    object is present, active and trusted in this gvmd (until R5: technical only)."""
    root = s.call(ReportFormats.get_report_formats(filter_string=REPORT_FORMATS_FILTER), "get_report_formats")
    usable = set()
    for node in root.findall("report_format"):
        trust = (node.findtext("trust") or "").strip()
        if (node.findtext("active") or "").strip() == "1" and trust == "yes":
            usable.add(node.get("id", ""))
    groups = {}
    for (fmt, lang, variant), rf_id in REPORT_FORMAT_IDS.items():
        if rf_id in usable:
            groups.setdefault((fmt, lang), []).append(variant)
    return [{"format": fmt, "lang": lang, "variants": variants} for (fmt, lang), variants in groups.items()]


def op_state_node(req: dict, env, connect, now, user: str, password: str) -> dict:
    """data_node. gvmd trouble is reported IN the snapshot (health), not as an error."""
    p = req["payload"]
    gvmd_up = authed = nvt_ok = False
    read_failed = False
    gmp_version, feeds, formats = None, [], []
    cm = None
    try:
        cm = connect(env, TIMEOUT_DEFAULT)
        gmp = cm.__enter__()
        gvmd_up = True
        s = _Session(gmp)
        _authenticate(s, user, password)
        authed = True
        try:
            version = (s.call(Version.get_version(), "get_version").findtext("version") or "").strip()
            if 1 <= len(version) <= 64 and _VERSION_RE.fullmatch(version):
                gmp_version = version
            feeds, nvt_ok = _read_feeds(s, now)
            formats = _read_report_formats(s)
        except (OpError, _GmpStatus, GvmError, OSError):
            read_failed = True
    except (OpError, _GmpStatus, GvmError, OSError):
        pass
    finally:
        if cm is not None and gvmd_up:
            try:
                cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001 - closing a dead socket is not news
                pass

    given = p.get("versions", {})
    versions = {}
    for key in ("gvmd", "gmp_protocol", "python_gvm", "openvas_scanner", "gsa", "control_plane"):
        if key == "gmp_protocol" and gmp_version:
            versions[key] = gmp_version
        elif key == "python_gvm":
            versions[key] = gvm.__version__
        elif key in given:
            versions[key] = given[key]
    extra = p.get("health", {})
    if not gvmd_up:
        status = "down"
    elif authed and nvt_ok and not read_failed and extra.get("scanner_up", True):
        status = "ok"
    else:
        status = "degraded"
    health = {"status": status, "gvmd_up": gvmd_up}
    for key in ("scanner_up", "disk_free_pct", "active_tasks", "clock_offset_s"):
        if key in extra:
            health[key] = extra[key]
    return {"output": {
        "node_kind": p["node_kind"],
        "connector_version": p["connector_version"],
        "versions": versions,
        "feeds": feeds,
        "health": health,
        "capabilities": {"supported_types": p["supported_types"], "state_kinds": p["state_kinds"],
                         "report_formats": formats},
        "policy": p["policy"],
        "policy_sha256": p["policy_sha256"],
        "replay_floor": p["replay_floor"],
    }}


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def _op(shape, user, handler, timeout=TIMEOUT_DEFAULT):
    return {"shape": shape, "user": user, "handler": handler, "timeout": timeout}


# The closed allowlist. user: "current" = the node's gvmd user (reads, operation),
# "tenant" = the tenant's gvmd user, which must be the credential given (D6).
_OPS = {
    "task.start": _op("command", "current", op_task_action),
    "task.stop": _op("command", "current", op_task_action),
    "task.resume": _op("command", "current", op_task_action),
    "task.create": _op("command", "tenant", op_task_create),
    "task.modify": _op("command", "tenant", op_task_modify),
    "task.clone": _op("command", "tenant", op_task_clone),
    "task.delete": _op("command", "tenant", op_task_delete),
    "target.create": _op("command", "tenant", op_target_create),
    "target.modify": _op("command", "tenant", op_target_modify),
    "target.delete": _op("command", "tenant", op_target_delete),
    "schedule.create": _op("command", "tenant", op_schedule_create),
    "schedule.modify": _op("command", "tenant", op_schedule_modify),
    "schedule.delete": _op("command", "tenant", op_schedule_delete),
    "report.export": _op("export", "current", op_report_export, TIMEOUT_EXPORT),
    "report.summary": _op("command", "current", op_report_summary, TIMEOUT_SUMMARY),
    "inspect.task": _op("command", "current", op_inspect_task),
    "inspect.target": _op("command", "current", op_inspect_target),
    "inspect.schedule": _op("command", "current", op_inspect_schedule),
    "state.node": _op("state_node", "current", None),
    "state.tasks": _op("state_list", "current", op_state_tasks),
    "state.targets": _op("state_list", "current", op_state_targets),
    "state.schedules": _op("state_list", "current", op_state_schedules),
    "state.reports": _op("state_list", "current", op_state_reports),
}


def _credentials(env):
    user, password = env.get("GMP_USERNAME") or "", env.get("GMP_PASSWORD") or ""
    if not user or not password:
        raise OpError("internal_error", "GMP_USERNAME and GMP_PASSWORD must be set in the environment")
    return user, password


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def execute(req: dict, env, connect=None, now=None) -> dict:
    connect, now = connect or _connect, now or _utcnow
    op = req["op"]
    spec = _OPS[op]
    user, password = _credentials(env)
    if spec["user"] == "tenant" and user != req["tenant_gmp_user"]:
        raise OpError("internal_error", f"{op} must run as the tenant's gvmd user (tenant_gmp_user)")
    if op == "state.node":
        return op_state_node(req, env, connect, now, user, password)

    try:
        cm = connect(env, spec["timeout"])
        gmp = cm.__enter__()
    except (GvmError, OSError) as e:
        if _is_timeout(e):
            raise OpError("timeout", "gvmd did not answer in time") from None
        raise OpError("unavailable", "gvmd socket unavailable") from None
    try:
        s = _Session(gmp)
        _authenticate(s, user, password)
        return spec["handler"](s, req, now)
    except _GmpStatus as e:
        raise _from_status(e) from None
    except OpError:
        raise
    except (GvmError, OSError) as e:
        if _is_timeout(e):
            raise OpError("timeout", "gvmd did not answer in time") from None
        raise OpError("gvm_error", "the gvmd connection failed during the operation") from None
    finally:
        try:
            cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001 - closing a dead socket is not news
            pass


def _error(code: str, message: str) -> dict:
    # Redact FIRST, then clean, then truncate: a cut can never leave a piece of a secret.
    text = _clean(_redact(message))[:MAX_MESSAGE] or "error"
    return {"ok": False, "error": {"code": code, "message": text}}


def handle(raw: bytes, env, connect=None, now=None):
    """(response object, exit code) for one raw request. `connect(env, timeout)` returns
    the context manager whose __enter__ yields an object with send_command (python-gvm's
    Gmp in production, a fake gvmd in the tests)."""
    _SECRETS[:] = [env.get("GMP_PASSWORD") or ""]
    try:
        req = parse_request(raw)
        return {"ok": True, **execute(req, env, connect, now)}, 0
    except OpError as e:
        return _error(e.code, e.message), 0
    except Exception as e:  # noqa: BLE001 - never a traceback: one JSON error, exit 1
        return _error("internal_error", f"unexpected failure ({type(e).__name__})"), 1
    finally:
        _SECRETS[:] = []


def dumps(obj) -> bytes:
    """Compact UTF-8 JSON, no ASCII escaping, no HTML escaping (ADR "Codificação JSON")."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def main() -> int:
    # Nothing but the one JSON object leaves the process: no library log, no warning.
    logging.disable(logging.CRITICAL)
    warnings.simplefilter("ignore")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    response, code = handle(raw, os.environ)
    sys.stdout.buffer.write(dumps(response) + b"\n")
    sys.stdout.buffer.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
