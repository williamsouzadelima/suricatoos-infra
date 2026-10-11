#!/usr/bin/env python3
"""Contract test for the ADR-0011 fleet schemas (schema/fleet-*.schema.json).

Validates every example under schema/examples/fleet/ against the schema, or the
$defs entry, it targets, OFFLINE: the six schemas are loaded from disk into a
`referencing` registry keyed by their $id; any other reference raises instead of
being fetched over the network.

  valid/<schema>/<case>.json    must parse (no duplicate key), validate and carry
                                the right raw-byte hashes: a signed command envelope
                                its payload_sha256 and a real Ed25519 signature, a
                                state snapshot its content_sha256
  invalid/<schema>/<case>.json  must fail exactly as its "expect" in fleet/index.json
                                says: {keyword, path} for a schema error (keyword +
                                instance JSON pointer), or {check, path} for
                                json_syntax (not exactly one JSON value, e.g. data
                                after it) | duplicate_key | payload_sha256 |
                                signature | content_sha256

A case named '<def>--<rest>.json' targets fleet-<schema>.schema.json#/$defs/<def>;
any other case targets the schema root.

Hashes cover the EXACT transmitted bytes (ADR-0011 "Codificação JSON"): the raw span
of 'payload' inside a command envelope and of 'data' inside a state snapshot, as
they are in the file -- never a re-serialization. One defect per case: an invalid
case that fails on the schema must still carry correct hashes and signature.

Signed envelopes are checked with an independent Python implementation of the
ADR-0011 canonical form and the PUBLIC golden test key (seed = SHA-256 of
'suricatoos-fleet-command-v1/golden-test-key'). The ADR's worked example is the
cross-language anchor: its envelope, canonical bytes, sha256, payload byte count,
test pubkey and pin are re-derived here byte for byte, and
valid/command/task-start.json must be that envelope verbatim.

It also fails when a file and index.json disagree, a target breaks the naming rule,
a schema has zero valid examples, or a catalog value (command type, state kind,
event type, result type, enroll/heartbeat message) has no valid example.

Usage:    python3 schema/examples/validate_fleet_examples.py   (exit 0 = contract holds)
Requires: jsonschema >= 4.18 (ships `referencing`) and cryptography (Ed25519).
"""
import base64
import hashlib
import json
import re
import sys
from importlib.metadata import version
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

HERE = Path(__file__).resolve().parent
SCHEMA_DIR = HERE.parent
ADR = SCHEMA_DIR.parent / "docs" / "adr" / "0011-gestao-remota-da-frota.md"
EXAMPLES = HERE / "fleet"
BASE = "https://suricatoos.dev/schema/"
SCHEMAS = ("command", "enroll", "heartbeat", "state", "event", "result")
CASE_RE = re.compile(r"^(valid|invalid)/(%s)/(?:[a-z][a-z_]*--)?[a-z0-9]+(?:-[a-z0-9]+)*\.json$" % "|".join(SCHEMAS))

# --- ADR-0011 signing contract ------------------------------------------------
DOMAIN = "suricatoos-fleet-command-v1"
SIGNED_FIELDS = ("schema_version", "command_id", "node_id", "tenant", "type", "issued_by",
                 "issued_at", "not_after", "nonce", "payload_sha256")
TEST_PUB = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"suricatoos-fleet-command-v1/golden-test-key").digest()).public_key()
TEST_SPKI = TEST_PUB.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def canonical(env):
    """Domain line, then 'key=<len in bytes>:<value>\\n' per signed field, in order."""
    lines = [DOMAIN] + [f"{k}={len(env[k].encode('utf-8'))}:{env[k]}" for k in SIGNED_FIELDS]
    return ("\n".join(lines) + "\n").encode("utf-8")


class DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise DuplicateKey(k)
        obj[k] = v
    return obj


def parse(text):
    return json.loads(text, object_pairs_hook=_no_duplicates)


# --- raw value spans (payload_sha256 covers the EXACT transmitted bytes) -----
_DEC = json.JSONDecoder()
_WS = re.compile(r"[ \t\n\r]*")


def _ws(s, i):
    return _WS.match(s, i).end()


def members(s, i):
    """{key: (start, end)} for the members of the JSON object at s[i] == '{'."""
    out, i = {}, _ws(s, i + 1)
    if s[i] == "}":
        return out
    while True:
        key, i = json.decoder.scanstring(s, i + 1)
        i = _ws(s, _ws(s, i) + 1)  # skip ':'
        _, end = _DEC.raw_decode(s, i)
        out[key] = (i, end)
        i = _ws(s, end)
        if s[i] == "}":
            return out
        i = _ws(s, i + 1)


def elements(s, i):
    """[(start, end)] for the elements of the JSON array at s[i] == '['."""
    out, i = [], _ws(s, i + 1)
    if s[i] == "]":
        return out
    while True:
        _, end = _DEC.raw_decode(s, i)
        out.append((i, end))
        i = _ws(s, end)
        if s[i] == "]":
            return out
        i = _ws(s, i + 1)


def envelope_problem(text, start):
    """None if the envelope at text[start] verifies, else 'payload_sha256' | 'signature'."""
    env, _ = _DEC.raw_decode(text, start)
    a, b = members(text, start)["payload"]
    if hashlib.sha256(text[a:b].encode("utf-8")).hexdigest() != env["payload_sha256"]:
        return "payload_sha256"
    try:
        TEST_PUB.verify(base64.b64decode(env["signature"], validate=True), canonical(env))
    except (InvalidSignature, ValueError):
        return "signature"
    return None


def snapshot_problem(text, start):
    """None if content_sha256 of the state snapshot at text[start] covers the raw 'data' span, else 'content_sha256'."""
    doc, _ = _DEC.raw_decode(text, start)
    a, b = members(text, start)["data"]
    return None if hashlib.sha256(text[a:b].encode("utf-8")).hexdigest() == doc["content_sha256"] else "content_sha256"


def envelopes(target, text):
    """(JSON pointer, start) of every signed command envelope inside an example."""
    start = _ws(text, 0)
    if target == "fleet-command.schema.json" or target.endswith("#/$defs/envelope"):
        return [("", start)]
    if target.endswith("#/$defs/poll_response"):
        a, _ = members(text, start)["commands"]
        return [(f"/commands/{n}", s) for n, (s, _) in enumerate(elements(text, a))]
    return []


def hashed(target, text):
    """(JSON pointer, checker, start) of every raw-byte hash inside an example."""
    out = [(ptr, envelope_problem, s) for ptr, s in envelopes(target, text)]
    if target == "fleet-state.schema.json":
        out.append(("", snapshot_problem, _ws(text, 0)))
    return out


def checkable(inst, ptr, checker):
    """Whether the value at ptr is complete enough to recompute its hash (used for the one-defect rule)."""
    for part in filter(None, ptr.split("/")):
        try:
            inst = inst[int(part)] if isinstance(inst, list) else inst[part]
        except (KeyError, IndexError, ValueError, TypeError):
            return False
    if not isinstance(inst, dict):
        return False
    if checker is snapshot_problem:
        return isinstance(inst.get("data"), dict) and isinstance(inst.get("content_sha256"), str)
    return "payload" in inst and all(isinstance(inst.get(k), str) for k in SIGNED_FIELDS + ("signature",))


def second_defect(target, text, inst):
    """For an invalid case that already fails on the schema: a hash/signature that ALSO fails, if any."""
    try:
        for ptr, checker, start in hashed(target, text):
            if checkable(inst, ptr, checker) and checker(text, start):
                return f"{checker(text, start)} mismatch at '{ptr}'"
    except (KeyError, IndexError, ValueError, TypeError):
        return None
    return None


def adr_anchor(task_start_text):
    """Re-derive the ADR-0011 worked example byte for byte; return a list of drifts."""
    try:
        adr = ADR.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"ADR-0011 not readable ({exc})"]
    found = {
        "envelope": re.search(r'^(\{"schema_version":"1\.0\.0","command_id":[^\n]*\})$', adr, re.M),
        "canonical": re.search(r"^```\n(" + re.escape(DOMAIN) + r"\n(?:[a-z_0-9]+=[0-9]+:[^\n]*\n)+)```", adr, re.M),
        "sha256": re.search(r"Bytes assinados \(`sha256` = `([0-9a-f]{64})`\)", adr),
        "bytes": re.search(r"sha256 dos ([0-9]+) bytes", adr),
        "pubkey": re.search(r"pubkey `([A-Za-z0-9+/=]+)`", adr),
        "pin": re.search(r"pin `(sha256:[0-9a-f]{64})`", adr),
    }
    missing = [k for k, m in found.items() if not m]
    if missing:
        return [f"ADR-0011 worked example: could not find {', '.join(missing)}"]
    env_text = found["envelope"].group(1)
    env, drifts = parse(env_text), []
    a, b = members(env_text, 0)["payload"]
    if canonical(env) != found["canonical"].group(1).encode("utf-8"):
        drifts.append("canonical form differs from the ADR's 'Bytes assinados' block")
    if hashlib.sha256(canonical(env)).hexdigest() != found["sha256"].group(1):
        drifts.append("canonical sha256 differs from the ADR")
    if len(env_text[a:b].encode("utf-8")) != int(found["bytes"].group(1)):
        drifts.append(f"payload is {len(env_text[a:b].encode('utf-8'))} bytes, the ADR says {found['bytes'].group(1)}")
    if envelope_problem(env_text, 0):
        drifts.append(f"ADR envelope fails: {envelope_problem(env_text, 0)}")
    if base64.b64encode(TEST_SPKI).decode() != found["pubkey"].group(1):
        drifts.append("golden test pubkey (SPKI base64) differs from the ADR")
    if "sha256:" + hashlib.sha256(TEST_SPKI).hexdigest() != found["pin"].group(1):
        drifts.append("golden test key pin differs from the ADR")
    if task_start_text is None or task_start_text.strip() != env_text:
        drifts.append("valid/command/task-start.json is not the ADR envelope verbatim")
    return [f"ADR-0011 worked example: {d}" for d in drifts]


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def target_of(rel):
    _, schema, name = rel.split("/")
    stem = name[: -len(".json")]
    base = f"fleet-{schema}.schema.json"
    return f"{base}#/$defs/{stem.split('--', 1)[0]}" if "--" in stem else base


def flat_errors(errors):
    for e in errors:
        yield e.validator, "".join("/" + str(p) for p in e.absolute_path)
        yield from flat_errors(e.context or ())


def offline(uri):
    raise NoSuchResource(ref=uri)  # only the six local schemas may resolve


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    surprises = []
    schemas = {n: load_json(SCHEMA_DIR / f"fleet-{n}.schema.json") for n in SCHEMAS}
    for s in schemas.values():
        Draft202012Validator.check_schema(s)
    registry = Registry(retrieve=offline).with_resources(
        [(s["$id"], Resource.from_contents(s)) for s in schemas.values()]
    )
    validators = {}

    def validator(target):
        if target not in validators:
            validators[target] = Draft202012Validator(
                {"$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": BASE + target},
                registry=registry,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )
        return validators[target]

    def valid_against(target, inst):
        return not any(True for _ in validator(target).iter_errors(inst))

    # index.json <-> files on disk
    index = load_json(EXAMPLES / "index.json")
    cases = {c["file"]: c for c in index["cases"]}
    on_disk = set()
    for p in sorted(EXAMPLES.rglob("*")):
        if p.is_file() and p != EXAMPLES / "index.json":
            rel = p.relative_to(EXAMPLES).as_posix()
            on_disk.add(rel)
            if not CASE_RE.match(rel):
                surprises.append(f"{rel}: path does not follow valid|invalid/<schema>/<case>.json")
    for rel in sorted(on_disk - set(cases)):
        surprises.append(f"{rel}: file not listed in index.json")
    for rel in sorted(set(cases) - on_disk):
        surprises.append(f"{rel}: listed in index.json but missing")

    alternatives = {n: [r["$ref"].rsplit("/", 1)[-1] for r in schemas[n].get("oneOf", [])] for n in SCHEMAS}
    seen = {n: set() for n in SCHEMAS}
    tally = {n: {"valid": [0, 0], "invalid": [0, 0]} for n in SCHEMAS}
    signed_ok = snapshots_ok = 0
    task_start_text = None

    for rel in sorted(set(cases) & on_disk):
        if not CASE_RE.match(rel):
            continue
        kind, schema, _ = rel.split("/")
        case, target = cases[rel], target_of(rel)
        if case.get("target") != target:
            surprises.append(f"{rel}: index target {case.get('target')!r} != {target!r} (naming rule)")
            continue
        tally[schema][kind][1] += 1
        try:
            text = (EXAMPLES / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            surprises.append(f"{rel}: unreadable ({exc})")
            continue
        if rel == "valid/command/task-start.json":
            task_start_text = text
        failure = None  # first failure, as an expectation-shaped dict
        try:
            inst = parse(text)
        except DuplicateKey as exc:
            failure = {"check": "duplicate_key", "path": "", "detail": f"duplicate key {exc}"}
        except ValueError as exc:
            failure = {"check": "json_syntax", "path": "", "detail": f"not one well-formed JSON value ({exc})"}
        errors = []
        if failure is None:
            try:
                errors = list(validator(target).iter_errors(inst))
            except Unresolvable as exc:
                surprises.append(f"{rel}: unresolvable $ref with the offline registry (nothing fetched): {exc}")
                continue
        if failure is None and not errors:
            for ptr, checker, start in hashed(target, text):
                problem = checker(text, start)
                if problem:
                    failure = {"check": problem, "path": ptr, "detail": f"{problem} mismatch at '{ptr}'"}
                    break
        if kind == "valid":
            if failure:
                surprises.append(f"{rel}: expected VALID, got {failure['detail']}")
            elif errors:
                surprises.append(f"{rel}: expected VALID, got: {errors[0].message[:160]}")
            else:
                tally[schema]["valid"][0] += 1
                signed_ok += len(envelopes(target, text))
                snapshots_ok += target == "fleet-state.schema.json"
                root = "#" not in target
                if schema == "command" and root:
                    seen[schema].add(inst["type"])
                elif schema == "state" and root:
                    seen[schema].add(inst["kind"])
                elif schema == "event" and root:
                    seen[schema].update(e["type"] for e in inst["events"])
                elif schema == "result" and root and inst["status"] == "succeeded":
                    seen[schema].add(inst["type"])
                elif alternatives[schema]:
                    if root:
                        seen[schema].update(a for a in alternatives[schema]
                                            if valid_against(f"fleet-{schema}.schema.json#/$defs/{a}", inst))
                    else:
                        seen[schema].add(target.rsplit("/", 1)[-1])
            continue
        expect = case.get("expect") or {}
        if failure:
            if (expect.get("check"), expect.get("path")) == (failure["check"], failure["path"]):
                tally[schema]["invalid"][0] += 1
            else:
                surprises.append(f"{rel}: fails with {failure['detail']}, but expect is {expect}")
        elif not errors:
            surprises.append(f"{rel}: expected INVALID, but it validates (schema and raw-byte hashes)")
        elif (expect.get("keyword"), expect.get("path")) in set(flat_errors(errors)):
            extra = second_defect(target, text, inst)
            if extra:
                surprises.append(f"{rel}: fails as expected, but carries a second defect ({extra}): one defect per case")
            else:
                tally[schema]["invalid"][0] += 1
        else:
            got = sorted(set(flat_errors(errors)))[:5]
            surprises.append(f"{rel}: fails, but not with {expect or 'an expect entry'}; got {got}")

    surprises.extend(adr_anchor(task_start_text))

    required = {
        "command": schemas["command"]["$defs"]["command_type"]["enum"],
        "state": schemas["state"]["$defs"]["state_kind"]["enum"],
        "event": schemas["event"]["$defs"]["event_type"]["enum"],
        "result": schemas["command"]["$defs"]["command_type"]["enum"],
        "enroll": alternatives["enroll"],
        "heartbeat": alternatives["heartbeat"],
    }
    label = {"command": "command types", "state": "state kinds", "event": "event types",
             "result": "succeeded result types", "enroll": "enroll messages", "heartbeat": "heartbeat messages"}
    coverage = []
    for n in SCHEMAS:
        if tally[n]["valid"][0] == 0:
            surprises.append(f"fleet-{n}.schema.json has zero valid examples")
        missing = [v for v in required[n] if v not in seen[n]]
        if missing:
            surprises.append(f"fleet-{n}.schema.json: no valid example for {', '.join(missing)}")
        coverage.append(f"{label[n]} {len(required[n]) - len(missing)}/{len(required[n])}")

    print(f"{'schema':<10} {'valid':>9} {'invalid':>9}")
    totals = [0, 0, 0, 0]
    for n in SCHEMAS:
        v, i = tally[n]["valid"], tally[n]["invalid"]
        totals = [totals[0] + v[0], totals[1] + v[1], totals[2] + i[0], totals[3] + i[1]]
        print(f"{n:<10} {v[0]:>4}/{v[1]:<4} {i[0]:>4}/{i[1]:<4}")
    print(f"{'TOTAL':<10} {totals[0]:>4}/{totals[1]:<4} {totals[2]:>4}/{totals[3]:<4}")
    print("coverage: " + "; ".join(coverage))
    print(f"signed envelopes verified (payload sha256 + Ed25519, golden test key): {signed_ok}")
    print(f"state snapshots verified (content_sha256 over the raw data span): {snapshots_ok}")
    print(f"jsonschema {version('jsonschema')}, referencing {version('referencing')}, "
          f"cryptography {version('cryptography')}, offline registry")
    if surprises:
        print(f"\nFAIL: {len(surprises)} surprise(s)")
        for s in surprises:
            print("  - " + s)
        return 1
    print("OK: valid examples validate (signed envelopes and state hashes verify), invalid ones fail for the"
          " expected reason only, and the ADR-0011 worked example is reproduced byte for byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
