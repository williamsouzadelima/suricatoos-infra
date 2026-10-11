#!/usr/bin/env python3
"""Contract test for the ADR-0011 fleet schemas (schema/fleet-*.schema.json).

Validates every example under schema/examples/fleet/ against the schema, or the
$defs entry, it targets, OFFLINE: the six schemas are loaded from disk into a
`referencing` registry keyed by their $id; any other reference raises instead of
being fetched over the network.

  valid/<schema>/<case>.json    must validate
  invalid/<schema>/<case>.json  must fail with an error whose JSON Schema keyword and
                                instance path (JSON pointer) match the case's
                                "expect" in fleet/index.json

A case named '<def>--<rest>.json' targets fleet-<schema>.schema.json#/$defs/<def>;
any other case targets the schema root.

It also fails when a file and index.json disagree, a target breaks the naming rule,
a schema has zero valid examples, or a catalog value (command type, state kind,
event type, result type, enroll/heartbeat message) has no valid example.

Usage:    python3 schema/examples/validate_fleet_examples.py   (exit 0 = contract holds)
Requires: jsonschema >= 4.18 (it ships `referencing`).
"""
import json
import re
import sys
from importlib.metadata import version
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

HERE = Path(__file__).resolve().parent
SCHEMA_DIR = HERE.parent
EXAMPLES = HERE / "fleet"
BASE = "https://suricatoos.dev/schema/"
SCHEMAS = ("command", "enroll", "heartbeat", "state", "event", "result")
CASE_RE = re.compile(r"^(valid|invalid)/(%s)/(?:[a-z][a-z_]*--)?[a-z0-9]+(?:-[a-z0-9]+)*\.json$" % "|".join(SCHEMAS))


def offline(uri):
    raise NoSuchResource(ref=uri)  # only the six local schemas may resolve


def load(path):
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


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    surprises = []
    schemas = {n: load(SCHEMA_DIR / f"fleet-{n}.schema.json") for n in SCHEMAS}
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
    index = load(EXAMPLES / "index.json")
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

    # roots whose oneOf alternatives must each be exercised by a valid example
    alternatives = {n: [r["$ref"].rsplit("/", 1)[-1] for r in schemas[n].get("oneOf", [])] for n in SCHEMAS}
    seen = {n: set() for n in SCHEMAS}
    tally = {n: {"valid": [0, 0], "invalid": [0, 0]} for n in SCHEMAS}

    for rel in sorted(set(cases) & on_disk):
        if not CASE_RE.match(rel):
            continue
        kind, schema, _ = rel.split("/")
        case, target = cases[rel], target_of(rel)
        if case.get("target") != target:
            surprises.append(f"{rel}: index target {case.get('target')!r} != {target!r} (naming rule)")
            continue
        try:
            inst = load(EXAMPLES / rel)
        except (OSError, ValueError) as exc:
            surprises.append(f"{rel}: unreadable JSON ({exc})")
            continue
        tally[schema][kind][1] += 1
        try:
            errors = list(validator(target).iter_errors(inst))
        except Unresolvable as exc:
            surprises.append(f"{rel}: unresolvable $ref with the offline registry (nothing fetched): {exc}")
            continue
        if kind == "valid":
            if errors:
                surprises.append(f"{rel}: expected VALID, got: {errors[0].message[:160]}")
                continue
            tally[schema]["valid"][0] += 1
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
        else:
            expect = case.get("expect") or {}
            if not errors:
                surprises.append(f"{rel}: expected INVALID, but it validates")
            elif (expect.get("keyword"), expect.get("path")) not in set(flat_errors(errors)):
                got = sorted(set(flat_errors(errors)))[:5]
                surprises.append(f"{rel}: fails, but not with {expect or 'an expect entry'}; got {got}")
            else:
                tally[schema]["invalid"][0] += 1

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
    print(f"jsonschema {version('jsonschema')}, referencing {version('referencing')}, offline registry")
    if surprises:
        print(f"\nFAIL: {len(surprises)} surprise(s)")
        for s in surprises:
            print("  - " + s)
        return 1
    print("OK: every valid example validates and every invalid one fails for the expected reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
