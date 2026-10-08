"""Unit tests for the MSRC CSAF mirror. Pure/stdlib; a fake fetch stands in for
HTTP so the tests never touch the network."""
import json
import os

import msrc_feed as m


def test_advisories_dir_url():
    meta = json.dumps({"distributions": [
        {"directory_url": "https://msrc.microsoft.com/csaf/vex"},
        {"directory_url": "https://msrc.microsoft.com/csaf/advisories/"},
    ]}).encode()
    assert m.advisories_dir_url(meta) == "https://msrc.microsoft.com/csaf/advisories"
    assert m.advisories_dir_url(json.dumps({"distributions": []}).encode()) == ""


def test_parse_changes_csv():
    text = "2024/msrc_cve-2024-38063.json,2024-08-13T07:00:00.000Z\nbad-line\n2025/x.json,2025-01-14T08:00:00.000Z\n"
    rows = m.parse_changes_csv(text)
    assert rows == [
        ("2024/msrc_cve-2024-38063.json", "2024-08-13T07:00:00.000Z"),
        ("2025/x.json", "2025-01-14T08:00:00.000Z"),
    ]


def test_safe_relpath_accepts_and_rejects():
    assert m.safe_relpath("2024/msrc_cve-2024-38063.json") == "2024/msrc_cve-2024-38063.json"
    assert m.safe_relpath("/2024/x.json") == "2024/x.json"  # leading slash stripped, still safe
    for bad in [
        "../etc/passwd.json",      # traversal
        "2024/../../etc/x.json",   # traversal mid-path
        "C:/windows/x.json",       # drive letter (':')
        "http://evil/x.json",      # scheme (':')
        "2024/report.txt",         # not json
        "",                        # empty
        "2024//x.json",            # empty segment
        "2024/./x.json",           # dot segment
    ]:
        assert m.safe_relpath(bad) is None, bad


def test_select_updates_year_bound_and_cursor():
    changes = [
        ("2014/old.json", "2014-01-01T00:00:00Z"),            # below year bound → drop
        ("2024/a.json", "2024-08-13T07:00:00.000Z"),          # keep (newer than cursor)
        ("2024/b.json", "2024-05-01T00:00:00.000Z"),          # == cursor → drop
        ("2025/c.json", "2025-02-01T00:00:00.000Z"),          # keep
        ("../evil.json", "2025-09-09T00:00:00Z"),             # unsafe → drop
    ]
    got = m.select_updates(changes, cursor_iso="2024-05-01T00:00:00.000Z", since_year=2016)
    rels = sorted(r for r, _ in got)
    assert rels == ["2024/a.json", "2025/c.json"]
    # empty cursor = full sync (still year/safety bounded)
    full = sorted(r for r, _ in m.select_updates(changes, "", 2016))
    assert full == ["2024/a.json", "2024/b.json", "2025/c.json"]


def test_write_atomic_nested(tmp_path):
    base = str(tmp_path)
    m.write_atomic(base, "2024/sub/x.json", b'{"ok":true}')
    dest = os.path.join(base, "2024", "sub", "x.json")
    assert open(dest, "rb").read() == b'{"ok":true}'
    assert not os.path.exists(dest + ".tmp")  # temp swapped away


def _fake_feed(docs, cursor_docs=None, raise_for=None):
    """Build a fake fetch over a provider-metadata + changes.csv + docs map."""
    base = "https://msrc.microsoft.com/csaf/advisories"
    meta = json.dumps({"distributions": [{"directory_url": base}]}).encode()
    changes_lines = "".join("%s,%s\n" % (rel, ts) for rel, ts in docs)
    store = {m.PROVIDER_METADATA_URL: meta, base + "/changes.csv": changes_lines.encode()}
    for rel, _ in docs:
        store[base + "/" + rel] = ('{"doc":"%s"}' % rel).encode()

    def fetch(url, timeout=60):
        if raise_for and url.endswith(raise_for):
            raise RuntimeError("boom")
        return store[url]

    return fetch


def test_sync_msrc_full_then_incremental(tmp_path):
    base_dir = str(tmp_path)
    docs = [
        ("2024/msrc_cve-2024-38063.json", "2024-08-13T07:00:00.000Z"),
        ("2025/msrc_cve-2025-21385.json", "2025-01-14T08:00:00.000Z"),
        ("../evil.json", "2025-09-09T00:00:00Z"),  # must be refused by the safety guard
    ]
    fetch = _fake_feed(docs)
    r1 = m.sync_msrc(base_dir, cursor_iso="", since_year=2016, fetch=fetch)
    assert r1["ok"] and r1["downloaded"] == 2, r1
    assert r1["cursor"] == "2025-01-14T08:00:00.000Z"
    assert os.path.exists(os.path.join(base_dir, "2024", "msrc_cve-2024-38063.json"))
    assert not os.path.exists(os.path.join(base_dir, "evil.json"))

    # second run from the stored cursor: nothing new → 0 downloads
    r2 = m.sync_msrc(base_dir, cursor_iso=r1["cursor"], since_year=2016, fetch=fetch)
    assert r2["downloaded"] == 0 and r2["total_candidates"] == 0, r2

    # a newer advisory appears → only that one is fetched
    docs2 = docs + [("2025/msrc_cve-2025-99999.json", "2025-03-01T00:00:00.000Z")]
    r3 = m.sync_msrc(base_dir, cursor_iso=r1["cursor"], since_year=2016, fetch=_fake_feed(docs2))
    assert r3["downloaded"] == 1 and r3["cursor"] == "2025-03-01T00:00:00.000Z", r3


def test_sync_msrc_counts_errors_without_aborting(tmp_path):
    docs = [
        ("2024/a.json", "2024-08-13T07:00:00.000Z"),
        ("2024/b.json", "2024-08-14T07:00:00.000Z"),
    ]
    fetch = _fake_feed(docs, raise_for="2024/a.json")
    r = m.sync_msrc(str(tmp_path), cursor_iso="", since_year=2016, fetch=fetch)
    assert r["errors"] == 1 and r["downloaded"] == 1 and not r["ok"], r
    # the good one still landed
    assert os.path.exists(os.path.join(str(tmp_path), "2024", "b.json"))


def test_sync_msrc_missing_advisories_url():
    def fetch(url, timeout=60):
        return json.dumps({"distributions": []}).encode()

    r = m.sync_msrc("/tmp/whatever", fetch=fetch)
    assert not r["ok"] and r["downloaded"] == 0
