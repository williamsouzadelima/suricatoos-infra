#!/usr/bin/env python3
"""MSRC CSAF mirror for the Suricatoos feed-updater.

Mirrors Microsoft's CSAF 2.0 advisories (https://msrc.microsoft.com/csaf/advisories)
into a local directory that the server-side MSRC correlator reads (ADR-0008).
HTTP + Python stdlib only (the feed-updater image has no pip). The mirror is
INCREMENTAL via the CSAF directory distribution's changes.csv cursor, so after
the first full sync only newly-changed advisories are fetched.

Dark by default (MSRC_FEED_ENABLED off); the correlator is wired to this mirror
in Fase 0c-3. Nothing here judges severity or invents data — it only mirrors the
authoritative Microsoft feed verbatim.
"""
import csv
import io
import json
import os
import urllib.request

PROVIDER_METADATA_URL = 'https://msrc.microsoft.com/csaf/provider-metadata.json'
DEFAULT_SINCE_YEAR = 2016  # Windows 10 cumulative-update era; older CVEs are pre-UBR


def http_get(url, timeout=60):
    """Fetch url and return the raw bytes. Isolated so tests inject a fake."""
    req = urllib.request.Request(url, headers={'User-Agent': 'suricatoos-feed-updater'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed MSRC host
        return resp.read()


def advisories_dir_url(provider_metadata_bytes):
    """Return the advisories directory_url from a CSAF provider-metadata.json."""
    meta = json.loads(provider_metadata_bytes)
    for dist in meta.get('distributions', []):
        url = str(dist.get('directory_url', '')).rstrip('/')
        if url.endswith('/advisories'):
            return url
    return ''


def parse_changes_csv(text):
    """Parse a CSAF changes.csv (rows: "<relative_path>,<ISO8601 timestamp>").

    Returns a list of (path, timestamp) tuples; malformed rows are skipped.
    """
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        path, ts = row[0].strip(), row[1].strip()
        if path and ts:
            out.append((path, ts))
    return out


def safe_relpath(path):
    """Return a normalized relative path safe to write under the mirror, or None.

    The index comes from a remote server, so a path MUST be relative, free of
    '..' traversal, free of a drive/scheme (':'), and end in .json. This is the
    guard that keeps a hostile or buggy index from writing outside the mirror.
    """
    p = path.strip().replace('\\', '/').lstrip('/')
    if not p or ':' in p:
        return None
    parts = p.split('/')
    if any(seg in ('', '.', '..') for seg in parts):
        return None
    if not p.lower().endswith('.json'):
        return None
    return '/'.join(parts)


def _year_ok(rel, since_year):
    """Keep paths whose leading directory is a year >= since_year. A non-year
    leading segment is kept (we never silently drop an unknown layout)."""
    if not since_year:
        return True
    head = rel.split('/', 1)[0]
    if head.isdigit():
        return int(head) >= since_year
    return True


def select_updates(changes, cursor_iso, since_year):
    """Select the (rel_path, ts) to (re)download: safe path, within the year
    bound, and strictly newer than cursor_iso (empty cursor = full sync).

    Timestamps are compared lexicographically, which is correct for the
    zero-padded ISO-8601 form MSRC emits (e.g. 2024-08-13T07:00:00.000Z).
    """
    out = []
    for path, ts in changes:
        rel = safe_relpath(path)
        if rel is None:
            continue
        if not _year_ok(rel, since_year):
            continue
        if cursor_iso and ts <= cursor_iso:
            continue
        out.append((rel, ts))
    return out


def write_atomic(base_dir, rel, data):
    """Write data to base_dir/rel atomically (temp + os.replace)."""
    dest = os.path.join(base_dir, *rel.split('/'))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.replace(tmp, dest)


def sync_msrc(msrc_dir, cursor_iso='', since_year=DEFAULT_SINCE_YEAR, fetch=http_get):
    """Mirror the changed CSAF advisories into msrc_dir.

    Returns a status dict: ok, downloaded, errors, total_candidates, cursor
    (the new max timestamp to persist for the next incremental run). A single
    document that fails to download increments errors but never aborts the run.
    """
    meta = fetch(PROVIDER_METADATA_URL)
    base = advisories_dir_url(meta)
    if not base:
        return {'ok': False, 'error': 'advisories directory_url ausente',
                'downloaded': 0, 'errors': 0, 'total_candidates': 0, 'cursor': cursor_iso}
    changes = parse_changes_csv(fetch(base + '/changes.csv').decode('utf-8', 'replace'))
    todo = select_updates(changes, cursor_iso, since_year)
    downloaded, errors, max_ts = 0, 0, cursor_iso
    for rel, ts in todo:
        try:
            data = fetch(base + '/' + rel)
            write_atomic(msrc_dir, rel, data)
            downloaded += 1
            if ts > max_ts:
                max_ts = ts
        except Exception:
            errors += 1
    return {'ok': errors == 0, 'downloaded': downloaded, 'errors': errors,
            'total_candidates': len(todo), 'cursor': max_ts}
