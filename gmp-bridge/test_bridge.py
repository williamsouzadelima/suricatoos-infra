"""Unit tests for the GMP bridge — no live gvmd required."""

import json
import unittest
from xml.etree import ElementTree as ET

from bridge import NVTMeta, fetch_nvt_meta, finding_report_to_xml, severity_to_threat

# OIDs of the two SAMPLE_REPORT findings, for building nvt_meta in tests.
OID_0 = "1.3.6.1.4.1.25623.1.1.1.1.2023.5418"
OID_1 = "1.3.6.1.4.1.25623.1.1.1.2.2024.3001"


SAMPLE_REPORT = {
    "schema_version": "1.0.0",
    "agent_id": "test-agent-abc",
    "host": "10.0.0.42",
    "collected_at": "2026-06-28T00:00:00Z",
    "findings": [
        {
            "oid": "1.3.6.1.4.1.25623.1.1.1.1.2023.5418",
            "cve": ["CVE-2023-5218", "CVE-2023-5487"],
            "severity": 9.8,
            "severity_origin": "feed-vt-metadata",
            "package_observed": "chromium-113.0.5672.126-1~deb12u1.amd64",
            "package_fixed": "chromium-114.0.5735.90-2~deb12u1",
            "specifier": ">=",
            "product": "Debian 12",
            "evidence": {
                "source": "dpkg",
                "matched_advisory": "debian_12.notus",
            },
            "detected_at": "2026-06-28T00:00:00Z",
        },
        {
            "oid": "1.3.6.1.4.1.25623.1.1.1.2.2024.3001",
            "severity": 0.0,
            "package_observed": "openssh-client-1:8.4p1-2+deb12u2.amd64",
            "package_fixed": "openssh-client-1:8.4p1-2+deb12u3",
            "specifier": ">=",
            "product": "Debian 12",
            "evidence": {
                "source": "dpkg",
                "matched_advisory": "debian_12.notus",
            },
            "detected_at": "2026-06-28T00:00:00Z",
        },
    ],
}


class TestFindingReportToXML(unittest.TestCase):
    def _parse(self):
        xml = finding_report_to_xml(SAMPLE_REPORT)
        return ET.fromstring(xml), xml

    def _parse_with_meta(self, meta):
        xml = finding_report_to_xml(SAMPLE_REPORT, nvt_meta=meta)
        return ET.fromstring(xml), xml

    def test_root_is_report(self):
        root, _ = self._parse()
        self.assertEqual(root.tag, "report")

    def test_report_has_id(self):
        root, _ = self._parse()
        self.assertTrue(root.get("id"), "report must have an id attribute")

    def test_results_count(self):
        root, _ = self._parse()
        results = root.findall("results/result")
        self.assertEqual(len(results), 2)

    def test_finding_oid(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        nvt = result.find("nvt")
        self.assertIsNotNone(nvt)
        self.assertEqual(nvt.get("oid"), "1.3.6.1.4.1.25623.1.1.1.1.2023.5418")

    def test_finding_host_is_text(self):
        # GMP result host: IP is the TEXT of <host>, not a <host><ip> child.
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        host = result.find("host")
        self.assertIsNotNone(host)
        self.assertEqual((host.text or "").strip(), "10.0.0.42")
        self.assertIsNone(host.find("ip"), "must not use a <host><ip> child")

    def test_no_feed_meta_is_log_no_severity_fabrication(self):
        # Without feed evidence, severity must be 0.0/Log even though the
        # finding carries a client-supplied severity of 9.8 (non-fabrication).
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        self.assertEqual(float(result.find("severity").text), 0.0)
        self.assertEqual(result.find("threat").text, "Log")

    def test_no_feed_meta_drops_client_cves(self):
        # The client-supplied CVE list must NOT be emitted as feed-attested refs.
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        cves = [r.get("id") for r in result.findall("nvt/refs/ref") if r.get("type") == "cve"]
        self.assertEqual(cves, [], "client CVEs must not appear without feed evidence")

    def test_feed_enrichment_wins(self):
        # With feed metadata, the feed score and CVEs win over client values.
        meta = {OID_0: NVTMeta(6.1, ["CVE-2023-0001"])}
        root, _ = self._parse_with_meta(meta)
        result = root.findall("results/result")[0]
        self.assertEqual(float(result.find("severity").text), 6.1)
        self.assertEqual(result.find("threat").text, "Medium")
        cves = [r.get("id") for r in result.findall("nvt/refs/ref") if r.get("type") == "cve"]
        self.assertEqual(cves, ["CVE-2023-0001"])

    def test_feed_zero_score_keeps_feed_cves(self):
        # An unscored-but-known VT (cvss 0.0) is Log, yet its real feed CVEs are
        # preserved — CVE provenance is decoupled from the numeric score.
        meta = {OID_0: NVTMeta(0.0, ["CVE-FEED-REAL"])}
        root, _ = self._parse_with_meta(meta)
        result = root.findall("results/result")[0]
        self.assertEqual(result.find("threat").text, "Log")
        cves = [r.get("id") for r in result.findall("nvt/refs/ref") if r.get("type") == "cve"]
        self.assertEqual(cves, ["CVE-FEED-REAL"])

    def test_no_feed_evidence_none_value(self):
        # An OID explicitly mapped to None (lookup failed) yields Log, no CVEs.
        meta = {OID_0: None}
        root, _ = self._parse_with_meta(meta)
        result = root.findall("results/result")[0]
        self.assertEqual(result.find("threat").text, "Log")
        cves = [r.get("id") for r in result.findall("nvt/refs/ref") if r.get("type") == "cve"]
        self.assertEqual(cves, [])

    def test_qod_package(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        qod_type = result.find("qod/type")
        self.assertIsNotNone(qod_type)
        self.assertEqual(qod_type.text, "package")

    def test_description_contains_evidence(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        desc = result.find("description")
        self.assertIsNotNone(desc)
        self.assertIn("debian_12.notus", desc.text)
        self.assertIn("dpkg", desc.text)

    def test_empty_findings(self):
        empty = {**SAMPLE_REPORT, "findings": []}
        xml = finding_report_to_xml(empty)
        root = ET.fromstring(xml)
        results = root.findall("results/result")
        self.assertEqual(len(results), 0)

    def test_unique_result_ids(self):
        root, _ = self._parse()
        ids = [r.get("id") for r in root.findall("results/result")]
        self.assertEqual(len(ids), len(set(ids)), "result ids must be unique")


class TestSeverityToThreat(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(severity_to_threat(9.0), "Critical")
        self.assertEqual(severity_to_threat(10.0), "Critical")

    def test_high(self):
        self.assertEqual(severity_to_threat(7.0), "High")
        self.assertEqual(severity_to_threat(8.9), "High")

    def test_medium(self):
        self.assertEqual(severity_to_threat(4.0), "Medium")
        self.assertEqual(severity_to_threat(6.9), "Medium")

    def test_low(self):
        self.assertEqual(severity_to_threat(0.1), "Low")
        self.assertEqual(severity_to_threat(3.9), "Low")

    def test_log(self):
        self.assertEqual(severity_to_threat(0.0), "Log")


class FakeGmp:
    """Minimal gmp stub: returns a canned XML envelope for send_command."""

    def __init__(self, response: str):
        self._response = response

    def send_command(self, _cmd: str) -> str:
        return self._response


class TestFetchNvtMeta(unittest.TestCase):
    def test_success_with_cvss_and_cves(self):
        resp = (
            '<get_nvts_response status="200" status_text="OK">'
            '<nvt oid="1.2.3"><cvss_base>7.5</cvss_base>'
            '<refs><ref type="cve" id="CVE-2024-1"/><ref type="cve" id="CVE-2024-1"/>'
            '<ref type="cve" id="CVE-2024-2"/><ref type="url" id="http://x"/></refs>'
            "</nvt></get_nvts_response>"
        )
        meta = fetch_nvt_meta(FakeGmp(resp), "1.2.3")
        self.assertIsNotNone(meta)
        self.assertEqual(meta.cvss_base, 7.5)
        self.assertEqual(meta.cves, ["CVE-2024-1", "CVE-2024-2"])  # deduped, url ignored

    def test_found_but_unscored_is_not_none(self):
        # cvss 0.0 with real CVEs: a known-but-unscored VT, NOT "no evidence".
        resp = (
            '<get_nvts_response status="200">'
            '<nvt oid="1.2.3"><cvss_base>0.0</cvss_base>'
            '<refs><ref type="cve" id="CVE-2024-9"/></refs></nvt>'
            "</get_nvts_response>"
        )
        meta = fetch_nvt_meta(FakeGmp(resp), "1.2.3")
        self.assertIsNotNone(meta)
        self.assertEqual(meta.cvss_base, 0.0)
        self.assertEqual(meta.cves, ["CVE-2024-9"])

    def test_oid_absent_is_none(self):
        resp = '<get_nvts_response status="200" status_text="OK"></get_nvts_response>'
        self.assertIsNone(fetch_nvt_meta(FakeGmp(resp), "1.2.3"))

    def test_error_status_is_none(self):
        # 404 (OID rejected) and 401 (auth) both mean "no feed evidence", not 0.0.
        for status in ("404", "401", "400"):
            resp = f'<get_nvts_response status="{status}" status_text="fail"/>'
            self.assertIsNone(fetch_nvt_meta(FakeGmp(resp), "1.2.3"), f"status {status}")


if __name__ == "__main__":
    unittest.main()
