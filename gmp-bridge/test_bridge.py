"""Unit tests for the GMP bridge — no live gvmd required."""

import json
import unittest
from xml.etree import ElementTree as ET

from bridge import finding_report_to_xml, severity_to_threat


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

    def test_finding_host(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        host = result.find("host/ip")
        self.assertIsNotNone(host)
        self.assertEqual(host.text, "10.0.0.42")

    def test_finding_cve_refs(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        refs = result.findall("nvt/refs/ref")
        cves = [r.get("id") for r in refs if r.get("type") == "cve"]
        self.assertIn("CVE-2023-5218", cves)
        self.assertIn("CVE-2023-5487", cves)

    def test_finding_severity(self):
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        severity = result.find("severity")
        self.assertIsNotNone(severity)
        self.assertEqual(float(severity.text), 9.8)
        threat = result.find("threat")
        self.assertEqual(threat.text, "Critical")

    def test_zero_severity_is_log(self):
        root, _ = self._parse()
        result = root.findall("results/result")[1]
        threat = result.find("threat")
        self.assertEqual(threat.text, "Log")

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


if __name__ == "__main__":
    unittest.main()
