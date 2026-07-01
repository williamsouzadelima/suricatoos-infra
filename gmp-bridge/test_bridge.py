"""Unit tests for the GMP bridge — no live gvmd required."""

import json
import unittest
from xml.etree import ElementTree as ET

from bridge import (
    NVTMeta,
    _find_task_id,
    fetch_nvt_meta,
    finding_report_to_xml,
    provision_cve_task,
    safe_host_id,
    severity_to_threat,
    valid_scan_time,
)

# finding_report_to_xml now keys the host identity on the UNIQUE agent_id, not
# the (collision-prone) OS hostname. SAMPLE_REPORT.agent_id is the expected host.
AGENT = "test-agent-abc"

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
        # GMP result host: identity is the TEXT of <host> (= agent_id), not a child.
        root, _ = self._parse()
        result = root.findall("results/result")[0]
        host = result.find("host")
        self.assertIsNotNone(host)
        self.assertEqual((host.text or "").strip(), AGENT)
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

    def test_report_level_host_block(self):
        # A report-level <host><ip>…</ip><start/><end/></host> registers the host
        # so the imported report is host-attributed (host_count) and an asset is
        # created; <scan_start>/<scan_end> frame the scan. Verified against gvmd.
        root, _ = self._parse()
        host = root.find("host")
        self.assertIsNotNone(host, "report must carry a report-level <host> block")
        self.assertEqual(host.findtext("ip"), AGENT)
        self.assertEqual(host.findtext("start"), "2026-06-28T00:00:00Z")
        self.assertEqual(host.findtext("end"), "2026-06-28T00:00:00Z")
        self.assertEqual(root.findtext("scan_start"), "2026-06-28T00:00:00Z")
        self.assertEqual(root.findtext("scan_end"), "2026-06-28T00:00:00Z")

    def test_report_host_ip_matches_result_host(self):
        # The report-level <host><ip> must byte-match each result's <host> text,
        # else gvmd will not associate the results with the host.
        root, _ = self._parse()
        report_ip = root.find("host/ip").text
        for result in root.findall("results/result"):
            self.assertEqual((result.find("host").text or "").strip(), report_ip)

    def test_empty_findings_emits_inventory_marker(self):
        # With no Notus findings, a single Log-severity "inventory" result anchors
        # the host so gvmd still registers it (and its CPE host-details).
        empty = {**SAMPLE_REPORT, "findings": []}
        xml = finding_report_to_xml(empty, cpes=["cpe:/a:openssl:openssl:3.0.2"])
        root = ET.fromstring(xml)
        results = root.findall("results/result")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].find("threat").text, "Log")
        self.assertEqual((results[0].find("host").text or "").strip(), AGENT)

    def test_null_findings_treated_as_empty(self):
        # Go marshals a nil slice as JSON null, so a 0-findings agent (e.g. Kali,
        # which Notus doesn't cover) sends "findings": null. It must NOT crash the
        # XML builder — treat it like [] (regression for bridge.py findings-null).
        null = {**SAMPLE_REPORT, "findings": None}
        xml = finding_report_to_xml(null, cpes=[])
        root = ET.fromstring(xml)
        results = root.findall("results/result")
        self.assertEqual(len(results), 1)  # single inventory marker, no crash
        self.assertEqual(results[0].find("threat").text, "Log")

    def test_cpe_host_details(self):
        # CPEs become <host><detail><name>App</name><value>cpe:...</value> blocks
        # that the CVE scanner consumes; non-empty findings keep their results.
        cpes = ["cpe:/a:openssl:openssl:3.0.2", "cpe:/o:linux:linux_kernel:5.15.0"]
        xml = finding_report_to_xml(SAMPLE_REPORT, cpes=cpes)
        root = ET.fromstring(xml)
        details = root.findall("host/detail")
        apps = [d.findtext("value") for d in details if d.findtext("name") == "App"]
        self.assertEqual(apps, cpes)
        # findings still produce their own results (2), no inventory marker added
        self.assertEqual(len(root.findall("results/result")), 2)

    def test_no_cpes_no_details(self):
        xml = finding_report_to_xml(SAMPLE_REPORT, cpes=[])
        root = ET.fromstring(xml)
        self.assertEqual(root.findall("host/detail"), [])

    def test_cve_only_report_is_findings_free(self):
        # CVE-only mode imports a findings-FREE CPE inventory (Notus NVT results
        # would make gvmd skip the CVE scan for the host). With findings cleared,
        # only the inventory marker remains and the CPE details are present.
        root = ET.fromstring(finding_report_to_xml({**SAMPLE_REPORT, "findings": []},
                                                    cpes=["cpe:/a:gnu:glibc:2.39"]))
        results = root.findall("results/result")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].find("nvt").get("oid"), "1.3.6.1.4.1.55683.1.0.1")
        apps = [d.findtext("value") for d in root.findall("host/detail") if d.findtext("name") == "App"]
        self.assertEqual(apps, ["cpe:/a:gnu:glibc:2.39"])

    def test_unique_result_ids(self):
        root, _ = self._parse()
        ids = [r.get("id") for r in root.findall("results/result")]
        self.assertEqual(len(ids), len(set(ids)), "result ids must be unique")


class TestValidScanTime(unittest.TestCase):
    def test_valid_passthrough(self):
        self.assertEqual(valid_scan_time("2026-06-28T00:00:00Z"), "2026-06-28T00:00:00Z")
        self.assertEqual(valid_scan_time("2026-06-30T12:00:00.123456789Z"), "2026-06-30T12:00:00.123456789Z")

    def test_zero_empty_and_malformed_fall_back_to_now(self):
        # Go's zero time, empty/None, malformed and implausible (far-future,
        # non-2000s) values must NOT reach gvmd (garbage epoch breaks the CVE
        # scan); they fall back to a real "now" timestamp.
        for bad in ("0001-01-01T00:00:00Z", "", None, "garbage",
                    "20bad-01-01T00:00:00Z", "9999-01-01T00:00:00Z",
                    "2026-13-01T00:00:00Z", "1999-01-01T00:00:00Z"):
            out = valid_scan_time(bad)
            self.assertRegex(out, r"^20\d\d-\d\d-\d\dT.*Z$", f"{bad!r} -> {out!r}")
            self.assertFalse(out.startswith("0001"))


class TestHostIdentity(unittest.TestCase):
    def test_safe_host_id_neutralizes_target_injection(self):
        # commas/slashes/spaces (multi-host, CIDR, range, XML-breaking) are removed
        self.assertEqual(safe_host_id("ok-host_1.example"), "ok-host_1.example")
        self.assertEqual(safe_host_id("a,10.0.0.0/24"), "a_10.0.0.0_24")
        self.assertEqual(safe_host_id("host with spaces"), "host_with_spaces")
        self.assertEqual(safe_host_id("evil<x>"), "evil_x")  # XML-breaking chars removed
        self.assertEqual(safe_host_id("\x00\x01"), "")  # only control chars → empty
        self.assertEqual(safe_host_id(""), "")

    def test_xml_uses_agent_id_not_hostname(self):
        # Identity must be the unique agent_id, not the (collision-prone) hostname.
        rep = {**SAMPLE_REPORT, "agent_id": "uniq-agent-7", "host": "localhost"}
        root = ET.fromstring(finding_report_to_xml(rep))
        self.assertEqual(root.find("host/ip").text, "uniq-agent-7")

    def test_xml_falls_back_to_host_when_no_agent_id(self):
        rep = {k: v for k, v in SAMPLE_REPORT.items() if k != "agent_id"}
        rep["host"] = "fallback-host"
        root = ET.fromstring(finding_report_to_xml(rep))
        self.assertEqual(root.find("host/ip").text, "fallback-host")


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


class ScriptedGmp:
    """gmp stub for the auto-provisioning path: scripted get_* responses and
    recorded create_* calls (the high-level methods provision_cve_task uses)."""

    def __init__(self, targets_xml="", tasks_xml="", target_id="TGT-NEW", task_id="TASK-NEW"):
        self._targets = targets_xml or '<get_targets_response status="200"/>'
        self._tasks = tasks_xml or '<get_tasks_response status="200"/>'
        self._tid = target_id
        self._kid = task_id
        self.calls = []

    def get_targets(self, filter_string=""):
        self.calls.append(("get_targets", filter_string))
        return self._targets

    def get_tasks(self, filter_string=""):
        self.calls.append(("get_tasks", filter_string))
        return self._tasks

    def create_target(self, **kw):
        self.calls.append(("create_target", kw))
        return f'<create_target_response status="201" id="{self._tid}"/>'

    def create_task(self, **kw):
        self.calls.append(("create_task", kw))
        return f'<create_task_response status="201" id="{self._kid}"/>'


class TestFindAndProvision(unittest.TestCase):
    def test_find_task_id_exact_match(self):
        # GMP name= filter is substring-ish; the exact name must be re-checked so
        # 'CVE: a-1' is not satisfied by 'CVE: a-10'.
        tasks = (
            '<get_tasks_response status="200">'
            '<task id="ID-1"><name>Suricatoos Agent CVE: a-1</name></task>'
            '<task id="ID-10"><name>Suricatoos Agent CVE: a-10</name></task>'
            "</get_tasks_response>"
        )
        g = ScriptedGmp(tasks_xml=tasks)
        self.assertEqual(_find_task_id(g, "Suricatoos Agent CVE: a-1"), "ID-1")
        self.assertEqual(_find_task_id(g, "Suricatoos Agent CVE: a-10"), "ID-10")
        self.assertIsNone(_find_task_id(g, "Suricatoos Agent CVE: a-99"))

    def test_provision_creates_when_absent(self):
        g = ScriptedGmp(target_id="TGT-1", task_id="TASK-1")  # empty get_* → not found
        tgt, task = provision_cve_task(g, "host-x")
        self.assertEqual((tgt, task), ("TGT-1", "TASK-1"))
        methods = [c[0] for c in g.calls]
        self.assertIn("create_target", methods)
        self.assertIn("create_task", methods)

    def test_provision_reuses_when_present(self):
        targets = (
            '<get_targets_response status="200">'
            '<target id="TGT-OLD"><name>Suricatoos Agent: host-x</name></target>'
            "</get_targets_response>"
        )
        tasks = (
            '<get_tasks_response status="200">'
            '<task id="TASK-OLD"><name>Suricatoos Agent CVE: host-x</name></task>'
            "</get_tasks_response>"
        )
        g = ScriptedGmp(targets_xml=targets, tasks_xml=tasks)
        tgt, task = provision_cve_task(g, "host-x")
        self.assertEqual((tgt, task), ("TGT-OLD", "TASK-OLD"))
        methods = [c[0] for c in g.calls]
        self.assertNotIn("create_target", methods)
        self.assertNotIn("create_task", methods)


if __name__ == "__main__":
    unittest.main()
