"""Unit tests for the reNgine→OpenVAS scan bridge — no live gvmd required."""

import unittest

from scan_bridge import (
    sanitize_ips,
    build_port_range,
    parse_report_results,
    _tag_value,
    _alive_test,
)

SAMPLE_REPORT_XML = """
<get_reports_response status="200" status_text="OK">
  <report id="outer">
    <report id="inner">
      <results start="1" max="100">
        <result id="r1">
          <host>203.0.113.10<asset asset_id="a"/></host>
          <port>443/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.150001">
            <name>Weak TLS configuration</name>
            <cvss_base>7.5</cvss_base>
            <tags>cvss_base_vector=CVSS:3.1/AV:N/AC:L|summary=Weak ciphers offered|solution=Disable weak ciphers|impact=MITM</tags>
            <refs>
              <ref type="cve" id="CVE-2023-1234"/>
              <ref type="cve" id="CVE-2023-1234"/>
              <ref type="url" id="https://example/adv"/>
            </refs>
          </nvt>
          <threat>High</threat>
          <severity>7.5</severity>
          <qod><value>80</value></qod>
        </result>
        <result id="r2">
          <host>203.0.113.11</host>
          <port>general/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.999"><name>Log note</name><cvss_base>0.0</cvss_base><tags></tags></nvt>
          <threat>Log</threat>
          <severity>0.0</severity>
        </result>
      </results>
    </report>
  </report>
</get_reports_response>
"""


class TestSanitizeIPs(unittest.TestCase):
    def test_valid_literals(self):
        hosts = [{"ip": "203.0.113.10"}, {"ip": "2001:db8::1"}]
        self.assertEqual(sanitize_ips(hosts), ["203.0.113.10", "2001:db8::1"])

    def test_hostname_raises(self):
        for bad in ("evil.com", "*.evil.com", "notanip", ""):
            with self.assertRaises(ValueError):
                sanitize_ips([{"ip": bad}])

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            sanitize_ips([])


class TestBuildPortRange(unittest.TestCase):
    def test_union_sorted(self):
        hosts = [{"ip": "1.1.1.1", "ports": [443, 80]}, {"ip": "1.1.1.2", "ports": [80, 8080]}]
        self.assertEqual(build_port_range(hosts), "T:80,443,8080")

    def test_ignores_out_of_range(self):
        hosts = [{"ip": "1.1.1.1", "ports": [80, 70000, 0, -1]}]
        self.assertEqual(build_port_range(hosts), "T:80")

    def test_no_ports_raises(self):
        with self.assertRaises(ValueError):
            build_port_range([{"ip": "1.1.1.1", "ports": []}])


class TestParseReport(unittest.TestCase):
    def test_parses_finding(self):
        fs = parse_report_results(SAMPLE_REPORT_XML)
        self.assertEqual(len(fs), 2)
        f = fs[0]
        self.assertEqual(f["host"], "203.0.113.10")
        self.assertEqual(f["port"], "443/tcp")
        self.assertEqual(f["oid"], "1.3.6.1.4.1.25623.1.0.150001")
        self.assertEqual(f["name"], "Weak TLS configuration")
        self.assertEqual(f["cvss_base"], 7.5)
        self.assertEqual(f["cvss_vector"], "CVSS:3.1/AV:N/AC:L")
        self.assertEqual(f["cves"], ["CVE-2023-1234"])  # deduped
        self.assertEqual(f["references"], ["https://example/adv"])
        self.assertEqual(f["summary"], "Weak ciphers offered")
        self.assertEqual(f["solution"], "Disable weak ciphers")
        self.assertEqual(f["impact"], "MITM")
        self.assertEqual(f["threat"], "High")
        self.assertEqual(f["qod"], 80)

    def test_log_finding_zero_severity(self):
        fs = parse_report_results(SAMPLE_REPORT_XML)
        self.assertEqual(fs[1]["cvss_base"], 0.0)
        self.assertEqual(fs[1]["qod"], 0)

    def test_empty_report(self):
        self.assertEqual(parse_report_results("<get_reports_response><report/></get_reports_response>"), [])


class TestHelpers(unittest.TestCase):
    def test_tag_value(self):
        tags = "cvss_base_vector=CVSS:3.1/AV:N|summary=hello world|solution=fix it"
        self.assertEqual(_tag_value(tags, "summary"), "hello world")
        self.assertEqual(_tag_value(tags, "missing"), "")

    def test_alive_test(self):
        self.assertIsNotNone(_alive_test("Consider Alive"))
        self.assertIsNone(_alive_test("Bogus Test"))


if __name__ == "__main__":
    unittest.main()
