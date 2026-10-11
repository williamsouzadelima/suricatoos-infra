"""Unit tests for the reNgine→OpenVAS scan bridge — no live gvmd required."""

import argparse
import unittest
from xml.etree import ElementTree as ET

from scan_bridge import (
    sanitize_ips,
    sanitize_targets,
    resolve_port_range,
    build_port_range,
    parse_report_results,
    cmd_fetch,
    _tag_value,
    _alive_test,
    _scan_id,
    _task_name,
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

# Resultados sintéticos (IPs RFC 5737) — um por classe de severidade do gvmd 26.
# O Crítico (CVSS >= 9.0) é classe PRÓPRIA, separada de Alto.
RES_CRITICAL = {"threat": "Critical", "severity": "9.8", "host": "192.0.2.10",
                "oid": "1.3.6.1.4.1.25623.1.0.990001", "name": "Remote code execution in demo service"}
RES_HIGH = {"threat": "High", "severity": "7.5", "host": "192.0.2.10",
            "oid": "1.3.6.1.4.1.25623.1.0.990002", "name": "Weak TLS configuration"}
# Resultado que um override marcou como falso positivo: classe `f`, severidade -1.
RES_FALSE_POSITIVE = {"threat": "False Positive", "severity": "-1.0", "host": "192.0.2.11",
                      "oid": "1.3.6.1.4.1.25623.1.0.990003", "name": "Overridden demo finding"}

# Classe de severidade -> letra do termo `levels=` do filtro do gvmd.
THREAT_LEVEL_LETTER = {"Critical": "c", "High": "h", "Medium": "m", "Low": "l",
                       "Log": "g", "False Positive": "f"}


def report_xml(results) -> str:
    """get_reports_response sintético (mesmo aninhamento do SAMPLE_REPORT_XML)."""
    body = "".join(
        f'<result id="r{i}"><host>{r["host"]}</host><port>443/tcp</port>'
        f'<nvt oid="{r["oid"]}"><name>{r["name"]}</name>'
        f'<cvss_base>{max(float(r["severity"]), 0.0)}</cvss_base><tags></tags></nvt>'
        f'<threat>{r["threat"]}</threat><severity>{r["severity"]}</severity>'
        "<qod><value>80</value></qod></result>"
        for i, r in enumerate(results, 1)
    )
    return (
        '<get_reports_response status="200" status_text="OK">'
        '<report id="outer"><report id="inner">'
        f'<results start="1" max="-1">{body}</results>'
        "</report></report></get_reports_response>"
    )


def filter_terms(filter_string: str) -> dict:
    """'a=1 b=2' -> {'a': '1', 'b': '2'} (termos chave=valor de um filtro GMP)."""
    return dict(t.split("=", 1) for t in filter_string.split() if "=" in t)


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


class TestSanitizeTargets(unittest.TestCase):
    def test_ip_and_cidr(self):
        req = {"targets": ["10.20.0.0/24", "10.20.5.5", "2001:db8::/64"]}
        self.assertEqual(sanitize_targets(req), ["10.20.0.0/24", "10.20.5.5", "2001:db8::/64"])

    def test_slash32_becomes_bare(self):
        self.assertEqual(sanitize_targets({"targets": ["10.0.0.5/32"]}), ["10.0.0.5"])

    def test_hostname_rejected(self):
        for bad in ("evil.com", "*.evil.com", "notanip", "10.0.0.0/33"):
            with self.assertRaises(ValueError):
                sanitize_targets({"targets": [bad]})

    def test_legacy_hosts_fallback(self):
        req = {"hosts": [{"ip": "10.0.0.5", "ports": [80]}]}
        self.assertEqual(sanitize_targets(req), ["10.0.0.5"])

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            sanitize_targets({"targets": []})


class TestResolvePortRange(unittest.TestCase):
    def test_explicit_range(self):
        self.assertEqual(resolve_port_range({"ports": "T:1-65535"}), "T:1-65535")
        self.assertEqual(resolve_port_range({"ports": "T:22,80,443"}), "T:22,80,443")

    def test_invalid_range_falls_back_to_hosts(self):
        # An injection-y ports string is ignored; the legacy per-host build is used.
        req = {"ports": "T:1; DROP", "hosts": [{"ip": "10.0.0.5", "ports": [80, 443]}]}
        self.assertEqual(resolve_port_range(req), "T:80,443")


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

    def test_critical_severity_preserved(self):
        # Severidade >= 9.0 (classe Crítico) passa intacta: sem clamp em 7.5/8.9 e sem descarte.
        fs = parse_report_results(report_xml([RES_CRITICAL, RES_HIGH]))
        self.assertEqual([f["cvss_base"] for f in fs], [9.8, 7.5])
        self.assertEqual([f["threat"] for f in fs], ["Critical", "High"])
        self.assertEqual(fs[0]["host"], "192.0.2.10")


class FakeGvmd:
    """Gmp falso para cmd_fetch (mesmo papel dos FakeGmp/ScriptedGmp do test_bridge).
    get_tasks devolve a tarefa concluída com last_report; send_command registra o
    <get_reports> enviado e responde como o gvmd 26: só devolve os resultados das
    classes listadas em `levels=` do filtro."""

    REPORT_ID = "11111111-2222-3333-4444-555555555555"

    def __init__(self, results, task_name):
        self.results = results
        self.task_name = task_name
        self.sent = []  # comandos GMP (XML) enviados via send_command

    def get_tasks(self, filter_string=""):
        return (
            '<get_tasks_response status="200" status_text="OK">'
            f'<task id="task-1"><name>{self.task_name}</name><status>Done</status>'
            f'<progress>100</progress><last_report><report id="{self.REPORT_ID}"/></last_report>'
            "</task></get_tasks_response>"
        )

    def send_command(self, cmd):
        self.sent.append(cmd)
        levels = filter_terms(ET.fromstring(cmd).get("filter", "")).get("levels", "")
        kept = [r for r in self.results if THREAT_LEVEL_LETTER[r["threat"]] in levels]
        return report_xml(kept)


class TestFetchIncluiClasseCritico(unittest.TestCase):
    """Regressão: no gvmd 26 o Crítico (CVSS >= 9.0) é classe própria; com `levels=hmlg`
    os achados mais graves ficavam FORA do fetch (e do loop reNgine/Score)."""

    def _fetch(self, results):
        gmp = FakeGvmd(results, task_name="suricatoos-sensor-scan-1")
        args = argparse.Namespace(task_prefix="suricatoos-sensor")
        return gmp, cmd_fetch(gmp, {"scan_id": "scan-1"}, args)

    def test_get_report_enviado_pede_a_classe_critico(self):
        gmp, _ = self._fetch([RES_HIGH])
        self.assertEqual(len(gmp.sent), 1)
        cmd = ET.fromstring(gmp.sent[0])
        self.assertEqual(cmd.tag, "get_reports")
        self.assertEqual(cmd.get("report_id"), FakeGvmd.REPORT_ID)
        terms = filter_terms(cmd.get("filter", ""))
        levels = terms.get("levels", "")
        self.assertIn("c", levels, "sem 'c' os achados Críticos ficam fora do fetch")
        self.assertNotIn("f", levels, "com 'f' o falso positivo (override) seria importado")
        self.assertEqual(set(levels), set("chmlg"))  # Crítico, Alto, Médio, Baixo, Log
        self.assertEqual(terms.get("apply_overrides"), "1")
        self.assertEqual(terms.get("rows"), "-1")
        self.assertEqual(terms.get("min_qod"), "0")

    def test_achado_critico_volta_em_findings_com_severidade_preservada(self):
        _, out = self._fetch([RES_CRITICAL, RES_HIGH])
        por_oid = {f["oid"]: f for f in out["findings"]}
        self.assertIn(RES_CRITICAL["oid"], por_oid, "achado Crítico (9.8) ficou fora do fetch")
        crit = por_oid[RES_CRITICAL["oid"]]
        self.assertEqual(crit["cvss_base"], 9.8)
        self.assertEqual(crit["threat"], "Critical")
        self.assertEqual(crit["host"], "192.0.2.10")
        self.assertEqual(por_oid[RES_HIGH["oid"]]["cvss_base"], 7.5)  # Alto continua vindo
        self.assertEqual(len(out["findings"]), 2)

    def test_falso_positivo_por_override_nao_e_importado(self):
        # Guarda contra a correção "óbvia demais" (levels=chmlgf): o resultado que um
        # override marcou como falso positivo NÃO pode entrar no fetch.
        _, out = self._fetch([RES_HIGH, RES_FALSE_POSITIVE])
        self.assertEqual([f["oid"] for f in out["findings"]], [RES_HIGH["oid"]])


class TestHelpers(unittest.TestCase):
    def test_tag_value(self):
        tags = "cvss_base_vector=CVSS:3.1/AV:N|summary=hello world|solution=fix it"
        self.assertEqual(_tag_value(tags, "summary"), "hello world")
        self.assertEqual(_tag_value(tags, "missing"), "")

    def test_alive_test(self):
        self.assertIsNotNone(_alive_test("Consider Alive"))
        self.assertIsNone(_alive_test("Bogus Test"))

    def test_scan_id_and_task_name(self):
        # sensor: correlation UUID via scan_id.
        self.assertEqual(_scan_id({"scan_id": "b21a-uuid"}), "b21a-uuid")
        self.assertEqual(_task_name({"scan_id": "b21a"}, "suricatoos-sensor"), "suricatoos-sensor-b21a")
        # loop: back-compat via rengine_scan_history_id (int) + default prefix.
        self.assertEqual(_scan_id({"rengine_scan_history_id": 1234}), "1234")
        self.assertEqual(_task_name({"rengine_scan_history_id": 1234}, "suricatoos-rengine"),
                         "suricatoos-rengine-1234")
        # scan_id wins when both present.
        self.assertEqual(_scan_id({"scan_id": "x", "rengine_scan_history_id": 9}), "x")


if __name__ == "__main__":
    unittest.main()
