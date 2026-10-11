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
    report_hosts_scanned,
    cmd_fetch,
    cmd_launch,
    cmd_status,
    cmd_stop,
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


# --------------------------------------------------------------------------- #
# Fetch honesto (hosts medidos / relatório ausente) e nome de task por pedido
# --------------------------------------------------------------------------- #

# request_id sintético no formato que o ingest gera (16 bytes em hex).
RID = "3f9a2c1b7e0d4a5b8c6d9e0f1a2b3c4d"
NOME_POR_PEDIDO = "suricatoos-rengine-1234-3f9a2c1b7e0d"  # mesmo literal do teste Go do taskName
NOME_LEGADO = "suricatoos-rengine-1234"
LOOP_ARGS = argparse.Namespace(
    task_prefix="suricatoos-rengine",
    config_id="daba56c8-73ec-11df-a475-002264764cea",
    scanner_id="08b69003-5fc2-4037-a479-93b440211c73",
    alive_test="Consider Alive",
)

# get_reports (details=1) na forma do gvmd 22/26: os <host> DO RELATÓRIO são filhos
# diretos do <report> interno (um por host medido, com <ip>) e <hosts><count> traz o
# total. O mesmo nome <host> aparece em results/result, ports/port e errors/error com
# outro papel — contar esses inflaria o número de hosts medidos.
REPORT_2_HOSTS = """
<get_reports_response status="200" status_text="OK">
  <report id="rep-2h" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
    <owner><name>suricatoos-scan</name></owner>
    <name>2026-10-11T10:00:00Z</name>
    <task id="task-1"><name>suricatoos-rengine-1234-3f9a2c1b7e0d</name></task>
    <report_format id="a994b278-1f62-11e1-96ac-406186ea4fc5"><name>XML</name></report_format>
    <report id="rep-2h">
      <gmp><version>22.4</version></gmp>
      <scan_run_status>Done</scan_run_status>
      <hosts><count>2</count></hosts>
      <closed_cves><count>0</count></closed_cves>
      <vulns><count>3</count></vulns>
      <os><count>1</count></os>
      <apps><count>2</count></apps>
      <ssl_certs><count>1</count></ssl_certs>
      <task id="task-1"><name>suricatoos-rengine-1234-3f9a2c1b7e0d</name><progress>100</progress></task>
      <timestamp>2026-10-11T10:00:00Z</timestamp>
      <scan_start>2026-10-11T10:00:05Z</scan_start>
      <ports start="1" max="-1"><count>2</count>
        <port>443/tcp<host>192.0.2.10</host><severity>7.5</severity><threat>High</threat></port>
        <port>22/tcp<host>192.0.2.11</host><severity>5.3</severity><threat>Medium</threat></port>
      </ports>
      <results start="1" max="-1">
        <result id="r1"><name>Weak TLS configuration</name>
          <host>192.0.2.10<asset asset_id="as-1"/><hostname></hostname></host><port>443/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.990002"><name>Weak TLS configuration</name><cvss_base>7.5</cvss_base><tags></tags></nvt>
          <threat>High</threat><severity>7.5</severity><qod><value>80</value></qod></result>
        <result id="r2"><name>Weak SSH key exchange</name>
          <host>192.0.2.11<asset asset_id="as-2"/><hostname></hostname></host><port>22/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.990004"><name>Weak SSH key exchange</name><cvss_base>5.3</cvss_base><tags></tags></nvt>
          <threat>Medium</threat><severity>5.3</severity><qod><value>80</value></qod></result>
        <result id="r3"><name>OS detection</name>
          <host>192.0.2.10<asset asset_id="as-1"/><hostname></hostname></host><port>general/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.990005"><name>OS detection</name><cvss_base>0.0</cvss_base><tags></tags></nvt>
          <threat>Log</threat><severity>0.0</severity><qod><value>80</value></qod></result>
      </results>
      <result_count>3<full>3</full><filtered>3</filtered></result_count>
      <host><ip>192.0.2.10</ip><asset asset_id="as-1"/>
        <start>2026-10-11T10:00:06Z</start><end>2026-10-11T10:04:50Z</end>
        <port_count><page>1</page></port_count><result_count><page>2</page></result_count>
        <detail><name>best_os_cpe</name><value>cpe:/o:debian:debian_linux</value></detail></host>
      <host><ip>192.0.2.11</ip><asset asset_id="as-2"/>
        <start>2026-10-11T10:00:06Z</start><end>2026-10-11T10:04:40Z</end>
        <port_count><page>1</page></port_count><result_count><page>1</page></result_count></host>
      <scan_end>2026-10-11T10:04:55Z</scan_end>
      <errors><count>1</count>
        <error><host>192.0.2.11<asset asset_id="as-2"/></host><port>22/tcp</port>
          <description>NVT timed out</description>
          <nvt oid="1.3.6.1.4.1.25623.1.0.990009"><name>Demo check</name></nvt></error>
      </errors>
    </report>
  </report>
</get_reports_response>
"""

# Scan cujo alive test não achou host vivo: Done em segundos, relatório sem host nenhum.
REPORT_0_HOSTS = """
<get_reports_response status="200" status_text="OK">
  <report id="rep-0h" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
    <owner><name>suricatoos-scan</name></owner>
    <task id="task-1"><name>suricatoos-rengine-1234-3f9a2c1b7e0d</name></task>
    <report id="rep-0h">
      <gmp><version>22.4</version></gmp>
      <scan_run_status>Done</scan_run_status>
      <hosts><count>0</count></hosts>
      <closed_cves><count>0</count></closed_cves>
      <vulns><count>0</count></vulns>
      <os><count>0</count></os>
      <apps><count>0</count></apps>
      <ssl_certs><count>0</count></ssl_certs>
      <timestamp>2026-10-11T10:00:00Z</timestamp>
      <scan_start>2026-10-11T10:00:05Z</scan_start>
      <ports start="1" max="-1"><count>0</count></ports>
      <results start="1" max="-1"></results>
      <result_count>0<full>0</full><filtered>0</filtered></result_count>
      <scan_end>2026-10-11T10:00:09Z</scan_end>
      <errors><count>0</count></errors>
    </report>
  </report>
</get_reports_response>
"""

# Relatório sem elementos <host> mas com o total em <hosts><count> (ex.: um host medido
# sem nenhum resultado que tenha sobrado depois do filtro): o fallback é hosts/count.
REPORT_SO_HOSTS_COUNT = """
<get_reports_response status="200" status_text="OK">
  <report id="rep-hc" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
    <report id="rep-hc">
      <scan_run_status>Done</scan_run_status>
      <hosts><count>1</count></hosts>
      <ports start="1" max="-1"><count>0</count></ports>
      <results start="1" max="-1"></results>
      <result_count>0<full>0</full><filtered>0</filtered></result_count>
      <errors><count>0</count></errors>
    </report>
  </report>
</get_reports_response>
"""


def _task(name, task_id, status, progress=0, report_id=""):
    return {"name": name, "id": task_id, "status": status, "progress": progress, "report_id": report_id}


class GvmdComEstado:
    """gvmd falso com estado, para os subcomandos inteiros do bridge.

    Tasks/targets ficam por NOME (como o bridge os acha) e reports por id. get_tasks e
    get_targets devolvem tudo: o bridge re-checa o nome EXATO, como faz contra o gvmd
    real. send_command interpreta os comandos GMP que o bridge envia e registra cada um
    em `sent`. Como no gvmd, <last_report> só existe depois de um relatório terminado."""

    def __init__(self, tasks=(), targets=None, reports=None):
        self.tasks = {t["name"]: dict(t) for t in tasks}
        self.targets = dict(targets or {})  # nome -> id
        self.reports = dict(reports or {})  # report_id -> XML do get_reports
        self.sent = []

    def get_tasks(self, filter_string=""):
        body = ""
        for t in self.tasks.values():
            last = f'<last_report><report id="{t["report_id"]}"/></last_report>' if t.get("report_id") else ""
            body += (f'<task id="{t["id"]}"><name>{t["name"]}</name><status>{t["status"]}</status>'
                     f'<progress>{t.get("progress", 0)}</progress>{last}</task>')
        return f'<get_tasks_response status="200" status_text="OK">{body}</get_tasks_response>'

    def get_targets(self, filter_string=""):
        body = "".join(f'<target id="{tid}"><name>{name}</name></target>' for name, tid in self.targets.items())
        return f'<get_targets_response status="200" status_text="OK">{body}</get_targets_response>'

    def send_command(self, cmd):
        self.sent.append(cmd)
        el = ET.fromstring(cmd)
        if el.tag == "create_target":
            tid = f"target-{len(self.targets) + 1}"
            self.targets[el.findtext("name")] = tid
            return f'<create_target_response status="201" status_text="OK, resource created" id="{tid}"/>'
        if el.tag == "create_task":
            tid = f"task-criada-{len(self.tasks) + 1}"
            name = el.findtext("name")
            self.tasks[name] = _task(name, tid, "New")
            return f'<create_task_response status="201" status_text="OK, resource created" id="{tid}"/>'
        if el.tag == "start_task":
            return ('<start_task_response status="202" status_text="OK, request submitted">'
                    "<report_id>rep-nova</report_id></start_task_response>")
        if el.tag == "stop_task":
            return '<stop_task_response status="202" status_text="OK, request submitted"/>'
        if el.tag == "get_reports":
            return self.reports[el.get("report_id")]
        raise AssertionError(f"comando GMP inesperado: {el.tag}")

    def comandos(self, tag):
        return [ET.fromstring(c) for c in self.sent if ET.fromstring(c).tag == tag]


def _req_loop(**extra):
    """Pedido do ingest (o Job serializado): scan_history_id + request_id do pedido."""
    req = {"rengine_scan_history_id": 1234, "request_id": RID, "target": "acme.example",
           "hosts": [{"ip": "192.0.2.10", "ports": [443]}]}
    req.update(extra)
    return req


class TestHostsMedidos(unittest.TestCase):
    """hosts_scanned = hosts presentes no relatório: os <host> do relatório (preferidos),
    com fallback para hosts/count; nunca 0 num relatório que tem achados."""

    def test_conta_os_hosts_do_relatorio_e_nao_os_host_de_resultado_porta_ou_erro(self):
        self.assertEqual(report_hosts_scanned(REPORT_2_HOSTS), 2)

    def test_scan_sem_host_vivo_tem_zero_hosts(self):
        self.assertEqual(report_hosts_scanned(REPORT_0_HOSTS), 0)

    def test_sem_elementos_host_usa_hosts_count(self):
        # Contar só os hosts dos resultados daria 0 aqui (host limpo vira "não mediu").
        self.assertEqual(report_hosts_scanned(REPORT_SO_HOSTS_COUNT), 1)

    def test_relatorio_com_achados_nunca_tem_zero_hosts(self):
        # Sem <host> nem hosts/count, mas com resultados em 2 hosts: um achado prova
        # que o host foi medido — declarar 0 descartaria achados reais como FAILED.
        self.assertEqual(report_hosts_scanned(SAMPLE_REPORT_XML), 2)


class TestFetchHonesto(unittest.TestCase):
    def _gvmd(self, report_xml=None, report_id="rep-1"):
        task = _task(NOME_POR_PEDIDO, "task-1", "Done", 100, report_id if report_xml else "")
        return GvmdComEstado(tasks=[task], reports={report_id: report_xml} if report_xml else {})

    def test_fetch_informa_hosts_medidos(self):
        gmp = self._gvmd(REPORT_2_HOSTS)
        out = cmd_fetch(gmp, _req_loop(gvm_task_id="task-1"), LOOP_ARGS)
        self.assertEqual(out["hosts_scanned"], 2)
        self.assertIs(out["report_missing"], False)
        self.assertEqual(len(out["findings"]), 3)

    def test_fetch_de_scan_sem_host_vivo_informa_zero_hosts(self):
        gmp = self._gvmd(REPORT_0_HOSTS)
        out = cmd_fetch(gmp, _req_loop(gvm_task_id="task-1"), LOOP_ARGS)
        self.assertEqual(out, {"findings": [], "hosts_scanned": 0, "report_missing": False})

    def test_task_done_sem_relatorio_nao_vira_lista_vazia_silenciosa(self):
        gmp = self._gvmd(report_xml=None)
        out = cmd_fetch(gmp, _req_loop(gvm_task_id="task-1"), LOOP_ARGS)
        self.assertEqual(out, {"findings": [], "hosts_scanned": 0, "report_missing": True})
        self.assertEqual(gmp.comandos("get_reports"), [])


class TestNomeDaTaskPorPedido(unittest.TestCase):
    def test_request_id_entra_no_nome(self):
        self.assertEqual(_task_name(_req_loop(), "suricatoos-rengine"), NOME_POR_PEDIDO)

    def test_sem_request_id_vale_o_nome_legado(self):
        # O sensor não manda request_id: o nome continua <prefix>-<scan_id>.
        self.assertEqual(_task_name({"scan_id": "b21a"}, "suricatoos-sensor"), "suricatoos-sensor-b21a")
        self.assertEqual(_task_name({"rengine_scan_history_id": 1234}, "suricatoos-rengine"), NOME_LEGADO)

    def test_sufixo_so_com_alfanumericos_do_request_id(self):
        # Defesa em profundidade: o nome vai para filtro GMP e para nome de target/task.
        req = {"rengine_scan_history_id": 7, "request_id": '"><x>-' + "a" * 20}
        self.assertEqual(_task_name(req, "p"), "p-7-xaaaaaaaaaaa")


class TestLaunchUsaONomePorPedido(unittest.TestCase):
    def test_pedido_novo_nao_adota_a_task_done_de_um_pedido_antigo(self):
        # O job antigo do mesmo scan_history_id foi expurgado (reap) e o pedido foi
        # reenviado: a task legada Done NÃO pode ser reencontrada (achados velhos).
        gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Done", 100, "rep-velho")],
                            targets={NOME_LEGADO: "target-velho"})
        out = cmd_launch(gmp, _req_loop(), LOOP_ARGS)
        self.assertEqual([c.findtext("name") for c in gmp.comandos("create_target")], [NOME_POR_PEDIDO])
        self.assertEqual([c.findtext("name") for c in gmp.comandos("create_task")], [NOME_POR_PEDIDO])
        self.assertNotEqual(out["task_id"], "task-velha")
        self.assertEqual([c.get("task_id") for c in gmp.comandos("start_task")], [out["task_id"]])
        self.assertEqual(out["status"], "Requested")
        self.assertEqual(out["report_id"], "rep-nova")

    def test_relancar_o_mesmo_pedido_reusa_a_propria_task(self):
        # Idempotência preservada: o launch re-tentado do MESMO pedido acha a task dele.
        gmp = GvmdComEstado(tasks=[_task(NOME_POR_PEDIDO, "task-1", "Running", 30)],
                            targets={NOME_POR_PEDIDO: "target-1"})
        out = cmd_launch(gmp, _req_loop(), LOOP_ARGS)
        self.assertEqual(gmp.sent, [])  # nada criado, nada (re)iniciado
        self.assertEqual((out["task_id"], out["target_id"], out["status"]), ("task-1", "target-1", "Running"))


class TestFallbackParaONomeLegado(unittest.TestCase):
    """Jobs lançados ANTES do nome por pedido seguem em voo com a task legada
    <prefix>-<scan_id>: status/fetch/stop procuram o nome novo e, se ele não existir,
    o legado — só se a task legada for a que o job registrou (gvm_task_id)."""

    def test_status_do_job_em_voo_acha_a_task_legada(self):
        gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Running", 40)])
        out = cmd_status(gmp, _req_loop(gvm_task_id="task-velha"), LOOP_ARGS)
        self.assertEqual(out, {"status": "Running", "progress": 40, "report_id": ""})

    def test_fetch_do_job_em_voo_le_o_relatorio_da_task_legada(self):
        gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Done", 100, "rep-2h")],
                            reports={"rep-2h": REPORT_2_HOSTS})
        out = cmd_fetch(gmp, _req_loop(gvm_task_id="task-velha"), LOOP_ARGS)
        self.assertEqual((out["hosts_scanned"], out["report_missing"], len(out["findings"])), (2, False, 3))

    def test_stop_do_job_em_voo_para_a_task_legada(self):
        gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Running", 40)])
        cmd_stop(gmp, _req_loop(gvm_task_id="task-velha"), LOOP_ARGS)
        self.assertEqual([c.get("task_id") for c in gmp.comandos("stop_task")], ["task-velha"])

    def test_nome_novo_tem_precedencia_sobre_o_legado(self):
        gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Done", 100, "rep-velho"),
                                   _task(NOME_POR_PEDIDO, "task-1", "Running", 10)])
        out = cmd_status(gmp, _req_loop(gvm_task_id="task-1"), LOOP_ARGS)
        self.assertEqual(out["status"], "Running")

    def test_task_legada_de_outro_pedido_nao_e_adotada(self):
        # A task do job sumiu (ex.: apagada na GSA) e existe a task legada Done de um pedido
        # antigo do mesmo scan_history_id: adotá-la devolveria achados velhos.
        for pino in ("task-do-job-que-sumiu", None):
            with self.subTest(gvm_task_id=pino):
                gmp = GvmdComEstado(tasks=[_task(NOME_LEGADO, "task-velha", "Done", 100, "rep-velho")],
                                    reports={"rep-velho": REPORT_2_HOSTS})
                req = _req_loop(gvm_task_id=pino) if pino else _req_loop()
                self.assertEqual(cmd_status(gmp, req, LOOP_ARGS)["status"], "Interrupted")
                self.assertIs(cmd_fetch(gmp, req, LOOP_ARGS)["report_missing"], True)
                cmd_stop(gmp, req, LOOP_ARGS)
                self.assertEqual(gmp.sent, [])  # nem get_reports nem stop_task na task alheia


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
