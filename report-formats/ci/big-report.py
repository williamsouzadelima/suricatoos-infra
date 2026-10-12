#!/usr/bin/env python3
"""Gera um relatorio do gvmd SINTETICO e GRANDE para a medicao (nao bloqueante)
de tempo e pico de memoria do Premium PDF no CI (ci/measure-big.sh): dezenas de
milhares de resultados, so' dado inventado -- enderecos RFC 5737, nomes sob
.example, OIDs da faixa sintetica 1.3.6.1.4.1.25623.1.0.99xxxx (nao existem no
feed), CVEs do ano 2099 e EPSS inventado. Deterministico: os mesmos parametros
dao os mesmos bytes.

A forma e' a de um export do gvmd 26: <ports> com a severidade MAXIMA por host
e porta, <result_count> com as faixas, um <host> por endereco. A mistura e' a
de um scan de rede comum: muito Log, um pouco de cada faixa, uma fracao de
indicadores (QoD abaixo de 70), uns 3% de falso positivo (override) para a
edicao do cliente ter o que tirar, e advisories VendorFix de alguns produtos
para os cards consolidados.

Uso:
    python3 report-formats/ci/big-report.py <saida.xml> [--hosts N] [--nvts N]
                                            [--results N] [--seed N]
"""
import argparse
import os
import random
import sys
from xml.sax.saxutils import escape

OID = "1.3.6.1.4.1.25623.1.0.%d"
NETS = ("192.0.2.%d", "198.51.100.%d", "203.0.113.%d")
PORTS = ("22/tcp", "25/tcp", "53/udp", "80/tcp", "110/tcp", "123/udp", "135/tcp", "139/tcp",
         "143/tcp", "161/udp", "389/tcp", "443/tcp", "445/tcp", "465/tcp", "587/tcp", "636/tcp",
         "993/tcp", "995/tcp", "1433/tcp", "1521/tcp", "2049/tcp", "3306/tcp", "3389/tcp",
         "5432/tcp", "5900/tcp", "5985/tcp", "6379/tcp", "8080/tcp", "8443/tcp", "9200/tcp")
# Severidade de cada NVT pela posicao (i % 20): 40% Log, como num scan comum.
SEVS = (9.8, 9.1, 8.1, 7.5, 7.5, 6.5, 5.9, 5.3, 5.0, 4.3, 2.6, 2.1,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
STYPES = ("VendorFix", "Mitigation", "Workaround", "VendorFix", "WillNotFix", "VendorFix",
          "NoneAvailable", "Mitigation")
TEXT = ("Synthetic text for the large measurement export: it only stands in for the length of a "
        "real advisory and describes nothing that exists. ")


def threat(sev):
    if sev < 0:
        return "False Positive"
    if sev >= 9.0:
        return "Critical"
    if sev >= 7.0:
        return "High"
    if sev >= 4.0:
        return "Medium"
    if sev >= 0.1:
        return "Low"
    return "Log"


def band(sev):
    if -1.5 < sev < 0:
        return "false_positive"
    return {"Critical": "critical", "High": "high", "Medium": "medium",
            "Low": "low", "Log": "log"}[threat(sev)]


def nvt_catalog(n):
    nvts = []
    for i in range(n):
        sev = SEVS[i % len(SEVS)]
        stype = STYPES[i % len(STYPES)]
        if stype == "VendorFix" and sev > 0:
            name = "Example Product %02d Advisory (EX-%04d)" % (i % 12, i)
            sol = "Upgrade Example Product %02d to version %d.%d or later." % (i % 12, 2 + i % 5, i % 10)
        else:
            name = "Example Synthetic Check %04d" % i
            sol = "Apply the vendor guidance for synthetic check %04d." % i
        qod = 30 if i % 11 == 0 else (97 if i % 2 else 80)
        cve = "CVE-2099-%04d" % (5000 + i) if i % 2 == 0 and sev > 0 else None
        epss = round(0.01 + (i % 37) / 40.0, 5) if cve and i % 4 == 0 else None
        nvts.append({"oid": OID % (995000 + i), "name": name, "sev": sev, "stype": stype,
                     "sol": sol, "qod": qod, "cve": cve, "epss": epss})
    return nvts


def nvt_xml(v):
    tags = ("summary=%s|insight=%s|impact=%s|affected=%s|vuldetect=%s|solution_type=%s"
            % (TEXT, TEXT * 2, TEXT, TEXT, TEXT, v["stype"]))
    refs = '<refs><ref type="cve" id="%s"/></refs>' % v["cve"] if v["cve"] else "<refs></refs>"
    epss = ""
    if v["epss"] is not None:
        epss = ("<epss><max_severity><score>%.5f</score><percentile>0.50000</percentile>"
                "<cve id=\"%s\"><severity>%.1f</severity></cve></max_severity>"
                "<max_epss><score>%.5f</score><percentile>0.50000</percentile>"
                "<cve id=\"%s\"><severity>%.1f</severity></cve></max_epss></epss>"
                % (v["epss"], v["cve"], v["sev"], v["epss"], v["cve"], v["sev"]))
    cvss = "%.1f" % v["sev"] if v["sev"] > 0 else ""
    return ('<nvt oid="%s"><type>nvt</type><name>%s</name><family>Synthetic</family>'
            "<cvss_base>%s</cvss_base><tags>%s</tags><solution type=\"%s\">%s</solution>%s%s</nvt>"
            % (v["oid"], escape(v["name"]), cvss, escape(tags), v["stype"], escape(v["sol"]), epss, refs))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--nvts", type=int, default=240)
    ap.add_argument("--results", type=int, default=30000)
    ap.add_argument("--seed", type=int, default=20261012)
    a = ap.parse_args()
    if not 1 <= a.hosts <= 3 * 254:
        sys.exit("big-report: --hosts entre 1 e 762 (os tres blocos RFC 5737)")
    rng = random.Random(a.seed)
    hosts = [NETS[i // 254] % (1 + i % 254) for i in range(a.hosts)]
    names = {h: "host%03d.example.com" % i for i, h in enumerate(hosts)}
    open_ports = {h: sorted(rng.sample(PORTS, rng.randint(3, 9))) + ["general/tcp"] for h in hosts}
    nvts = nvt_catalog(a.nvts)
    nvt_cache = {}
    results, ports, counts = [], {}, {}
    for r in range(a.results):
        h = hosts[r % a.hosts]
        v = nvts[rng.randrange(a.nvts)]
        p = rng.choice(open_ports[h])
        sev = -1.0 if rng.random() < 0.03 else v["sev"]
        results.append((r, h, p, v, sev))
        k = (h, p)
        ports[k] = max(ports.get(k, sev), sev)
        counts[band(sev)] = counts.get(band(sev), 0) + 1
    start, end = "2026-09-01T08:00:00Z", "2026-09-01T14:30:00Z"
    rc = "%d<full>%d</full><filtered>%d</filtered>" % (a.results, a.results, a.results) + "".join(
        "<%s><full>%d</full><filtered>%d</filtered></%s>" % (b, counts.get(b, 0), counts.get(b, 0), b)
        for b in ("critical", "high", "medium", "low", "log", "false_positive"))
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        w = fh.write
        w('<?xml version="1.0" encoding="UTF-8"?>\n')
        w("<!-- Relatorio SINTETICO grande da medicao do CI (ci/big-report.py): dado inventado. -->\n")
        w('<report extension="pdf" content_type="application/pdf" id="00000000-0000-4000-8000-0000000b1600">\n')
        w('  <task id="00000000-0000-4000-8000-0000000b1601">\n    <name>Example Large Synthetic Export</name>\n'
          "  </task>\n")
        w("  <scan_run_status>Done</scan_run_status>\n")
        w("  <timezone>Coordinated Universal Time</timezone>\n  <timezone_abbrev>UTC</timezone_abbrev>\n")
        w("  <scan_start>%s</scan_start>\n  <scan_end>%s</scan_end>\n" % (start, end))
        w("  <hosts><count>%d</count></hosts>\n" % a.hosts)
        w("  <result_count>%s</result_count>\n" % rc)
        w('  <filters id="00000000-0000-4000-8000-0000000b1602">\n'
          "    <term>apply_overrides=1 levels=chmlgf rows=-1 min_qod=1 first=1 sort-reverse=severity</term>\n"
          "  </filters>\n")
        w('  <ports start="1" max="-1">\n')
        for (h, p), s in sorted(ports.items()):
            w("    <port><host>%s</host>%s<severity>%.1f</severity><threat>%s</threat></port>\n"
              % (h, p, s, threat(s)))
        w("  </ports>\n")
        for h in hosts:
            w("  <host>\n    <ip>%s</ip>\n    <start>%s</start>\n    <end>%s</end>\n"
              "    <detail><name>hostname</name><value>%s</value></detail>\n  </host>\n"
              % (h, start, end, names[h]))
        w('  <results start="1" max="-1">\n')
        for r, h, p, v, sev in results:
            if v["oid"] not in nvt_cache:
                nvt_cache[v["oid"]] = nvt_xml(v)
            w('    <result id="00000000-0000-4000-8000-%012d">\n'
              "      <host>%s<hostname>%s</hostname></host>\n      <port>%s</port>\n      %s\n"
              "      <threat>%s</threat>\n      <severity>%.1f</severity>\n"
              "      <qod><value>%d</value><type>remote_banner</type></qod>\n"
              "      <description>Synthetic detection output %d on %s %s. %s</description>\n"
              "    </result>\n"
              % (r + 1, h, names[h], p, nvt_cache[v["oid"]], threat(sev), sev, v["qod"],
                 r + 1, h, p, TEXT))
        w("  </results>\n</report>\n")
    # Uma linha para o resumo da medicao (measure-big.sh).
    print("%d resultados (%d falso positivo, %d Log), %d hosts, %d NVTs, %.1f MB de XML"
          % (a.results, counts.get("false_positive", 0), counts.get("log", 0), a.hosts, a.nvts,
             os.path.getsize(a.out) / 1048576.0))


if __name__ == "__main__":
    main()
