#!/usr/bin/env python3
"""Pilha-esqueleto: prova, no Engine do CI, o que o portao estatico nao prova.

O check_networks.py confere a TOPOLOGIA declarada (quem esta em qual rede). Aqui sobe uma
pilha minima com as MESMAS redes -- resolvidas da combinacao shared-host, a de producao -- e
MEDE o comportamento do Docker: quem alcanca quem (por nome e por IP), por qual gateway cada
servico sai e de que IP o nginx ve o trafego que entra pela porta publicada (de que dependem o
set_real_ip_from e o gate de rede do /feed-sync/ no nginx/default.conf).

Sete servicos, uma imagem so (busybox), copiando do config resolvido APENAS `networks` (com
aliases) e `ports`; cada um serve HTTP nas portas reais (httpd) e /cgi-bin/ra ecoa o
REMOTE_ADDR. As redes de topo perdem o `name` (o projeto `skel` as prefixa) mas mantem
`internal`.

Prova o Engine DO CI, NAO o de producao: as conferencias pos-deploy no host continuam
obrigatorias. Cada verificacao imprime esperado x obtido; qualquer falha = exit 1.

  python3 compose/test/skeleton_stack.py     # precisa de Docker; no CI roda no job `esqueleto`

Saida: 0 tudo como esperado; 1 alguma verificacao falhou; 2 nao deu para montar a pilha.
Sem dependencias fora da biblioteca padrao.
"""
import collections
import concurrent.futures
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

import check_networks as cn

PROJECT = "skel"
IMAGE = "busybox:1.36.1"
HERE = os.path.dirname(os.path.abspath(__file__))

# servico -> portas REAIS onde escuta (HTTP puro: aqui importa a rede, nao o TLS).
PORTS = {
    "nginx": (443, 9392),
    "gsad": (9392,),
    "gvmd": (9390,),
    "docker-socket-proxy": (2375,),
    "feed-updater": (8008,),
    "control-plane": (8080,),
    "ingest": (9090,),
}

# DEVEM alcancar. As duas ultimas linhas sao controles positivos das FONTES dos negativos
# (so' prova que gvmd/gsad/control-plane nao alcancam X quem prova que eles sabem fazer wget).
POSITIVOS = [
    ("nginx", "gsad"), ("nginx", "control-plane"), ("nginx", "ingest"), ("nginx", "feed-updater"),
    ("ingest", "control-plane"), ("feed-updater", "docker-socket-proxy"),
    ("gvmd", "gsad"), ("gsad", "gvmd"), ("control-plane", "ingest"),
]

# DEVEM FALHAR (por nome E por IP).
NEGATIVOS = [(s, d) for s in ("gsad", "gvmd")
             for d in ("docker-socket-proxy", "control-plane", "ingest", "feed-updater")] + [
    ("nginx", "docker-socket-proxy"), ("control-plane", "docker-socket-proxy")]

# servico -> rede cujo gateway deve ser a rota padrao (None = nao pode ter rota padrao).
ROTAS = {
    "nginx": "default",               # portas publicadas e IP real do cliente dependem disso
    "docker-socket-proxy": None,      # so' docker-api (internal): sem rota para fora
    "control-plane": "egress",
    "ingest": "egress",
    "feed-updater": "egress",         # o espelho MSRC sai por aqui
}

RETRY_SECONDS = 20                    # tempo para o httpd de cada container subir
RETRY_STEP = 0.5                      # intervalo entre tentativas

Result = collections.namedtuple("Result", "kind desc expected got ok")


# ---------------------------------------------------------------------------
# Modelo da pilha
# ---------------------------------------------------------------------------
def boot(ports):
    """Shell que serve HTTP em cada porta (httpd do busybox) e cria /cgi-bin/ra, que ecoa o
    REMOTE_ADDR. Sem `$` de proposito: o Compose o interpolaria."""
    cgi = r"#!/bin/sh\necho Content-Type: text/plain\necho\nenv | grep ^REMOTE_ADDR=\n"
    servers = "".join("httpd -p %d -h /www; " % p for p in ports[:-1])
    return ("mkdir -p /www/cgi-bin && echo ok > /www/index.html && printf '" + cgi
            + "' > /www/cgi-bin/ra && chmod +x /www/cgi-bin/ra && " + servers
            + "exec httpd -f -p %d -h /www" % ports[-1])


def build_skeleton(cfg):
    """Config resolvido (JSON do `docker compose config`) -> modelo de compose da pilha."""
    services, used = {}, set()
    for name, ports in PORTS.items():
        if name not in cfg["services"]:
            raise cn.InputError("servico %s ausente do config resolvido (a pilha o espelha)" % name)
        src = cfg["services"][name]
        nets = src.get("networks") or {}
        svc = {"image": IMAGE, "networks": nets, "command": ["sh", "-c", boot(ports)]}
        if src.get("ports"):
            svc["ports"] = src["ports"]
        services[name] = svc
        used.update(nets)
    declared = cfg.get("networks") or {}
    networks = {}
    for key in sorted(used):
        internal = bool((declared.get(key) or {}).get("internal"))
        networks[key] = {"internal": True} if internal else {}
    return {"services": services, "networks": networks}


def published_port(skel):
    """Porta do host que publica a 443 do nginx (None se nao publica). Aceita a forma longa
    ({target, published}) e a curta ("[ip:]publicada:alvo[/proto]")."""
    for p in skel["services"]["nginx"].get("ports") or []:
        if isinstance(p, dict):
            target, published = p.get("target"), p.get("published")
        else:
            parts = str(p).split("/")[0].split(":")
            if len(parts) < 2:
                continue
            target, published = parts[-1], parts[-2]
        if str(target) == "443" and str(published).isdigit():
            return int(published)
    return None


def default_gateway(route_text):
    m = re.search(r"^default via (\S+)", route_text or "", re.M)
    return m.group(1) if m else None


def inside_subnet(ip_text, subnet):
    """ip_text esta em subnet? Normaliza o REMOTE_ADDR observado antes de conferir: tira os
    colchetes (so' se balanceados) e trata o IPv4 mapeado em IPv6 (::ffff:a.b.c.d ou a forma
    hexa) como o a.b.c.d -- o httpd do busybox escuta em dual-stack e no CI real reportou
    `[::ffff:172.20.0.1]`. Lixo, colchete desbalanceado e IPv6 de verdade nao estao numa
    sub-rede IPv4 (False, sem excecao)."""
    text = (ip_text or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip in ipaddress.ip_network(subnet)


# ---------------------------------------------------------------------------
# Docker de verdade (so' o CI tem)
# ---------------------------------------------------------------------------
def _run(args, timeout=120):
    """Roda args. Devolve (returncode, texto): so' o stdout quando deu certo (avisos do
    docker no stderr nao podem sujar o que se parseia); stdout+stderr quando falhou (para o
    diagnostico). Estouro de tempo vira falha de comando (124), nunca excecao."""
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout apos %ss: %s" % (timeout, " ".join(args))
    return p.returncode, p.stdout if p.returncode == 0 else p.stdout + p.stderr


def _http_get(url, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:                      # qualquer falha = "sem resposta" (quem chama repete)
        return ""


class Engine(object):
    def __init__(self, workdir, run=_run, http_get=_http_get, host_port=8443):
        self.file = os.path.join(workdir, "skeleton.yml")
        self.run, self.http_get, self.host_port = run, http_get, host_port

    def _dc(self, *args, **kw):
        return self.run(["docker", "compose", "-p", PROJECT, "-f", self.file] + list(args), **kw)

    def up(self):
        for _ in range(3):                 # o Docker Hub pode limitar pulls anonimos
            rc, out = self.run(["docker", "pull", IMAGE])
            if rc == 0:
                break
            time.sleep(3)
        else:
            raise cn.InputError("docker pull %s falhou:\n%s" % (IMAGE, out))
        rc, out = self._dc("up", "-d")
        if rc != 0:
            raise cn.InputError("docker compose up falhou:\n%s" % out)

    def down(self):
        self._dc("down", "-v", "--remove-orphans")

    def reach(self, src, host, port):
        # wget -T 2: sem rota/isolado nao pode travar o job; o timeout do subprocess e' so'
        # uma rede de seguranca caso o wget do busybox ignore o -T
        rc, _ = self._dc("exec", "-T", src, "wget", "-q", "-T", "2", "-O", "/dev/null",
                         "http://%s:%d/" % (host, port), timeout=15)
        return rc == 0

    def ips(self, svc):
        rc, out = self._dc("ps", "-q", svc)
        cid = out.split()[0] if rc == 0 and out.split() else None
        if not cid:
            return []
        rc, out = self.run(["docker", "inspect", "-f",
                            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid])
        return out.split() if rc == 0 else []

    def route(self, svc):
        return self._dc("exec", "-T", svc, "ip", "route")[1]

    def net(self, key):
        rc, out = self.run(["docker", "network", "inspect", "-f",
                            "{{(index .IPAM.Config 0).Subnet}} {{(index .IPAM.Config 0).Gateway}}",
                            "%s_%s" % (PROJECT, key)])
        parts = out.split()
        if rc != 0 or len(parts) != 2:
            raise cn.InputError("docker network inspect %s_%s falhou:\n%s" % (PROJECT, key, out))
        return parts[0], parts[1]

    def host_remote_addr(self):
        m = re.search(r"REMOTE_ADDR=(\S+)",
                      self.http_get("http://127.0.0.1:%d/cgi-bin/ra" % self.host_port))
        return m.group(1) if m else None

    def diagnostics(self):
        parts = [self._dc("ps", "-a")[1], self.run(["docker", "network", "ls", "--filter",
                                                    "name=%s_" % PROJECT])[1]]
        return "\n".join(p.rstrip() for p in parts)


# ---------------------------------------------------------------------------
# Verificacoes
# ---------------------------------------------------------------------------
def wait_for(fn, seconds, step=None, sleep=time.sleep):
    """Repete fn() ate devolver algo verdadeiro ou estourar `seconds` (0 = uma tentativa)."""
    step = RETRY_STEP if step is None else step
    deadline = time.monotonic() + seconds
    while True:
        value = fn()
        if value or time.monotonic() >= deadline:
            return value
        sleep(step)


def run_checks(eng, retry_seconds=RETRY_SECONDS, host_port=None):
    out = []

    def add(kind, desc, expected, got, ok):
        out.append(Result(kind, desc, expected, got, bool(ok)))

    # 1) alcance que DEVE existir (com tempo para o httpd subir)
    for src, dst in POSITIVOS:
        port = PORTS[dst][0]
        ok = wait_for(lambda: eng.reach(src, dst, port), retry_seconds)
        add("alcance", "%s -> %s:%d" % (src, dst, port), "alcanca",
            "alcanca" if ok else "NAO alcanca", ok)

    # 2) alcance que NAO pode existir: por nome (DNS) e por IP (isolamento entre bridges)
    def negative(pair):
        src, dst = pair
        port = PORTS[dst][0]
        ips = eng.ips(dst)
        return pair, port, eng.reach(src, dst, port), ips, [ip for ip in ips if eng.reach(src, ip, port)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for (src, dst), port, by_name, ips, by_ip in ex.map(negative, NEGATIVOS):
            add("isolamento", "%s -> %s:%d por nome" % (src, dst, port), "NAO alcanca",
                "alcanca" if by_name else "NAO alcanca", not by_name)
            if not ips:
                add("isolamento", "%s -> %s por IP" % (src, dst), "NAO alcanca",
                    "sem IP (container ausente?)", False)
            else:
                add("isolamento", "%s -> %s:%d por IP (%s)" % (src, dst, port, ", ".join(ips)),
                    "NAO alcanca", ("alcanca " + ", ".join(by_ip)) if by_ip else "NAO alcanca",
                    not by_ip)

    # 3) rota padrao de cada servico
    gateways = {key: eng.net(key)[1] for key in {k for k in ROTAS.values() if k}}
    for svc, key in ROTAS.items():
        gw = default_gateway(eng.route(svc))
        got = ("default via " + gw) if gw else "sem rota padrao"
        if key is None:
            add("rota", svc, "sem rota padrao", got, gw is None)
        else:
            add("rota", svc, "default via %s (%s_%s)" % (gateways[key], PROJECT, key), got,
                gw == gateways[key])

    # 4) IP de origem do trafego que entra pela porta publicada do nginx
    subnet = eng.net("default")[0]
    ra = wait_for(eng.host_remote_addr, retry_seconds)
    add("origem", "porta publicada do nginx (127.0.0.1:%s) -> REMOTE_ADDR" % (host_port or "?"),
        "IP na sub-rede %s (%s_default)" % (subnet, PROJECT), ra or "sem resposta",
        bool(ra) and inside_subnet(ra, subnet))
    return out


def render(r):
    return "%s %-10s %-62s esperado=%-40s obtido=%s" % (
        "[ OK ]" if r.ok else "[FALHA]", r.kind, r.desc, r.expected, r.got)


def report(results, out=None):
    out = out or sys.stdout
    for r in results:
        print(render(r), file=out)
    failures = [r for r in results if not r.ok]
    print("\n%d verificacoes, %d falha(s)" % (len(results), len(failures)), file=out)
    return 1 if failures else 0


# ---------------------------------------------------------------------------
def main(compose_dir=None, runner=cn.run_docker_compose, engine_factory=None, workdir=None):
    cdir = compose_dir or os.path.dirname(HERE)
    try:
        cfg = cn.resolve_config(cdir, ["docker-compose.shared-host.yml"], runner=runner)
        skel = build_skeleton(cfg)
    except cn.InputError as e:
        print("ENTRADA INVALIDA: %s" % e)
        return 2
    workdir = workdir or os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), PROJECT)
    os.makedirs(workdir, exist_ok=True)
    with open(os.path.join(workdir, "skeleton.yml"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(skel, f, indent=2)            # JSON e' YAML valido
    port = published_port(skel)
    eng = (engine_factory or (lambda w, s: Engine(w, host_port=port or 8443)))(workdir, skel)
    try:
        try:
            eng.up()
            results = run_checks(eng, host_port=port)
        except cn.InputError as e:             # o Docker nao respondeu como o esqueleto precisa
            print("ENTRADA INVALIDA: %s\n\n-- diagnostico --\n%s" % (e, eng.diagnostics()))
            return 2
        code = report(results)
        if code:
            print("\n-- diagnostico --\n%s" % eng.diagnostics())
        return code
    finally:
        eng.down()


if __name__ == "__main__":
    sys.exit(main())
