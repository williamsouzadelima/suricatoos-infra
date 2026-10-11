#!/usr/bin/env python3
"""Confere a politica de redes do compose (isolamento do docker-socket-proxy).

POR QUE EXISTE
  Todos os servicos do projeto viviam na mesma rede. O docker-socket-proxy
  aceita POST em /containers (= criar container = root no host) e o :8080 do
  control-plane / :9090 do ingest assumem que SO o nginx chega neles. A topologia
  nova (redes docker-api, backend e egress, declaradas em
  docker-compose.override.yml) so vale se ninguem a desfizer sem querer: este
  script e o portao que reprova o PR quando isso acontece.

USO
  # Resolve cada combinacao de COMPOSE_FILE em uso com
  # `docker compose config --format json` e confere a politica em todas
  # (CI, e dev que tenha Docker):
  python3 compose/test/check_networks.py --resolve

  # Offline: confere um JSON ja resolvido (fixture, ou saida salva do compose):
  python3 compose/test/check_networks.py arquivo.json

SAIDA
  0  politica respeitada em tudo que foi conferido
  1  violacao da politica (ou o `docker compose` falhou numa combinacao)
  2  entrada que nao permite provar nada (JSON invalido, sem servicos, docker
     ausente): um portao que nao consegue olhar NAO passa

O portao nao se contenta com ausencia de problema: exige a PRESENCA dos servicos
e das redes que a politica descreve, entao um JSON vazio ou truncado nao passa.

Sem dependencias fora da biblioteca padrao (roda no runner sem pip install).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# POLITICA - fonte unica da verdade. Mudar uma linha aqui e uma decisao de
# arquitetura: o diff precisa ser revisado como tal (e o override do compose
# atualizado junto). Racional completo no bloco `networks:` do
# compose/docker-compose.override.yml.
# ---------------------------------------------------------------------------
DEFAULT = "default"

# Servicos com redes FIXADAS (conjunto exato). Todo servico fora desta tabela
# precisa estar SOMENTE na `default` - e isso inclui, de proposito, gvmd,
# ospd-openvas, pg-gvm e redis-server: mudar a rede de um servico muda o hash da
# config dele, e o deploy passaria a recria-lo (recriar o ospd-openvas mata scan
# em curso).
PINNED = {
    # Unico elo com a API do docker (= root no host): so na docker-api.
    "docker-socket-proxy": {"docker-api"},
    # Fala com o gsad (default), publica as portas (default) e alcanca
    # control-plane/ingest/feed-updater (backend).
    "nginx": {DEFAULT, "backend"},
    # FORA da default: o :8008 e' a API admin SEM auth propria (o portao e' o nginx),
    # entao gsad/ospd/gvmd nao podem alcanca-lo. docker-api: o proxy; backend: upstream
    # HTTP do nginx; egress: o espelho MSRC baixa da internet de dentro do container
    # (os pulls de imagem sao do daemon, via proxy).
    "feed-updater": {"docker-api", "backend", "egress"},
    # Fora da default: so o nginx (e o ingest, p/ a CRL) chegam no :8080/:9090.
    # egress: planner de IA / push p/ o Score precisam de saida p/ internet.
    "control-plane": {"backend", "egress"},
    "ingest": {"backend", "egress"},
}

# Redes que o projeto declara - nem mais, nem menos - e se sao `internal`.
EXPECTED_NETWORKS = {
    DEFAULT: False,      # portas publicadas do nginx
    "docker-api": True,  # sem rota p/ fora: so proxy + feed-updater
    "backend": True,     # sem rota p/ fora; nao pode virar gateway do nginx
    "egress": False,     # internal cortaria a saida de control-plane/ingest/feed-updater
}

# Servicos que a politica cita por nome e que PRECISAM existir no config
# resolvido (presenca, nao so ausencia de problema).
REQUIRED_SERVICES = set(PINNED) | {
    "gsad", "gvmd", "ospd-openvas", "pg-gvm", "redis-server",
}

# Nunca publicam porta no host: sao alcancaveis so por rede interna.
NO_PUBLISHED_PORTS = {"docker-socket-proxy", "control-plane", "ingest"}

# Por que cada flag `internal` e' o que e' (vai na mensagem quando alguem a muda).
WHY_INTERNAL = {
    "docker-api": "sem `internal: true` a docker-api ganha rota p/ fora",
    "backend": "sem `internal: true` a backend pode virar o gateway do nginx: as portas "
               "publicadas e o IP real do cliente (set_real_ip_from 172.16.0.0/12 em "
               "nginx/default.conf) passariam a depender dela. Se control-plane/ingest "
               "precisam de saida p/ internet, ela vem da egress, nao de tirar o internal",
    DEFAULT: "`internal: true` na default derruba as portas publicadas do nginx",
    "egress": "`internal: true` corta a saida p/ internet de control-plane/ingest/feed-updater "
              "(planner de IA, push dos achados do sensor p/ o Score, espelho MSRC)",
}

WHY_NETWORK = {
    "docker-api": "docker-api e o unico caminho ate a API do docker (= root no host): "
                  "so docker-socket-proxy e feed-updater",
    "backend": "backend e a rede dos upstreams HTTP do nginx (control-plane, ingest, "
               "feed-updater): quem mais entrar enxerga :8080/:9090",
    "egress": "egress e so do control-plane, do ingest e do feed-updater (saida p/ internet)",
    DEFAULT: "a default e a rede do motor do GVM: control-plane/ingest/feed-updater e o "
             "proxy do docker ficam FORA dela",
}

# Combinacoes de COMPOSE_FILE em uso (relativas a compose/). As duas primeiras
# entradas de arquivos valem sempre; o resto e o que cada perfil acrescenta.
BASE_FILES = ["compose.yaml", "docker-compose.override.yml"]
COMBOS = [
    ("override", []),
    ("shared-host", ["docker-compose.shared-host.yml"]),
    ("shared-host+scap-order",
     ["docker-compose.shared-host.yml", "docker-compose.scap-order.yml"]),
    ("standalone", ["docker-compose.standalone.yml"]),
]

# Valores FICTICIOS, so p/ interpolar o compose neste teste (repo publico: nada
# de IP/host/dominio real). 192.0.2.0/24 e a faixa de documentacao (RFC 5737).
# Passar --env-file tambem impede que um compose/.env real do host seja lido.
FICTITIOUS_ENV = (
    "# Valores ficticios so p/ interpolar o compose neste teste.\n"
    "SCANNER_BIND_IP=192.0.2.10\n"
    "COMPOSE_DIR_HOST=/srv/exemplo/compose\n"
)

Violation = collections.namedtuple("Violation", "rule message")


class InputError(Exception):
    """Entrada que nao permite conferir nada (exit 2)."""


# ---------------------------------------------------------------------------
# Leitura do config resolvido
# ---------------------------------------------------------------------------
def validate_shape(cfg):
    """Garante o minimo para conferir; senao InputError (um portao cego nao passa)."""
    if not isinstance(cfg, dict):
        raise InputError("raiz do JSON nao e um objeto")
    services = cfg.get("services")
    if not isinstance(services, dict) or not services:
        raise InputError("sem `services` (ou vazio): nada a conferir")
    for name, svc in services.items():
        if not isinstance(svc, dict):
            raise InputError("servico %r nao e um objeto" % (name,))
    nets = cfg.get("networks")
    if nets is not None and not isinstance(nets, dict):
        raise InputError("`networks` de topo nao e um objeto")


def service_networks(svc):
    """Redes de um servico no JSON resolvido.

    O compose emite `networks` como mapa {rede: config|null}; aceita-se lista
    tambem. Servico sem `networks` (e sem `network_mode`) cai na `default` - o
    compose normaliza assim, mas a conferencia nao depende de isso vir escrito.
    """
    nets = svc.get("networks")
    if isinstance(nets, dict):
        return set(nets)
    if isinstance(nets, list):
        return set(str(n) for n in nets)
    if nets is None:
        return set() if svc.get("network_mode") else {DEFAULT}
    raise InputError("`networks` de servico com formato inesperado: %r" % (nets,))


def members(cfg):
    """{rede: {servicos}} derivado do config resolvido."""
    out = collections.defaultdict(set)
    for name, svc in cfg["services"].items():
        for net in service_networks(svc):
            out[net].add(name)
    return out


# ---------------------------------------------------------------------------
# Conferencia
# ---------------------------------------------------------------------------
def _fmt(items):
    items = sorted(items)
    return "{" + ", ".join(items) + "}" if items else "{}"


def check(cfg):
    """Devolve a lista de Violation (vazia = dentro da politica)."""
    validate_shape(cfg)
    services = cfg["services"]
    declared = cfg.get("networks") or {}
    out = []

    # PRES-SVC: presenca. Sem isto, renomear/remover um servico faria a
    # conferencia dele passar no vazio.
    for name in sorted(REQUIRED_SERVICES - set(services)):
        out.append(Violation(
            "PRES-SVC", "servico %s ausente do config resolvido (a politica o cita; "
            "se foi renomeado/removido de proposito, atualize a politica)" % name))

    # PRES-NET: o conjunto de redes declaradas e EXATAMENTE o da politica. A
    # `default` e' implicita no Compose (nasce quando algum servico a usa, e o
    # `config` costuma lista-la): se ela faltar no topo do JSON mas houver servico
    # nela, nao e' violacao -- o que a politica precisa e' das redes NOVAS declaradas.
    implicit_default = any(DEFAULT in service_networks(svc) for svc in services.values())
    for name in sorted(set(EXPECTED_NETWORKS) - set(declared)):
        if name == DEFAULT and implicit_default:
            continue
        out.append(Violation("PRES-NET", "rede %s nao declarada" % name))
    for name in sorted(set(declared) - set(EXPECTED_NETWORKS)):
        out.append(Violation(
            "PRES-NET", "rede %s declarada mas fora da politica (uma rede nova, "
            "ainda mais `external`, muda o que enxerga o que: revise e atualize a "
            "politica)" % name))

    # NET-INTERNAL: flags. docker-api/backend internal; default/egress NAO.
    for name, want in sorted(EXPECTED_NETWORKS.items()):
        if name not in declared:
            continue
        conf = declared[name] or {}
        got = bool(conf.get("internal", False)) if isinstance(conf, dict) else False
        if got != want:
            why = WHY_INTERNAL.get(name, "flag `internal` fora da politica")
            out.append(Violation(
                "NET-INTERNAL", "rede %s: internal=%s, esperado %s (%s)"
                % (name, str(got).lower(), str(want).lower(), why)))

    # SVC-NETS: conjunto exato de redes por servico.
    for name in sorted(services):
        svc = services[name]
        got = service_networks(svc)
        want = PINNED.get(name, {DEFAULT})
        if got == want:
            continue
        extra, missing = got - want, want - got
        parts = []
        if extra:
            parts.append("a mais: %s" % _fmt(extra))
        if missing:
            parts.append("faltando: %s" % _fmt(missing))
        notes = [WHY_NETWORK[n] for n in sorted(extra) if n in WHY_NETWORK]
        if name == "feed-updater" and DEFAULT in extra:
            notes.append("o :8008 e a API admin SEM auth do feed-updater (o portao e o nginx): "
                         "na default o gsad/ospd/gvmd a alcancariam")
        if name == "feed-updater" and "egress" in missing:
            notes.append("sem a egress o espelho MSRC (download de dentro do container) "
                         "fica sem saida")
        if name not in PINNED:
            notes.append("servico do upstream/sem regra propria: so na default; mudar a "
                         "rede dele muda o hash da config e o deploy o RECRIA (gvmd/"
                         "ospd-openvas: mata scan em curso)")
        if name == "nginx" and DEFAULT in missing:
            notes.append("declarar `networks:` num servico remove a default implicita: "
                         "liste `default` de novo")
        out.append(Violation(
            "SVC-NETS", "%s: redes %s, esperado %s -- %s%s"
            % (name, _fmt(got), _fmt(want), "; ".join(parts),
               (" (" + " | ".join(notes) + ")") if notes else "")))

    # NETMODE: network_mode contorna toda a segmentacao (host/container:).
    for name in sorted(services):
        mode = services[name].get("network_mode")
        if mode:
            out.append(Violation(
                "NETMODE", "%s usa network_mode=%s: contorna as redes isoladas"
                % (name, mode)))

    # PORTS: o que e interno nao publica porta no host.
    for name in sorted(NO_PUBLISHED_PORTS & set(services)):
        ports = services[name].get("ports")
        if ports:
            out.append(Violation(
                "PORTS", "%s publica porta(s) no host (%d): deve ser alcancavel so por "
                "rede interna" % (name, len(ports))))

    return out


def render_table(cfg):
    """Tabela legivel (servico -> redes, rede -> membros) p/ o log do CI."""
    services = cfg["services"]
    declared = cfg.get("networks") or {}
    lines = []
    width = max(len(n) for n in services)
    lines.append("  %-*s  redes" % (width, "servico"))
    for name in sorted(services):
        lines.append("  %-*s  %s" % (width, name, ", ".join(sorted(service_networks(services[name])))))
    mem = members(cfg)
    lines.append("")
    nwidth = max([len(n) for n in set(declared) | set(mem)] + [4])
    lines.append("  %-*s  internal  membros" % (nwidth, "rede"))
    for net in sorted(set(declared) | set(mem)):
        conf = declared.get(net) or {}
        internal = bool(conf.get("internal", False)) if isinstance(conf, dict) else False
        who = sorted(mem.get(net, ()))
        if net == DEFAULT and len(who) > 8:
            others = sorted(set(services) - set(who))
            shown = "%d servicos (%s)" % (
                len(who), ("todos menos " + ", ".join(others)) if others else "todos")
        else:
            shown = ", ".join(who)
        lines.append("  %-*s  %-8s  %s" % (nwidth, net, "sim" if internal else "nao", shown))
    return "\n".join(lines)


def report(label, cfg, out=None):
    """Imprime a tabela + violacoes de um config. Devolve 0 (ok) ou 1."""
    out = out or sys.stdout
    violations = check(cfg)
    print("== %s ==" % label, file=out)
    print(render_table(cfg), file=out)
    if violations:
        print("", file=out)
        for v in violations:
            print("  REPROVADO [%s] %s" % (v.rule, v.message), file=out)
        print("  => %d violacao(oes) da politica de redes em %r" % (len(violations), label),
              file=out)
        return 1
    print("", file=out)
    print("  OK: politica de redes respeitada (%d servicos, %d redes)"
          % (len(cfg["services"]), len(cfg.get("networks") or {})), file=out)
    return 0


# ---------------------------------------------------------------------------
# Modo --resolve: docker compose config --format json por combinacao
# ---------------------------------------------------------------------------
def _clean_env():
    """Ambiente sem COMPOSE_*: o resultado nao pode depender do shell de quem roda."""
    return {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}


def run_docker_compose(args, cwd, env):
    """Executa `docker compose <args>`. Devolve (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            ["docker", "compose"] + list(args), cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, encoding="utf-8", errors="replace", timeout=180)
    except FileNotFoundError:
        raise InputError("`docker` nao encontrado no PATH (sem Docker, confira um JSON ja "
                         "resolvido: check_networks.py arquivo.json)")
    except subprocess.TimeoutExpired:
        raise InputError("`docker compose config` excedeu 180s")
    return p.returncode, p.stdout, p.stderr


def resolve_all(compose_dir, runner=run_docker_compose, out=None):
    """Resolve e confere TODAS as combinacoes. Devolve o exit code (0/1/2)."""
    out = out or sys.stdout
    tmp = tempfile.mkdtemp(prefix="compose-networks-")
    worst = 0
    try:
        envfile = os.path.join(tmp, "exemplo.env")
        with open(envfile, "w", encoding="utf-8", newline="\n") as f:
            f.write(FICTITIOUS_ENV)
        env = _clean_env()
        for label, extra in COMBOS:
            files = BASE_FILES + extra
            args = ["--env-file", envfile]
            for name in files:
                args += ["-f", name]
            args += ["config", "--format", "json"]
            print("$ docker compose -f %s config --format json" % " -f ".join(files), file=out)
            try:
                rc, stdout, stderr = runner(args, compose_dir, env)
                if rc != 0:
                    print("  FALHOU `docker compose config` em %r (exit %d):\n%s"
                          % (label, rc, _indent(stderr or stdout)), file=out)
                    worst = max(worst, 1)
                    continue
                try:
                    cfg = json.loads(stdout)
                except ValueError as e:
                    raise InputError("saida do compose nao e JSON (%s)" % e)
                worst = max(worst, report(label, cfg, out))
            except InputError as e:
                print("  ENTRADA INVALIDA em %r: %s" % (label, e), file=out)
                worst = max(worst, 2)
            print("", file=out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return worst


def _indent(text, prefix="    "):
    return "\n".join(prefix + line for line in (text or "").rstrip().splitlines())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def check_files(paths, out=None):
    worst = 0
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            worst = max(worst, report(path, cfg, out))
        except (OSError, ValueError, InputError) as e:
            print("== %s ==\n  ENTRADA INVALIDA: %s\n" % (path, e), file=out or sys.stdout)
            worst = max(worst, 2)
    return worst


def main(argv=None, runner=run_docker_compose, compose_dir=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(
        description="Confere a politica de redes do compose (ver docstring do modulo).")
    ap.add_argument("--resolve", action="store_true",
                    help="resolve as combinacoes de COMPOSE_FILE com `docker compose config`")
    ap.add_argument("files", nargs="*", help="JSON(s) ja resolvido(s) (modo offline)")
    args = ap.parse_args(argv)
    if args.resolve == bool(args.files):
        ap.error("use --resolve OU informe um ou mais arquivos JSON (nao os dois, nem nenhum)")
    if args.resolve:
        cdir = compose_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return resolve_all(cdir, runner=runner)
    return check_files(args.files)


if __name__ == "__main__":
    sys.exit(main())
