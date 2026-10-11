#!/usr/bin/env python3
"""Confere a politica de redes do compose (isolamento do docker-socket-proxy).

POR QUE EXISTE
  Todos os servicos do projeto viviam na mesma rede. O docker-socket-proxy
  aceita POST em /containers (= criar container = root no host), o :8008 do
  feed-updater e' uma API admin sem auth propria, e o :8080 do control-plane /
  :9090 do ingest sao interfaces internas do nginx. A topologia nova (redes
  docker-api, backend e egress, declaradas em docker-compose.override.yml) tira
  gsad, gvmd e o resto da `default` do caminho -- e so vale se ninguem a desfizer
  sem querer: este script e o portao que reprova o PR quando isso acontece.

  Alcance REAL na backend (internal): nginx, control-plane, ingest e feed-updater
  se enxergam entre si. NAO e' o "so o nginx" que a remediacao exige (condicao (c)
  do WIRING-CRITICAL em control-plane/remediation/service.go): essa condicao
  continua NAO atendida e a remediacao segue DARK; o follow-up e' uma rede
  exclusiva nginx<->control-plane, com a CRL servida ao ingest por um caminho do
  nginx. Este portao NAO garante essa condicao.

USO
  # Resolve cada combinacao de COMPOSE_FILE em uso com
  # `docker compose config --format json` e confere a politica em todas
  # (CI, e dev que tenha Docker):
  python3 compose/test/check_networks.py --resolve

  # Compara o hash de recriacao do Compose (`config --hash=*`) dos servicos protegidos
  # (gvmd, ospd-openvas, pg-gvm, redis-server) entre o merge-base com a main e o HEAD,
  # por combinacao, com o mesmo binario. Precisa de historico completo (fetch-depth: 0):
  python3 compose/test/check_networks.py --hashes [--base-ref origin/main]

  # Offline: confere um JSON ja resolvido (fixture, ou saida salva do compose):
  python3 compose/test/check_networks.py arquivo.json

REGRAS (ids na saida): PRES-SVC/PRES-NET (presenca), NET-INTERNAL (flag internal),
  NET-DECL (rede local, driver padrao, nome <projeto>_<chave>), SVC-NETS (redes exatas por
  servico), NETMODE, PORTS (nao publicam porta), SOCKET (so o proxy monta o docker.sock --
  por bind, diretorio ancestral, volume nomeado com device ou volumes_from do proxy),
  COVER (todo YAML de compose/ esta em alguma combinacao) e HASH (modo --hashes).

SAIDA
  0  politica respeitada em tudo que foi conferido
  1  violacao da politica (ou o `docker compose` falhou numa combinacao)
  2  entrada que nao permite provar nada (JSON invalido, sem servicos, docker
     ausente, sem merge-base): um portao que nao consegue olhar NAO passa

O portao nao se contenta com ausencia de problema: exige a PRESENCA dos servicos
e das redes que a politica descreve, entao um JSON vazio ou truncado nao passa.

Sem dependencias fora da biblioteca padrao (roda no runner sem pip install).
"""
from __future__ import annotations

import argparse
import collections
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
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
    # Fora da default: gsad/gvmd/ospd nao chegam no :8080/:9090. Quem chega, pela backend:
    # no :8080 o nginx, o ingest (CRL) e o feed-updater; no :9090 o nginx, o control-plane
    # e o feed-updater -- NAO e' "so o nginx": a condicao (c) do WIRING-CRITICAL da
    # remediacao segue NAO atendida (follow-up: rede exclusiva nginx<->control-plane).
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

# Nunca publicam porta no host: sao alcancaveis so por rede interna. (O :8008 do
# feed-updater e' a API admin SEM auth propria; o portao dela e' o nginx.)
NO_PUBLISHED_PORTS = {"docker-socket-proxy", "control-plane", "ingest", "feed-updater"}

# Unico servico que pode montar o socket do docker (e' o proxy que o restringe).
SOCKET_OWNER = "docker-socket-proxy"
DOCKER_SOCKET_PATHS = {"/var/run/docker.sock", "/run/docker.sock"}
# Montar um destes diretorios (ou a raiz) entrega o docker.sock junto.
DOCKER_SOCKET_ANCESTORS = {"/", "/var", "/var/run", "/run"}

# YAML dentro de compose/ que NAO e' arquivo de compose (caminho relativo a compose/,
# com `/`). Vazio hoje: todo .yml/.yaml la dentro precisa estar em alguma combinacao.
IGNORED_YAML = set()

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

# Servicos cujo HASH DE RECRIACAO do Compose nao pode mudar: e' o criterio que o proprio
# Compose usa para decidir recriar um container no `up`. Recriar o ospd-openvas mata o scan
# em curso (e o gvmd/pg-gvm/redis-server derrubam o que ele usa). Comparar com o hash da
# main, com o MESMO binario do Compose, prova que o deploy nao encosta neles.
HASH_PROTECTED = ("gvmd", "ospd-openvas", "pg-gvm", "redis-server")
DEFAULT_BASE_REF = "origin/main"

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
    # O nome do projeto prefixa o nome real de toda rede (<projeto>_<chave>): sem ele
    # nao se confere NET-DECL, e portao que nao consegue conferir nao aprova.
    if not isinstance(cfg.get("name"), str) or not cfg["name"]:
        raise InputError("sem `name` (projeto) no topo: nao da para conferir o nome das redes")


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


def _socket_path_note(path):
    """Se `path` (caminho ABSOLUTO do host) e' o docker.sock ou um diretorio que o contem,
    devolve uma descricao; senao None."""
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    norm = posixpath.normpath(path)                  # '/var/run/' -> '/var/run'
    if norm in DOCKER_SOCKET_PATHS or posixpath.basename(norm) == "docker.sock":
        return "%s (o proprio socket)" % path
    if norm in DOCKER_SOCKET_ANCESTORS:
        return "%s (diretorio que contem o docker.sock)" % path
    return None


def socket_mounts(svc):
    """Descricao dos volumes do servico que expoem o docker.sock (ou um diretorio que o contem).

    O compose emite `volumes` como lista de objetos {type, source, target, ...}; aceita-se
    tambem a sintaxe curta ("origem:destino[:modo]"). Fail-safe: o `type` declarado nao
    desativa a conferencia -- so conta a ORIGEM ser um caminho absoluto do host (volume
    nomeado e tmpfs nao tem origem assim).
    """
    found = []
    for vol in svc.get("volumes") or []:
        if isinstance(vol, dict):
            source = vol.get("source")
        elif isinstance(vol, str):
            source = vol.split(":", 1)[0]
        else:
            continue
        note = _socket_path_note(source)
        if note:
            found.append(note)
    return found


def volumes_from_refs(svc):
    """Nomes que o servico referencia em `volumes_from`: "servico[:ro|rw]",
    "service:servico[:ro|rw]" ou "container:nome[:ro|rw]". Entrada que nao e' texto, vazia ou
    so' com o prefixo e' ignorada (sem excecao)."""
    refs = []
    for entry in svc.get("volumes_from") or []:
        if not isinstance(entry, str):
            continue
        parts = entry.strip().split(":")
        if len(parts) > 1 and parts[-1] in ("ro", "rw"):
            parts = parts[:-1]
        if len(parts) > 1 and parts[0] in ("service", "container"):
            parts = parts[1:]
        ref = ":".join(parts)
        if ref:
            refs.append(ref)
    return refs


def _inherits(ref, guarded):
    """`ref` (de um volumes_from) herda o socket? Ou e' um servico guardado, ou -- na forma
    `container:` -- um container cujo nome carrega o do proxy (<projeto>-docker-socket-proxy-1)."""
    return ref in guarded or SOCKET_OWNER in ref


def socket_volumes(cfg):
    """{volume nomeado: descricao} dos volumes de topo que sao um bind do docker.sock
    disfarcado (driver_opts.device apontando para o socket ou um diretorio que o contem)."""
    found = {}
    for vname, vconf in (cfg.get("volumes") or {}).items():
        opts = vconf.get("driver_opts") if isinstance(vconf, dict) else None
        note = _socket_path_note((opts or {}).get("device")) if isinstance(opts, dict) else None
        if note:
            found[vname] = note
    return found


def covered_yaml():
    """Arquivos de compose (relativos a compose/) que alguma combinacao usa."""
    files = set(BASE_FILES)
    for _, extra in COMBOS:
        files.update(extra)
    return sorted(files)


def find_uncovered_yaml(compose_dir):
    """YAML dentro de compose/ (recursivo, .yml e .yaml) que nenhuma combinacao usa e que
    IGNORED_YAML nao libera. Overlay novo fora das combinacoes = rede nunca conferida."""
    covered = set(covered_yaml()) | set(IGNORED_YAML)
    root_dir = os.path.abspath(compose_dir)
    found = []
    for root, dirs, files in os.walk(root_dir):
        skip = {"__pycache__", ".git"}
        if os.path.abspath(root) == root_dir:
            skip.add("test")             # o diretorio de testes (fixtures) nao e' compose
        dirs[:] = sorted(d for d in dirs if d not in skip)
        for fname in sorted(files):
            if fname.endswith((".yml", ".yaml")):
                rel = os.path.relpath(os.path.join(root, fname), root_dir).replace(os.sep, "/")
                if rel not in covered:
                    found.append(rel)
    return sorted(found)


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

    # NET-DECL: toda rede e' uma bridge LOCAL do projeto, com o nome <projeto>_<chave>.
    # Sem isto `backend: {name: <proj>_default}` passaria (as chaves estao certas, mas
    # a "backend" seria a propria default), e `external`/outro driver trocariam o que
    # enxerga o que sem aparecer nas chaves.
    project = cfg["name"]
    for key in sorted(declared):
        conf = declared[key] if isinstance(declared[key], dict) else {}
        if conf.get("external"):
            out.append(Violation(
                "NET-DECL", "rede %s e `external`: ela existe fora deste projeto e ninguem "
                "aqui controla quem mais esta nela" % key))
        driver = conf.get("driver")
        if driver not in (None, "", "bridge"):
            out.append(Violation(
                "NET-DECL", "rede %s usa driver=%s: o isolamento depende do driver padrao "
                "(bridge); host/overlay/macvlan/null mudam o que enxerga o que" % (key, driver)))
        want_name = "%s_%s" % (project, key)
        if conf.get("name") != want_name:
            out.append(Violation(
                "NET-DECL", "rede %s: name=%r, esperado %r (um `name:` apontando p/ outra rede, "
                "ex. a default, desfaz o isolamento sem mudar as chaves)"
                % (key, conf.get("name"), want_name)))

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

    # SOCKET: so o docker-socket-proxy monta o docker.sock (ou um diretorio que o contem).
    # O socket e' root no host; o proxy e' quem restringe a API a containers/imagens/redes.
    owners = set()
    for name in sorted(services):
        mounts = socket_mounts(services[name])
        if mounts:
            owners.add(name)
            if name != SOCKET_OWNER:
                out.append(Violation(
                    "SOCKET", "%s monta o socket do docker (%s): so o %s pode -- o socket e' "
                    "root no host e o proxy e' quem restringe a API"
                    % (name, "; ".join(mounts), SOCKET_OWNER)))
    if SOCKET_OWNER in services and SOCKET_OWNER not in owners:
        out.append(Violation(
            "SOCKET", "%s nao monta o docker.sock: o feed-updater ficaria sem docker (e a "
            "regra de dono unico perderia o sentido)" % SOCKET_OWNER))
    for vname, note in sorted(socket_volumes(cfg).items()):
        out.append(Violation(
            "SOCKET", "o volume nomeado %s aponta (driver_opts.device) para %s: e um bind do "
            "docker.sock disfarcado de volume nomeado" % (vname, note)))

    # SOCKET (volumes_from): herdar os volumes do proxy -- ou de quem monta o socket, ou de
    # quem herda de um deles -- e' ter o socket montado sem declarar nenhum `volumes:`.
    refs = {name: volumes_from_refs(services[name]) for name in services}
    guarded = {SOCKET_OWNER} | owners
    changed = True
    while changed:                                           # fecho transitivo (e termina em ciclo)
        changed = False
        for name in sorted(services):
            if name not in guarded and any(_inherits(r, guarded) for r in refs[name]):
                guarded.add(name)
                changed = True
    for name in sorted(services):
        if name == SOCKET_OWNER:
            continue
        for ref in refs[name]:
            if _inherits(ref, guarded):
                out.append(Violation(
                    "SOCKET", "%s usa volumes_from %s: herdaria os volumes de %s, inclusive o "
                    "docker.sock -- so o %s pode ter o socket" % (name, ref, ref, SOCKET_OWNER)))

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
    # COVER: YAML novo em compose/ fora das combinacoes e' rede nunca conferida.
    for rel in find_uncovered_yaml(compose_dir):
        print("  REPROVADO [COVER] %s: YAML em compose/ fora de qualquer combinacao conferida "
              "(acrescente-o a COMBOS em check_networks.py, ou a IGNORED_YAML se nao for "
              "arquivo de compose)" % rel, file=out)
        worst = 1
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


def resolve_config(compose_dir, extra_files=(), runner=run_docker_compose):
    """`docker compose config --format json` de BASE_FILES + extra_files (com o --env-file
    ficticio) -> dict. Usado pela pilha-esqueleto (skeleton_stack.py)."""
    tmp = tempfile.mkdtemp(prefix="compose-config-")
    try:
        envfile = os.path.join(tmp, "exemplo.env")
        with open(envfile, "w", encoding="utf-8", newline="\n") as f:
            f.write(FICTITIOUS_ENV)
        args = ["--env-file", envfile]
        for name in BASE_FILES + list(extra_files):
            args += ["-f", name]
        args += ["config", "--format", "json"]
        rc, stdout, stderr = runner(args, compose_dir, _clean_env())
        if rc != 0:
            raise InputError("`docker compose config` falhou (exit %d):\n%s"
                             % (rc, _indent(stderr or stdout)))
        try:
            return json.loads(stdout)
        except ValueError as e:
            raise InputError("saida do compose nao e JSON (%s)" % e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _indent(text, prefix="    "):
    return "\n".join(prefix + line for line in (text or "").rstrip().splitlines())


# ---------------------------------------------------------------------------
# Modo --hashes: o deploy nao pode recriar gvmd/ospd-openvas/pg-gvm/redis-server
# ---------------------------------------------------------------------------
_HASH_LINE = re.compile(r"^(\S+)\s+([0-9a-fA-F]{16,})$")


def parse_hashes(text):
    """Saida de `docker compose config --hash=*` ("<servico> <hash>" por linha) -> dict.
    Linhas fora do formato (avisos) sao ignoradas; nenhuma linha valida = InputError."""
    out = {}
    for line in text.splitlines():
        m = _HASH_LINE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).lower()
    if not out:
        raise InputError("a saida de `docker compose config --hash` nao trouxe nenhuma "
                         "linha 'servico hash'")
    return out


def compare_hashes(base, head, protected=HASH_PROTECTED):
    """Compara {servico: hash} da base e do HEAD. Devolve (violacoes, mudancas): mudancas =
    [(servico, 'alterado'|'novo'|'removido')] ordenada; violacao = protegido alterado/removido."""
    changed = []
    for svc in sorted(set(base) | set(head)):
        if svc not in base:
            changed.append((svc, "novo"))
        elif svc not in head:
            changed.append((svc, "removido"))
        elif base[svc] != head[svc]:
            changed.append((svc, "alterado"))
    kinds = dict(changed)
    violations = []
    for svc in protected:
        if svc not in head:
            # removido do HEAD, ou ausente nas duas pontas (renomeado): nao ha o que provar
            # sobre ele, e portao que nao consegue provar nao aprova
            violations.append(Violation(
                "HASH", "%s: ausente do config do HEAD (%s) -- o hash de recriacao nao pode ser "
                "conferido e o deploy o removeria/recriaria"
                % (svc, "removido" if svc in base else "nem a base o tem")))
        elif kinds.get(svc) == "alterado":
            violations.append(Violation(
                "HASH", "%s: hash de recriacao alterado em relacao a base -- o deploy recriaria o "
                "servico (ospd-openvas/gvmd: mata scan em curso)" % svc))
    return violations, changed


def _git(repo_root, *args):
    """git -C repo_root <args>. Devolve (returncode, stdout bytes, stderr texto)."""
    try:
        p = subprocess.run(["git", "-C", repo_root] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise InputError("git indisponivel: %s" % e)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace").strip()


def _export_compose(repo_root, rev, dest):
    """Extrai compose/ de `rev` em dest/compose (git archive: nao toca o checkout)."""
    rc, data, err = _git(repo_root, "archive", "--format=tar", rev, "compose")
    if rc != 0:
        raise InputError("git archive %s compose falhou: %s" % (rev[:10], err))
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar.getmembers():
            if m.issym() or m.islnk() or m.name.startswith("/") or ".." in m.name.split("/"):
                raise InputError("entrada suspeita no git archive: %r" % m.name)
        try:
            tar.extractall(dest, filter="data")
        except TypeError:                                    # Python sem o parametro `filter`
            tar.extractall(dest)


def hash_gate(repo_root, base_ref=DEFAULT_BASE_REF, runner=run_docker_compose, out=None):
    """Compara, por combinacao, o hash de recriacao de cada servico entre o merge-base do HEAD
    com `base_ref` e o HEAD. Devolve 0 (ok), 1 (protegido mudou) ou 2 (nao deu para conferir).

    Base e HEAD sao exportados (git archive) SEQUENCIALMENTE para o MESMO diretorio e
    resolvidos com o MESMO --env-file e o MESMO binario: o hash do Compose leva nos labels o
    diretorio de trabalho, os caminhos dos -f, o --env-file e a versao do Compose; com
    qualquer um deles diferente TODO servico mudaria de hash.
    """
    out = out or sys.stdout
    tmp = tempfile.mkdtemp(prefix="compose-hashes-")
    try:
        try:
            rc, so, err = _git(repo_root, "rev-parse", "HEAD")
            if rc != 0:
                raise InputError("git rev-parse HEAD falhou: %s" % err)
            head = so.decode().strip()
            rc, so, err = _git(repo_root, "merge-base", "HEAD", base_ref)
            if rc != 0 or not so.strip():
                raise InputError("nao achei o merge-base de HEAD com %r (%s). Clone raso? Use "
                                 "actions/checkout com `fetch-depth: 0`." % (base_ref, err))
            base = so.decode().strip()
            print("== hash de recriacao (docker compose config --hash=*): base=%s head=%s =="
                  % (base[:10], head[:10]), file=out)
            if base == head:
                print("  HEAD e o merge-base com %s: nada a comparar." % base_ref, file=out)
                return 0
            envfile = os.path.join(tmp, "exemplo.env")
            with open(envfile, "w", encoding="utf-8", newline="\n") as f:
                f.write(FICTITIOUS_ENV)
            env = _clean_env()
            work = os.path.join(tmp, "work")
            hashes = {}
            for side, rev in (("base", base), ("head", head)):
                shutil.rmtree(work, ignore_errors=True)
                os.makedirs(work)
                _export_compose(repo_root, rev, work)
                cdir = os.path.join(work, "compose")
                hashes[side] = {}
                for label, extra in COMBOS:
                    files = BASE_FILES + extra
                    if not all(os.path.exists(os.path.join(cdir, name)) for name in files):
                        hashes[side][label] = None
                        continue
                    args = ["--env-file", envfile]
                    for name in files:
                        args += ["-f", name]
                    args += ["config", "--hash=*"]
                    rc, stdout, stderr = runner(args, cdir, env)
                    if rc != 0:
                        raise InputError("`docker compose config --hash` falhou em %r (%s, exit "
                                         "%d):\n%s" % (label, side, rc, _indent(stderr or stdout)))
                    hashes[side][label] = parse_hashes(stdout)
        except InputError as e:
            print("  ENTRADA INVALIDA: %s" % e, file=out)
            return 2

        if not any(hashes["base"][label] is not None and hashes["head"][label] is not None
                   for label, _ in COMBOS):
            print("  ENTRADA INVALIDA: nenhuma combinacao comparavel (a base ou o HEAD nao tem os "
                  "arquivos de nenhuma combinacao): nada foi provado", file=out)
            return 2

        worst = 0
        for label, _ in COMBOS:
            b, h = hashes["base"][label], hashes["head"][label]
            print("-- %s --" % label, file=out)
            if b is None:
                print("  sem base para comparar: a combinacao usa arquivo(s) que a base nao tem "
                      "(overlay novo)", file=out)
                continue
            if h is None:
                print("  a combinacao nao existe no HEAD (overlay removido): nada a comparar",
                      file=out)
                continue
            violations, changed = compare_hashes(b, h)
            for kind in ("alterado", "novo", "removido"):
                names = [s for s, k in changed if k == kind]
                if names:
                    note = " (sera RECRIADO no deploy)" if kind == "alterado" else ""
                    print("  hash %s%s: %s" % (kind, note, ", ".join(names)), file=out)
            if not changed:
                print("  nenhum servico mudou de hash", file=out)
            kept = [s for s in HASH_PROTECTED if s in b and s in h and b[s] == h[s]]
            print("  protegidos sem mudanca: %s" % (", ".join(kept) or "(nenhum)"), file=out)
            for v in violations:
                print("  REPROVADO [%s] %s (combinacao %s)" % (v.rule, v.message, label), file=out)
                worst = 1
        if worst:
            print("  => o deploy desta mudanca recriaria servico(s) protegido(s)", file=out)
        else:
            print("  OK: o hash de recriacao dos servicos protegidos nao mudou", file=out)
        return worst
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
    ap.add_argument("--hashes", action="store_true",
                    help="compara o hash de recriacao do Compose dos servicos protegidos entre "
                         "o merge-base com --base-ref e o HEAD (precisa de historico completo)")
    ap.add_argument("--base-ref", default=DEFAULT_BASE_REF,
                    help="ref da base do --hashes (padrao: %(default)s)")
    ap.add_argument("files", nargs="*", help="JSON(s) ja resolvido(s) (modo offline)")
    args = ap.parse_args(argv)
    if int(args.resolve) + int(args.hashes) + int(bool(args.files)) != 1:
        ap.error("use UM modo: --resolve, --hashes ou um ou mais arquivos JSON")
    cdir = compose_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if args.resolve:
        return resolve_all(cdir, runner=runner)
    if args.hashes:
        return hash_gate(os.path.dirname(os.path.abspath(cdir)), args.base_ref, runner=runner)
    return check_files(args.files)


if __name__ == "__main__":
    sys.exit(main())
