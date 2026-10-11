"""Testes do portao de redes (check_networks.py): controle positivo + MUTACOES.

Um portao so vale se reprova de verdade. Aqui cada violacao da politica que
importa e fabricada sobre uma fixture saudavel (fixtures/resolved-ok.json,
escrita a mao no formato de `docker compose config --format json`) e o portao
TEM de reprovar - no codigo e no exit code do CLI. O modo --resolve roda contra
um `docker compose` simulado, entao nada aqui precisa de Docker.

    python3 -m unittest discover -s compose/test -v
"""
import contextlib
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_networks as cn  # noqa: E402

COMPOSE_DIR = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, "check_networks.py")
FIXTURE = os.path.join(HERE, "fixtures", "resolved-ok.json")
WORKFLOW = os.path.join(os.path.dirname(COMPOSE_DIR), ".github", "workflows", "compose-ci.yml")


def load_ok():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def add_net(cfg, svc, net):
    cfg["services"][svc].setdefault("networks", {})[net] = None


def drop_net(cfg, svc, net):
    del cfg["services"][svc]["networks"][net]


def bind(src, dst, ro=False):
    """Volume de bind no formato (forma longa) que o `docker compose config` emite."""
    v = {"type": "bind", "source": src, "target": dst, "bind": {"create_host_path": True}}
    if ro:
        v["read_only"] = True
    return v


def add_volume(cfg, svc, vol):
    cfg["services"][svc].setdefault("volumes", []).append(vol)


def hits(cfg, rule, needle):
    """Violacoes da regra `rule` cuja mensagem cita `needle`."""
    return [v for v in cn.check(cfg) if v.rule == rule and needle in v.message]


def run_cli(*args):
    p = subprocess.run(
        [sys.executable, SCRIPT] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, encoding="utf-8", errors="replace", timeout=60)
    return p.returncode, p.stdout + p.stderr


class WithTmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def write(self, cfg, name="resolved.json"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        return path


class PositiveControl(WithTmp):
    """Sem controle positivo nao se sabe se o portao reprova ou se esta cego."""

    def test_fixture_is_within_policy(self):
        self.assertEqual(cn.check(load_ok()), [])

    def test_cli_exits_zero_on_fixture(self):
        rc, out = run_cli(FIXTURE)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK: politica de redes respeitada", out)

    def test_policy_is_self_consistent(self):
        for svc, nets in cn.PINNED.items():
            self.assertTrue(nets <= set(cn.EXPECTED_NETWORKS), svc)
        # o que a politica cita por nome existe na fixture
        self.assertTrue(cn.REQUIRED_SERVICES <= set(load_ok()["services"]))

    def test_tolerates_list_form_and_implicit_default(self):
        cfg = load_ok()
        cfg["services"]["control-plane"]["networks"] = ["backend", "egress"]
        del cfg["services"]["gvmd"]["networks"]          # implicita: default
        cfg["services"]["pg-gvm"]["networks"] = ["default"]
        self.assertEqual(cn.check(cfg), [])

    def test_default_network_may_be_implicit_at_top_level(self):
        # a `default` e' implicita no Compose: faltar no topo do JSON, com servicos
        # nela, nao e' violacao (as redes NOVAS e' que tem de estar declaradas)
        cfg = load_ok()
        del cfg["networks"]["default"]
        self.assertEqual(cn.check(cfg), [])

    def test_check_does_not_mutate_input(self):
        cfg = load_ok()
        before = copy.deepcopy(cfg)
        cn.check(cfg)
        self.assertEqual(cfg, before)


class Mutations(WithTmp):
    """Cada mutacao reproduz um jeito real de desfazer o isolamento."""

    def assert_rejected(self, cfg, rule, needle, cli=True):
        found = hits(cfg, rule, needle)
        self.assertTrue(found, "nenhuma violacao [%s] citando %r; achou: %r"
                        % (rule, needle, cn.check(cfg)))
        if cli:
            # e o CLI sai com 1 (o exit code que o CI enxerga)
            rc, out = run_cli(self.write(cfg))
            self.assertEqual(rc, 1, out)
            self.assertIn("REPROVADO [%s]" % rule, out)

    # --- o proxy do docker --------------------------------------------------
    def test_proxy_back_on_default(self):
        cfg = load_ok()
        add_net(cfg, "docker-socket-proxy", "default")
        self.assert_rejected(cfg, "SVC-NETS", "docker-socket-proxy")
        self.assertIn("a mais: {default}", hits(cfg, "SVC-NETS", "docker-socket-proxy")[0].message)

    def test_random_service_on_docker_api(self):
        cfg = load_ok()
        add_net(cfg, "gsad", "docker-api")      # o servico exposto a internet via nginx
        self.assert_rejected(cfg, "SVC-NETS", "gsad")

    def test_new_service_on_docker_api(self):
        cfg = load_ok()
        cfg["services"]["sidecar"] = {"image": "exemplo/sidecar",
                                      "networks": {"default": None, "docker-api": None}}
        self.assert_rejected(cfg, "SVC-NETS", "sidecar")

    def test_nginx_on_docker_api(self):
        cfg = load_ok()
        add_net(cfg, "nginx", "docker-api")
        self.assert_rejected(cfg, "SVC-NETS", "nginx")

    def test_feed_updater_loses_docker_api(self):
        cfg = load_ok()
        drop_net(cfg, "feed-updater", "docker-api")      # nao falaria mais com o proxy
        self.assert_rejected(cfg, "SVC-NETS", "feed-updater")

    def test_proxy_publishes_a_port(self):
        cfg = load_ok()
        cfg["services"]["docker-socket-proxy"]["ports"] = [
            {"mode": "ingress", "target": 2375, "published": "2375", "protocol": "tcp"}]
        self.assert_rejected(cfg, "PORTS", "docker-socket-proxy")

    # --- control-plane / ingest ---------------------------------------------
    def test_control_plane_back_on_default(self):
        cfg = load_ok()
        add_net(cfg, "control-plane", "default")
        self.assert_rejected(cfg, "SVC-NETS", "control-plane")

    def test_ingest_back_on_default(self):
        cfg = load_ok()
        add_net(cfg, "ingest", "default")
        self.assert_rejected(cfg, "SVC-NETS", "ingest")

    def test_control_plane_loses_egress(self):
        cfg = load_ok()
        drop_net(cfg, "control-plane", "egress")         # planner de IA perderia a saida
        self.assert_rejected(cfg, "SVC-NETS", "control-plane")

    def test_ingest_publishes_a_port(self):
        cfg = load_ok()
        cfg["services"]["ingest"]["ports"] = [
            {"mode": "ingress", "target": 9090, "published": "9090", "protocol": "tcp"}]
        self.assert_rejected(cfg, "PORTS", "ingest")

    # --- nginx e feed-updater: a armadilha da `default` implicita -----------
    def test_nginx_loses_default(self):
        # `networks: [backend]` sozinho tira o nginx da default (some a UI)
        cfg = load_ok()
        drop_net(cfg, "nginx", "default")
        self.assert_rejected(cfg, "SVC-NETS", "nginx")
        self.assertIn("faltando: {default}", hits(cfg, "SVC-NETS", "nginx")[0].message)

    def test_nginx_loses_backend(self):
        cfg = load_ok()
        drop_net(cfg, "nginx", "backend")                # nao alcancaria control-plane/ingest
        self.assert_rejected(cfg, "SVC-NETS", "nginx")

    def test_feed_updater_back_on_default(self):
        # na default o gsad/ospd/gvmd alcancariam a API admin SEM auth do :8008
        cfg = load_ok()
        add_net(cfg, "feed-updater", "default")
        self.assert_rejected(cfg, "SVC-NETS", "feed-updater")
        self.assertIn("a mais: {default}", hits(cfg, "SVC-NETS", "feed-updater")[0].message)
        self.assertIn(":8008", hits(cfg, "SVC-NETS", "feed-updater")[0].message)

    def test_feed_updater_loses_egress(self):
        cfg = load_ok()
        drop_net(cfg, "feed-updater", "egress")          # sem saida p/ o espelho MSRC
        self.assert_rejected(cfg, "SVC-NETS", "feed-updater")
        self.assertIn("faltando: {egress}", hits(cfg, "SVC-NETS", "feed-updater")[0].message)

    # --- upstream: mudar a rede recria o gvmd/ospd e mata scan --------------
    def test_upstream_services_must_stay_on_default_only(self):
        for name in ("gvmd", "ospd-openvas", "pg-gvm", "redis-server", "gsad"):
            for net in ("backend", "docker-api", "egress"):
                cfg = load_ok()
                add_net(cfg, name, net)
                self.assert_rejected(cfg, "SVC-NETS", name, cli=False)
        cfg = load_ok()
        cfg["services"]["gvmd"]["networks"] = {"backend": None}   # troca de rede
        self.assert_rejected(cfg, "SVC-NETS", "gvmd", cli=False)
        cfg = load_ok()
        add_net(cfg, "ospd-openvas", "backend")
        self.assert_rejected(cfg, "SVC-NETS", "ospd-openvas")     # + exit code do CLI

    # --- flags das redes -----------------------------------------------------
    def test_docker_api_not_internal(self):
        cfg = load_ok()
        del cfg["networks"]["docker-api"]["internal"]
        self.assert_rejected(cfg, "NET-INTERNAL", "docker-api")

    def test_backend_not_internal(self):
        cfg = load_ok()
        cfg["networks"]["backend"]["internal"] = False
        self.assert_rejected(cfg, "NET-INTERNAL", "backend")

    def test_egress_internal_cuts_outbound(self):
        cfg = load_ok()
        cfg["networks"]["egress"]["internal"] = True
        self.assert_rejected(cfg, "NET-INTERNAL", "egress")

    def test_default_internal(self):
        cfg = load_ok()
        cfg["networks"]["default"]["internal"] = True
        self.assert_rejected(cfg, "NET-INTERNAL", "default")

    # --- redes e modos que contornam a segmentacao ---------------------------
    def test_network_mode_host(self):
        cfg = load_ok()
        cfg["services"]["ingest"]["network_mode"] = "host"
        del cfg["services"]["ingest"]["networks"]
        self.assert_rejected(cfg, "NETMODE", "ingest")

    def test_unknown_network_declared(self):
        cfg = load_ok()
        cfg["networks"]["frontal"] = {"name": "frontal", "external": True}
        self.assert_rejected(cfg, "PRES-NET", "frontal")

    def test_required_network_missing(self):
        cfg = load_ok()
        del cfg["networks"]["docker-api"]
        self.assert_rejected(cfg, "PRES-NET", "docker-api")

    # --- presenca: o portao nao passa no vazio -------------------------------
    def test_required_service_missing(self):
        for name in sorted(cn.REQUIRED_SERVICES):
            cfg = load_ok()
            del cfg["services"][name]
            self.assert_rejected(cfg, "PRES-SVC", name, cli=False)
        cfg = load_ok()
        del cfg["services"]["docker-socket-proxy"]
        self.assert_rejected(cfg, "PRES-SVC", "docker-socket-proxy")   # + exit code do CLI

    # --- feed-updater nao publica porta (API admin sem auth) -----------------
    def test_feed_updater_publishes_a_port(self):
        cfg = load_ok()
        cfg["services"]["feed-updater"]["ports"] = [
            {"mode": "ingress", "target": 8008, "published": "8008", "protocol": "tcp"}]
        self.assert_rejected(cfg, "PORTS", "feed-updater")

    # --- docker.sock: so o docker-socket-proxy monta -------------------------
    def test_other_service_mounts_the_docker_socket(self):
        for name, src in (("gsad", "/var/run/docker.sock"), ("nginx", "/run/docker.sock"),
                          ("ingest", "/var/run/docker.sock")):
            cfg = load_ok()
            add_volume(cfg, name, bind(src, "/var/run/docker.sock"))
            self.assert_rejected(cfg, "SOCKET", name, cli=False)
        cfg = load_ok()
        add_volume(cfg, "feed-updater", bind("/var/run/docker.sock", "/var/run/docker.sock", True))
        self.assert_rejected(cfg, "SOCKET", "feed-updater")       # + exit code do CLI

    def test_docker_socket_mounted_at_another_target(self):
        cfg = load_ok()
        add_volume(cfg, "gvmd", bind("/var/run/docker.sock", "/srv/x.sock"))
        self.assert_rejected(cfg, "SOCKET", "gvmd")

    def test_docker_socket_mounted_through_a_parent_directory(self):
        for src in ("/", "/var", "/var/run", "/run", "/var/run/"):
            cfg = load_ok()
            add_volume(cfg, "gsad", bind(src, "/host"))
            self.assert_rejected(cfg, "SOCKET", "gsad", cli=False)

    def test_docker_socket_in_short_syntax(self):
        cfg = load_ok()
        cfg["services"]["gsad"]["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock:ro"]
        self.assert_rejected(cfg, "SOCKET", "gsad")

    def test_proxy_without_the_docker_socket(self):
        cfg = load_ok()
        cfg["services"]["docker-socket-proxy"]["volumes"] = []
        self.assert_rejected(cfg, "SOCKET", "docker-socket-proxy")

    def test_absolute_source_is_checked_whatever_the_declared_type(self):
        # fail-safe: o tipo declarado nao desativa a conferencia do caminho
        cfg = load_ok()
        add_volume(cfg, "gsad", {"type": "volume", "source": "/var/run/docker.sock", "target": "/x"})
        self.assert_rejected(cfg, "SOCKET", "gsad", cli=False)

    def test_named_volume_bound_to_the_docker_socket(self):
        # um volume local com driver_opts.device e' um bind disfarcado de volume nomeado
        for device in ("/var/run/docker.sock", "/run/docker.sock", "/var/run", "/"):
            cfg = load_ok()
            cfg["volumes"] = {"sockvol": {
                "name": "greenbone-community-edition_sockvol", "driver": "local",
                "driver_opts": {"type": "none", "o": "bind", "device": device}}}
            self.assert_rejected(cfg, "SOCKET", "sockvol", cli=False)
        self.assert_rejected(cfg, "SOCKET", "sockvol")           # + exit code do CLI

    def test_ordinary_named_volumes_are_not_flagged(self):
        cfg = load_ok()
        cfg["volumes"] = {
            "dados": {"name": "greenbone-community-edition_dados"},
            "ext": {"name": "soos_ext", "external": True},
            "montado": {"name": "x_montado", "driver": "local",
                        "driver_opts": {"type": "none", "o": "bind", "device": "/srv/exemplo/dados"}}}
        self.assertEqual(cn.check(cfg), [])

    def test_ordinary_mounts_are_not_flagged(self):
        cfg = load_ok()
        add_volume(cfg, "gsad", bind("/var/lib/suricatoos-cp", "/data"))
        add_volume(cfg, "gsad", {"type": "volume", "source": "gvmd_socket_vol", "target": "/run/gvmd"})
        add_volume(cfg, "gsad", {"type": "tmpfs", "target": "/tmp"})
        cfg["services"]["gvmd"]["volumes"] = ["gvmd_socket_vol:/run/gvmd", "./nginx/default.conf:/x:ro"]
        self.assertEqual(cn.check(cfg), [])

    # --- declaracao das redes: nem external, nem driver, nem nome trocado -----
    def test_external_network(self):
        cfg = load_ok()
        cfg["networks"]["backend"]["external"] = True
        self.assert_rejected(cfg, "NET-DECL", "backend")

    def test_non_default_network_driver(self):
        for driver in ("host", "overlay", "macvlan", "null"):
            cfg = load_ok()
            cfg["networks"]["docker-api"]["driver"] = driver
            self.assert_rejected(cfg, "NET-DECL", "docker-api", cli=False)

    def test_explicit_bridge_driver_is_the_default(self):
        cfg = load_ok()
        cfg["networks"]["backend"]["driver"] = "bridge"
        self.assertEqual(cn.check(cfg), [])

    def test_network_aliased_to_another_network_name(self):
        # `backend: {name: <proj>_default}` aponta a rede para a default: passaria
        # por qualquer conferencia que so olhe as chaves
        cfg = load_ok()
        cfg["networks"]["backend"]["name"] = "greenbone-community-edition_default"
        self.assert_rejected(cfg, "NET-DECL", "backend")
        self.assertIn("greenbone-community-edition_backend", hits(cfg, "NET-DECL", "backend")[0].message)

    def test_network_name_without_the_project_prefix(self):
        cfg = load_ok()
        cfg["networks"]["egress"]["name"] = "egress"
        self.assert_rejected(cfg, "NET-DECL", "egress")

    def test_network_without_a_name(self):
        cfg = load_ok()
        del cfg["networks"]["docker-api"]["name"]
        self.assert_rejected(cfg, "NET-DECL", "docker-api")

    def test_name_of_the_default_network_is_checked_too(self):
        cfg = load_ok()
        cfg["networks"]["default"]["name"] = "outra_default"
        self.assert_rejected(cfg, "NET-DECL", "default")

    # --- o defeito original ---------------------------------------------------
    def test_original_flat_topology_is_rejected(self):
        """Tudo na `default`, sem as redes novas: o estado de antes desta fatia."""
        cfg = load_ok()
        for svc in cfg["services"].values():
            svc["networks"] = {"default": None}
        cfg["networks"] = {"default": cfg["networks"]["default"]}
        self.assertEqual({v.rule for v in cn.check(cfg)}, {"SVC-NETS", "PRES-NET"})
        # o proxy (e control-plane/ingest) na default e a falha que motivou a fatia;
        # nginx/feed-updater sem as redes novas tambem nao fecham com a politica
        for name in ("docker-socket-proxy", "control-plane", "ingest", "nginx", "feed-updater"):
            self.assertTrue(hits(cfg, "SVC-NETS", name), name)
        rc, out = run_cli(self.write(cfg))
        self.assertEqual(rc, 1, out)


class FailClosed(WithTmp):
    """Entrada que nao permite olhar nada NAO pode virar 'passou'."""

    def assert_input_error(self, path, needle):
        rc, out = run_cli(path)
        self.assertEqual(rc, 2, out)
        self.assertIn("ENTRADA INVALIDA", out)
        self.assertIn(needle, out)

    def test_empty_object(self):
        self.assert_input_error(self.write({}), "sem `services`")

    def test_no_services(self):
        self.assert_input_error(self.write({"services": {}, "networks": {}}), "sem `services`")

    def test_services_not_an_object(self):
        self.assert_input_error(self.write({"services": ["nginx"]}), "sem `services`")

    def test_service_not_an_object(self):
        self.assert_input_error(self.write({"services": {"nginx": None}}), "nginx")

    def test_root_not_an_object(self):
        self.assert_input_error(self.write([1, 2, 3]), "raiz do JSON")

    def test_invalid_json(self):
        path = os.path.join(self.tmp, "ruim.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{ nao e json")
        self.assert_input_error(path, "ruim.json")

    def test_missing_project_name(self):
        # sem `name` nao da para conferir o nome das redes: nao se aprova no escuro
        cfg = json.load(open(FIXTURE, encoding="utf-8"))
        del cfg["name"]
        self.assert_input_error(self.write(cfg), "name")

    def test_missing_file(self):
        self.assert_input_error(os.path.join(self.tmp, "nao-existe.json"), "nao-existe.json")

    def test_usage_error_is_nonzero(self):
        self.assertEqual(run_cli()[0], 2)                       # nem --resolve nem arquivo
        self.assertEqual(run_cli("--resolve", FIXTURE)[0], 2)   # os dois

    def test_one_bad_file_among_good_still_fails(self):
        bad = self.write({}, "vazio.json")
        rc, _ = run_cli(FIXTURE, bad)
        self.assertEqual(rc, 2)


class FakeCompose(object):
    """`docker compose config --format json` simulado: devolve o config por combinacao."""

    def __init__(self, cfg_for=None, rc=0, stderr="", stdout=None, fail_for=None):
        self.cfg_for = cfg_for or {}
        self.rc, self.stderr, self.stdout = rc, stderr, stdout
        self.fail_for = fail_for or {}      # {arquivos: stderr} -> `docker compose` sai com 1
        self.calls = []

    @staticmethod
    def files_of(args):
        return [args[i + 1] for i, a in enumerate(args) if a == "-f"]

    def __call__(self, args, cwd, env):
        with open(args[args.index("--env-file") + 1], encoding="utf-8") as f:
            envfile = f.read()
        files = tuple(self.files_of(args))
        self.calls.append({"args": list(args), "cwd": cwd, "env": dict(env),
                           "files": files, "envfile": envfile})
        if files in self.fail_for:
            return 1, "", self.fail_for[files]
        if self.stdout is not None:
            return self.rc, self.stdout, self.stderr
        cfg = self.cfg_for.get(files) or load_ok()
        return self.rc, json.dumps(cfg), self.stderr


def resolve(fake, compose_dir=COMPOSE_DIR):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cn.main(["--resolve"], runner=fake, compose_dir=compose_dir)
    return rc, buf.getvalue()


class ResolveMode(unittest.TestCase):
    EXPECTED = [
        ("compose.yaml", "docker-compose.override.yml"),
        ("compose.yaml", "docker-compose.override.yml", "docker-compose.shared-host.yml"),
        ("compose.yaml", "docker-compose.override.yml", "docker-compose.shared-host.yml",
         "docker-compose.scap-order.yml"),
        ("compose.yaml", "docker-compose.override.yml", "docker-compose.standalone.yml"),
    ]

    def test_every_combo_is_resolved_in_order(self):
        fake = FakeCompose()
        rc, out = resolve(fake)
        self.assertEqual(rc, 0, out)
        self.assertEqual([c["files"] for c in fake.calls], self.EXPECTED)
        for c in fake.calls:
            self.assertEqual(c["args"][-3:], ["config", "--format", "json"])
            self.assertEqual(c["cwd"], COMPOSE_DIR)

    def test_environment_is_hermetic_and_fictitious(self):
        with mock.patch.dict(os.environ, {"COMPOSE_FILE": "x.yml", "COMPOSE_PROJECT_NAME": "real",
                                          "COMPOSE_PROFILES": "p"}):
            fake = FakeCompose()
            rc, out = resolve(fake)
        self.assertEqual(rc, 0, out)
        for c in fake.calls:
            self.assertFalse([k for k in c["env"] if k.startswith("COMPOSE_")], c["env"].keys())
            self.assertIn("SCANNER_BIND_IP=192.0.2.10", c["envfile"])     # RFC 5737
            self.assertIn("/srv/exemplo/", c["envfile"])

    def test_violation_in_one_combo_fails_but_all_combos_are_still_checked(self):
        bad = load_ok()
        add_net(bad, "docker-socket-proxy", "default")
        files = tuple(self.EXPECTED[3])       # so a standalone quebra
        fake = FakeCompose(cfg_for={files: bad})
        rc, out = resolve(fake)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(fake.calls), 4, "parou na primeira falha")
        self.assertIn("REPROVADO [SVC-NETS] docker-socket-proxy", out)
        for label in ("== override ==", "== shared-host ==", "== shared-host+scap-order ==",
                      "== standalone =="):
            self.assertIn(label, out)

    def test_compose_failure_is_a_failure(self):
        rc, out = resolve(FakeCompose(rc=1, stdout="", stderr="service x refers to undefined network y"))
        self.assertEqual(rc, 1)
        self.assertIn("undefined network y", out)

    def test_compose_failure_in_one_combo_still_checks_the_others(self):
        # a PRIMEIRA combinacao deixa de resolver ("undefined network") e as demais
        # continuam sendo conferidas, com o erro do compose no log
        fake = FakeCompose(fail_for={self.EXPECTED[0]: "service x refers to undefined network y"})
        rc, out = resolve(fake)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(fake.calls), 4, "parou na primeira falha")
        self.assertIn("undefined network y", out)
        self.assertEqual(out.count("OK: politica de redes respeitada"), 3, out)

    def test_non_json_output_is_input_error(self):
        rc, out = resolve(FakeCompose(stdout="name: yaml-nao-json\n"))
        self.assertEqual(rc, 2, out)

    def test_empty_output_is_input_error(self):
        rc, _ = resolve(FakeCompose(stdout="{}"))
        self.assertEqual(rc, 2)

    def test_docker_missing_is_input_error(self):
        with mock.patch.object(cn.subprocess, "run", side_effect=FileNotFoundError("docker")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cn.main(["--resolve"], compose_dir=COMPOSE_DIR)
        self.assertEqual(rc, 2, buf.getvalue())
        self.assertIn("docker", buf.getvalue())


class HashParsing(unittest.TestCase):
    H1 = "a" * 64
    H2 = "b" * 64

    def test_parse_hashes(self):
        text = "gvmd %s\nospd-openvas %s\n" % (self.H1, self.H2)
        self.assertEqual(cn.parse_hashes(text), {"gvmd": self.H1, "ospd-openvas": self.H2})

    def test_parse_ignores_noise_lines(self):
        text = "WARN algo\n\ngvmd %s\nlinha com tres palavras %s\n" % (self.H1, self.H2)
        self.assertEqual(cn.parse_hashes(text), {"gvmd": self.H1})

    def test_parse_requires_at_least_one_hash(self):
        for text in ("", "\n\n", "so avisos\nsem hash nenhum\n", "gvmd nao-e-hex\n"):
            with self.assertRaises(cn.InputError):
                cn.parse_hashes(text)

    def test_compare_flags_only_protected_services(self):
        base = {"gvmd": "1", "ospd-openvas": "2", "pg-gvm": "3", "redis-server": "4", "nginx": "5"}
        head = dict(base, nginx="9", **{"control-plane": "7"})
        violations, changed = cn.compare_hashes(base, head)
        self.assertEqual(violations, [])
        self.assertEqual(changed, [("control-plane", "novo"), ("nginx", "alterado")])

    def test_compare_flags_changed_and_removed_protected_services(self):
        base = {"gvmd": "1", "ospd-openvas": "2", "pg-gvm": "3", "redis-server": "4"}
        head = {"gvmd": "X", "ospd-openvas": "2", "pg-gvm": "3"}
        violations, changed = cn.compare_hashes(base, head)
        self.assertEqual(sorted(v.message.split(":")[0] for v in violations), ["gvmd", "redis-server"])
        self.assertTrue(all(v.rule == "HASH" for v in violations))
        self.assertEqual(changed, [("gvmd", "alterado"), ("redis-server", "removido")])


def sha(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class FakeHashCompose(object):
    """`docker compose config --hash=*` simulado. O "hash" de cada servico depende do
    CONTEUDO dos arquivos que o runner encontra em `cwd` (linhas `#svc <servico>: <valor>`),
    entao so vale se o gate exportar a arvore certa para o diretorio certo."""

    def __init__(self, rc=0, stderr=""):
        self.rc, self.stderr, self.calls = rc, stderr, []

    def __call__(self, args, cwd, env):
        files = [args[i + 1] for i, a in enumerate(args) if a == "-f"]
        envfile = args[args.index("--env-file") + 1]
        self.calls.append({"args": list(args), "cwd": cwd, "files": files, "envfile": envfile,
                           "env": dict(env)})
        if self.rc != 0:
            return self.rc, "", self.stderr
        vals = {}
        for name in files:
            with open(os.path.join(cwd, name), encoding="utf-8") as f:
                for m in re.finditer(r"^#svc (\S+): (.*)$", f.read(), re.M):
                    vals.setdefault(m.group(1), []).append(m.group(2))
        lines = ["%s %s" % (s, sha(s + "|" + "|".join(v))) for s, v in sorted(vals.items())]
        return 0, "\n".join(lines) + "\n", "WARN aviso que o gate deve ignorar\n"


class HashGate(WithTmp):
    """O gate de hash de recriacao, contra um repositorio git DE VERDADE (descartavel)."""

    SERVICES = ("gvmd", "ospd-openvas", "pg-gvm", "redis-server", "gsad", "nginx", "ingest")
    FILES = ["compose.yaml", "docker-compose.override.yml", "docker-compose.shared-host.yml",
             "docker-compose.scap-order.yml", "docker-compose.standalone.yml"]

    def git(self, *args):
        cmd = ["git", "-c", "user.name=teste", "-c", "user.email=teste@example.invalid",
               "-c", "core.autocrlf=false", "-C", self.repo] + list(args)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, encoding="utf-8")
        self.assertEqual(p.returncode, 0, "%s -> %s" % (" ".join(args), p.stderr))
        return p.stdout.strip()

    def put(self, name, text):
        path = os.path.join(self.repo, "compose", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def marker_file(self, **svc):
        return "services: {}\n" + "".join("#svc %s: %s\n" % kv for kv in sorted(svc.items()))

    def setUp(self):
        super(HashGate, self).setUp()
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.put("compose.yaml", "services: {}\n")
        self.put("docker-compose.override.yml", self.marker_file(**{s: "v1" for s in self.SERVICES}))
        for name in self.FILES[2:]:
            self.put(name, "services: {}\n")
        self.commit_all("base")
        self.base = self.git("rev-parse", "HEAD")

    def commit_all(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def branch_off(self, name="feature"):
        self.git("checkout", "-q", "-b", name)

    def run_gate(self, fake, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cn.main(["--hashes", "--base-ref", "main"] + list(extra), runner=fake,
                         compose_dir=os.path.join(self.repo, "compose"))
        return rc, buf.getvalue()

    def edit_override(self, **changes):
        vals = {s: "v1" for s in self.SERVICES}
        vals.update(changes)
        self.put("docker-compose.override.yml", self.marker_file(**vals))

    # --- o que passa -------------------------------------------------------
    def test_unchanged_protected_services_pass_and_the_recreate_set_is_listed(self):
        self.branch_off()
        self.edit_override(nginx="v2", ingest="v2")
        self.commit_all("muda so nginx e ingest")
        fake = FakeHashCompose()
        rc, out = self.run_gate(fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("ingest, nginx", out)                         # lista o que sera recriado
        self.assertIn("gvmd, ospd-openvas, pg-gvm, redis-server", out)
        self.assertNotIn("REPROVADO", out)

    # --- o que reprova ------------------------------------------------------
    def test_each_protected_service_is_guarded(self):
        for svc in cn.HASH_PROTECTED:
            self.git("checkout", "-q", "main")
            self.git("checkout", "-q", "-B", "feature-" + svc)
            self.edit_override(**{svc: "v2"})
            self.commit_all("muda " + svc)
            rc, out = self.run_gate(FakeHashCompose())
            self.assertEqual(rc, 1, (svc, out))
            self.assertIn("REPROVADO [HASH] %s" % svc, out)

    def test_change_only_in_a_profile_overlay_is_caught_in_those_combos(self):
        self.branch_off()
        self.put("docker-compose.shared-host.yml", self.marker_file(gvmd="mem_limit=3g"))
        self.commit_all("gvmd ganha limite no shared-host")
        rc, out = self.run_gate(FakeHashCompose())
        self.assertEqual(rc, 1, out)
        reproved = [l for l in out.splitlines() if "REPROVADO [HASH] gvmd" in l]
        self.assertEqual(len(reproved), 2, out)                     # shared-host e shared-host+scap-order
        self.assertTrue(all("shared-host" in l for l in reproved))

    def test_removed_protected_service_fails(self):
        self.branch_off()
        vals = {s: "v1" for s in self.SERVICES if s != "pg-gvm"}
        self.put("docker-compose.override.yml", self.marker_file(**vals))
        self.commit_all("remove pg-gvm")
        rc, out = self.run_gate(FakeHashCompose())
        self.assertEqual(rc, 1, out)
        self.assertIn("REPROVADO [HASH] pg-gvm", out)

    # --- o plumbing do git ----------------------------------------------------
    def test_base_is_the_merge_base_not_the_tip_of_main(self):
        self.branch_off()
        self.edit_override(nginx="v2")
        self.commit_all("feature mexe no nginx")
        self.git("checkout", "-q", "main")
        self.edit_override(gvmd="v-da-main")                        # a main anda DEPOIS do fork
        self.commit_all("main mexe no gvmd")
        self.git("checkout", "-q", "feature")
        fake = FakeHashCompose()
        rc, out = self.run_gate(fake)
        self.assertEqual(rc, 0, out)                                # o gvmd da main nao conta
        self.assertIn("base=%s" % self.base[:10], out)

    def test_base_and_head_are_hashed_from_the_same_directory_and_env_file(self):
        # o hash do Compose leva o diretorio de trabalho, os arquivos e o --env-file nos
        # labels: se base e HEAD fossem resolvidos de caminhos diferentes, TODO servico
        # mudaria de hash e o gate nunca passaria (ou passaria vazio)
        self.branch_off()
        self.edit_override(nginx="v2")
        self.commit_all("muda nginx")
        fake = FakeHashCompose()
        rc, out = self.run_gate(fake)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(fake.calls), 8, "4 combinacoes x (base, HEAD)")
        self.assertEqual(len({c["cwd"] for c in fake.calls}), 1)
        self.assertEqual(len({c["envfile"] for c in fake.calls}), 1)
        self.assertTrue(all(c["args"][-2:] == ["config", "--hash=*"] for c in fake.calls))
        self.assertFalse([k for c in fake.calls for k in c["env"] if k.startswith("COMPOSE_")])

    def test_head_equal_to_the_merge_base_has_nothing_to_compare(self):
        fake = FakeHashCompose()
        rc, out = self.run_gate(fake)                               # HEAD == main
        self.assertEqual(rc, 0, out)
        self.assertEqual(fake.calls, [])
        self.assertIn("nada a comparar", out)

    def test_unresolvable_base_ref_is_an_input_error_with_the_fetch_depth_hint(self):
        self.branch_off()
        fake = FakeHashCompose()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cn.main(["--hashes", "--base-ref", "origin/nao-existe"], runner=fake,
                         compose_dir=os.path.join(self.repo, "compose"))
        self.assertEqual(rc, 2, buf.getvalue())
        self.assertIn("fetch-depth", buf.getvalue())
        self.assertEqual(fake.calls, [])

    def test_combo_without_a_base_is_skipped_with_a_notice(self):
        self.git("checkout", "-q", "-B", "sem-standalone")
        os.remove(os.path.join(self.repo, "compose", "docker-compose.standalone.yml"))
        self.commit_all("base sem standalone")
        self.git("checkout", "-q", "-B", "main")                    # esta passa a ser a main
        self.branch_off("feature")
        self.put("docker-compose.standalone.yml", "services: {}\n")  # overlay NOVO no HEAD
        self.commit_all("adiciona standalone")
        rc, out = self.run_gate(FakeHashCompose())
        self.assertEqual(rc, 0, out)
        self.assertIn("standalone", out)
        self.assertIn("sem base", out)

    def test_compose_failure_is_an_input_error(self):
        self.branch_off()
        self.edit_override(nginx="v2")
        self.commit_all("muda nginx")
        rc, out = self.run_gate(FakeHashCompose(rc=1, stderr="yaml invalido na base"))
        self.assertEqual(rc, 2, out)
        self.assertIn("yaml invalido na base", out)

    def test_hashes_mode_is_exclusive_with_the_other_modes(self):
        for argv in (["--hashes", "--resolve"], ["--hashes", FIXTURE]):
            with self.assertRaises(SystemExit) as cm:
                with contextlib.redirect_stderr(io.StringIO()):
                    cn.main(argv, runner=FakeHashCompose(), compose_dir=os.path.join(self.repo, "compose"))
            self.assertEqual(cm.exception.code, 2)


class YamlCoverage(WithTmp):
    """YAML novo em compose/ (qualquer extensao, qualquer subdiretorio) sem entrar nas
    combinacoes = rede nunca conferida. O --resolve e esses testes reprovam ate cobrir."""

    COVERED = ["compose.yaml", "docker-compose.override.yml", "docker-compose.shared-host.yml",
               "docker-compose.scap-order.yml", "docker-compose.standalone.yml"]

    def make_compose_dir(self, *extra):
        d = os.path.join(self.tmp, "compose")
        for name in list(self.COVERED) + list(extra):
            path = os.path.join(d, *name.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("services: {}\n")
        return d

    def test_every_compose_yaml_in_the_repo_is_in_a_combo(self):
        self.assertEqual(cn.find_uncovered_yaml(COMPOSE_DIR), [])
        covered = set(cn.BASE_FILES)
        for _, extra in cn.COMBOS:
            covered.update(extra)
        for name in covered:
            self.assertTrue(os.path.exists(os.path.join(COMPOSE_DIR, name)), name)

    def test_covered_files_alone_are_clean(self):
        self.assertEqual(cn.find_uncovered_yaml(self.make_compose_dir()), [])

    def test_new_overlays_are_found_whatever_the_extension_or_depth(self):
        d = self.make_compose_dir("docker-compose.novo.yaml", "docker-compose.outro.yml",
                                  "overlays/extra.yml", "overlays/deep/mais.yaml")
        self.assertEqual(cn.find_uncovered_yaml(d), [
            "docker-compose.novo.yaml", "docker-compose.outro.yml",
            "overlays/deep/mais.yaml", "overlays/extra.yml"])

    def test_own_test_dir_and_pycache_are_not_scanned(self):
        d = self.make_compose_dir("test/fixtures/qualquer.yml", "__pycache__/x.yaml")
        self.assertEqual(cn.find_uncovered_yaml(d), [])

    def test_explicit_allowlist_is_respected(self):
        d = self.make_compose_dir("overlays/nao-e-compose.yml", "docker-compose.novo.yaml")
        with mock.patch.object(cn, "IGNORED_YAML", {"overlays/nao-e-compose.yml"}):
            self.assertEqual(cn.find_uncovered_yaml(d), ["docker-compose.novo.yaml"])

    def test_resolve_fails_when_a_yaml_is_not_covered(self):
        d = self.make_compose_dir("docker-compose.novo.yaml")
        fake = FakeCompose()
        rc, out = resolve(fake, compose_dir=d)
        self.assertEqual(rc, 1, out)
        self.assertIn("docker-compose.novo.yaml", out)
        self.assertEqual(len(fake.calls), 4, "as combinacoes conhecidas ainda sao conferidas")


def workflow_paths(text):
    """{evento: [globs]} dos `paths:` do workflow (parser minimo p/ o formato deste arquivo)."""
    out, event, in_paths = {}, None, False
    for line in text.splitlines():
        m = re.match(r"^  (push|pull_request):\s*$", line)
        if m:
            event, in_paths = m.group(1), False
            out.setdefault(event, [])
            continue
        if re.match(r"^\S", line):                      # chave de topo: sai do `on:`
            event, in_paths = None, False
        if event and re.match(r"^    paths:\s*$", line):
            in_paths = True
            continue
        if event and in_paths:
            m = re.match(r'^      - "(.+)"\s*$', line)
            if m:
                out[event].append(m.group(1))
                continue
            in_paths = False
    return out


def gh_glob_match(pattern, path):
    """Subconjunto do 'filter pattern cheat sheet' do GitHub Actions: `*` nao cruza `/`,
    `**` casa qualquer sequencia (inclusive `/`)."""
    rx, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            rx, i = rx + ".*", i + 2
        elif pattern[i] == "*":
            rx, i = rx + "[^/]*", i + 1
        else:
            rx, i = rx + re.escape(pattern[i]), i + 1
    return re.fullmatch(rx, path) is not None


class WorkflowPaths(unittest.TestCase):
    """Se o `paths:` do workflow nao pega um YAML de compose, o PR que o altera passa sem CI."""

    SAMPLES = ["compose/compose.yaml", "compose/docker-compose.override.yml",
               "compose/docker-compose.shared-host.yml", "compose/docker-compose.novo.yaml",
               "compose/docker-compose.novo.yml", "compose/overlays/extra.yml",
               "compose/overlays/deep/mais.yaml", "compose/test/check_networks.py",
               ".github/workflows/compose-ci.yml"]

    @staticmethod
    def uncovered(paths, samples):
        return [s for s in samples if not any(gh_glob_match(g, s) for g in paths)]

    def read(self):
        with open(WORKFLOW, encoding="utf-8") as f:
            return f.read()

    def test_matcher_follows_the_cheat_sheet(self):
        self.assertTrue(gh_glob_match("compose/**.yml", "compose/a/b.yml"))
        self.assertTrue(gh_glob_match("compose/**.yml", "compose/b.yml"))
        self.assertFalse(gh_glob_match("compose/**.yml", "compose/b.yaml"))
        self.assertTrue(gh_glob_match("compose/*.yml", "compose/b.yml"))
        self.assertFalse(gh_glob_match("compose/*.yml", "compose/a/b.yml"))
        self.assertTrue(gh_glob_match("compose/test/**", "compose/test/fixtures/x.json"))

    def test_parser_reads_both_events(self):
        paths = workflow_paths(self.read())
        self.assertEqual(sorted(paths), ["pull_request", "push"])
        self.assertTrue(all(paths[e] for e in paths))

    def test_every_compose_yaml_triggers_push_and_pull_request(self):
        paths = workflow_paths(self.read())
        repo_yaml = ["compose/" + n for n in cn.covered_yaml()]
        for event in ("push", "pull_request"):
            self.assertEqual(self.uncovered(paths[event], self.SAMPLES + repo_yaml), [], event)

    def test_dropping_the_yaml_glob_is_detected(self):
        text = self.read()
        for dropped in ("compose/**.yaml", "compose/**.yml"):
            mutated = text.replace('      - "%s"\n' % dropped, "")
            self.assertNotEqual(mutated, text, dropped)
            paths = workflow_paths(mutated)
            for event in ("push", "pull_request"):
                self.assertTrue(self.uncovered(paths[event], self.SAMPLES), (dropped, event))


if __name__ == "__main__":
    unittest.main()
