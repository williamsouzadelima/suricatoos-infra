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
import glob
import io
import json
import os
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


def load_ok():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def add_net(cfg, svc, net):
    cfg["services"][svc].setdefault("networks", {})[net] = None


def drop_net(cfg, svc, net):
    del cfg["services"][svc]["networks"][net]


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

    def test_feed_updater_loses_default(self):
        cfg = load_ok()
        drop_net(cfg, "feed-updater", "default")         # sem saida p/ o espelho MSRC
        self.assert_rejected(cfg, "SVC-NETS", "feed-updater")

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


def resolve(fake):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cn.main(["--resolve"], runner=fake, compose_dir=COMPOSE_DIR)
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

    def test_every_compose_file_in_the_repo_is_covered(self):
        """Overlay novo sem entrar no COMBOS = rede nao conferida: reprova ate cobrir."""
        covered = set(cn.BASE_FILES)
        for _, extra in cn.COMBOS:
            covered.update(extra)
        on_disk = {os.path.basename(p) for p in glob.glob(os.path.join(COMPOSE_DIR, "docker-compose.*.yml"))}
        on_disk |= {os.path.basename(p) for p in glob.glob(os.path.join(COMPOSE_DIR, "compose.*y*ml"))}
        self.assertEqual(on_disk - covered, set(), "overlay(s) fora das combinacoes conferidas")
        for name in covered:
            self.assertTrue(os.path.exists(os.path.join(COMPOSE_DIR, name)), name)

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


if __name__ == "__main__":
    unittest.main()
