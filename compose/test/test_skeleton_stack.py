"""Testes da pilha-esqueleto (skeleton_stack.py) SEM Docker: o modelo gerado, o plano de
verificacoes e a orquestracao, contra um Docker simulado (FakeEngine) que implementa as regras
de rede que a pilha existe para provar.

ATENCAO ao que isto NAO prova: o FakeEngine e' o modelo que EU tenho do Docker. Quem prova o
comportamento do Engine de verdade (DNS por rede, isolamento entre bridges, escolha do gateway,
IP de origem da porta publicada) e' o job `esqueleto` do compose-ci, no Engine do CI.

    python3 -m unittest discover -s compose/test -v
"""
import contextlib
import copy
import io
import ipaddress
import json
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_networks as cn  # noqa: E402
import skeleton_stack as sk  # noqa: E402

COMPOSE_DIR = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "resolved-ok.json")
WORKFLOW = os.path.join(os.path.dirname(COMPOSE_DIR), ".github", "workflows", "compose-ci.yml")


def load_ok():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


class FakeEngine(object):
    """Docker simulado a partir do modelo do esqueleto. Regras (as que a pilha existe para
    provar contra o Engine real): DNS so' entre servicos que dividem uma rede; um IP so'
    alcanca quem esta na MESMA rede (isolamento entre bridges); o gateway de um container e'
    o da primeira rede NAO internal por ordem de nome; o trafego da porta publicada chega com
    o IP do gateway da rede do gateway do nginx."""

    def __init__(self, skel):
        self.skel = skel
        self.keys = sorted(skel["networks"])
        self.nets = {s: sorted(c.get("networks") or {}) for s, c in skel["services"].items()}
        self.downs = 0

    def up(self):
        pass

    def down(self):
        self.downs += 1

    def diagnostics(self):
        return "diagnostico simulado"

    def net(self, key):
        i = self.keys.index(key) + 1
        return "10.%d.0.0/24" % i, "10.%d.0.1" % i

    def ip_of(self, svc, key):
        return "10.%d.0.%d" % (self.keys.index(key) + 1, 10 + sorted(self.skel["services"]).index(svc))

    def ips(self, svc):
        return [self.ip_of(svc, k) for k in self.nets[svc]]

    def reach(self, src, host, port):
        if host in self.skel["services"]:                           # por NOME (DNS embutido)
            dst, shared = host, set(self.nets[src]) & set(self.nets[host])
        else:                                                       # por IP
            owners = [(s, k) for s in self.nets for k in self.nets[s] if self.ip_of(s, k) == host]
            if not owners:
                return False
            dst, key = owners[0]
            shared = {key} & set(self.nets[src])
        return bool(shared) and port in sk.PORTS[dst]

    def gateway_net(self, svc):
        for key in self.nets[svc]:
            if not self.skel["networks"][key].get("internal"):
                return key
        return None

    def route(self, svc):
        lines = []
        gw = self.gateway_net(svc)
        if gw:
            lines.append("default via %s dev eth0" % self.net(gw)[1])
        lines += ["%s dev eth%d scope link" % (self.net(k)[0], i) for i, k in enumerate(self.nets[svc])]
        return "\n".join(lines) + "\n"

    def host_remote_addr(self):
        if not self.skel["services"]["nginx"].get("ports"):
            return None
        gw = self.gateway_net("nginx")
        return self.net(gw)[1] if gw else None


def skeleton(cfg=None):
    return sk.build_skeleton(cfg or load_ok())


def run(skel, retry=0):
    eng = FakeEngine(skel)
    return eng, sk.run_checks(eng, retry_seconds=retry)


def failed(results, kind=None):
    return [r for r in results if not r.ok and (kind is None or r.kind == kind)]


class BuildSkeleton(unittest.TestCase):
    def test_keeps_only_the_seven_services_with_image_networks_ports_and_command(self):
        skel = skeleton()
        self.assertEqual(sorted(skel["services"]), sorted(
            ["nginx", "gsad", "gvmd", "docker-socket-proxy", "feed-updater", "control-plane", "ingest"]))
        for name, svc in skel["services"].items():
            self.assertLessEqual(set(svc), {"image", "networks", "ports", "command"}, name)
            self.assertEqual(svc["image"], "busybox:1.36.1", name)

    def test_networks_and_aliases_are_copied_verbatim_from_the_resolved_config(self):
        cfg = load_ok()
        cfg["services"]["nginx"]["networks"]["default"] = {"aliases": ["alias-exemplo"]}
        skel = skeleton(cfg)
        self.assertEqual(skel["services"]["nginx"]["networks"], cfg["services"]["nginx"]["networks"])
        for name in skel["services"]:
            self.assertEqual(skel["services"][name]["networks"], cfg["services"][name]["networks"], name)

    def test_top_level_networks_have_no_name_and_keep_internal(self):
        skel = skeleton()
        self.assertEqual(skel["networks"], {
            "backend": {"internal": True}, "default": {}, "docker-api": {"internal": True}, "egress": {}})

    def test_only_nginx_publishes_ports_and_they_are_the_resolved_ones(self):
        skel = skeleton()
        self.assertEqual(skel["services"]["nginx"]["ports"], load_ok()["services"]["nginx"]["ports"])
        self.assertEqual([n for n, s in skel["services"].items() if "ports" in s], ["nginx"])

    def test_each_service_listens_on_its_real_ports(self):
        skel = skeleton()
        want = {"nginx": (443, 9392), "gsad": (9392,), "gvmd": (9390,), "docker-socket-proxy": (2375,),
                "feed-updater": (8008,), "control-plane": (8080,), "ingest": (9090,)}
        for name, ports in want.items():
            cmd = skel["services"][name]["command"][2]
            self.assertEqual(sorted(int(p) for p in re.findall(r"httpd (?:-f )?-p (\d+)", cmd)),
                             sorted(ports), name)
        self.assertIn("-f -p 9392", skel["services"]["nginx"]["command"][2])    # a ultima, em foreground

    def test_cgi_echoes_remote_addr_and_there_is_no_dollar_for_compose_to_interpolate(self):
        text = json.dumps(skeleton())
        self.assertIn("REMOTE_ADDR", text)
        self.assertIn("/cgi-bin/ra", text)
        self.assertNotIn("$", text)

    def test_a_service_missing_from_the_resolved_config_is_an_input_error(self):
        cfg = load_ok()
        del cfg["services"]["gvmd"]
        with self.assertRaises(cn.InputError):
            skeleton(cfg)

    def test_published_port_from_long_and_short_syntax(self):
        self.assertEqual(sk.published_port(skeleton()), 8443)
        short = {"services": {"nginx": {"ports": ["127.0.0.1:9392:9392", "127.0.0.1:8444:443/tcp"]}}}
        self.assertEqual(sk.published_port(short), 8444)
        short = {"services": {"nginx": {"ports": ["443:443"]}}}
        self.assertEqual(sk.published_port(short), 443)
        self.assertIsNone(sk.published_port({"services": {"nginx": {"ports": ["127.0.0.1:9392:9392"]}}}))
        self.assertIsNone(sk.published_port({"services": {"nginx": {}}}))

    def test_does_not_mutate_the_resolved_config(self):
        cfg = load_ok()
        before = copy.deepcopy(cfg)
        skeleton(cfg)
        self.assertEqual(cfg, before)


class InsideSubnet(unittest.TestCase):
    """Normalizacao do REMOTE_ADDR observado antes da conferencia de sub-rede. A entrada
    `[::ffff:172.20.0.1]` e' EXATAMENTE o que o busybox httpd reportou no CI real (run
    38167041377): dual-stack, IPv4 mapeado em IPv6, entre colchetes."""

    SUBNET = "172.20.0.0/16"

    def test_plain_ipv4(self):
        self.assertTrue(sk.inside_subnet("172.20.0.1", self.SUBNET))
        self.assertFalse(sk.inside_subnet("172.21.0.1", self.SUBNET))

    def test_ipv4_mapped_ipv6(self):
        self.assertTrue(sk.inside_subnet("::ffff:172.20.0.1", self.SUBNET))

    def test_bracketed_ipv4_mapped_ipv6_exactly_as_the_busybox_httpd_reported_it_in_ci(self):
        self.assertTrue(sk.inside_subnet("[::ffff:172.20.0.1]", self.SUBNET))

    def test_hex_form_of_the_mapped_address(self):
        self.assertTrue(sk.inside_subnet("[::ffff:ac14:1]", self.SUBNET))      # 172.20.0.1
        self.assertTrue(sk.inside_subnet("::ffff:ac14:1", self.SUBNET))

    def test_bracketed_plain_ipv4(self):
        self.assertTrue(sk.inside_subnet("[172.20.0.1]", self.SUBNET))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertTrue(sk.inside_subnet("  [::ffff:172.20.0.1]\n", self.SUBNET))

    def test_an_address_outside_the_subnet_still_fails_whatever_its_form(self):
        for text in ("192.0.2.77", "::ffff:192.0.2.77", "[::ffff:192.0.2.77]", "[::ffff:172.21.0.1]",
                     "[::ffff:c000:24d]", "127.0.0.1", "[::ffff:127.0.0.1]"):
            self.assertFalse(sk.inside_subnet(text, self.SUBNET), text)

    def test_a_real_ipv6_address_is_not_in_an_ipv4_subnet(self):
        self.assertFalse(sk.inside_subnet("[2001:db8::1]", self.SUBNET))
        self.assertFalse(sk.inside_subnet("::1", self.SUBNET))

    def test_garbage_and_unbalanced_brackets_fail_without_crashing(self):
        for text in ("", "[]", "[nao-e-ip]", "[::ffff:172.20.0.1", "::ffff:172.20.0.1]",
                     "[[::ffff:172.20.0.1]]", "isto-nao-e-um-ip", None):
            self.assertFalse(sk.inside_subnet(text, self.SUBNET), repr(text))


class Plan(unittest.TestCase):
    def pairs(self, plan):
        return {(s, d) for s, d in plan}

    def test_positive_checks_include_the_required_ones(self):
        required = {("nginx", "gsad"), ("nginx", "control-plane"), ("nginx", "ingest"),
                    ("nginx", "feed-updater"), ("ingest", "control-plane"),
                    ("feed-updater", "docker-socket-proxy")}
        self.assertTrue(required <= self.pairs(sk.POSITIVOS))

    def test_positive_controls_make_every_negative_source_and_target_non_vacuous(self):
        sources = {s for s, _ in sk.POSITIVOS}
        targets = {d for _, d in sk.POSITIVOS}
        for src, dst in sk.NEGATIVOS:
            self.assertIn(src, sources, "a fonte %s nunca prova que consegue fazer wget" % src)
            self.assertIn(dst, targets, "o alvo %s nunca prova que esta de pe' e servindo" % dst)

    def test_negative_checks_are_exactly_the_required_ones(self):
        required = ({(s, d) for s in ("gsad", "gvmd")
                     for d in ("docker-socket-proxy", "control-plane", "ingest", "feed-updater")}
                    | {("nginx", "docker-socket-proxy"), ("control-plane", "docker-socket-proxy")})
        self.assertEqual(self.pairs(sk.NEGATIVOS), required)

    def test_routes(self):
        self.assertEqual(sk.ROTAS["nginx"], "default")
        self.assertIsNone(sk.ROTAS["docker-socket-proxy"])
        self.assertEqual(sk.ROTAS["control-plane"], "egress")
        self.assertEqual(sk.ROTAS["feed-updater"], "egress")

    def test_default_gateway_parser(self):
        self.assertEqual(sk.default_gateway("default via 172.18.0.1 dev eth1\n172.18.0.0/16 dev eth1\n"),
                         "172.18.0.1")
        self.assertIsNone(sk.default_gateway("172.20.0.0/16 dev eth0 scope link  src 172.20.0.2\n"))
        self.assertIsNone(sk.default_gateway(""))


class RunChecks(unittest.TestCase):
    def test_everything_passes_on_the_expected_topology(self):
        _, results = run(skeleton())
        self.assertEqual(failed(results), [], [sk.render(r) for r in failed(results)])
        kinds = {r.kind for r in results}
        self.assertEqual(kinds, {"alcance", "isolamento", "rota", "origem"})
        self.assertGreaterEqual(len(results), 30)

    def test_every_line_shows_expected_and_got(self):
        _, results = run(skeleton())
        for r in results:
            line = sk.render(r)
            self.assertIn("esperado=", line)
            self.assertIn("obtido=", line)
            self.assertTrue(line.startswith("[ OK ]"), line)

    def test_negative_checks_run_by_name_and_by_ip(self):
        _, results = run(skeleton())
        descs = [r.desc for r in results if r.kind == "isolamento"]
        self.assertTrue(any("por nome" in d for d in descs))
        self.assertTrue(any("por IP" in d for d in descs))

    def test_gsad_on_docker_api_is_caught(self):
        skel = skeleton()
        skel["services"]["gsad"]["networks"]["docker-api"] = None
        _, results = run(skel)
        bad = failed(results, "isolamento")
        self.assertTrue(any("gsad -> docker-socket-proxy" in r.desc for r in bad), [r.desc for r in bad])
        self.assertIn("FALHA", sk.render(bad[0]))
        self.assertIn("esperado=NAO alcanca", sk.render(bad[0]))

    def test_feed_updater_back_on_default_is_caught(self):
        skel = skeleton()
        skel["services"]["feed-updater"]["networks"]["default"] = None
        _, results = run(skel)
        bad = failed(results, "isolamento")
        self.assertTrue(any("-> feed-updater" in r.desc for r in bad))
        self.assertTrue(failed(results, "rota"))                    # a rota padrao agora e' outra

    def test_proxy_on_default_is_caught(self):
        skel = skeleton()
        skel["services"]["docker-socket-proxy"]["networks"]["default"] = None
        _, results = run(skel)
        self.assertTrue(any("-> docker-socket-proxy" in r.desc for r in failed(results, "isolamento")))
        self.assertTrue(failed(results, "rota"))                    # o proxy ganhou rota padrao

    def test_non_internal_backend_flips_nginx_gateway_and_source_ip(self):
        # o risco que motivou a rede `egress` e o `internal` na backend: com duas redes com
        # gateway a escolha vai por ordem de nome ('backend' < 'default') e o nginx publica
        # a porta pela rede errada -> IP de origem fora da `default`
        skel = skeleton()
        skel["networks"]["backend"] = {}
        _, results = run(skel)
        self.assertTrue(any(r.desc.startswith("nginx") for r in failed(results, "rota")))
        self.assertTrue(failed(results, "origem"))

    def test_internal_egress_removes_the_control_plane_default_route(self):
        skel = skeleton()
        skel["networks"]["egress"] = {"internal": True}
        _, results = run(skel)
        self.assertTrue(any(r.desc.startswith("control-plane") for r in failed(results, "rota")))

    def test_nginx_without_backend_cannot_reach_control_plane(self):
        skel = skeleton()
        del skel["services"]["nginx"]["networks"]["backend"]
        _, results = run(skel)
        self.assertTrue(any("nginx -> control-plane" in r.desc for r in failed(results, "alcance")))

    def test_ipv4_mapped_remote_addr_counts_as_the_ipv4_address(self):
        # o httpd do busybox pode escutar em dual-stack e reportar ::ffff:a.b.c.d
        skel = skeleton()
        eng = FakeEngine(skel)
        eng.host_remote_addr = lambda: "::ffff:" + eng.net("default")[1]
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertEqual(failed(results, "origem"), [])

    def test_bracketed_ipv4_mapped_remote_addr_exactly_as_seen_in_ci(self):
        # run 38167041377: obtido=[::ffff:172.20.0.1] com 172.20.0.1 = gateway da skel_default
        eng = FakeEngine(skeleton())
        eng.host_remote_addr = lambda: "[::ffff:%s]" % eng.net("default")[1]
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertEqual(failed(results), [], [sk.render(r) for r in failed(results)])
        (origem,) = [r for r in results if r.kind == "origem"]
        self.assertIn("[::ffff:", origem.got)                      # a linha mostra o que o servidor disse

    def test_bracketed_remote_addr_outside_the_default_subnet_still_fails(self):
        eng = FakeEngine(skeleton())
        eng.host_remote_addr = lambda: "[::ffff:192.0.2.77]"
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertEqual([r.kind for r in failed(results)], ["origem"])
        self.assertIn("[::ffff:192.0.2.77]", failed(results)[0].got)

    def test_garbage_remote_addr_is_a_failure_not_a_crash(self):
        eng = FakeEngine(skeleton())
        eng.host_remote_addr = lambda: "isto-nao-e-um-ip"
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertEqual([r.kind for r in failed(results)], ["origem"])

    def test_remote_addr_outside_the_default_subnet_fails(self):
        eng = FakeEngine(skeleton())
        eng.host_remote_addr = lambda: "192.0.2.77"
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertEqual([r.kind for r in failed(results)], ["origem"])

    def test_negative_check_with_no_ip_cannot_pass_vacuously(self):
        eng = FakeEngine(skeleton())
        eng.ips = lambda svc: []                                   # container sumiu
        results = sk.run_checks(eng, retry_seconds=0)
        self.assertTrue(any("sem IP" in r.got for r in failed(results, "isolamento")))

    def test_missing_published_port_fails_the_origin_check(self):
        skel = skeleton()
        del skel["services"]["nginx"]["ports"]
        _, results = run(skel)
        self.assertTrue(failed(results, "origem"))


class WaitFor(unittest.TestCase):
    def test_returns_as_soon_as_the_value_is_truthy(self):
        calls = []

        def fn():
            calls.append(1)
            return len(calls) >= 3
        self.assertTrue(sk.wait_for(fn, 5, step=0, sleep=lambda s: None))
        self.assertEqual(len(calls), 3)

    def test_gives_up_after_the_deadline_and_returns_the_last_value(self):
        calls = []
        self.assertFalse(sk.wait_for(lambda: calls.append(1) or False, 0.05, step=0.01))
        self.assertGreater(len(calls), 1)

    def test_zero_seconds_is_a_single_attempt(self):
        calls = []
        self.assertFalse(sk.wait_for(lambda: calls.append(1) or False, 0, step=0, sleep=lambda s: None))
        self.assertEqual(len(calls), 1)


class RunChecksTiming(unittest.TestCase):
    def test_a_service_that_comes_up_late_is_waited_for(self):
        eng = FakeEngine(skeleton())
        real, seen = eng.reach, {"n": 0}

        def late(src, host, port):
            if (src, host) == ("nginx", "control-plane") and seen["n"] < 2:
                seen["n"] += 1
                return False
            return real(src, host, port)
        eng.reach = late
        with mock.patch.object(sk, "RETRY_STEP", 0.001):
            results = sk.run_checks(eng, retry_seconds=5)
        self.assertEqual(failed(results), [])
        self.assertEqual(seen["n"], 2)

    def test_a_service_that_never_comes_up_fails(self):
        eng = FakeEngine(skeleton())
        real = eng.reach
        eng.reach = lambda s, h, p: False if (s, h) == ("nginx", "ingest") else real(s, h, p)
        with mock.patch.object(sk, "RETRY_STEP", 0.001):
            results = sk.run_checks(eng, retry_seconds=0.05)
        self.assertTrue(any("nginx -> ingest" in r.desc for r in failed(results, "alcance")))

    def test_ip_level_reachability_is_caught_even_if_dns_isolation_holds(self):
        # simula um host sem o isolamento entre bridges do Docker: o nome nao resolve, o IP responde
        eng = FakeEngine(skeleton())
        real = eng.reach
        eng.reach = lambda s, h, p: True if h.startswith("10.") else real(s, h, p)
        results = sk.run_checks(eng, retry_seconds=0)
        bad = failed(results)
        self.assertTrue(bad)
        self.assertTrue(all(r.kind == "isolamento" and "por IP" in r.desc for r in bad), [r.desc for r in bad])


class Report(unittest.TestCase):
    def test_exit_code_and_summary(self):
        _, ok = run(skeleton())
        buf = io.StringIO()
        self.assertEqual(sk.report(ok, out=buf), 0)
        self.assertIn("0 falha(s)", buf.getvalue())
        skel = skeleton()
        skel["services"]["gvmd"]["networks"]["backend"] = None
        _, bad = run(skel)
        buf = io.StringIO()
        self.assertEqual(sk.report(bad, out=buf), 1)
        self.assertIn("[FALHA]", buf.getvalue())
        self.assertRegex(buf.getvalue(), r"[1-9]\d* falha\(s\)")


class Main(unittest.TestCase):
    def fake_runner(self, cfg):
        def runner(args, cwd, env):
            return 0, json.dumps(cfg), ""
        return runner

    def run_main(self, cfg, engines):
        def factory(workdir, skel):
            eng = FakeEngine(skel)
            engines.append(eng)
            return eng
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sk.main(compose_dir=COMPOSE_DIR, runner=self.fake_runner(cfg), engine_factory=factory)
        return rc, buf.getvalue()

    def test_ok_topology_exits_zero_and_tears_down(self):
        engines = []
        rc, out = self.run_main(load_ok(), engines)
        self.assertEqual(rc, 0, out)
        self.assertEqual(engines[0].downs, 1)

    def test_broken_topology_exits_one_prints_each_check_and_tears_down(self):
        cfg = load_ok()
        cfg["services"]["gsad"]["networks"]["docker-api"] = None
        engines = []
        rc, out = self.run_main(cfg, engines)
        self.assertEqual(rc, 1, out)
        self.assertIn("[FALHA]", out)
        self.assertIn("esperado=", out)
        self.assertIn("-- diagnostico --", out)                    # so' quando falha
        self.assertEqual(engines[0].downs, 1)

    def test_engine_problem_during_the_checks_is_exit_two_with_diagnostics_and_teardown(self):
        engines = []

        def factory(workdir, skel):
            eng = FakeEngine(skel)

            def broken_net(key):
                raise cn.InputError("docker network inspect skel_%s falhou" % key)
            eng.net = broken_net
            engines.append(eng)
            return eng
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sk.main(compose_dir=COMPOSE_DIR, runner=self.fake_runner(load_ok()), engine_factory=factory)
        self.assertEqual(rc, 2, buf.getvalue())
        self.assertIn("ENTRADA INVALIDA", buf.getvalue())
        self.assertIn("-- diagnostico --", buf.getvalue())
        self.assertEqual(engines[0].downs, 1)

    def test_unresolvable_config_is_exit_two(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sk.main(compose_dir=COMPOSE_DIR, runner=lambda a, c, e: (1, "", "boom"),
                         engine_factory=lambda w, s: FakeEngine(s))
        self.assertEqual(rc, 2, buf.getvalue())

    def test_teardown_happens_even_if_a_check_raises(self):
        engines = []

        def factory(workdir, skel):
            eng = FakeEngine(skel)
            eng.reach = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("docker caiu"))
            engines.append(eng)
            return eng
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                sk.main(compose_dir=COMPOSE_DIR, runner=self.fake_runner(load_ok()), engine_factory=factory)
        self.assertEqual(engines[0].downs, 1)


class RunHelper(unittest.TestCase):
    """O _run real (subprocess) -- exercitado com o proprio Python, sem Docker."""

    def test_success_returns_only_stdout_so_warnings_do_not_pollute_parsing(self):
        rc, out = sk._run([sys.executable, "-c",
                           "import sys; print('so-stdout'); print('ruido', file=sys.stderr)"])
        self.assertEqual((rc, out.strip()), (0, "so-stdout"))

    def test_failure_returns_stdout_and_stderr_for_the_diagnosis(self):
        rc, out = sk._run([sys.executable, "-c",
                           "import sys; print('saida'); print('erro', file=sys.stderr); sys.exit(3)"])
        self.assertEqual(rc, 3)
        self.assertIn("saida", out)
        self.assertIn("erro", out)

    def test_timeout_is_a_failed_command_not_an_exception(self):
        rc, out = sk._run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.3)
        self.assertEqual(rc, 124)
        self.assertIn("timeout", out)


class EngineCommands(unittest.TestCase):
    """O Engine real so' monta comandos e le a saida: confere ambos, sem Docker."""

    def make(self, answers):
        calls = []

        def run(args, **kw):
            calls.append(args)
            return answers(args)
        return sk.Engine(os.path.join("tmp", "skel"), run=run, http_get=lambda url: "REMOTE_ADDR=10.1.0.1\n"), calls

    def test_reach_is_a_two_second_wget_inside_the_source_container(self):
        eng, calls = self.make(lambda a: (0, ""))
        self.assertTrue(eng.reach("gsad", "control-plane", 8080))
        (args,) = calls
        self.assertEqual(args[:5], ["docker", "compose", "-p", "skel", "-f"])
        self.assertEqual(args[-10:], ["exec", "-T", "gsad", "wget", "-q", "-T", "2", "-O", "/dev/null",
                                      "http://control-plane:8080/"])
        eng, _ = self.make(lambda a: (1, "bad address"))
        self.assertFalse(eng.reach("gsad", "control-plane", 8080))

    def test_network_info(self):
        eng, calls = self.make(lambda a: (0, "172.18.0.0/16 172.18.0.1\n"))
        self.assertEqual(eng.net("default"), ("172.18.0.0/16", "172.18.0.1"))
        self.assertIn("skel_default", calls[0])

    def test_ips_asks_compose_for_the_container_then_inspects_it(self):
        def answers(args):
            if "ps" in args:
                return 0, "abc123\n"
            return 0, "172.18.0.2 172.19.0.3 \n"
        eng, calls = self.make(answers)
        self.assertEqual(eng.ips("nginx"), ["172.18.0.2", "172.19.0.3"])
        self.assertEqual(calls[1][:2], ["docker", "inspect"])

    def test_route_returns_ip_route_output(self):
        eng, calls = self.make(lambda a: (0, "default via 172.18.0.1 dev eth0\n"))
        self.assertEqual(sk.default_gateway(eng.route("nginx")), "172.18.0.1")
        self.assertEqual(calls[0][-3:], ["nginx", "ip", "route"])

    def test_host_remote_addr_parses_the_cgi_echo(self):
        eng, _ = self.make(lambda a: (0, ""))
        self.assertEqual(eng.host_remote_addr(), "10.1.0.1")

    def test_host_remote_addr_keeps_what_the_server_reported_brackets_included(self):
        # o Engine devolve o texto observado (e' o que aparece em `obtido=`); quem normaliza
        # e' inside_subnet, so' para a conferencia
        calls = []
        eng = sk.Engine(os.path.join("tmp", "skel"), run=lambda a, **kw: (0, ""),
                        http_get=lambda url: calls.append(url) or "REMOTE_ADDR=[::ffff:172.20.0.1]\n",
                        host_port=8443)
        self.assertEqual(eng.host_remote_addr(), "[::ffff:172.20.0.1]")
        self.assertEqual(calls, ["http://127.0.0.1:8443/cgi-bin/ra"])

    def test_down_removes_volumes_and_orphans(self):
        eng, calls = self.make(lambda a: (0, ""))
        eng.down()
        self.assertEqual(calls[0][-3:], ["down", "-v", "--remove-orphans"])


class WorkflowSkeletonJob(unittest.TestCase):
    def read(self):
        with open(WORKFLOW, encoding="utf-8") as f:
            return f.read()

    def job(self, name):
        text = self.read()
        m = re.search(r"^  %s:\n(.*?)(?=^  \S|\Z)" % re.escape(name), text, re.S | re.M)
        self.assertIsNotNone(m, "job %s ausente do workflow" % name)
        return m.group(1)

    def test_skeleton_job_runs_the_script(self):
        self.assertIn("python3 compose/test/skeleton_stack.py", self.job("esqueleto"))

    def test_skeleton_job_always_tears_the_stack_down(self):
        job = self.job("esqueleto")
        m = re.search(r"- name: [^\n]*\n\s+if: always\(\)\n\s+run: \|?\s*\n?(.*)", job, re.S)
        self.assertIsNotNone(m, "falta um passo `if: always()` no job esqueleto")
        self.assertIn("docker compose -p skel", m.group(1))
        self.assertIn("down", m.group(1))

    def test_hash_job_checks_out_the_full_history(self):
        job = self.job("redes")
        self.assertRegex(job, r"fetch-depth:\s*0")
        self.assertIn("check_networks.py --hashes", job)


if __name__ == "__main__":
    unittest.main()
