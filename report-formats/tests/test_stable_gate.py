#!/usr/bin/env python3
"""Testes do portao da tag `stable' (ci/stable-gate.sh): quando o publish pode mover
`suricatoos-report-formats:stable' para um commit.

A producao puxa `stable' direto; mover para um commit VELHO faz a frota voltar atras no
sync seguinte, sem que o GSA mostre nada. O publish dispara por workflow_run (inclusive
o re-run de um CI antigo e um CI lento que termina depois de um mais novo) e por
disparo manual (de qualquer branch), entao a regra e' do historico git: `stable' so'
anda para o commit mais novo da main que toca o relatorio.

Cada teste monta um repositorio git de verdade (commits, branches, merges) e roda o
script nele. O CI roda isto no job feed-sync. So' biblioteca padrao, bash e git.

    python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.abspath(os.environ.get("REPORT_FORMATS_DIR") or os.path.dirname(HERE))
GATE = os.path.join(RF, "ci", "stable-gate.sh").replace("\\", "/")


def achar_bash():
    """O bash do Git ou do Linux, nao o bash.exe do WSL (System32), que roda outro mundo."""
    p = shutil.which("bash")
    if not p or "system32" in p.lower().replace("/", "\\"):
        return None
    return p


BASH = achar_bash()
GIT = shutil.which("git")


class Repo:
    """Um repositorio git de verdade, isolado da configuracao de quem roda o teste."""

    def __init__(self, tmp, nome="repo"):
        self.dir = os.path.join(tmp, nome)
        os.makedirs(self.dir)
        vazio = os.path.join(tmp, "gitconfig-vazio")
        open(vazio, "w").close()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=vazio, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="Teste", GIT_AUTHOR_EMAIL="teste@example.com",
                        GIT_COMMITTER_NAME="Teste", GIT_COMMITTER_EMAIL="teste@example.com",
                        GIT_TERMINAL_PROMPT="0")
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args, check=True):
        r = subprocess.run([GIT, "-C", self.dir] + list(args), capture_output=True, env=self.env)
        out = r.stdout.decode("utf-8", "replace").strip()
        if check and r.returncode != 0:
            raise AssertionError("git %s: %s" % (" ".join(args), r.stderr.decode("utf-8", "replace")))
        return out

    def commit(self, arquivos, msg):
        """Grava `arquivos' ({caminho: texto, ou None para apagar}) e faz o commit; devolve o sha."""
        for caminho, texto in arquivos.items():
            p = os.path.join(self.dir, caminho)
            if texto is None:
                os.remove(p)
                continue
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(texto + "\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")


def gate(repo_dir, src, main="main", env=None):
    r = subprocess.run([BASH, GATE, src, main], cwd=repo_dir, capture_output=True, env=env)
    out = r.stdout.decode("utf-8", "replace")
    dados = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    return r.returncode, dados, out, r.stderr.decode("utf-8", "replace")


@unittest.skipUnless(BASH and GIT, "precisa de bash (nao o do WSL) e de git")
class PortaoDaTagStable(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rf-gate-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.r = Repo(self.tmp)
        self.c0 = self.r.commit({"report-formats/a.txt": "1", "README.md": "r", "compose/c.yml": "x"}, "inicio")
        self.c1 = self.r.commit({"report-formats/a.txt": "2"}, "relatorio: muda a")

    def decide(self, src, main="main"):
        rc, dados, out, err = gate(self.r.dir, src, main, self.r.env)
        self.assertEqual(rc, 0, err)
        return dados

    # --- os cinco cenarios do controlador ---------------------------------------------------------
    def test_o_commit_mais_novo_do_relatorio_move_stable(self):
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "true")
        self.assertIn("ponta", d["STABLE_REASON"])

    def test_re_run_de_commit_velho_com_commit_mais_novo_do_relatorio_na_main_nao_move(self):
        c2 = self.r.commit({"report-formats/b.txt": "novo"}, "relatorio: arquivo novo")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("1 commit(s)", d["STABLE_REASON"])
        self.assertIn("relatorio: arquivo novo", d["STABLE_REASON"])
        self.assertEqual(self.decide(c2)["MOVE_STABLE"], "true")       # o mais novo continua podendo

    def test_re_run_de_commit_velho_cujos_commits_mais_novos_nao_tocam_o_relatorio_move(self):
        self.r.commit({"docs/x.md": "doc"}, "docs: x")
        self.r.commit({"compose/c.yml": "y"}, "compose: outro componente")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "true")
        self.assertIn("2 commit(s) depois dele, nenhum toca", d["STABLE_REASON"])

    def test_disparo_da_ponta_da_main_move(self):
        tip = self.r.commit({"docs/x.md": "doc"}, "docs: x")
        self.assertEqual(self.decide(tip)["MOVE_STABLE"], "true")
        self.assertEqual(self.decide("main")["MOVE_STABLE"], "true")   # o ref tambem vale como commit

    def test_disparo_de_um_branch_de_feature_nao_move(self):
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        f1 = self.r.commit({"report-formats/a.txt": "3"}, "feature: muda a")
        self.r.git("checkout", "-q", "main")
        for main_anda in (False, True):
            if main_anda:
                self.r.commit({"docs/x.md": "doc"}, "docs: x")
            d = self.decide(f1)
            self.assertEqual(d["MOVE_STABLE"], "false", main_anda)
            self.assertIn("nao e' ancestral", d["STABLE_REASON"])
        # um branch que so' toca outra coisa tambem nao e' a main: nao move
        self.r.git("checkout", "-q", "-b", "feature/y", self.c1)
        f2 = self.r.commit({"docs/y.md": "doc"}, "feature: so' docs")
        self.assertEqual(self.decide(f2)["MOVE_STABLE"], "false")

    # --- variacoes -----------------------------------------------------------------------------
    def test_branch_ja_integrado_na_main_move_se_nada_mais_novo_toca_o_relatorio(self):
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        f1 = self.r.commit({"report-formats/a.txt": "3"}, "feature: muda a")
        self.r.git("checkout", "-q", "main")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge da feature", "feature/x")
        self.assertEqual(self.decide(f1)["MOVE_STABLE"], "true")

    def test_workflows_do_relatorio_contam_os_outros_nao(self):
        casos = [
            (".github/workflows/report-formats-publish.yml", "false"),
            (".github/workflows/report-formats-ci.yml", "false"),
            (".github/workflows/hygiene.yml", "true"),
            (".github/workflows/report-formats-gvmd-stable.yml", "true"),   # vigia agendado: nao muda a imagem nem a aprovacao
        ]
        for caminho, esperado in casos:
            with self.subTest(arquivo=caminho):
                r = Repo(self.tmp, "wf-" + os.path.basename(caminho))
                base = r.commit({"report-formats/a.txt": "1"}, "inicio")
                r.commit({caminho: "on: push"}, "workflow")
                rc, d, _, err = gate(r.dir, base, "main", r.env)
                self.assertEqual((rc, d["MOVE_STABLE"]), (0, esperado), err)

    def test_apagar_arquivo_do_relatorio_conta(self):
        self.r.commit({"report-formats/a.txt": None}, "relatorio: apaga a")
        self.assertEqual(self.decide(self.c1)["MOVE_STABLE"], "false")

    def test_a_lista_dos_commits_mais_novos_e_curta_e_conta_o_resto(self):
        for i in range(5):
            self.r.commit({"report-formats/n%d.txt" % i: "x"}, "relatorio: n%d" % i)
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("5 commit(s)", d["STABLE_REASON"])
        self.assertIn("(+2)", d["STABLE_REASON"])           # lista 3 e conta os outros 2
        self.assertNotIn("\n", d["STABLE_REASON"])

    # --- merges: o lado conservador ------------------------------------------------------------------
    def test_merge_que_traz_mudanca_do_relatorio_depois_do_commit_bloqueia(self):
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        self.r.commit({"report-formats/a.txt": "feature"}, "feature: muda a")
        self.r.git("checkout", "-q", "main")
        self.r.commit({"docs/x.md": "doc"}, "docs: x")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge da feature", "feature/x")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("feature: muda a", d["STABLE_REASON"])

    def test_merge_que_traz_so_mudanca_de_outra_coisa_nao_bloqueia(self):
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        self.r.commit({"docs/y.md": "feature"}, "feature: so' docs")
        self.r.git("checkout", "-q", "main")
        self.r.commit({"compose/c.yml": "z"}, "compose: z")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge da feature", "feature/x")
        self.assertEqual(self.decide(self.c1)["MOVE_STABLE"], "true")

    def test_merge_que_descarta_a_mudanca_do_relatorio_da_main_continua_bloqueando(self):
        # --full-history: a mudanca que o merge descartou ainda e' um commit novo que toca o
        # relatorio. O lado conservador: na duvida, `stable' nao anda.
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        self.r.commit({"report-formats/a.txt": "da feature"}, "feature: a")
        self.r.git("checkout", "-q", "main")
        self.r.commit({"report-formats/a.txt": "da main"}, "main: a")
        self.r.git("merge", "-q", "--no-ff", "-X", "theirs", "-m", "merge descartando a main", "feature/x")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("main: a", d["STABLE_REASON"])

    # --- erros: o chamador PARA, nao assume nada ---------------------------------------------------------
    def test_clone_raso_e_erro(self):
        raso = os.path.join(self.tmp, "raso")
        r = subprocess.run([GIT, "clone", "-q", "--depth", "1", pathlib.Path(self.r.dir).as_uri(), raso],
                           capture_output=True, env=self.r.env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        rc, dados, out, err = gate(raso, "HEAD", "HEAD", self.r.env)
        self.assertEqual(rc, 2)
        self.assertIn("raso", err)
        self.assertEqual(out, "")

    def test_commit_ou_ref_desconhecido_e_erro(self):
        rc, _, out, err = gate(self.r.dir, "deadbeefdeadbeefdeadbeef", "main", self.r.env)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("commit desconhecido", err)
        rc, _, out, err = gate(self.r.dir, self.c1, "origin/main", self.r.env)     # sem remoto: nao ha' origin/main
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ref desconhecido", err)

    def test_fora_de_um_repositorio_e_erro(self):
        fora = os.path.join(self.tmp, "fora")
        os.makedirs(fora)
        rc, _, out, err = gate(fora, "HEAD", "main", dict(self.r.env, GIT_CEILING_DIRECTORIES=self.tmp))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("fora de um repositorio", err)

    # --- o contrato da saida --------------------------------------------------------------------------
    def test_a_saida_sao_so_as_duas_linhas_do_github_env(self):
        rc, d, out, err = gate(self.r.dir, self.c1, "main", self.r.env)
        linhas = out.splitlines()
        self.assertEqual(len(linhas), 2, out)
        self.assertTrue(linhas[0].startswith("MOVE_STABLE="))
        self.assertTrue(linhas[1].startswith("STABLE_REASON="))

    def test_rodar_de_uma_subpasta_da_o_mesmo_resultado(self):
        self.r.commit({"report-formats/b.txt": "novo"}, "relatorio: novo")
        sub = os.path.join(self.r.dir, "report-formats")
        rc, d, _, err = gate(sub, self.c1, "main", self.r.env)
        self.assertEqual((rc, d["MOVE_STABLE"]), (0, "false"), err)


if __name__ == "__main__":
    unittest.main()
