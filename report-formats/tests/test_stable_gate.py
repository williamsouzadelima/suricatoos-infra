#!/usr/bin/env python3
"""Testes do portao da tag `stable' (ci/stable-gate.sh): quando o publish pode mover
`suricatoos-report-formats:stable' para um commit.

A producao puxa `stable' direto; mover para um commit VELHO faz a frota voltar atras no
sync seguinte, sem que o GSA mostre nada. O publish dispara por workflow_run (inclusive
o re-run de um CI antigo e um CI lento que termina depois de um mais novo) e por
disparo manual (de qualquer branch), entao a regra e' do historico git: `stable' so'
anda para o commit mais novo da main que toca o relatorio, e a decisao e' EXATA -- o
relatorio da main tem de ter o mesmo conteudo que o do commit.

Cada teste monta um repositorio git de verdade (commits, branches, merges, tags) e roda o
script nele. O CI roda isto no job feed-sync. So' biblioteca padrao, bash e git.

    python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.abspath(os.environ.get("REPORT_FORMATS_DIR") or os.path.dirname(HERE))
GATE = os.path.join(RF, "ci", "stable-gate.sh").replace("\\", "/")
MAIN = "refs/heads/main"          # o ref COMPLETO da main nos repositorios de teste


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

    def many_commits(self, n, subject_len=110):
        """`n' commits em cima de `main', cada um criando report-formats/n<i>.txt, por git
        fast-import (um por um levaria minutos). Os assuntos tem `subject_len' caracteres."""
        parent = self.git("rev-parse", "HEAD")
        partes = []
        for i in range(n):
            msg = ("relatorio: mudanca numero %d " % i).ljust(subject_len, "x").encode("ascii") + b"\n"
            conteudo = b"conteudo %d\n" % i
            partes.append(b"commit refs/heads/main\ncommitter Teste <teste@example.com> %d +0000\ndata %d\n%s\n"
                          % (1700000000 + i, len(msg), msg))
            if i == 0:
                partes.append(b"from %s\n" % parent.encode("ascii"))
            partes.append(b"M 100644 inline report-formats/n%d.txt\ndata %d\n%s\n\n" % (i, len(conteudo), conteudo))
        r = subprocess.run([GIT, "-C", self.dir, "fast-import", "--quiet"], input=b"".join(partes),
                           capture_output=True, env=self.env)
        if r.returncode != 0:
            raise AssertionError("git fast-import: %s" % r.stderr.decode("utf-8", "replace"))
        self.git("reset", "-q", "--hard")
        return self.git("rev-parse", "HEAD")


def gate(repo_dir, src, main=MAIN, env=None):
    """Roda o portao. `main=None' omite o 2o argumento (o padrao do script)."""
    cmd = [BASH, GATE, src] + ([] if main is None else [main])
    r = subprocess.run(cmd, cwd=repo_dir, capture_output=True, env=env)
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

    def decide(self, src, main=MAIN):
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

    # --- o ref da main: nome COMPLETO (N1) ----------------------------------------------------------
    def test_tag_com_o_nome_do_remoto_nao_sombreia_o_ref_completo(self):
        # git resolve um nome curto como `origin/main' na ordem refs/tags/, refs/heads/,
        # refs/remotes/: uma TAG com esse nome num commit velho sombreia o ref remoto, e o portao
        # liberaria o commit velho (a regressao silenciosa que ele existe para impedir).
        c2 = self.r.commit({"report-formats/b.txt": "novo"}, "relatorio: arquivo novo")
        self.r.git("update-ref", "refs/remotes/origin/main", c2)       # o que o `git fetch' do publish escreve
        self.r.git("tag", "origin/main", self.c1)                      # a tag que sombreia, no commit VELHO
        self.assertEqual(self.r.git("rev-parse", "origin/main"), self.c1)   # a premissa do ataque
        # sem o 2o argumento o padrao e' o ref remoto COMPLETO: c1 nao e' a ponta, ha' commit novo
        rc, d, out, err = gate(self.r.dir, self.c1, None, self.r.env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("relatorio: arquivo novo", d["STABLE_REASON"])
        self.assertEqual(gate(self.r.dir, c2, None, self.r.env)[1]["MOVE_STABLE"], "true")
        # e o nome curto que a tag sombreia e' recusado, nao resolvido
        rc, _, out, err = gate(self.r.dir, self.c1, "origin/main", self.r.env)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("COMPLETO", err)

    def test_nome_curto_do_ref_e_recusado(self):
        for curto in ("main", "origin/main", "HEAD", "heads/main"):
            with self.subTest(ref=curto):
                rc, _, out, err = gate(self.r.dir, self.c1, curto, self.r.env)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn("COMPLETO", err)

    def test_o_padrao_e_o_ref_remoto_completo(self):
        rc, _, out, err = gate(self.r.dir, self.c1, None, self.r.env)             # nao ha' refs/remotes/origin/main
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("refs/remotes/origin/main", err)
        self.r.git("update-ref", "refs/remotes/origin/main", self.c1)
        rc, d, out, err = gate(self.r.dir, self.c1, None, self.r.env)
        self.assertEqual((rc, d["MOVE_STABLE"]), (0, "true"), err)

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
                rc, d, _, err = gate(r.dir, base, MAIN, r.env)
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

    # --- a lista longa nao derruba o script (N2) -------------------------------------------------------
    def test_lista_longa_de_commits_novos_nao_derruba_o_script_com_sigpipe(self):
        # Mais de 64 KiB de "%h %s": um `head' no fim de um pipe, sob pipefail, morria de SIGPIPE
        # (exit 141, sem saida) em vez do 0 documentado. 2500 commits de ~118 bytes.
        self.r.many_commits(2500, subject_len=110)
        rc, d, out, err = gate(self.r.dir, self.c1, MAIN, self.r.env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("2500 commit(s)", d["STABLE_REASON"])
        self.assertIn("(+2497)", d["STABLE_REASON"])
        self.assertIn("arquivos:", d["STABLE_REASON"])
        self.assertEqual(len(out.splitlines()), 2, out[:300])

    # --- a decisao e' EXATA: o conteudo do relatorio, nao a forma da historia (N3) -------------------------
    def test_commits_que_se_anulam_deixam_o_relatorio_identico_e_liberam(self):
        self.r.commit({"report-formats/a.txt": "3"}, "relatorio: muda a")
        self.r.commit({"report-formats/a.txt": "2"}, "relatorio: volta a")     # o conteudo de c1 de novo
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "true")
        self.assertIn("identico", d["STABLE_REASON"])
        self.assertIn("2 dos 2 commit(s)", d["STABLE_REASON"])

    def test_merge_de_branch_so_de_outra_coisa_criado_antes_do_commit_libera(self):
        # Um branch de docs que sai ANTES de SRC e volta DEPOIS: o merge difere do pai que nao e'
        # ancestral de SRC (a caminhada pela historia o listaria), mas o relatorio e' o mesmo.
        self.r.git("checkout", "-q", "-b", "docs", self.c0)
        self.r.commit({"docs/y.md": "d"}, "docs: y")
        self.r.git("checkout", "-q", "main")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge dos docs", "docs")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "true")
        self.assertIn("identico", d["STABLE_REASON"])

    def test_branch_ja_integrado_antes_de_o_commit_existir_libera(self):
        # O commit SRC (c1) e' o TOPO de um branch ja' integrado: o merge o traz, e nada mais muda.
        self.r.git("checkout", "-q", "-b", "feature/z", self.c1)
        z1 = self.r.commit({"docs/z.md": "z"}, "feature: so' docs")
        self.r.git("checkout", "-q", "main")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge de z", "feature/z")
        self.assertEqual(self.decide(z1)["MOVE_STABLE"], "true")

    def test_conteudo_diferente_bloqueia_e_lista_os_arquivos(self):
        self.r.commit({"report-formats/b.txt": "novo", "report-formats/c.txt": "novo"}, "relatorio: b e c")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("DIFERE", d["STABLE_REASON"])
        self.assertIn("arquivos: report-formats/b.txt, report-formats/c.txt", d["STABLE_REASON"])

    # --- merges: o bloqueio e' explicado pela historia (--full-history, o lado conservador) ----------------
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
        # O conteudo difere (a feature tambem mexeu em a.txt) e a EXPLICACAO usa --full-history: a
        # mudanca que o merge descartou ainda e' um commit novo que toca o relatorio, e e' nomeada.
        self.r.git("checkout", "-q", "-b", "feature/x", self.c1)
        self.r.commit({"report-formats/a.txt": "da feature"}, "feature: a")
        self.r.git("checkout", "-q", "main")
        self.r.commit({"report-formats/a.txt": "da main"}, "main: a")
        self.r.git("merge", "-q", "--no-ff", "-X", "theirs", "-m", "merge descartando a main", "feature/x")
        d = self.decide(self.c1)
        self.assertEqual(d["MOVE_STABLE"], "false")
        self.assertIn("main: a", d["STABLE_REASON"])

    # --- a saida e' limpa (N8) -----------------------------------------------------------------------------
    def test_caracteres_de_controle_do_assunto_nao_chegam_a_saida(self):
        # A razao vai para o $GITHUB_ENV e para um ::warning::: CR, ESC, BEL e tab do assunto de um
        # commit sairiam como estao.
        self.r.commit({"report-formats/b.txt": "novo"}, "relatorio: a\rb\x1b[31mc\x07d\te")
        rc, d, out, err = gate(self.r.dir, self.c1, MAIN, self.r.env)
        self.assertEqual((rc, d["MOVE_STABLE"]), (0, "false"), err)
        self.assertEqual(re.findall(r"[\x00-\x09\x0b-\x1f\x7f]", out), [], repr(out))
        self.assertEqual(len(out.splitlines()), 2, repr(out))
        self.assertIn("relatorio: ab[31mcde", d["STABLE_REASON"])           # o resto do texto fica

    # --- erros: o chamador PARA, nao assume nada ---------------------------------------------------------
    def test_clone_raso_e_erro(self):
        raso = os.path.join(self.tmp, "raso")
        r = subprocess.run([GIT, "clone", "-q", "--depth", "1", pathlib.Path(self.r.dir).as_uri(), raso],
                           capture_output=True, env=self.r.env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        rc, dados, out, err = gate(raso, "HEAD", MAIN, self.r.env)
        self.assertEqual(rc, 2)
        self.assertIn("raso", err)
        self.assertEqual(out, "")

    def test_commit_ou_ref_desconhecido_e_erro(self):
        rc, _, out, err = gate(self.r.dir, "deadbeefdeadbeefdeadbeef", MAIN, self.r.env)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("commit desconhecido", err)
        # um ref COMPLETO que nao existe (aqui, sem remoto: nao ha' refs/remotes/origin/main)
        rc, _, out, err = gate(self.r.dir, self.c1, "refs/remotes/origin/main", self.r.env)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ref desconhecido", err)

    def test_fora_de_um_repositorio_e_erro(self):
        fora = os.path.join(self.tmp, "fora")
        os.makedirs(fora)
        rc, _, out, err = gate(fora, "HEAD", MAIN, dict(self.r.env, GIT_CEILING_DIRECTORIES=self.tmp))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("fora de um repositorio", err)

    # --- o contrato da saida --------------------------------------------------------------------------
    def test_a_saida_sao_so_as_duas_linhas_do_github_env(self):
        rc, d, out, err = gate(self.r.dir, self.c1, MAIN, self.r.env)
        linhas = out.splitlines()
        self.assertEqual(len(linhas), 2, out)
        self.assertTrue(linhas[0].startswith("MOVE_STABLE="))
        self.assertTrue(linhas[1].startswith("STABLE_REASON="))

    def test_rodar_de_uma_subpasta_da_o_mesmo_resultado(self):
        self.r.commit({"report-formats/b.txt": "novo"}, "relatorio: novo")
        sub = os.path.join(self.r.dir, "report-formats")
        rc, d, _, err = gate(sub, self.c1, MAIN, self.r.env)
        self.assertEqual((rc, d["MOVE_STABLE"]), (0, "false"), err)


if __name__ == "__main__":
    unittest.main()
