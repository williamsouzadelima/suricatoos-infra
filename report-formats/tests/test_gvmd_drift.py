#!/usr/bin/env python3
"""Testes do vigia da deriva do gvmd (ci/gvmd-drift.sh): o gvmd fixado por digest no CI
(ci/lib.sh) contra a `stable' que a producao puxa.

O script e' agendado e informativo: sai 0 sempre e escreve o veredito no resumo. Aqui ele roda
de verdade, com um `docker', um `sleep' e um `compile.sh' de mentira no PATH/na pasta, e se
confere cada ramo: sem deriva (nao compila), deriva com a compilacao passando, deriva com a
compilacao reprovando, stable que nao baixa, pin que nao e' digest. O CI roda isto no job
feed-sync. So' biblioteca padrao, bash e sh.

    python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.abspath(os.environ.get("REPORT_FORMATS_DIR") or os.path.dirname(HERE))


def achar_bash():
    """O bash do Git ou do Linux, nao o bash.exe do WSL (System32), que roda outro mundo."""
    p = shutil.which("bash")
    if not p or "system32" in p.lower().replace("/", "\\"):
        return None
    return p


BASH = achar_bash()

FAKE_DOCKER = r"""#!/bin/sh
# docker de mentira para o gvmd-drift.sh (so' o que o lib.sh e o script usam)
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
  image)
    case "$*" in
      *RepoDigests*)
        [ -n "$FAKE_PULL_FAIL" ] && exit 1
        echo "$FAKE_STABLE_REF"; exit 0 ;;
      *Labels*) echo "${FAKE_VERSION:-v99.0.0}"; exit 0 ;;
      *Created*) echo "2026-10-19T07:00:00Z"; exit 0 ;;
      *) [ -n "$FAKE_PULL_FAIL" ] && exit 1; exit 0 ;;      # `docker image inspect <ref>': a imagem ja' esta' aqui
    esac ;;
  pull) [ -n "$FAKE_PULL_FAIL" ] && exit 1; exit 0 ;;
esac
exit 0
"""

FAKE_COMPILE = r"""#!/bin/sh
echo "COMPILE lang=$1 variant=$2 dir=$3 GVMD_IMAGE=$GVMD_IMAGE" >> "$FAKE_LOG"
echo "linha de log da compilacao de mentira"
exit "${FAKE_COMPILE_RC:-0}"
"""


def escreve(path, texto, exec_=True):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(texto)
    if exec_:
        os.chmod(path, 0o755)


@unittest.skipUnless(BASH, "precisa de bash (nao o do WSL)")
class VigiaDaDeriva(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rf-deriva-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ci = os.path.join(self.tmp, "ci")
        os.makedirs(self.ci)
        for nome in ("gvmd-drift.sh", "lib.sh"):
            shutil.copy(os.path.join(RF, "ci", nome), self.ci)
        escreve(os.path.join(self.ci, "compile.sh"), FAKE_COMPILE)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        escreve(os.path.join(self.bin, "docker"), FAKE_DOCKER)
        escreve(os.path.join(self.bin, "sleep"), "#!/bin/sh\nexit 0\n")      # o gvmd_pull dorme 20 s entre tentativas
        with open(os.path.join(self.ci, "lib.sh"), encoding="utf-8") as fh:
            m = re.search(r"gvmd@(sha256:[0-9a-f]{64})\}", fh.read())
        self.assertTrue(m, "o lib.sh do repo nao tem o gvmd fixado por digest")
        self.pin = m.group(1)
        self.log = os.path.join(self.tmp, "chamadas.log")
        open(self.log, "w").close()
        self.summary = os.path.join(self.tmp, "summary.md")

    def roda(self, stable_digest=None, **extra):
        """Roda o script e devolve (rc, stdout, deriva.md, resumo-do-job, chamadas)."""
        out = os.path.join(self.tmp, "saida")
        env = dict(os.environ, PATH=os.pathsep.join([self.bin, os.environ["PATH"]]), FAKE_LOG=self.log,
                   GITHUB_STEP_SUMMARY=self.summary, FAKE_STABLE_REF="registry.community.greenbone.net/community/gvmd@"
                   + (stable_digest or self.pin))
        env.pop("GVMD_IMAGE", None)
        env.update({k: v for k, v in extra.items() if v is not None})
        script = os.path.join(self.ci, "gvmd-drift.sh").replace("\\", "/")
        r = subprocess.run([BASH, script, out.replace("\\", "/")], capture_output=True, env=env)
        def ler(p):
            if not os.path.exists(p):
                return ""
            with open(p, encoding="utf-8") as fh:
                return fh.read()
        return (r.returncode, r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace"),
                ler(os.path.join(out, "deriva.md")), ler(self.summary), ler(self.log))

    def outro_digest(self):
        return "sha256:" + "0" * 63 + "1"

    # --- sem deriva -------------------------------------------------------------------------------
    def test_mesmo_digest_do_pin_nao_compila_e_nao_avisa(self):
        rc, out, md, resumo, chamadas = self.roda()
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)
        self.assertNotIn("COMPILE", chamadas)
        self.assertNotIn("::warning::", out)
        self.assertEqual(resumo, md)                     # o resumo do job e' o relatorio

    def test_um_gvmd_image_herdado_do_ambiente_nao_esconde_o_pin(self):
        rc, out, md, _, chamadas = self.roda(GVMD_IMAGE="registry.example/gvmd:qualquer")
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)                  # comparou a stable com o PIN, nao com o valor herdado
        self.assertIn(self.pin, md)

    # --- deriva -----------------------------------------------------------------------------------
    def test_digest_diferente_avisa_e_compila_uma_combinacao_na_stable(self):
        novo = self.outro_digest()
        rc, out, md, resumo, chamadas = self.roda(stable_digest=novo, FAKE_VERSION="v99.1.2")
        self.assertEqual(rc, 0, out)
        self.assertIn("DERIVA", md)
        self.assertIn(self.pin, md)
        self.assertIn(novo, md)
        self.assertIn("v99.1.2", md)
        self.assertIn("A compilacao passou", md)
        self.assertIn("::warning::A gvmd:stable (v99.1.2", out)               # anotacao do GitHub
        compilou = [l for l in chamadas.splitlines() if l.startswith("COMPILE")]
        self.assertEqual(len(compilou), 1, chamadas)
        self.assertIn("lang=en variant=technical", compilou[0])
        self.assertIn("GVMD_IMAGE=registry.community.greenbone.net/community/gvmd:stable", compilou[0])   # na stable, nao no pin
        self.assertEqual(resumo, md)

    def test_compilacao_que_reprova_na_stable_avisa_mais_alto_e_ainda_sai_0(self):
        rc, out, md, _, chamadas = self.roda(stable_digest=self.outro_digest(), FAKE_COMPILE_RC="1")
        self.assertEqual(rc, 0, out)                      # informativo: nao bloqueia
        self.assertIn("A COMPILACAO REPROVOU", md)
        self.assertIn("linha de log da compilacao de mentira", md)           # as ultimas linhas do log vao no resumo
        self.assertIn("::warning::A compilacao do relatorio (en/technical) REPROVOU", out)
        self.assertNotIn("A compilacao passou", md)

    def test_a_combinacao_vem_do_ambiente(self):
        rc, out, md, _, chamadas = self.roda(stable_digest=self.outro_digest(), DRIFT_LANG="pt_BR", DRIFT_VARIANT="client")
        self.assertEqual(rc, 0, out)
        self.assertIn("lang=pt_BR variant=client", chamadas)

    # --- sem como comparar: avisa, nao reprova ------------------------------------------------------------
    def test_stable_que_nao_baixa_avisa_e_nao_compila(self):
        rc, out, md, _, chamadas = self.roda(FAKE_PULL_FAIL="1")
        self.assertEqual(rc, 0, out)
        self.assertIn("nao consegui baixar", md)
        self.assertIn("::warning::Nao consegui baixar a gvmd:stable", out)
        self.assertNotIn("COMPILE", chamadas)

    def test_pin_que_nao_e_digest_avisa_e_nao_chama_o_docker(self):
        path = os.path.join(self.ci, "lib.sh")
        with open(path, encoding="utf-8") as fh:
            texto = fh.read()
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(re.sub(r"gvmd@sha256:[0-9a-f]{64}\}", "gvmd:stable}", texto))
        rc, out, md, _, chamadas = self.roda()
        self.assertEqual(rc, 0, out)
        self.assertIn("nao esta' fixado por digest", md)
        self.assertIn("::warning::O gvmd de report-formats/ci/lib.sh nao esta' fixado por digest", out)
        self.assertEqual(chamadas, "")

    def test_digest_ilegivel_avisa(self):
        rc, out, md, _, chamadas = self.roda(stable_digest="sha256:curto")
        self.assertEqual(rc, 0, out)
        self.assertIn("nao consegui ler o digest", md)
        self.assertNotIn("COMPILE", chamadas)

    # --- o contrato ---------------------------------------------------------------------------------------
    def test_sem_github_step_summary_funciona_e_escreve_o_relatorio_no_stdout(self):
        rc, out, md, resumo, _ = self.roda(GITHUB_STEP_SUMMARY="")
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", out)
        self.assertEqual(resumo, "")


if __name__ == "__main__":
    unittest.main()
