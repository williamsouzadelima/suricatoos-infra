#!/usr/bin/env python3
"""Testes do vigia da deriva da base do feed (ci/base-drift.sh): a imagem de que o
report-formats/Dockerfile parte, FIXADA por digest no `FROM', contra a tag flutuante dela.

O script e' agendado e informativo: sai 0 sempre e escreve o veredito no resumo. Aqui ele roda
de verdade, com um `docker' e um `sleep' de mentira no PATH, e se confere cada ramo: sem
deriva, deriva, digest fixado que nao baixa mais, tag que nao baixa, nova tentativa do pull,
FROM sem digest / sem FROM / com varios / com opcao, a tag lida do FROM. O ultimo grupo
confere o Dockerfile DO REPO: o FROM e' unico, fixado por digest, e o script o entende. O CI
roda isto no job feed-sync. So' biblioteca padrao, bash e sh.

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
# docker de mentira para o base-drift.sh (so' o que o script usa)
echo "docker $*" >> "$FAKE_LOG"
for a in "$@"; do ref=$a; done                      # a referencia e' o ultimo argumento
case "$1" in
  pull)
    n=0
    [ -f "$FAKE_COUNT" ] && n=$(cat "$FAKE_COUNT")
    n=$((n + 1))
    echo "$n" > "$FAKE_COUNT"
    [ "$n" -le "${FAKE_PULL_FAIL_FIRST:-0}" ] && exit 1
    case "$ref" in
      *@sha256:*) [ -n "$FAKE_PIN_PULL_FAIL" ] && exit 1 ;;
      *)          [ -n "$FAKE_TAG_PULL_FAIL" ] && exit 1 ;;
    esac
    exit 0 ;;
  image)
    case "$*" in
      *RepoDigests*) echo "$FAKE_TAG_REF"; exit 0 ;;
      *Created*)
        case "$ref" in
          *@sha256:*) echo "2026-08-24T06:45:28Z" ;;
          *)          echo "2026-10-19T05:00:00Z" ;;
        esac
        exit 0 ;;
    esac ;;
esac
exit 0
"""

DIGEST_A = "sha256:" + "a" * 64                     # o digest fixado
DIGEST_B = "sha256:" + "b" * 64                     # o que a tag serve depois que anda
BASE = "registry.example.test/comunidade/feed-base"


def escreve(path, texto, exec_=True):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(texto)
    if exec_:
        os.chmod(path, 0o755)


def dockerfile(*froms):
    return "# comentario\n" + "".join("FROM %s\n" % f for f in froms) + "USER root\n"


class _Ambiente:
    """O script no ambiente de mentira (docker e sleep falsos no PATH). Sem testes aqui."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rf-base-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ci = os.path.join(self.tmp, "ci")
        os.makedirs(self.ci)
        shutil.copy(os.path.join(RF, "ci", "base-drift.sh"), self.ci)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        escreve(os.path.join(self.bin, "docker"), FAKE_DOCKER)
        escreve(os.path.join(self.bin, "sleep"), "#!/bin/sh\nexit 0\n")          # o pull dorme 20 s entre tentativas
        self.log = os.path.join(self.tmp, "chamadas.log")
        self.count = os.path.join(self.tmp, "pulls.n")
        self.summary = os.path.join(self.tmp, "summary.md")
        self.saida = os.path.join(self.tmp, "saida")

    def roda(self, df=None, tag_digest=DIGEST_A, tag_ref=None, **extra):
        """Roda o script (do zero) contra o Dockerfile `df' (texto; None = o do ambiente) e
        devolve (rc, stdout+stderr, deriva-base.md, resumo-do-job, chamadas ao docker)."""
        for p in (self.count, self.summary):
            if os.path.exists(p):
                os.remove(p)
        open(self.log, "w").close()
        shutil.rmtree(self.saida, ignore_errors=True)
        env = dict(os.environ, PATH=os.pathsep.join([self.bin, os.environ["PATH"]]), FAKE_LOG=self.log,
                   FAKE_COUNT=self.count, GITHUB_STEP_SUMMARY=self.summary,
                   FAKE_TAG_REF=tag_ref if tag_ref is not None else "%s@%s" % (BASE, tag_digest))
        for k in ("DOCKERFILE", "FAKE_PULL_FAIL_FIRST", "FAKE_PIN_PULL_FAIL", "FAKE_TAG_PULL_FAIL"):
            env.pop(k, None)
        if df is not None:
            path = os.path.join(self.tmp, "Dockerfile.teste")
            escreve(path, df, exec_=False)
            env["DOCKERFILE"] = path.replace("\\", "/")
        env.update({k: v for k, v in extra.items() if v is not None})
        script = os.path.join(self.ci, "base-drift.sh").replace("\\", "/")
        r = subprocess.run([BASH, script, self.saida.replace("\\", "/")], capture_output=True, env=env)

        def ler(p):
            if not os.path.exists(p):
                return ""
            with open(p, encoding="utf-8") as fh:
                return fh.read()
        return (r.returncode, r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace"),
                ler(os.path.join(self.saida, "deriva-base.md")), ler(self.summary), ler(self.log))

    @staticmethod
    def pulls(chamadas):
        """As referencias dos `docker pull', na ordem."""
        return [l.split()[-1] for l in chamadas.splitlines() if l.startswith("docker pull")]


@unittest.skipUnless(BASH, "precisa de bash (nao o do WSL)")
class VigiaDaBase(_Ambiente, unittest.TestCase):
    # --- sem deriva -------------------------------------------------------------------------------
    def test_mesmo_digest_do_pin_nao_avisa(self):
        rc, out, md, resumo, chamadas = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)))
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)
        self.assertNotIn("::warning::", out)
        self.assertEqual(resumo, md)                      # o resumo do job e' o relatorio
        self.assertEqual(self.pulls(chamadas), ["%s@%s" % (BASE, DIGEST_A), "%s:latest" % BASE])
        self.assertIn(DIGEST_A, md)

    # --- deriva -----------------------------------------------------------------------------------
    def test_digest_diferente_avisa_com_os_dois_digests_e_nao_bloqueia(self):
        rc, out, md, resumo, _ = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), tag_digest=DIGEST_B)
        self.assertEqual(rc, 0, out)
        self.assertIn("DERIVA", md)
        self.assertIn(DIGEST_A, md)
        self.assertIn(DIGEST_B, md)
        self.assertIn("2026-10-19T05:00:00Z", md)         # a criacao da base nova
        self.assertIn("::warning::A base do feed (%s:latest, %s" % (BASE, DIGEST_B), out)
        self.assertNotIn("NAO BAIXA", md)                 # o pin baixou: so' a deriva
        self.assertEqual(resumo, md)

    def test_digest_fixado_que_nao_baixa_mais_avisa_que_o_publish_vai_falhar(self):
        rc, out, md, _, chamadas = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)),
                                             tag_digest=DIGEST_B, FAKE_PIN_PULL_FAIL="1")
        self.assertEqual(rc, 0, out)
        self.assertIn("O DIGEST FIXADO NAO BAIXA", md)
        self.assertIn("::warning::A base fixada no report-formats/Dockerfile (%s) nao baixa mais" % DIGEST_A, out)
        self.assertIn("DERIVA", md)                       # e a comparacao com a tag segue
        self.assertEqual(self.pulls(chamadas).count("%s@%s" % (BASE, DIGEST_A)), 3)       # tentou 3 vezes

    def test_pull_que_falha_duas_vezes_e_refeito(self):
        rc, out, md, _, chamadas = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), FAKE_PULL_FAIL_FIRST="2")
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)
        self.assertNotIn("NAO BAIXA", md)
        self.assertEqual(self.pulls(chamadas).count("%s@%s" % (BASE, DIGEST_A)), 3)

    # --- sem como comparar: avisa, nao reprova -------------------------------------------------------------
    def test_tag_que_nao_baixa_avisa_e_diz_que_nao_deu_para_comparar(self):
        rc, out, md, _, chamadas = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), FAKE_TAG_PULL_FAIL="1")
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem como comparar", md)
        self.assertIn("nao consegui baixar `%s:latest`" % BASE, md)
        self.assertIn("::warning::Nao consegui baixar %s:latest" % BASE, out)
        self.assertNotIn("DERIVA", md)
        self.assertEqual(self.pulls(chamadas).count("%s:latest" % BASE), 3)

    def test_digest_ilegivel_da_tag_avisa(self):
        rc, out, md, _, _ = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), tag_ref="%s@sha256:curto" % BASE)
        self.assertEqual(rc, 0, out)
        self.assertIn("nao consegui ler o digest", md)
        self.assertIn("::warning::Nao consegui ler o digest", out)

    def test_base_sem_digest_avisa_e_nao_chama_o_docker(self):
        rc, out, md, _, chamadas = self.roda(dockerfile("%s:latest" % BASE))
        self.assertEqual(rc, 0, out)
        self.assertIn("nao esta' fixada por digest", md)
        self.assertIn("::warning::A base do report-formats/Dockerfile nao esta' fixada por digest", out)
        self.assertEqual(chamadas, "")

    def test_froms_que_o_script_nao_sabe_ler_avisam_e_nao_chamam_o_docker(self):
        casos = {
            "sem FROM": dockerfile(),
            "dois FROM": dockerfile("%s:latest@%s" % (BASE, DIGEST_A), "%s:latest@%s" % (BASE, DIGEST_A)),
            "FROM com opcao": dockerfile("--platform=linux/amd64 %s:latest@%s" % (BASE, DIGEST_A)),
            "referencia com texto de workflow": dockerfile("%s%%0A::error::x@%s" % (BASE, DIGEST_A)),
        }
        for nome, df in casos.items():
            with self.subTest(nome):
                rc, out, md, _, chamadas = self.roda(df)
                self.assertEqual(rc, 0, out)
                self.assertIn("Sem como comparar", md)
                self.assertIn("exatamente um `FROM <imagem>` simples", md)
                self.assertEqual(out.count("::warning::"), 1, out)                 # so' o aviso do script
                self.assertEqual([l for l in out.splitlines() if l.startswith("::") and "::warning::" not in l], [])
                self.assertEqual(chamadas, "")

    def test_dockerfile_que_nao_existe_avisa(self):
        rc, out, md, _, chamadas = self.roda(DOCKERFILE=os.path.join(self.tmp, "nao-existe").replace("\\", "/"))
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem como comparar", md)
        self.assertEqual(chamadas, "")

    # --- a tag vem do FROM -----------------------------------------------------------------------------------
    def test_a_tag_e_o_registro_com_porta_vem_do_proprio_from(self):
        casos = [
            ("%s:edge@%s" % (BASE, DIGEST_A), "%s:edge" % BASE),
            ("%s@%s" % (BASE, DIGEST_A), "%s:latest" % BASE),                       # sem tag: latest
            ("localhost:5000/x/y@%s" % DIGEST_A, "localhost:5000/x/y:latest"),      # a porta nao e' tag
            ("localhost:5000/x/y:v2@%s" % DIGEST_A, "localhost:5000/x/y:v2"),
        ]
        for ref, esperado in casos:
            with self.subTest(ref):
                rc, out, md, _, chamadas = self.roda(dockerfile(ref))
                self.assertEqual(rc, 0, out)
                self.assertEqual(self.pulls(chamadas), [esperado.rsplit(":", 1)[0] + "@" + DIGEST_A, esperado], chamadas)

    def test_sem_a_variavel_le_o_dockerfile_ao_lado_de_ci(self):
        escreve(os.path.join(self.tmp, "Dockerfile"), dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), exec_=False)
        rc, out, md, _, _ = self.roda(None)
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)

    # --- o contrato ---------------------------------------------------------------------------------------
    def test_sem_github_step_summary_funciona_e_escreve_o_relatorio_no_stdout(self):
        rc, out, md, resumo, _ = self.roda(dockerfile("%s:latest@%s" % (BASE, DIGEST_A)), GITHUB_STEP_SUMMARY="")
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", out)
        self.assertEqual(resumo, "")


@unittest.skipUnless(BASH, "precisa de bash (nao o do WSL)")
class DockerfileDoRepo(_Ambiente, unittest.TestCase):
    """O Dockerfile que o publish constroi: a base fixada por digest, e o vigia a entende."""

    def setUp(self):
        super().setUp()
        with open(os.path.join(RF, "Dockerfile"), encoding="utf-8") as fh:
            self.texto = fh.read()
        self.froms = [l for l in self.texto.splitlines() if re.match(r"FROM\s", l)]

    def test_o_from_e_unico_e_fixado_por_digest(self):
        self.assertEqual(len(self.froms), 1, self.froms)
        self.assertRegex(self.froms[0], r"^FROM \S+@sha256:[0-9a-f]{64}$",
                         "a base do feed tem de ser fixada por digest (tag flutuante: o publish muda sem PR)")

    def test_o_vigia_entende_o_from_do_repo(self):
        pin = re.search(r"@(sha256:[0-9a-f]{64})$", self.froms[0]).group(1)
        rc, out, md, _, chamadas = self.roda(self.texto, tag_digest=pin)
        self.assertEqual(rc, 0, out)
        self.assertIn("Sem deriva", md)
        self.assertIn(pin, md)
        pulls = self.pulls(chamadas)
        self.assertEqual(len(pulls), 2, pulls)
        self.assertTrue(pulls[0].endswith("@" + pin), pulls)               # o digest fixado
        self.assertRegex(pulls[1], r"^\S+:[\w.-]+$")                       # e a tag flutuante de que ele veio


WORKFLOW = os.path.join(os.path.dirname(RF), ".github", "workflows", "report-formats-base-drift.yml")


@unittest.skipUnless(os.path.isfile(WORKFLOW), "sem .github/workflows ao lado de report-formats/")
class WorkflowDoVigia(unittest.TestCase):
    """O workflow semanal: agendado ou a mao (nunca em PR ou push) e que nao bloqueia nada."""

    def setUp(self):
        with open(WORKFLOW, "rb") as fh:
            self.texto = fh.read().decode("utf-8").replace("\r\n", "\n")

    def test_so_agendado_ou_a_mao_nunca_em_pr_ou_push(self):
        gatilhos = self.texto.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(sorted(re.findall(r"(?m)^  (\w+):", gatilhos)), ["schedule", "workflow_dispatch"])
        self.assertRegex(gatilhos, r"- cron: '[^']+'")

    def test_o_job_nao_bloqueia_nada(self):
        self.assertRegex(self.texto, r"(?m)^    continue-on-error: true$")
        self.assertNotRegex(self.texto, r"(?m)^    needs:")

    def test_roda_o_script_que_existe(self):
        m = re.search(r'(?m)^        run: (report-formats/ci/base-drift\.sh) "\$RUNNER_TEMP/[\w-]+"$', self.texto)
        self.assertTrue(m, "o workflow nao chama mais o ci/base-drift.sh")
        self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(RF), m.group(1))))


if __name__ == "__main__":
    unittest.main()
