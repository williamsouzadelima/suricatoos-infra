#!/usr/bin/env python3
"""Trava a FIACAO do publish: o que, no report-formats-publish.yml, impede que a tag `stable'
da imagem volte para um commit velho (a producao a puxa direto e o GSA nao mostra a regressao).

O ci/stable-gate.sh decide; este teste garante que o workflow o USA do jeito certo. Sem ele,
uma "simplificacao" futura (docker push --all-tags, o push da `stable' fora do `if', o portao do
commit em vez do da main, um nome curto de ref, o checkout raso) passaria por todos os outros
testes: o simulador que prova o comportamento de ponta a ponta mora fora do repo.

Le o texto do workflow com expressoes regulares (o CI nao tem PyYAML), como o teste de higiene
que le o job feed-sync. Linha so' de comentario nao conta: uma copia comentada de uma guarda nao
e' guarda. O CI roda isto no job feed-sync. So' biblioteca padrao.

    python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v
"""
import os
import re
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.abspath(os.environ.get("REPORT_FORMATS_DIR") or os.path.dirname(HERE))
WORKFLOWS = os.path.join(os.path.dirname(RF), ".github", "workflows")
PUBLISH = os.path.join(WORKFLOWS, "report-formats-publish.yml")
CI = os.path.join(WORKFLOWS, "report-formats-ci.yml")


def ler(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8").replace("\r\n", "\n")


def bloco_do_job(texto, job):
    """O texto do job `job' (do `  <job>:' ate' o proximo job)."""
    resto = texto.split("\njobs:\n", 1)[1]
    m = re.search(r"(?m)^  %s:\s*\n((?:(?:    .*)?\n)*)" % re.escape(job), resto)
    assert m, "o workflow nao define mais o job `%s'" % job
    return m.group(1)


def passos(job_txt):
    """[(nome, texto do passo)] do job, na ordem."""
    corpo = job_txt.split("\n    steps:\n", 1)[1]
    out = []
    for bloco in re.split(r"(?m)^      - (?=name:|uses:)", corpo):
        if not bloco.strip():
            continue
        m = re.match(r"(?:name|uses): (.*)", bloco)
        nome = m.group(1).strip() if m else "?"
        out.append((nome, bloco))
    return out


def linhas_de_run(bloco):
    """As linhas do `run: |' do passo, sem as que sao so' comentario."""
    m = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)*)", bloco)
    if not m:
        return []
    return [l for l in m.group(1).split("\n") if l.strip() and not l.lstrip().startswith("#")]


def todas_as_linhas(job_txt):
    return [(i, nome, l) for i, (nome, b) in enumerate(passos(job_txt)) for l in linhas_de_run(b)]


@unittest.skipUnless(os.path.isfile(PUBLISH), "sem .github/workflows ao lado de report-formats/")
class FiacaoDoPublish(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = ler(PUBLISH)
        cls.job = bloco_do_job(cls.texto, "build-publish")
        cls.passos = passos(cls.job)
        cls.linhas = todas_as_linhas(cls.job)

    def passo_com(self, trecho):
        achados = [(i, n, b) for i, (n, b) in enumerate(self.passos) if any(trecho in l for l in linhas_de_run(b))]
        self.assertEqual(len(achados), 1, "esperado UM passo com %r, ha' %d" % (trecho, len(achados)))
        return achados[0]

    # --- os gatilhos e o `if' ------------------------------------------------------------------------
    def test_roda_depois_do_ci_e_a_mao_nunca_no_push(self):
        on = self.texto.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertRegex(on, r"(?m)^  workflow_run:\n    workflows: \[report-formats-ci\]\n    types: \[completed\]\n    branches: \[main\]")
        self.assertRegex(on, r"(?m)^  workflow_dispatch:")
        self.assertNotRegex(on, r"(?m)^  push:")

    def test_o_job_so_publica_ci_aprovado_de_push_neste_repositorio(self):
        cond = re.sub(r"\s+", " ", re.search(r"(?s)    if: >-\n(.*?)\n    runs-on:", self.job).group(1))
        for trecho in ("github.event_name == 'workflow_dispatch'",
                       "github.event.workflow_run.conclusion == 'success'",
                       "github.event.workflow_run.event == 'push'",
                       "github.event.workflow_run.head_repository.full_name == github.repository"):
            self.assertIn(trecho, cond)

    # --- a tag stable: so' sob o portao, uma por vez ----------------------------------------------------
    def test_nunca_docker_push_all_tags(self):
        self.assertEqual([l for _, _, l in self.linhas if "--all-tags" in l], [])

    def test_o_build_so_gera_a_tag_do_commit(self):
        builds = [l for _, _, l in self.linhas if "docker build" in l]
        self.assertEqual(len(builds), 1)
        self.assertIn('-t "$IMG:${SRC_SHA::12}"', builds[0])
        self.assertNotIn(":stable", builds[0])

    def test_so_ha_um_push_e_um_tag_da_stable_e_os_dois_estao_sob_move_stable(self):
        push = [(i, l) for i, _, l in self.linhas if "docker push" in l and ":stable" in l]
        tag = [(i, l) for i, _, l in self.linhas if "docker tag" in l and ":stable" in l]
        self.assertEqual(len(push), 1, push)
        self.assertEqual(len(tag), 1, tag)
        _, nome, bloco = self.passo_com('docker push "$IMG:stable"')
        run = linhas_de_run(bloco)
        ifs = [k for k, l in enumerate(run) if l.strip() == 'if [ "$MOVE_STABLE" = true ]; then']
        self.assertEqual(len(ifs), 1, "o push da stable tem de estar sob `if [ \"$MOVE_STABLE\" = true ]; then'")
        k_if = ifs[0]
        indent = len(run[k_if]) - len(run[k_if].lstrip())
        fim = next(k for k in range(k_if + 1, len(run))
                   if run[k].strip() in ("else", "fi") and len(run[k]) - len(run[k].lstrip()) == indent)
        k_tag = next(k for k, l in enumerate(run) if "docker tag" in l and ":stable" in l)
        k_push = next(k for k, l in enumerate(run) if "docker push" in l and ":stable" in l)
        self.assertTrue(k_if < k_tag < k_push < fim, "docker tag/push da stable fora do bloco do MOVE_STABLE")
        self.assertEqual(run[fim].strip(), "else", "o ramo de nao mover precisa existir (o aviso)")

    def test_o_push_da_tag_do_commit_vem_antes_do_passo_da_stable(self):
        i_sha, _, _ = self.passo_com('docker push "$IMG:${SRC_SHA::12}"')
        i_stable, _, _ = self.passo_com('docker push "$IMG:stable"')
        self.assertLess(i_sha, i_stable)

    def test_o_portao_roda_no_mesmo_passo_da_stable_antes_do_if(self):
        _, nome, bloco = self.passo_com('docker push "$IMG:stable"')
        run = linhas_de_run(bloco)
        k_fetch = [k for k, l in enumerate(run) if l.strip().startswith("git fetch")]
        k_gate = [k for k, l in enumerate(run) if "stable-gate.sh" in l and "bash" in l]
        k_if = [k for k, l in enumerate(run) if 'if [ "$MOVE_STABLE" = true ]' in l]
        self.assertEqual((len(k_fetch), len(k_gate), len(k_if)), (1, 1, 1), run)
        self.assertLess(k_fetch[0], k_gate[0])
        self.assertLess(k_gate[0], k_if[0])

    # --- o ref da main e' explicito e completo (N1) ---------------------------------------------------------
    def test_a_main_e_buscada_para_um_ref_explicito(self):
        fetchs = [l.strip() for _, _, l in self.linhas if l.strip().startswith("git fetch")]
        self.assertEqual(fetchs, ["git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'"])

    def test_nenhum_nome_curto_origin_main(self):
        for _, nome, l in self.linhas:
            for m in re.finditer(r"origin/main", l):
                self.assertTrue(l[:m.start()].endswith("refs/remotes/"),
                                "nome curto origin/main (uma tag com esse nome o sombreia) em %r: %s" % (nome, l.strip()))

    # --- o portao e' o da main (N4) ----------------------------------------------------------------------------
    def test_o_portao_que_roda_e_o_da_main_nao_o_da_arvore_do_commit(self):
        _, nome, bloco = self.passo_com('docker push "$IMG:stable"')
        run = "\n".join(linhas_de_run(bloco))
        self.assertIn("MAIN=refs/remotes/origin/main", run)
        self.assertIn('git show "$MAIN:report-formats/ci/stable-gate.sh" > "$RUNNER_TEMP/stable-gate.sh"', run)
        self.assertIn('bash "$RUNNER_TEMP/stable-gate.sh" "$SRC_SHA" "$MAIN"', run)
        for _, _, l in self.linhas:
            self.assertNotRegex(l, r"bash\s+(\./)?report-formats/ci/stable-gate\.sh", "o portao do commit, nao o da main")

    def test_a_main_sem_o_portao_nao_derruba_o_job_so_segura_a_stable(self):
        _, nome, bloco = self.passo_com('docker push "$IMG:stable"')
        run = "\n".join(linhas_de_run(bloco))
        self.assertIn("git ls-tree --name-only", run)                  # so' arvores: serve num clone sem blobs
        self.assertIn("MOVE_STABLE=false", run)

    # --- a razao do portao leva texto de commits: nao chega crua a comandos do runner (N8) ------------------------------
    def test_o_aviso_escapa_o_porcento_da_razao(self):
        # Um `%0A' no assunto de um commit, num comando de workflow, vira quebra de linha e abriria
        # um ::error:: falso. Os caracteres de controle ja' saem no portao (test_stable_gate); o `%'
        # escapa aqui, onde o texto vira ::warning::.
        _, nome, bloco = self.passo_com('docker push "$IMG:stable"')
        avisos = [l for l in linhas_de_run(bloco) if "::warning::" in l]
        self.assertEqual(len(avisos), 1, avisos)
        self.assertIn("${STABLE_REASON//%/%25}", avisos[0])

    def test_a_razao_chega_ao_github_env_so_pela_saida_do_portao(self):
        escritas = [l.strip() for _, _, l in self.linhas if "GITHUB_ENV" in l and "STABLE_REASON" in l]
        self.assertEqual(escritas, [], "o texto da razao so' pode entrar no GITHUB_ENV como saida do portao (ja' sem controles)")
        decisao = [l.strip() for _, _, l in self.linhas if l.strip() == 'echo "$decisao" >> "$GITHUB_ENV"']
        self.assertEqual(len(decisao), 1)

    # --- o checkout: historico completo, sem blobs (Out-of-scope 4) --------------------------------------------------
    def test_checkout_do_commit_aprovado_com_historico_completo_e_sem_blobs(self):
        nome, bloco = next((n, b) for n, b in self.passos if b.startswith("name: Checkout"))
        self.assertIn("uses: actions/checkout@v4", bloco)
        with_ = bloco.split("with:\n", 1)[1]
        self.assertRegex(with_, r"(?m)^          ref: \$\{\{ github\.event\.workflow_run\.head_sha \|\| github\.sha \}\}$")
        self.assertRegex(with_, r"(?m)^          fetch-depth: 0$")
        self.assertRegex(with_, r"(?m)^          filter: blob:none$")

    # --- a concorrencia por commit ---------------------------------------------------------------------------------
    def test_concorrencia_por_commit_sem_cancelar(self):
        m = re.search(r"(?m)^concurrency:\n  group: (.*)\n  cancel-in-progress: (.*)$", self.texto)
        self.assertTrue(m, "o publish perdeu o bloco concurrency")
        self.assertEqual(m.group(1), "report-formats-publish-${{ github.event.workflow_run.head_sha || github.sha }}")
        self.assertEqual(m.group(2), "false")


def paths_do_gatilho(texto, gatilho):
    """Os `paths:' do gatilho (`pull_request' ou `push') do bloco `on:' de um workflow."""
    on = texto.split("\non:\n", 1)[1]
    m = re.search(r"(?m)^  %s:\n((?:    .*\n)+)" % re.escape(gatilho), on)
    assert m, "o workflow nao tem o gatilho %s" % gatilho
    return re.findall(r"(?m)^      - '([^']+)'", m.group(1))


@unittest.skipUnless(os.path.isfile(CI), "sem .github/workflows ao lado de report-formats/")
class FiacaoDoCI(unittest.TestCase):
    def test_um_pr_que_so_mexe_no_workflow_do_publish_roda_o_ci(self):
        # Este teste (job feed-sync) e' a trava da fiacao do publish: tem de rodar quando o workflow
        # dele muda. No push na main nao: mudar so' o publish nao republica a imagem (o README diz).
        self.assertIn(".github/workflows/report-formats-publish.yml", paths_do_gatilho(ler(CI), "pull_request"))
        self.assertNotIn(".github/workflows/report-formats-publish.yml", paths_do_gatilho(ler(CI), "push"))

    def test_push_na_main_nao_cancela_o_ci_de_outro_commit_so_pr_cancela(self):
        # O re-run de um CI antigo reentra com o ref e o sha do run original: agrupado por ref, ele
        # cancelava o CI em andamento do commit mais novo.
        texto = ler(CI)
        m = re.search(r"(?m)^concurrency:\n  group: (.*)\n  cancel-in-progress: (.*)$", texto)
        self.assertTrue(m, "o CI perdeu o bloco concurrency")
        self.assertEqual(m.group(1), "report-formats-ci-${{ github.event_name == 'pull_request' && github.ref || github.sha }}")
        self.assertEqual(m.group(2), "${{ github.event_name == 'pull_request' }}")


if __name__ == "__main__":
    unittest.main()
