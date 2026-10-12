#!/usr/bin/env python3
"""Testes do feed do Suricatoos Premium PDF: a VERSION derivada do conteudo, a
geracao idempotente dos nove objetos e o que o repo versiona (e o que nao).

O CI roda isto no job feed-sync, depois do build. So' biblioteca padrao.

    python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v

REPORT_FORMATS_DIR aponta OUTRO report-formats/ (o harness de mutantes,
mutantes-variantes.py, roda estes testes contra um builder mutado).

A VERSION e' uma funcao PURA do que o feed entrega: os membros do bundle que vao
nos objetos e os textos do build-feed-xml.py. Aqui se prova os dois sentidos:
  - o mesmo conteudo da a mesma VERSION, em outro diretorio, com outras datas de
    modificacao, em outro processo, com outra semente de hash e outra codificacao;
  - um byte a mais, a menos ou trocado em qualquer coisa que o feed entrega da
    outra VERSION; arquivo da pasta do bundle que nao vai no feed, nao.
"""
import base64
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
RF = os.path.abspath(os.environ.get("REPORT_FORMATS_DIR") or os.path.dirname(HERE))
LANGS = ("en", "pt_BR", "es")
VERSION_RE = re.compile(r"sha256-[0-9a-f]{12}")

_loaded = 0


def load_builder(rf_dir):
    """O build-feed-xml.py de `rf_dir', como modulo novo a cada chamada."""
    global _loaded
    _loaded += 1
    spec = importlib.util.spec_from_file_location(
        "bfx_teste_%d" % _loaded, os.path.join(rf_dir, "build-feed-xml.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def copy_tree(dst, src=None):
    """O builder e o bundle (sem o descritor gerado) numa pasta nova, que e' o
    que o build precisa para rodar sozinho: a copia de uma `git archive'."""
    src = src or RF
    os.makedirs(dst)
    shutil.copy(os.path.join(src, "build-feed-xml.py"), dst)
    shutil.copytree(os.path.join(src, "suricatoos-premium-pdf"), os.path.join(dst, "suricatoos-premium-pdf"),
                    ignore=shutil.ignore_patterns("__pycache__", "report_format.xml"))
    return dst


def run_builder(rf_dir, *args, env=None, utf8=True):
    cmd = [sys.executable] + (["-X", "utf8"] if utf8 else ["-X", "utf8=0"]) + [
        os.path.join(rf_dir, "build-feed-xml.py")] + list(args)
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(cmd, capture_output=True, env=e)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def generated(rf_dir):
    """Nome -> sha256 de tudo que o build escreve numa pasta."""
    out = {}
    for n in sorted(os.listdir(rf_dir)):
        if n.startswith("pdf-suricatoos-") and n.endswith(".xml"):
            out[n] = sha256_of(os.path.join(rf_dir, n))
    out["manifest.json"] = sha256_of(os.path.join(rf_dir, "manifest.json"))
    out["suricatoos-premium-pdf/report_format.xml"] = sha256_of(
        os.path.join(rf_dir, "suricatoos-premium-pdf", "report_format.xml"))
    return out


def append(path, data=b"x"):
    with open(path, "ab") as fh:
        fh.write(data)


def drop_last_byte(path):
    with open(path, "rb") as fh:
        data = fh.read()
    with open(path, "wb") as fh:
        fh.write(data[:-1])


def flip_middle_byte(path):
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    data[len(data) // 2] ^= 0x01
    with open(path, "wb") as fh:
        fh.write(bytes(data))


def replace_in(path, old, new):
    with open(path, "rb") as fh:
        data = fh.read()
    if data.count(old) != 1:
        raise AssertionError("%s: trecho achado %d vez(es), esperado 1: %r" % (path, data.count(old), old[:60]))
    with open(path, "wb") as fh:
        fh.write(data.replace(old, new))


class VersaoPorConteudo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rf-teste-")
        cls.base_dir = copy_tree(os.path.join(cls.tmp, "base"))
        cls.builder = load_builder(cls.base_dir)
        cls.version = cls.builder.derive_version()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def version_apos(self, nome, edicao):
        """A VERSION de uma copia nova do builder + bundle depois de `edicao(pasta)'."""
        d = copy_tree(os.path.join(self.tmp, nome))
        edicao(d)
        return load_builder(d).derive_version()

    def bundle(self, d, *partes):
        return os.path.join(d, "suricatoos-premium-pdf", *partes)

    # --- o formato --------------------------------------------------------------------------
    def test_formato_sha256_e_12_hex(self):
        self.assertRegex(self.version, r"^sha256-[0-9a-f]{12}$")

    def test_o_formato_nao_vira_numero_em_yaml_ou_json(self):
        # "1e5" ou "000123" seriam float/int para alguns consumidores; o prefixo evita.
        self.assertFalse(re.fullmatch(r"[0-9.eE+-]+", self.version))

    # --- mesmo conteudo => mesma VERSION ---------------------------------------------------------
    def test_a_versao_da_arvore_e_a_da_copia(self):
        self.assertEqual(load_builder(RF).derive_version(), self.version)

    def test_outro_diretorio_e_outras_datas_de_modificacao_dao_a_mesma_versao(self):
        d = copy_tree(os.path.join(self.tmp, "outra-maquina"))
        for raiz, _, nomes in os.walk(d):
            for n in nomes:
                os.utime(os.path.join(raiz, n), (946684800, 946684800))   # 2000-01-01
        self.assertEqual(load_builder(d).derive_version(), self.version)

    def test_outro_processo_semente_de_hash_e_codificacao_dao_a_mesma_versao(self):
        vistas = set()
        for env, utf8 in (({"PYTHONHASHSEED": "0"}, True), ({"PYTHONHASHSEED": "12345"}, True),
                          ({"PYTHONHASHSEED": "random"}, False)):
            rc, out, err = run_builder(self.base_dir, "--print-version", env=env, utf8=utf8)
            self.assertEqual(rc, 0, err)
            vistas.add(out.strip())
        self.assertEqual(vistas, {self.version})

    def test_print_version_nao_escreve_nada(self):
        d = copy_tree(os.path.join(self.tmp, "so-versao"))
        antes = sorted(os.listdir(d))
        rc, out, err = run_builder(d, "--print-version")
        self.assertEqual((rc, out.strip()), (0, self.version), err)
        self.assertEqual(sorted(os.listdir(d)), antes)

    # --- um byte a mais, a menos ou trocado => outra VERSION -------------------------------------
    def test_um_byte_a_mais_em_cada_membro_do_feed_muda_a_versao(self):
        membros = [n for n in self.builder.object_file_names("en") if n != "report_format.xml"]
        membros += ["nvt-i18n-pt_BR.xml", "nvt-i18n-es.xml"]    # cada objeto leva so' o catalogo do seu idioma
        self.assertGreaterEqual(len(membros), 13)
        for n in membros:
            with self.subTest(membro=n):
                v = self.version_apos("mais-" + n, lambda d, n=n: append(self.bundle(d, n)))
                self.assertNotEqual(v, self.version)
                self.assertRegex(v, VERSION_RE.pattern)

    def test_um_byte_a_menos_ou_trocado_muda_a_versao(self):
        self.assertNotEqual(self.version_apos("menos", lambda d: drop_last_byte(self.bundle(d, "latex.xsl"))),
                            self.version)
        self.assertNotEqual(self.version_apos("trocado", lambda d: flip_middle_byte(self.bundle(d, "plex-min.tar.gz"))),
                            self.version)

    def test_versoes_de_edicoes_diferentes_nao_colidem(self):
        v = {self.version_apos("c%d" % i, lambda d, i=i: append(self.bundle(d, "latex.xsl"), b"%d" % i))
             for i in range(8)}
        v.add(self.version)
        self.assertEqual(len(v), 9)

    def test_o_texto_do_proprio_builder_entra_na_versao(self):
        # Resumo/descricao/nome/UUID sao conteudo dos objetos: mudar um deles sem tocar no bundle
        # era o "formato igual com conteudo diferente" que a VERSION manual deixava passar.
        casos = [
            (b"per-host appendix (English). ", b"per-host appendix (English), changed. "),
            (b'"Suricatoos PDF \xe2\x80\x94 Cliente (PT-BR)"', b'"Suricatoos PDF \xe2\x80\x94 Cliente  (PT-BR)"'),
        ]
        for i, (velho, novo) in enumerate(casos):
            with self.subTest(trecho=velho[:40]):
                v = self.version_apos("texto%d" % i,
                                      lambda d, velho=velho, novo=novo: replace_in(
                                          os.path.join(d, "build-feed-xml.py"), velho, novo))
                self.assertNotEqual(v, self.version)

    def test_um_sty_novo_no_bundle_e_descoberto_e_entra_na_versao(self):
        def novo(d):
            with open(self.bundle(d, "suricatoos-extra.sty"), "wb") as fh:
                fh.write(b"\\endinput\n")
        d = copy_tree(os.path.join(self.tmp, "sty-novo"))
        novo(d)
        b = load_builder(d)
        self.assertIn("suricatoos-extra.sty", b.object_file_names("en"))
        self.assertNotEqual(b.derive_version(), self.version)

    # --- o que nao vai no feed nao conta ----------------------------------------------------------
    def test_arquivo_da_pasta_do_bundle_que_nao_vai_no_feed_nao_muda_a_versao(self):
        nao_vao = ["FONTS.md", "NVT-I18N.md", "NVT-I18N-ES.md", "main.tex",
                   os.path.join("tools", "build-torture-fixture.py")]
        for n in nao_vao:
            with self.subTest(arquivo=n):
                self.assertNotIn(os.path.basename(n), self.builder.object_file_names("en"))
                v = self.version_apos("fora-" + n.replace(os.sep, "_"),
                                      lambda d, n=n: append(self.bundle(d, n), b"\nmais uma linha\n"))
                self.assertEqual(v, self.version)

    def test_o_descritor_de_referencia_gerado_nao_entra_na_versao(self):
        # Ele embute a VERSION: se contasse, a VERSION dependeria de si mesma.
        def descritor(d):
            with open(self.bundle(d, "report_format.xml"), "wb") as fh:
                fh.write(b"<descritor-velho/>\n")
        self.assertEqual(self.version_apos("descritor", descritor), self.version)


class GeracaoDoFeed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rf-teste-")
        cls.dir = copy_tree(os.path.join(cls.tmp, "gerado"))
        cls.builder = load_builder(cls.dir)
        cls.version = cls.builder.derive_version()
        rc, cls.out, err = run_builder(cls.dir)
        assert rc == 0, err
        cls.primeira = generated(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_escreve_nove_objetos_o_manifesto_e_o_descritor_e_so_isso(self):
        esperado = {"pdf-suricatoos-%s.xml" % f[2] for f in self.builder.FORMATS}
        self.assertEqual(len(esperado), 9)
        self.assertEqual(set(self.primeira), esperado | {"manifest.json", "suricatoos-premium-pdf/report_format.xml"})
        self.assertEqual(sorted(n for n in os.listdir(self.dir) if n not in esperado),
                         ["build-feed-xml.py", "manifest.json", "suricatoos-premium-pdf"])

    def test_geracao_idempotente_no_mesmo_lugar(self):
        rc, _, err = run_builder(self.dir)
        self.assertEqual(rc, 0, err)
        self.assertEqual(generated(self.dir), self.primeira)

    def test_geracao_idempotente_em_outro_lugar(self):
        d = copy_tree(os.path.join(self.tmp, "outro-lugar"))
        rc, _, err = run_builder(d)
        self.assertEqual(rc, 0, err)
        self.assertEqual(generated(d), self.primeira)

    def test_o_log_diz_a_versao_e_o_sha256_de_cada_objeto(self):
        self.assertIn("VERSION %s" % self.version, self.out)
        for nome, digest in self.primeira.items():
            if nome.startswith("pdf-suricatoos-"):
                self.assertIn("%s  (" % nome, self.out)
                self.assertIn("sha256 %s" % digest[:12], self.out)

    def test_toda_a_versao_do_feed_e_a_derivada_e_nenhum_marcador_sobra(self):
        token = self.builder.VERSION_TOKEN
        textos = 0
        for lang, variant, fmt_id, name in self.builder.FORMATS:
            path = os.path.join(self.dir, "pdf-suricatoos-%s.xml" % fmt_id)
            with open(path, "rb") as fh:
                data = fh.read()
            self.assertNotIn(token.encode(), data, path)
            root = ET.fromstring(data)
            files = {f.get("name"): f.text or "" for f in root.findall("file")}
            desc_bytes = base64.b64decode(files["report_format.xml"])
            self.assertNotIn(token.encode(), desc_bytes, path)
            desc = ET.fromstring(desc_bytes)
            for tag in ("summary", "description"):
                for no in (root, desc):
                    texto = no.findtext(tag)
                    self.assertEqual(VERSION_RE.findall(texto), [self.version], (path, tag))
                    self.assertTrue(texto.endswith(" %s." % self.version), (path, tag))
                    textos += 1
        self.assertEqual(textos, 36)

    def test_o_manifesto_gerado_e_o_versionado_e_nao_traz_versao(self):
        with open(os.path.join(self.dir, "manifest.json"), "rb") as fh:
            gerado = fh.read()
        self.assertEqual(gerado, self.builder.manifest_bytes())
        self.assertNotIn(b'"version"', gerado)
        # O do repo e' o que o build escreve (o job feed-sync tambem reprova o git diff).
        with open(os.path.join(RF, "manifest.json"), "rb") as fh:
            self.assertEqual(fh.read(), gerado)

    def test_check_manifest_passa_no_que_o_build_escreveu(self):
        r = subprocess.run([sys.executable, "-X", "utf8", os.path.join(RF, "ci", "check-manifest.py"),
                            "--dir", self.dir], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stdout.decode("utf-8", "replace"))


def dentro_de_um_checkout_git():
    """Falso numa copia de pasta (os mutantes) ou num `git archive': nao ha indice para conferir."""
    if not shutil.which("git"):
        return False
    r = subprocess.run(["git", "-C", RF, "rev-parse", "--is-inside-work-tree"], capture_output=True)
    return r.returncode == 0 and r.stdout.strip() == b"true"


@unittest.skipUnless(dentro_de_um_checkout_git(), "sem checkout git: nada a conferir sobre o indice")
class OQueOGitVersiona(unittest.TestCase):
    def git(self, *args):
        r = subprocess.run(["git", "-C", RF] + list(args), capture_output=True)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")

    def test_nenhum_objeto_gerado_esta_versionado(self):
        # ~21 MB por mudanca de relatorio no historico do repo publico.
        rc, out, err = self.git("ls-files", "--", "pdf-suricatoos-*.xml", "suricatoos-premium-pdf/report_format.xml")
        self.assertEqual((rc, out.split()), (0, []), err)

    def test_o_gitignore_cobre_o_que_o_build_escreve_menos_o_manifesto(self):
        # --no-index: vale o padrao do .gitignore, mesmo para arquivo ja' rastreado.
        b = load_builder(RF)
        gerados = ["pdf-suricatoos-%s.xml" % f[2] for f in b.FORMATS] + ["suricatoos-premium-pdf/report_format.xml"]
        for caminho in gerados:
            rc, _, err = self.git("check-ignore", "--no-index", "-q", caminho)
            self.assertEqual(rc, 0, "%s deveria estar no .gitignore" % caminho)
        rc, _, _ = self.git("check-ignore", "--no-index", "-q", "manifest.json")
        self.assertEqual(rc, 1, "manifest.json e' versionado (o conector da frota o le): fora do .gitignore")


if __name__ == "__main__":
    unittest.main()
