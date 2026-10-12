"""Testes do checador de higiene (ci/hygiene/check_public_hygiene.py).

Os IPs publicos usados como massa de teste sao montados em tempo de execucao
(`_ip`): o proprio checador varre este arquivo, e um literal publico aqui exigiria
uma entrada na allowlist so para os testes passarem. Literais de faixas isentas
(RFC 1918, RFC 5737, loopback...) e de numeros que NAO sao IP podem ficar escritos.

Rodar: python -m pytest ci/hygiene -q
"""
import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import check_public_hygiene as h

SCRIPT = Path(h.__file__).resolve()


def _ip(a, b, c, d):
    return f"{a}.{b}.{c}.{d}"


PUBLIC = _ip(8, 8, 8, 8)
OTHER_PUBLIC = _ip(1, 1, 1, 1)
WHY = "justificativa de teste com tamanho suficiente"      # >= h.MIN_JUSTIFICATION


# --- o que reprova / o que passa ------------------------------------------------

@pytest.mark.parametrize("ip", [
    PUBLIC,
    OTHER_PUBLIC,
    _ip(93, 184, 216, 34),
    # o primeiro endereco publico logo depois / antes de cada faixa isenta
    _ip(1, 0, 0, 0),
    _ip(9, 255, 255, 255), _ip(11, 0, 0, 0),
    _ip(100, 63, 255, 255), _ip(100, 128, 0, 0),
    _ip(126, 255, 255, 255), _ip(128, 0, 0, 0),
    _ip(169, 253, 255, 255), _ip(169, 255, 0, 0),
    _ip(172, 15, 255, 255), _ip(172, 32, 0, 0),
    _ip(192, 0, 1, 255), _ip(192, 0, 3, 0),
    _ip(192, 167, 255, 255), _ip(192, 169, 0, 0),
    _ip(198, 51, 99, 255), _ip(198, 51, 101, 0),
    _ip(203, 0, 112, 255), _ip(203, 0, 114, 0),
    _ip(223, 255, 255, 255),
])
def test_public_ip_is_reported(ip):
    assert h.find_public_ips(f"host = {ip}\n") == [(1, ip)]


@pytest.mark.parametrize("ip", [
    "0.0.0.0", "0.255.255.255",                    # 0.0.0.0/8
    "10.0.0.0", "10.255.255.255",                  # RFC 1918
    "172.16.0.0", "172.31.255.255",                # RFC 1918
    "192.168.0.0", "192.168.255.255",              # RFC 1918
    "192.0.2.0", "192.0.2.255",                    # RFC 5737 TEST-NET-1
    "198.51.100.0", "198.51.100.255",              # RFC 5737 TEST-NET-2
    "203.0.113.0", "203.0.113.255",                # RFC 5737 TEST-NET-3
    "100.64.0.0", "100.127.255.255",               # CGNAT
    "127.0.0.1", "127.255.255.255",                # loopback
    "169.254.0.0", "169.254.169.254",              # link-local
    "224.0.0.0", "239.255.255.255",                # multicast
    "240.0.0.0", "255.255.255.254",                # reservado
    "255.255.255.255",                             # broadcast
])
def test_exempt_ranges_pass(ip):
    assert h.find_public_ips(f"host = {ip}\n") == []


@pytest.mark.parametrize("text", [
    "10.0.22631.4317",              # versao de build do Windows: terceiro componente > 255
    "6.3.9600.16384",
    "1.2.3",                        # tres componentes
    "256.1.1.1", "1.256.1.1", "1.1.256.1", "1.1.1.256", "999.999.999.999",
    "1.2.3.4.5",                    # cinco componentes: numero de versao, nao endereco
    "1.3.6.1.4.1.25623.1.0.100000", # OID
    "1234.5.6.7", "1.2.3.4567",     # componente com 4 digitos
    "v1.2.3.4",                     # colado em letras: identificador/versao
    "1.1.1-lp156.3.3.1",            # release de pacote rpm
])
def test_not_an_ip_is_not_reported(text):
    assert h.find_public_ips(text) == []


@pytest.mark.parametrize("template", [
    "{ip}", "{ip}.", "{ip},", "({ip})", '"{ip}"', "[{ip}]",
    "{ip}:8080", "{ip}/24", "http://{ip}/x", "x={ip}", "user@{ip}",
    "::ffff:{ip}", "scan_{ip}.xml", "{ip}_x", "{ip}-x", "{ip}.example.test",
    "a\\n{ip}", "a\\r\\n{ip}", "a\\t{ip}", "{ip}\\n",
    # escape percentual (URL) terminado em letra logo antes: %0A, %2F, %3A...
    "a%0A{ip}", "http://x/%2F{ip}", "x%3A{ip}", "{ip}%0A",
])
def test_public_ip_is_found_in_context(template):
    text = template.format(ip=PUBLIC)
    assert [ip for _, ip in h.find_public_ips(text)] == [PUBLIC]


def test_percent_escape_ending_in_a_digit_still_flags_an_address():
    # "%20" seguido de um IP que comeca por 8 le-se tambem como "%" + um IP que comeca
    # por 208: outro literal, mas ainda um IP publico, entao o vazamento nao passa.
    assert h.find_public_ips("a%20" + PUBLIC) != []


def test_ip_followed_by_a_fifth_component_is_not_reported():
    assert h.find_public_ips(PUBLIC + ".5") == []
    assert h.find_public_ips("5." + PUBLIC) == []


def test_all_occurrences_are_reported_with_their_line():
    text = f"{PUBLIC} e {OTHER_PUBLIC}\nlimpa 10.0.0.1\n{PUBLIC}"
    assert h.find_public_ips(text) == [(1, PUBLIC), (1, OTHER_PUBLIC), (3, PUBLIC)]


def test_line_numbers_follow_newline_only():
    # CRLF conta como uma quebra; form feed / separadores unicode nao contam.
    assert h.find_public_ips("a\r\nb\r\n" + PUBLIC) == [(3, PUBLIC)]
    assert h.find_public_ips("a\x0cb\x1c\n" + PUBLIC) == [(2, PUBLIC)]


def test_leading_zeros_are_normalized():
    padded = _ip("008", "008", "008", "008")
    assert h.find_public_ips(padded) == [(1, padded)]
    assert h.find_public_ips(padded, frozenset({PUBLIC})) == []   # allowlist compara normalizado
    assert h.find_public_ips("010.000.000.001") == []             # 10/8 com zeros


# --- limites conhecidos: executaveis, para a documentacao nao apodrecer ----------------

def _blind_spot_forms():
    octets = PUBLIC.split(".")
    return {
        "defanged": "[.]".join(octets),
        "dashed": "-".join(octets),
        "integer": str(int(ipaddress.IPv4Address(PUBLIC))),
        "hex": hex(int(ipaddress.IPv4Address(PUBLIC))),
        "percent-escaped dots": "%2E".join(octets),
        "regex-escaped dots": "\\.".join(octets),
        "ipv6": "2606:4700:4700::1111",
    }


@pytest.mark.xfail(strict=True, reason="limite conhecido, listado em LIMITE CONHECIDO no topo do checador")
@pytest.mark.parametrize("form", sorted(_blind_spot_forms()))
def test_known_blind_spots_are_not_detected_yet(form):
    # Se alguem passar a detectar uma destas formas, este teste vira XPASS (estrito) e
    # reprova: e' o aviso para tirar a forma de LIMITE CONHECIDO e virar teste normal.
    text = _blind_spot_forms()[form]
    assert h.find_public_ips("host " + text) != []


@pytest.mark.xfail(strict=True, reason="limite conhecido: a limpeza de d=/points= e' lexical (regex, nao parser)")
@pytest.mark.parametrize("attr", ["d", "points"])
@pytest.mark.parametrize("ext_text", ["{ip}", "M0,0 {ip} z"])
def test_an_ip_inside_a_geometry_attribute_is_skipped(attr, ext_text):
    # Vale para .svg e .patch: o IP escrito no valor desses atributos some junto com a geometria.
    text = h.blank_svg_geometry(f'<g {attr}="{ext_text.format(ip=PUBLIC)}"/>')
    assert h.find_public_ips(text) != []


def test_every_blind_spot_form_is_named_in_the_docstring():
    doc = h.__doc__.lower()
    for word in ("defang", "tracej", "inteiro", "hex", "percent", "regex", "ipv6", "base64", "léxica"):
        assert word in doc, word
    # a limpeza lexical vale para os dois tipos de arquivo, e o texto diz isso
    assert ".svg" in doc and ".patch" in doc and "d=`/`points=" in doc


def _feed_sync_job():
    """Texto do job `feed-sync` do report-formats-ci.yml (do `  feed-sync:` ate o proximo job)."""
    wf = (h.ROOT / ".github" / "workflows" / "report-formats-ci.yml").read_bytes().decode("utf-8").replace("\r\n", "\n")
    assert "\njobs:\n" in wf, "o workflow perdeu a chave `jobs:`"
    jobs = wf.split("\njobs:\n", 1)[1]
    m = re.search(r"(?m)^  feed-sync:\s*\n((?:(?:    .*)?\n)*)", jobs)       # recuo de 4 = dentro do job
    assert m, "o workflow nao define mais o job `feed-sync`"
    return m.group(1)


def _code_lines(text):
    """As linhas do trecho de workflow que NAO sao so' comentario: uma copia comentada de uma
    guarda (`# test -z ...') nao e' guarda, e o teste nao pode se contentar com ela."""
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


# A guarda: a linha COMECA em `test -z "$(git ls-files ... pdf-suricatoos-...)"' (comentario depois
# dela, tudo bem). Um `test -z' que aparece so' no fim de outra linha ou num comentario nao conta.
_FEED_GUARD = re.compile(r"""^\s*test -z "\$\(git ls-files\b[^"]*pdf-suricatoos-[^"]*\)"(\s+#.*)?\s*$""")


def _feed_guards(job):
    return [l for l in _code_lines(job) if _FEED_GUARD.match(l)]


def test_docstring_names_the_workflow_that_keeps_the_feed_in_sync():
    refs = set(re.findall(r"\.github/workflows/[\w.-]+\.yml", h.__doc__))
    assert ".github/workflows/report-formats-ci.yml" in refs
    assert "feed-sync" in h.__doc__
    for ref in refs:                                  # nome citado => arquivo existe
        assert (h.ROOT / ref).is_file(), ref
    # ... e o job citado existe e faz o que a docstring diz: os XMLs de feed sao GERADOS (o job
    # roda o build) e NAO versionados -- o job reprova um `pdf-suricatoos-*.xml' que volte ao git
    # (git add -f), que e' o que tira o XML da varredura deste checador. So' linha de CODIGO conta:
    # o build e a guarda comentados nao fazem nada.
    job = _feed_sync_job()
    assert "build-feed-xml.py" in "\n".join(_code_lines(job)), "o job feed-sync nao roda mais o build (ou so' o cita num comentario)"
    assert _feed_guards(job), ("o job feed-sync nao reprova mais um pdf-suricatoos-*.xml versionado: sem uma linha "
                               "`test -z \"$(git ls-files ... pdf-suricatoos-...)\"' fora de comentario")


_GUARD_LINE = """          test -z "$(git ls-files -- 'report-formats/pdf-suricatoos-*.xml' report-formats/x.xml)\""""


@pytest.mark.parametrize("linhas,esperado", [
    ([_GUARD_LINE], 1),                                              # a guarda de verdade
    ([_GUARD_LINE + "  # tem de dar vazio"], 1),                     # comentario DEPOIS da guarda: continua guarda
    (["          # " + _GUARD_LINE.strip()], 0),                      # a guarda comentada
    (["#" + _GUARD_LINE], 0),                                        # idem, comentario na coluna 0
    (["          true  # " + _GUARD_LINE.strip()], 0),               # a guarda no rabo de comentario de outra linha
    (["          echo \"" + _GUARD_LINE.strip() + "\""], 0),         # entre aspas de outro comando
    (["          test -n \"$(git ls-files -- 'report-formats/pdf-suricatoos-*.xml')\""], 0),   # nao e' `test -z'
    (["          test -z \"$(git status --porcelain -- 'report-formats/pdf-suricatoos-*.xml')\""], 0),   # nao e' git ls-files
])
def test_the_feed_guard_must_be_a_real_code_line(linhas, esperado):
    assert len(_feed_guards("\n".join(linhas) + "\n")) == esperado


def test_a_commented_out_build_does_not_count_as_running_the_build():
    job = "    steps:\n      - run: |\n          # python3 report-formats/build-feed-xml.py\n          true\n"
    assert "build-feed-xml.py" not in "\n".join(_code_lines(job))


# --- allowlist ------------------------------------------------------------------

def test_allowlist_suppresses_only_the_listed_ip():
    text = f"{PUBLIC} {OTHER_PUBLIC}\n"
    assert h.find_public_ips(text, frozenset({PUBLIC})) == [(1, OTHER_PUBLIC)]
    assert h.find_public_ips(text, frozenset({PUBLIC, OTHER_PUBLIC})) == []


def test_find_public_ips_records_which_allowlisted_ips_were_seen():
    used = set()
    text = f"{PUBLIC}\n{_ip('008', '008', '008', '008')}\nlimpa\n"
    assert h.find_public_ips(text, {PUBLIC: 3, OTHER_PUBLIC: 4}, used) == []
    assert used == {PUBLIC}                           # so' o que apareceu, na forma canonica


def test_load_allowlist_reads_entries_and_ignores_comments(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_bytes((                        # bytes: o CRLF da linha 3 e' de verdade em qualquer SO
        "# cabecalho\n\n"
        f"{PUBLIC}   # resolver publico citado em docs\r\n"
        f"  {OTHER_PUBLIC}\t# outro, com recuo e justificativa\n"
        "   # comentario recuado\n").encode("utf-8"))
    assert dict(h.load_allowlist(f)) == {PUBLIC: 3, OTHER_PUBLIC: 4}      # IP -> linha


def test_load_allowlist_normalizes_leading_zeros(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text(f"{_ip('008', '008', '008', '008')} # {WHY}\n", encoding="utf-8")
    assert dict(h.load_allowlist(f)) == {PUBLIC: 1}


@pytest.mark.parametrize("line", ["{ip}", "{ip}  #", "{ip} #    ", "{ip}#"])
def test_load_allowlist_requires_a_justification(tmp_path, line):
    f = tmp_path / "allow.txt"
    f.write_text("# ok\n" + line.format(ip=PUBLIC) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"allow\.txt:2: falta a justificativa"):
        h.load_allowlist(f)


def test_load_allowlist_rejects_a_too_short_justification(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# ok\n" + f"{PUBLIC} # curto demais\n", encoding="utf-8")     # 12 caracteres
    with pytest.raises(ValueError, match=r"allow\.txt:2: justificativa curta demais"):
        h.load_allowlist(f)


def test_justification_needs_the_minimum_length(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text(f"{PUBLIC} # " + "x" * (h.MIN_JUSTIFICATION - 1) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=str(h.MIN_JUSTIFICATION)):
        h.load_allowlist(f)
    f.write_text(f"{PUBLIC} # " + "x" * h.MIN_JUSTIFICATION + "\n", encoding="utf-8")
    assert dict(h.load_allowlist(f)) == {PUBLIC: 1}


def test_load_allowlist_rejects_a_repeated_entry(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text(f"{PUBLIC} # {WHY}\n{_ip('008', '008', '008', '008')} # {WHY}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"allow\.txt:2: entrada repetida .*linha 1"):
        h.load_allowlist(f)


def test_load_allowlist_counts_lines_by_newline_only(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_bytes(b"# um CR solto\r no meio do comentario\n" + f"{PUBLIC} # {WHY}\n".encode())
    assert dict(h.load_allowlist(f)) == {PUBLIC: 2}


@pytest.mark.parametrize("entry", [
    "not-an-ip", "999.1.1.1", "1.2.3", "1.2.3.4.5", PUBLIC + ":53",
    PUBLIC + "/24",                # CIDR nao e suportado: um IP por linha
])
def test_load_allowlist_rejects_malformed_entries(tmp_path, entry):
    f = tmp_path / "allow.txt"
    f.write_text(f"{entry} # {WHY}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"allow\.txt:1: .*IPv4"):
        h.load_allowlist(f)


# --- exclusoes e decodificacao ----------------------------------------------------

@pytest.mark.parametrize("rel", [
    "report-formats/suricatoos-premium-pdf/nvt-i18n-pt_BR.xml",
    "report-formats/suricatoos-premium-pdf/nvt-i18n-es.xml",
])
def test_excluded_paths(rel):
    assert h.is_excluded(rel)


@pytest.mark.parametrize("rel", [
    # patches/ NAO e' exclusao: o patch do GSA cria arquivos proprios (tema, telas, locales)
    "patches/gsa-v27.4.1.patch", "patches/sub/dir/x.patch",
    "docs/x.md", "patches", "patches-extra/x.patch", "Patches/x.patch",
    "report-formats/suricatoos-premium-pdf/main.tex",
    "report-formats/sample/sample-report.xml",
    "outro/nvt-i18n-pt_BR.xml",
    "Report-Formats/suricatoos-premium-pdf/nvt-i18n-pt_BR.xml",     # o git distingue maiusculas
])
def test_paths_that_must_still_be_scanned(rel):
    assert not h.is_excluded(rel)


def test_binary_content_is_skipped():
    assert h.decode_text(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR") is None
    assert h.decode_text(b"abc\x00" + PUBLIC.encode()) is None


def test_text_with_invalid_utf8_is_still_scanned():
    text = h.decode_text(b"caf\xe9 " + PUBLIC.encode())
    assert text is not None and PUBLIC in text


def test_utf16_with_bom_is_scanned_like_text():
    line = "host " + PUBLIC
    assert h.decode_text(line.encode("utf-16")) == line                      # BOM nativo
    assert h.decode_text(b"\xfe\xff" + line.encode("utf-16-be")) == line      # BOM big-endian


@pytest.mark.parametrize("rel", ["logo.svg", "assets/LOGO.SVG", "patches/gsa-v27.4.1.patch", "a/b.PATCH"])
def test_geometry_blanking_applies_to_svg_and_patch_files(rel):
    assert h.has_geometry_data(rel)


@pytest.mark.parametrize("rel", ["docs/x.md", "x.svg.txt", "svg", "patches/readme.txt", "x.svgz"])
def test_geometry_blanking_does_not_apply_to_other_files(rel):
    assert not h.has_geometry_data(rel)


def test_svg_geometry_is_blanked_but_text_is_still_scanned():
    noise = _ip(13, 52, 48, 61)    # dado de path colado: '13.52 .48 .61'
    svg = (f'<svg>\n<path class="a" d="M0,0\nc-{noise}z"/>\n'
           f"<polygon points='1,2 3,4 -{noise}'/>\n<text>{PUBLIC}</text>\n</svg>\n")
    assert [ip for _, ip in h.find_public_ips(svg)] == [noise, noise, PUBLIC]   # sem a limpeza, casa
    cleaned = h.blank_svg_geometry(svg)
    assert cleaned.count("\n") == svg.count("\n")                              # linhas preservadas
    assert h.find_public_ips(cleaned) == [(5, PUBLIC)]


def test_svg_blanking_does_not_hide_other_attributes():
    assert h.find_public_ips(h.blank_svg_geometry(f'<g id="{PUBLIC}"/>')) == [(1, PUBLIC)]
    assert h.find_public_ips(h.blank_svg_geometry(f'<g data-d="{PUBLIC}"/>')) == [(1, PUBLIC)]


# --- ponta a ponta: git + CLI -------------------------------------------------------

def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git indisponivel")
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    return r


def _track(repo, files):
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        _git(repo, "add", "--", rel)


def _allow(tmp_path, body="# vazia\n"):
    f = tmp_path / "allow.txt"
    f.write_text(body, encoding="utf-8")
    return f


SUMMARY = re.compile(
    r"hygiene: varridos=(\d+) binarios=(\d+) excluidos=(\d+) ignorados=(\d+) allowlist=(\d+)/(\d+)\n")


def _summary(err):
    m = SUMMARY.search(err)
    assert m, err
    return tuple(int(g) for g in m.groups())


def test_main_reports_file_line_ip_and_exits_1(repo, tmp_path, capsys):
    _track(repo, {
        "docs/a.md": f"ok 192.0.2.7\nhost {PUBLIC}\n",
        "src/b.txt": f"{OTHER_PUBLIC}",
        "report-formats/suricatoos-premium-pdf/nvt-i18n-pt_BR.xml": f"<n>{PUBLIC}</n>",   # excluido
        "bin/blob.dat": b"\x00\x01" + PUBLIC.encode(),             # binario
        "logo.svg": f'<path d="M0,0c-{_ip(13, 52, 48, 61)}z"/>\n',  # so geometria
    })
    (repo / "untracked.txt").write_text(PUBLIC)                    # nao rastreado
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert rc == 1
    assert out.out.splitlines() == [f"docs/a.md:2: {PUBLIC}", f"src/b.txt:1: {OTHER_PUBLIC}"]
    assert "allowed_ips.txt" in out.err                              # orienta a saida do problema
    assert _summary(out.err) == (3, 1, 1, 0, 0, 0)                   # varridos, binarios, excluidos, ignorados, allowlist


def test_main_scans_patch_files_and_ignores_svg_geometry_inside_them(repo, tmp_path, capsys):
    noise = _ip(13, 52, 48, 61)
    patch = (
        "diff --git a/ui/Panel.tsx b/ui/Panel.tsx\n"
        "+++ b/ui/Panel.tsx\n"
        "@@ -1,2 +1,4 @@\n"
        f'+const SCAN_HOST = "{PUBLIC}";\n'
        f'+<path d="M0,0c-{noise}z"/>\n'
        f'-  <path class="x" d="M1 1 -{noise}"/>\n'
        f'+<polygon points="1,2 -{noise}"/>\n')
    _track(repo, {"patches/ui.patch": patch})
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert rc == 1
    assert out.out.splitlines() == [f"patches/ui.patch:4: {PUBLIC}"]   # a linha de TSX, so ela


def test_main_exits_0_and_only_summarises_when_clean(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": "10.0.0.1 e 203.0.113.9 e 1.2.3 e 10.0.22631.4317\n"})
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert (rc, out.out) == (0, "")
    assert _summary(out.err) == (1, 0, 0, 0, 0, 0)
    assert out.err.count("\n") == 1                                  # uma linha so', no stderr


def test_main_honours_the_allowlist(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": f"{PUBLIC} {OTHER_PUBLIC}\n"})
    allow = _allow(tmp_path, f"{PUBLIC} # {WHY}\n")
    rc = h.main(["--root", str(repo), "--allowlist", str(allow)])
    assert rc == 1
    out = capsys.readouterr()
    assert out.out.splitlines() == [f"docs/a.md:1: {OTHER_PUBLIC}"]
    assert _summary(out.err)[4:] == (1, 1)                           # a entrada foi usada


def test_main_counts_tracked_files_missing_from_disk(repo, tmp_path, capsys):
    _track(repo, {"gone.txt": PUBLIC, "ok.txt": "nada\n"})
    (repo / "gone.txt").unlink()
    assert h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))]) == 0
    assert _summary(capsys.readouterr().err) == (1, 0, 0, 1, 0, 0)


def test_main_exits_2_when_nothing_was_scanned(repo, tmp_path, capsys):
    # repositorio vazio, ou so' binarios: "limpo" por nao ter olhado nada nao vale
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert (rc, out.out) == (2, "")
    assert "nenhum arquivo" in out.err and _summary(out.err)[0] == 0
    _track(repo, {"bin/blob.dat": b"\x00\x01\x02"})
    assert h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))]) == 2


def test_main_exits_2_on_an_allowlist_entry_that_matches_nothing(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": "nada\n"})
    allow = _allow(tmp_path, f"# cabecalho\n{PUBLIC} # {WHY}\n")
    rc = h.main(["--root", str(repo), "--allowlist", str(allow)])
    out = capsys.readouterr()
    assert (rc, out.out) == (2, "")
    assert f"allow.txt:2: {PUBLIC}" in out.err and "sem uso" in out.err


def test_an_entry_seen_only_in_the_allowlist_file_itself_is_stale(repo, capsys):
    # a allowlist rastreada cita o proprio IP: isso nao pode contar como "uso"
    _track(repo, {"ci/hygiene/allowed_ips.txt": f"{PUBLIC} # {WHY}\n", "docs/a.md": "nada\n"})
    allow = repo / "ci" / "hygiene" / "allowed_ips.txt"
    assert h.main(["--root", str(repo), "--allowlist", str(allow)]) == 2
    assert "sem uso" in capsys.readouterr().err
    _track(repo, {"docs/a.md": f"host {PUBLIC}\n"})                  # agora ha' uso de verdade
    assert h.main(["--root", str(repo), "--allowlist", str(allow)]) == 0


def test_hits_and_a_stale_entry_are_both_reported_and_the_exit_is_2(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": f"host {PUBLIC}\n"})
    allow = _allow(tmp_path, f"{OTHER_PUBLIC} # {WHY}\n")
    rc = h.main(["--root", str(repo), "--allowlist", str(allow)])
    out = capsys.readouterr()
    assert rc == 2
    assert out.out.splitlines() == [f"docs/a.md:1: {PUBLIC}"]
    assert "sem uso" in out.err and "allowed_ips.txt" in out.err


def test_main_exits_2_on_a_malformed_allowlist(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": "nada\n"})
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path, f"{PUBLIC}\n"))])
    out = capsys.readouterr()
    assert (rc, out.out) == (2, "")
    assert "justificativa" in out.err


def test_main_exits_2_when_the_allowlist_is_missing(repo, tmp_path, capsys):
    rc = h.main(["--root", str(repo), "--allowlist", str(tmp_path / "nao-existe.txt")])
    assert rc == 2
    assert capsys.readouterr().err.startswith("erro:")


def test_main_exits_2_outside_a_git_repository(tmp_path, capsys, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git indisponivel")
    # tmp_path pode estar DENTRO de uma arvore git (TMPDIR no home de alguem, por exemplo):
    # o teto impede o git de subir ate' ela e de achar um repositorio que nao e' o do teste.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(var, raising=False)
    plain = tmp_path / "plain"
    plain.mkdir()
    rc = h.main(["--root", str(plain), "--allowlist", str(_allow(tmp_path))])
    assert rc == 2
    assert capsys.readouterr().err.startswith("erro:")


def test_cli_entry_point(repo, tmp_path):
    _track(repo, {"docs/a.md": f"host {PUBLIC}\n"})
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(repo), "--allowlist", str(_allow(tmp_path))],
        capture_output=True, text=True)
    assert proc.returncode == 1
    assert proc.stdout.splitlines() == [f"docs/a.md:1: {PUBLIC}"]
    assert _summary(proc.stderr)[0] == 1
