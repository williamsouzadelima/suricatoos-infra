"""Testes do checador de higiene (ci/hygiene/check_public_hygiene.py).

Os IPs publicos usados como massa de teste sao montados em tempo de execucao
(`_ip`): o proprio checador varre este arquivo, e um literal publico aqui exigiria
uma entrada na allowlist so para os testes passarem. Literais de faixas isentas
(RFC 1918, RFC 5737, loopback...) e de numeros que NAO sao IP podem ficar escritos.

Rodar: python -m pytest ci/hygiene -q
"""
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
])
def test_public_ip_is_found_in_context(template):
    text = template.format(ip=PUBLIC)
    assert [ip for _, ip in h.find_public_ips(text)] == [PUBLIC]


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


# --- allowlist ------------------------------------------------------------------

def test_allowlist_suppresses_only_the_listed_ip():
    text = f"{PUBLIC} {OTHER_PUBLIC}\n"
    assert h.find_public_ips(text, frozenset({PUBLIC})) == [(1, OTHER_PUBLIC)]
    assert h.find_public_ips(text, frozenset({PUBLIC, OTHER_PUBLIC})) == []


def test_load_allowlist_reads_entries_and_ignores_comments(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text(
        "# cabecalho\n\n"
        f"{PUBLIC}   # resolver publico citado em docs\r\n"
        f"  {OTHER_PUBLIC}\t# outro, com recuo\n"
        "   # comentario recuado\n",
        encoding="utf-8")
    assert h.load_allowlist(f) == frozenset({PUBLIC, OTHER_PUBLIC})


def test_load_allowlist_normalizes_leading_zeros(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text(f"{_ip('008', '008', '008', '008')} # com zeros\n", encoding="utf-8")
    assert h.load_allowlist(f) == frozenset({PUBLIC})


@pytest.mark.parametrize("line", ["{ip}", "{ip}  #", "{ip} #    ", "{ip}#"])
def test_load_allowlist_requires_a_justification(tmp_path, line):
    f = tmp_path / "allow.txt"
    f.write_text("# ok\n" + line.format(ip=PUBLIC) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"allow\.txt:2: .*justificativa"):
        h.load_allowlist(f)


@pytest.mark.parametrize("entry", [
    "not-an-ip", "999.1.1.1", "1.2.3", "1.2.3.4.5", PUBLIC + ":53",
    PUBLIC + "/24",                # CIDR nao e suportado: um IP por linha
])
def test_load_allowlist_rejects_malformed_entries(tmp_path, entry):
    f = tmp_path / "allow.txt"
    f.write_text(f"{entry} # motivo\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"allow\.txt:1: .*IPv4"):
        h.load_allowlist(f)


# --- exclusoes e decodificacao ----------------------------------------------------

@pytest.mark.parametrize("rel", [
    "patches/gsa-v27.4.1.patch",
    "patches/sub/dir/x.patch",
    "report-formats/suricatoos-premium-pdf/nvt-i18n-pt_BR.xml",
    "report-formats/suricatoos-premium-pdf/nvt-i18n-es.xml",
])
def test_excluded_paths(rel):
    assert h.is_excluded(rel)


@pytest.mark.parametrize("rel", [
    "docs/x.md", "patches", "patches-extra/x.patch", "Patches/x.patch",
    "report-formats/suricatoos-premium-pdf/main.tex",
    "report-formats/sample/sample-report.xml",
    "outro/nvt-i18n-pt_BR.xml",
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


def test_main_reports_file_line_ip_and_exits_1(repo, tmp_path, capsys):
    _track(repo, {
        "docs/a.md": f"ok 192.0.2.7\nhost {PUBLIC}\n",
        "src/b.txt": f"{OTHER_PUBLIC}",
        "patches/x.patch": f"+ {PUBLIC}\n",                       # excluido
        "bin/blob.dat": b"\x00\x01" + PUBLIC.encode(),             # binario
        "logo.svg": f'<path d="M0,0c-{_ip(13, 52, 48, 61)}z"/>\n',  # so geometria
    })
    (repo / "untracked.txt").write_text(PUBLIC)                    # nao rastreado
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert rc == 1
    assert out.out.splitlines() == [f"docs/a.md:2: {PUBLIC}", f"src/b.txt:1: {OTHER_PUBLIC}"]
    assert "allowed_ips.txt" in out.err                              # orienta a saida do problema


def test_main_exits_0_and_prints_nothing_when_clean(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": "10.0.0.1 e 203.0.113.9 e 1.2.3 e 10.0.22631.4317\n"})
    rc = h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))])
    out = capsys.readouterr()
    assert (rc, out.out, out.err) == (0, "", "")


def test_main_honours_the_allowlist(repo, tmp_path, capsys):
    _track(repo, {"docs/a.md": f"{PUBLIC} {OTHER_PUBLIC}\n"})
    allow = _allow(tmp_path, f"{PUBLIC} # resolver publico citado em docs\n")
    rc = h.main(["--root", str(repo), "--allowlist", str(allow)])
    assert rc == 1
    assert capsys.readouterr().out.splitlines() == [f"docs/a.md:1: {OTHER_PUBLIC}"]


def test_main_skips_tracked_files_missing_from_disk(repo, tmp_path):
    _track(repo, {"gone.txt": PUBLIC})
    (repo / "gone.txt").unlink()
    assert h.main(["--root", str(repo), "--allowlist", str(_allow(tmp_path))]) == 0


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


def test_main_exits_2_outside_a_git_repository(tmp_path, capsys):
    if shutil.which("git") is None:
        pytest.skip("git indisponivel")
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
