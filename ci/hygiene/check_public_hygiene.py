#!/usr/bin/env python3
"""Checador de higiene do repositório PÚBLICO: reprova IPv4 público literal.

Este repositório é público. Um IP público escrito em arquivo versionado quase
sempre é dado de ambiente real (host de terceiros, alvo de scan, infraestrutura)
que não deveria estar aqui. O checador varre os arquivos de TEXTO rastreados
pelo git e imprime `arquivo:linha: IP` para cada IPv4 público literal.

    python3 ci/hygiene/check_public_hygiene.py [--root DIR] [--allowlist ARQUIVO]

Saída: 0 = limpo; 1 = achou IP público (as ocorrências vão para o stdout);
2 = erro de uso ou de ambiente (git ausente, allowlist malformada ou com entrada
sem uso, nenhum arquivo de texto varrido...). Toda execução imprime no stderr uma
linha de resumo: `hygiene: varridos=N binarios=N excluidos=N ignorados=N
allowlist=usadas/total`. "Limpo" sem ter varrido nada não vale: varridos=0 é erro.

O QUE É UM IPv4 LITERAL
  Quatro números decimais de até 3 dígitos, cada um <= 255, separados por ponto,
  que não fazem parte de algo maior: nem de um número pontuado mais longo (versão
  `1.2.3.4.5`, OID), nem colados em letras ou dígitos (`v1.2.3.4`, release de
  pacote `lp156.3.3.1`). Um ponto final de frase logo depois do IP, ou um `\\n` de
  string ou um escape percentual (`%0A`, `%20`) logo antes, não o escondem. Zeros
  à esquerda são normalizados (008 == 8).

O QUE NÃO É REPROVADO
  Faixas que não identificam ambiente real: RFC 5737 (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24), RFC 1918 (10/8, 172.16/12, 192.168/16),
  CGNAT 100.64/10, loopback 127/8, link-local 169.254/16, 0.0.0.0/8, multicast
  224/4, reservado 240/4 (inclui 255.255.255.255) e os IPs de `allowed_ips.txt`.

ALLOWLIST (`allowed_ips.txt`, ao lado deste script)
  Um IPv4 por linha, seguido de `# justificativa` (obrigatória, com no mínimo 15
  caracteres; sem ela, ou repetindo um IP, o checador cai). Só para IP legítimo de
  terceiros ou de documentação (resolver público citado em exemplo, fixture de
  teste...). NUNCA para IP de ambiente real (host de terceiros, alvo de scan):
  esse se troca por um endereço RFC 5737. A lista não acumula resíduo: entrada que
  nenhum arquivo varrido cita (a própria allowlist não conta) derruba o checador
  como "sem uso".

EXCLUSÕES (o que NÃO é varrido)
  - arquivos binários: qualquer byte NUL no conteúdo (PNG, PDF, tar.gz...).
    Texto UTF-16 só é lido se começar com BOM (exportações do Windows);
  - os catálogos NVT gerados (`nvt-i18n-*.xml`): tradução de textos do feed
    público da Greenbone, cheia de números de versão com 4 componentes
    (a.b.c.d) que são indistinguíveis de um IP;
  - symlinks, submódulos e arquivos rastreados que não existem no disco;
  - em `.svg` e `.patch`, o valor dos atributos `d` e `points` (dados de
    geometria, em que números decimais vêm colados uns nos outros, como `.5.5.5`).
    O texto e os demais atributos continuam varridos.
  `patches/` NÃO é exclusão: o patch do GSA cria arquivos próprios (tema, telas,
  locales) e é varrido como código; só a geometria SVG que ele carrega é ignorada.

LIMITE CONHECIDO
  Conteúdo codificado não é decodificado. Os XML de feed de report format
  (`report-formats/pdf-suricatoos-*.xml`) levam cópias dos arquivos do bundle em
  base64; elas valem o que o bundle vale porque `build-feed-xml.py` as regenera e o
  job `feed-sync` de `.github/workflows/report-formats-ci.yml` reprova XML
  divergente. O bundle, esse sim, é varrido.
  Só o IPv4 em decimal pontuado é reconhecido. Ficam de fora, de propósito ou por
  custo: formas defanged (`8.8.8[.]8`), formas tracejadas (`ip-8-8-8-8` em
  hostname), IP como inteiro ou hex (`134744072`, `0x08080808`), pontos escapados
  (percent `%2E`; regex `8\\.8\\.8\\.8`) e IPv6. Cada uma tem um teste xfail estrito:
  quando uma passar a ser detectada, o teste reprova e esta lista é atualizada.

Só biblioteca padrão (Python >= 3.9). Testes: python -m pytest ci/hygiene -q
"""
from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_ALLOWLIST = HERE / "allowed_ips.txt"

# Tamanho mínimo da justificativa de uma entrada da allowlist.
MIN_JUSTIFICATION = 15

# Caminhos (relativos à raiz, com `/`) que não são varridos. Ver EXCLUSÕES acima.
EXCLUDED_GLOBS = (
    "report-formats/suricatoos-premium-pdf/nvt-i18n-*.xml",
)

# Arquivos cujos atributos `d`/`points` (geometria SVG) são ignorados.
GEOMETRY_SUFFIXES = (".svg", ".patch")

# Faixas que nunca são reprovadas. Ver "O QUE NÃO É REPROVADO" acima.
EXEMPT_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "esta rede"
    "10.0.0.0/8",       # RFC 1918
    "100.64.0.0/10",    # CGNAT (RFC 6598)
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # RFC 1918
    "192.0.2.0/24",     # RFC 5737 (TEST-NET-1)
    "192.168.0.0/16",   # RFC 1918
    "198.51.100.0/24",  # RFC 5737 (TEST-NET-2)
    "203.0.113.0/24",   # RFC 5737 (TEST-NET-3)
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reservado; inclui o broadcast 255.255.255.255
))

# Borda esquerda: sem letra/dígito colado. `_` não conta (`scan_<ip>.xml` é IP), e um
# escape `\n`, `\r` ou `\t` (`"a\n<ip>"` num literal de string) ou percentual (`%0A<ip>`
# numa URL) logo antes também não.
# `(?<!\d\.)` / `(?!\.\d)`: não é pedaço de um número pontuado maior.
# Borda direita: sem dígito colado; um ponto final de frase ainda deixa o IP valer.
_IPV4 = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt])|(?<=%[0-9A-Fa-f]{2}))(?<!\d\.)"
    r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
    r"(?!\d)(?!\.\d)"
)
# Entrada da allowlist: o IPv4 e só ele (nada de CIDR, porta ou texto).
_IPV4_ENTRY = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

# Atributos de geometria do SVG. `(?<![\w:-])` evita `id=`, `data-d=`, `xlink:d=`.
_SVG_GEOMETRY = re.compile(r"""(?<![\w:-])(?:d|points)\s*=\s*(?:"[^"]*"|'[^']*')""")


class ScanResult(NamedTuple):
    hits: list          # (arquivo, linha, IP)
    scanned: int        # arquivos de texto varridos
    binary: int         # binários ignorados
    excluded: int       # ignorados por caminho (EXCLUDED_GLOBS)
    skipped: int        # ausentes do disco, symlinks, submódulos
    used: set           # IPs da allowlist que algum arquivo varrido citou


def _parse_ipv4(match: re.Match) -> ipaddress.IPv4Address | None:
    octets = [int(g) for g in match.groups()]
    if max(octets) > 255:
        return None
    return ipaddress.IPv4Address(bytes(octets))


def is_exempt(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in EXEMPT_NETWORKS)


def find_public_ips(text: str, allowed=frozenset(), used: set | None = None) -> list[tuple[int, str]]:
    """(linha, literal) de cada IPv4 público de `text` que não está em `allowed`.

    As linhas são contadas só por `\\n`: CRLF vale uma quebra e separadores como
    form feed não valem, para o número bater com o que o GitHub e os editores mostram.
    Se `used` é dado, recebe a forma canônica de cada IP da allowlist que apareceu.
    """
    found = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        for match in _IPV4.finditer(line):
            ip = _parse_ipv4(match)
            if ip is None or is_exempt(ip):
                continue
            canon = str(ip)
            if canon in allowed:
                if used is not None:
                    used.add(canon)
                continue
            found.append((lineno, match.group(0)))
    return found


def load_allowlist(path: Path) -> dict[str, int]:
    """{IP canônico: linha} de `path`. Levanta ValueError em linha malformada."""
    entries: dict[str, int] = {}
    # Bytes, não read_text: sem tradução de quebra de linha, a contagem é a mesma
    # (`\n`) dos arquivos varridos e do que o GitHub e os editores mostram.
    text = Path(path).read_bytes().decode("utf-8-sig")
    for lineno, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry, _, why = line.partition("#")
        entry, why = entry.strip(), why.strip()
        match = _IPV4_ENTRY.fullmatch(entry)
        ip = _parse_ipv4(match) if match else None
        if ip is None:
            raise ValueError(f"{path}:{lineno}: entrada nao e um IPv4 (um por linha): {entry!r}")
        if not why:
            raise ValueError(f"{path}:{lineno}: falta a justificativa ('IP  # motivo'): {entry}")
        if len(why) < MIN_JUSTIFICATION:
            raise ValueError(f"{path}:{lineno}: justificativa curta demais "
                             f"(minimo {MIN_JUSTIFICATION} caracteres): {entry}")
        if str(ip) in entries:
            raise ValueError(f"{path}:{lineno}: entrada repetida (ja esta na linha {entries[str(ip)]}): {entry}")
        entries[str(ip)] = lineno
    return entries


def is_excluded(rel: str) -> bool:
    """`rel` (relativo à raiz, com `/`) está numa exclusão por caminho?"""
    return any(fnmatch.fnmatchcase(rel, glob) for glob in EXCLUDED_GLOBS)


def has_geometry_data(rel: str) -> bool:
    """O arquivo carrega geometria SVG (que `blank_svg_geometry` deve limpar)?"""
    return rel.lower().endswith(GEOMETRY_SUFFIXES)


def decode_text(data: bytes) -> str | None:
    """Texto do arquivo, ou None se for binário (byte NUL, salvo UTF-16 com BOM)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def blank_svg_geometry(text: str) -> str:
    """Troca por espaços o valor dos atributos `d`/`points`; as quebras de linha ficam."""
    return _SVG_GEOMETRY.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def tracked_files(root: Path) -> list[str]:
    proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError("git ls-files falhou: " + proc.stderr.decode("utf-8", "replace").strip())
    return [os.fsdecode(p) for p in proc.stdout.split(b"\0") if p]


def scan_repo(root: Path, allowed, allowlist_rel: str | None = None) -> ScanResult:
    """Varre os arquivos de texto rastreados. `allowlist_rel` é o caminho da própria
    allowlist, se rastreada: ela é varrida, mas o que cita não conta como "uso"."""
    hits, used = [], set()
    scanned = binary = excluded = skipped = 0
    for rel in tracked_files(root):
        if is_excluded(rel):
            excluded += 1
            continue
        path = Path(root) / rel
        if path.is_symlink() or not path.is_file():
            skipped += 1
            continue
        text = decode_text(path.read_bytes())
        if text is None:
            binary += 1
            continue
        scanned += 1
        if has_geometry_data(rel):
            text = blank_svg_geometry(text)
        seen = None if rel == allowlist_rel else used
        hits.extend((rel, lineno, ip) for lineno, ip in find_public_ips(text, allowed, seen))
    return ScanResult(hits, scanned, binary, excluded, skipped, used)


def _relative_to_root(path: Path, root: Path) -> str | None:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reprova IPv4 publico literal em arquivos de texto rastreados pelo git.")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="raiz do repositorio (padrao: a deste script)")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST,
                        help="arquivo de IPs permitidos (padrao: ci/hygiene/allowed_ips.txt)")
    args = parser.parse_args(argv)
    try:
        allowed = load_allowlist(args.allowlist)
        res = scan_repo(args.root, allowed, _relative_to_root(args.allowlist, args.root))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    for rel, lineno, ip in res.hits:
        print(f"{rel}:{lineno}: {ip}")
    print(f"hygiene: varridos={res.scanned} binarios={res.binary} excluidos={res.excluded} "
          f"ignorados={res.skipped} allowlist={len(res.used)}/{len(allowed)}", file=sys.stderr)
    status = 0
    if res.hits:
        print(f"{len(res.hits)} IPv4 publico(s) literal(is) em arquivos rastreados. "
              "Ambiente real: troque por um endereco de documentacao "
              "(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). "
              "Exemplo legitimo de terceiros: acrescente o IP a ci/hygiene/allowed_ips.txt "
              "com a justificativa.", file=sys.stderr)
        status = 1
    if res.scanned == 0:
        print("erro: nenhum arquivo de texto varrido (raiz errada? repositorio vazio?)", file=sys.stderr)
        return 2
    for ip, lineno in sorted(allowed.items(), key=lambda kv: kv[1]):
        if ip not in res.used:
            print(f"erro: {args.allowlist}:{lineno}: {ip} sem uso na allowlist "
                  "(nenhum arquivo varrido o cita); remova a linha", file=sys.stderr)
            status = 2
    return status


if __name__ == "__main__":
    sys.exit(main())
