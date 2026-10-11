#!/usr/bin/env python3
"""Checador de higiene do repositório PÚBLICO: reprova IPv4 público literal.

Este repositório é público. Um IP público escrito em arquivo versionado quase
sempre é dado de ambiente real (host de terceiros, alvo de scan, infraestrutura)
que não deveria estar aqui. O checador varre os arquivos de TEXTO rastreados
pelo git e imprime `arquivo:linha: IP` para cada IPv4 público literal.

    python3 ci/hygiene/check_public_hygiene.py [--root DIR] [--allowlist ARQUIVO]

Saída: 0 = limpo; 1 = achou IP público (as ocorrências vão para o stdout);
2 = erro de uso ou de ambiente (git ausente, allowlist malformada...).

O QUE É UM IPv4 LITERAL
  Quatro números decimais de até 3 dígitos, cada um <= 255, separados por ponto,
  que não fazem parte de algo maior: nem de um número pontuado mais longo (versão
  `1.2.3.4.5`, OID), nem colados em letras ou dígitos (`v1.2.3.4`, release de
  pacote `lp156.3.3.1`). Um ponto final de frase logo depois do IP, ou um `\\n` de
  string logo antes, não o escondem. Zeros à esquerda são normalizados (008 == 8).

O QUE NÃO É REPROVADO
  Faixas que não identificam ambiente real: RFC 5737 (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24), RFC 1918 (10/8, 172.16/12, 192.168/16),
  CGNAT 100.64/10, loopback 127/8, link-local 169.254/16, 0.0.0.0/8, multicast
  224/4, reservado 240/4 (inclui 255.255.255.255) e os IPs de `allowed_ips.txt`.

ALLOWLIST (`allowed_ips.txt`, ao lado deste script)
  Um IPv4 por linha, seguido de `# justificativa` (obrigatória; linha sem ela
  derruba o checador). Só para IP legítimo de terceiros ou de documentação
  (resolver público citado em exemplo, fixture de teste...). NUNCA para IP de
  ambiente real (host de terceiros, alvo de scan): esse se troca por um endereço
  RFC 5737.

EXCLUSÕES (o que NÃO é varrido)
  - arquivos binários: qualquer byte NUL no conteúdo (PNG, PDF, tar.gz...).
    Texto UTF-16 só é lido se começar com BOM (exportações do Windows);
  - `patches/`: diffs de código de terceiros (upstream do GSA/gsad), com os
    dados do upstream;
  - os catálogos NVT gerados (`nvt-i18n-*.xml`): tradução de textos do feed
    público da Greenbone, cheia de números de versão com 4 componentes
    (a.b.c.d) que são indistinguíveis de um IP;
  - symlinks, submódulos e arquivos rastreados que não existem no disco;
  - em `.svg`, o valor dos atributos `d` e `points` (dados de geometria, em que
    números decimais vêm colados uns nos outros, como `.5.5.5`). O texto e os
    demais atributos continuam varridos.

LIMITE CONHECIDO: conteúdo codificado não é decodificado. Os XML de feed de
report format (`report-formats/pdf-suricatoos-*.xml`) levam cópias dos arquivos do
bundle em base64; elas valem o que o bundle vale porque `build-feed-xml.py`
as regenera e o CI de report-formats reprova XML divergente. O bundle, esse sim,
é varrido.

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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_ALLOWLIST = HERE / "allowed_ips.txt"

# Caminhos (relativos à raiz, com `/`) que não são varridos. Ver EXCLUSÕES acima.
EXCLUDED_GLOBS = (
    "patches/*",
    "report-formats/suricatoos-premium-pdf/nvt-i18n-*.xml",
)

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

# Borda esquerda: sem letra/dígito colado. `_` não conta (`scan_<ip>.xml` é IP) e um
# escape `\n`, `\r` ou `\t` logo antes também não (`"a\n<ip>"` num literal de string).
# `(?<!\d\.)` / `(?!\.\d)`: não é pedaço de um número pontuado maior.
# Borda direita: sem dígito colado; um ponto final de frase ainda deixa o IP valer.
_IPV4 = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt]))(?<!\d\.)"
    r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
    r"(?!\d)(?!\.\d)"
)
# Entrada da allowlist: o IPv4 e só ele (nada de CIDR, porta ou texto).
_IPV4_ENTRY = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

# Atributos de geometria do SVG. `(?<![\w:-])` evita `id=`, `data-d=`, `xlink:d=`.
_SVG_GEOMETRY = re.compile(r"""(?<![\w:-])(?:d|points)\s*=\s*(?:"[^"]*"|'[^']*')""")


def _parse_ipv4(match: re.Match) -> ipaddress.IPv4Address | None:
    octets = [int(g) for g in match.groups()]
    if max(octets) > 255:
        return None
    return ipaddress.IPv4Address(bytes(octets))


def is_exempt(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in EXEMPT_NETWORKS)


def find_public_ips(text: str, allowed: frozenset[str] = frozenset()) -> list[tuple[int, str]]:
    """(linha, literal) de cada IPv4 público de `text` que não está em `allowed`.

    As linhas são contadas só por `\\n`: CRLF vale uma quebra e separadores como
    form feed não valem, para o número bater com o que o GitHub e os editores mostram.
    """
    found = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        for match in _IPV4.finditer(line):
            ip = _parse_ipv4(match)
            if ip is None or is_exempt(ip) or str(ip) in allowed:
                continue
            found.append((lineno, match.group(0)))
    return found


def load_allowlist(path: Path) -> frozenset[str]:
    """IPs (forma canônica) de `path`. Levanta ValueError em linha malformada."""
    entries = set()
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8-sig").split("\n"), start=1):
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
        entries.add(str(ip))
    return frozenset(entries)


def is_excluded(rel: str) -> bool:
    """`rel` (relativo à raiz, com `/`) está numa exclusão por caminho?"""
    return any(fnmatch.fnmatchcase(rel, glob) for glob in EXCLUDED_GLOBS)


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


def scan_repo(root: Path, allowed: frozenset[str]) -> list[tuple[str, int, str]]:
    """(arquivo, linha, IP) de cada IPv4 público nos arquivos de texto rastreados."""
    hits = []
    for rel in tracked_files(root):
        if is_excluded(rel):
            continue
        path = Path(root) / rel
        if path.is_symlink() or not path.is_file():
            continue
        text = decode_text(path.read_bytes())
        if text is None:
            continue
        if rel.lower().endswith(".svg"):
            text = blank_svg_geometry(text)
        hits.extend((rel, lineno, ip) for lineno, ip in find_public_ips(text, allowed))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reprova IPv4 publico literal em arquivos de texto rastreados pelo git.")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="raiz do repositorio (padrao: a deste script)")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST,
                        help="arquivo de IPs permitidos (padrao: ci/hygiene/allowed_ips.txt)")
    args = parser.parse_args(argv)
    try:
        hits = scan_repo(args.root, load_allowlist(args.allowlist))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    for rel, lineno, ip in hits:
        print(f"{rel}:{lineno}: {ip}")
    if hits:
        print(f"{len(hits)} IPv4 publico(s) literal(is) em arquivos rastreados. "
              "Ambiente real: troque por um endereco de documentacao "
              "(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). "
              "Exemplo legitimo de terceiros: acrescente o IP a ci/hygiene/allowed_ips.txt "
              "com a justificativa.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
