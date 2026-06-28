# 0005 — Coletor de pacotes rpm

- **Status:** ACEITO (2026-06-28)
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md)

## Contexto e problema

O agente precisa coletar o inventário de pacotes em distros rpm (RHEL/Fedora/SUSE). Há tensão entre
dois requisitos do brief: "ler a base de pacotes de forma robusta — **não shell-out frágil**" e o NFR
§8 "**agente leve** (CPU/RAM/IO baixos)". Em dpkg o problema não existe (lemos `/var/lib/dpkg/status`
direto, texto). Em rpm o banco é binário e, desde RHEL 9 / Fedora 33, **SQLite**.

## Opções consideradas

- **go-rpmdb (ler o rpmdb direto).** Lê BDB/NDB/SQLite nativamente.
  - 👍 Honra "sem shell-out".
  - 👎 O backend SQLite exige um driver SQLite pure-Go (`modernc.org/sqlite`) — **dependência pesada**
    (libc/mathutil/…), binário do agente bem maior, contra o NFR de leveza.
- **`rpm -qa --qf` estruturado (recomendado).** Lê via a ferramenta `rpm` com formato de saída fixo
  (`%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}`).
  - 👍 **Zero dependências**, binário enxuto; usa a fonte autoritativa; formato fixo/tab-separado é
    **robusto, não frágil** (não é parsing de saída livre).
  - 👎 É shell-out; depende do binário `rpm` no host (presente por padrão em distros rpm).

## Decisão

**`rpm -qa --qf` estruturado.** Para um agente de endpoint, o **footprint** (NFR explícito) pesa mais
que a pureza "sem shell-out", e um formato de query fixo **não é** o "shell-out frágil" que o brief
quer evitar (o que se evita é parsear saída livre/heurística). A execução é **injetável**
(`Collector.rpmList`), então o parser é testável sem `rpm` instalado. Decisão **reversível** para
go-rpmdb se o trade-off mudar.

## Consequências

- 👍 Sem dependências externas no módulo do agente; binário pequeno; resultado autoritativo.
- 👎 Um host rpm sem o binário `rpm` (raríssimo) não coleta pacotes — erro claro, não silencioso.
- `gpg-pubkey` é excluído (é chave GPG importada, não software).
- A seleção é automática: dpkg quando `/var/lib/dpkg/status` existe, senão rpm.
