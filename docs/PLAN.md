# Suricatoos Agent — PLAN.md

> **Status: ACEITO — A1 · B1 · C1 · D1 confirmados em 2026-06-28. Fase 0 (fundações) entregue; Fase 1 a seguir.**
> Data: 2026-06-28 · Componente novo do fork `suricatoos-infra` (stack Greenbone/GVM).
> Este documento NÃO é código. É a especificação que dirige a construção (per §0 do brief).

---

## 1. Resumo executivo

O **Suricatoos Agent** é um agente de endpoint cross-platform (Windows, GNU/Linux, macOS)
que coleta **localmente** a postura de vulnerabilidade de um host e a entrega ao plano central
de forma autenticada e **outbound** (agente → central), resolvendo o gap do scanning baseado em
rede da GVM para hosts fora da rede, atrás de NAT/VPN ou que aparecem de forma esporádica.

O agente é **passivo/local**: coleta inventário de software normalizado + fatos de SO; a
**correlação de vulnerabilidade roda server-side** (modelo Notus, reaproveitando o feed Greenbone);
os achados são **importados no gvmd como report** (via container task) e aparecem na GSA.

Nada de scanning de rede, exploração ou capacidade ofensiva no endpoint. Nada de achado sem
evidência rastreável.

---

## 2. Entendimento do problema

| Cenário cego para o scanner de rede | Como o agente resolve |
|---|---|
| Host fora da rede corporativa (home office, roaming) | Agente coleta local e faz push outbound quando há conectividade |
| Host atrás de VPN/NAT (scanner central não inicia conexão) | Inversão do sentido da conexão (agente → central) |
| Endpoint esporádico que nunca coincide com a janela de scan | Fila offline (store-and-forward) + heartbeat |

Consequência hoje: cobertura cega de uma parcela crescente do parque. A Greenbone tem
agent-based scanning **ainda nascente** (ver §3, Decisão D) → o gap é legítimo agora.

---

## 3. Fatos verificados (não de memória — per §0.3)

Verificados na **stack viva** (tenho SSH ao deploy) e contra **repositórios/docs oficiais**:

| # | Fato | Valor verificado | Fonte |
|---|---|---|---|
| 1 | Versão do gvmd / GMP | **GVM Manager 26.31.1**, Manager DB rev 279; fala **GMP v22.x** (python-gvm `gmpv224`/`gmpv225`) | stack viva + python-gvm docs |
| 2 | Import de report externo | **`create_container_task(name, comment)` → `import_report(report, task_id, in_assets)`**. `create_report` **não existe** no python-gvm. Container task = "meta task to import and view reports from other systems" | [python-gvm gmpv224](https://greenbone.github.io/python-gvm/api/gmpv224.html), [gvm-tools script](https://github.com/greenbone/gvm-tools/blob/main/scripts/create-consolidated-report.gmp.py) |
| 3 | Estrutura do report | `<report><report id><ports/><results><result>…</result></results></report></report>`; cada `<result>` carrega host/port/nvt(oid)/threat/severity/description | gvm-tools script (código real) |
| 4 | Schema da advisory Notus | `/var/lib/notus/products/<produto>.notus` (JSON): `{package_type:"rpm"\|"deb", product_name, advisories:[{oid, fixed_packages:[{full_name:"name-version-release.arch", specifier:">="}]}]}` | stack viva (`docker compose exec ospd-openvas`) |
| 5 | Modelo de correlação Notus | lista de software instalado é comparada **direto** contra o JSON de pacotes vulneráveis (sem rodar VT por check). `oid` = NVT OID `1.3.6.1.4.1.25623.1.1.2.*` | [Greenbone blog Notus](https://www.greenbone.net/en/blog/notus/) |
| 6 | Roadmap do scanner | **openvasd** (Rust) substitui ospd-openvas (OSP/XML → **REST HTTP**); **GOS 24.10 já usa openvasd p/ local checks** no lugar do notus-scanner; long-term Rust substitui openvas-scanner+ospd+notus+OSP | [community.greenbone.net openvasd](https://community.greenbone.net/blog/introducing-openvasd-and-a-performance-enhanced-notus-engine/) |
| 7 | Plataforma do fork | Community Edition 22.4; gsa v27.4.1, gsad v26.4.0; FEED_RELEASE 24.10; projeto compose `greenbone-community-edition` | `VERSIONS.md` |

**Limite descoberto (vira Decisão D):** as advisories Notus existem **só para distros Linux**
(`package_type` = `rpm`/`deb`). **Não há advisory Notus para Windows nem macOS.** Logo, o modelo
de correlação "tipo Notus" cobre Linux nativamente; Windows/macOS precisam de **outra fonte de
correlação** (ver §4 Decisão D e §8 Risco R1). Isso não estava explícito no brief e muda o escopo
de correlação cross-platform.

---

## 4. Decisões de arquitetura (resumo — detalhe nos ADRs)

> Recomendação para cada uma abaixo; ADRs em `docs/adr/`. **Preciso da sua confirmação de A/B/C/D
> antes da Fase 1.**

### Decisão A — Modelo de coleta de vulnerabilidade · **Recomendo A1** · [ADR-0001](adr/0001-modelo-de-coleta.md)
- **A1 (recomendado):** correlação baseada em pacote (modelo Notus) — agente coleta inventário
  normalizado; correlação server-side compara com advisories. Offline, footprint mínimo, reaproveita
  o feed Greenbone. Gancho de plugin para checks locais de config (CIS-like) como extensão pós-v1.
- A2: mini-scanner local embarcado — mais cobertura, mas pesado e arriscado cross-platform.

### Decisão B — Destino e correlação dos resultados · **Recomendo B1 (com interface plugável p/ B2/openvasd)** · [ADR-0002](adr/0002-destino-dos-resultados.md)
- **B1 (recomendado):** bridge GMP → gvmd via `create_container_task` + `import_report` (verificado).
  Achados aparecem na GSA imediatamente. Correlação isolada atrás de interface.
- B2: collector/ingest próprio do Suricatoos (correlação server-side + store próprio, sincroniza com
  gvmd) — mais flexível, mais código. Plugável depois sem reescrever o agente.
- **Nota de roadmap (Fato #6):** o landing fica **abstraído atrás de uma interface `ResultSink`**
  para poder mirar **openvasd (REST)** quando ele substituir o ospd/OSP, sem reescrever o agente.

### Decisão C — Linguagem do agente · **Recomendo C1 (Go)** · [ADR-0003](adr/0003-linguagem-do-agente.md)
- **C1 (recomendado):** Go — binário estático único, cross-compilation trivial p/ os 3 SOs,
  ecossistema maduro (Windows Service/systemd/launchd via `kardianos/service`, `gopsutil`).
- C2: Rust — alinhado ao novo stack Rust da Greenbone, ótimo footprint, mas curva/velocidade maiores.
- Control-plane/bridge: Python (reusa `python-gvm`) **ou** Go — decidir no ADR-0002 (recomendo
  **Python no gmp-bridge** por causa do `python-gvm`, Go no resto).

### Decisão D (NOVA, descoberta na verificação) — Fonte de correlação cross-platform · **Recomendo D1**
- **D1 (recomendado):** v1 correlaciona **Linux via Notus** (alta fidelidade, reusa o feed).
  Windows/macOS: o agente **coleta inventário** (Fase 3) mas a **correlação fica atrás da mesma
  interface**, plugando uma fonte adequada depois (CPE→NVD, ou os Local Security Checks de Windows
  do feed Greenbone). Sem fabricar achados onde não há dado.
- D2: já na v1, correlação cross-platform via mapeamento **CPE → NVD/CVE** para os 3 SOs (engine de
  correlação maior, mais ruído de matching, mais manutenção).
- D3: v1 **Linux-only** ponta-a-ponta; Windows/macOS ficam para roadmap (inclusive a coleta).

---

## 5. Arquitetura alvo

**Componentes** (split-plane: separa autoridade de dados):

1. **Suricatoos Agent** (endpoint, Go): enrollment, coleta, fila offline, reporte, auto-update.
2. **Control plane** (orquestração): registro de agentes, policy/escopo, tokens de bootstrap
   (gerar/validar/revogar), comandos (rescan/update/uninstall), distribuição de updates. *Outbound-only
   do ponto de vista do agente.*
3. **Data plane / Ingest**: recebe inventários (mTLS, assinados, idempotentes).
4. **Correlation engine**: aplica advisories Notus ao inventário (server-side). Atrás de interface.
5. **GMP bridge** (Python, `python-gvm`): converte achados → report XML → `import_report` na container
   task → visível na GSA.

```
[Admin/UI autenticada] gera bundle de enrollment (binário genérico assinado + bootstrap token + endpoint + CA pinada)
        │  (download autenticado por attachment OU handle de uso único — NUNCA segredo em query string)
        ▼
[Agent] gera par de chaves + CSR  --CSR + bootstrap token (mTLS bootstrap)-->  [Control plane]
[Control plane] valida token (assinatura/TTL/usos/escopo) + CSR (PoP) → emite cert mTLS + policy; CONSOME o token
[Agent] coleta inventário normalizado + fatos de SO        --push assinado (outbound, mTLS)-->  [Ingest]
[Correlation] inventário × advisories Notus (server-side) → achados (cada um com evidência)
[GMP bridge] achados → import_report(container_task) → GSA/relatórios
[Agent] heartbeat + processa comandos (rescan/update/kill/uninstall)
Sem conectividade: agente enfileira local (store-and-forward) + retry/backoff com jitter.
```

Sinergia com o que já existe: o **feed-updater** (já implementado) mantém as advisories Notus
frescas no servidor → a correlação consome dados atualizados (mitiga achado obsoleto).

---

## 6. Schema do inventário/achado (fonte da verdade — versionado)

**Inventário (normalizado, independente de SO)** — `schema/inventory.schema.json`:
```jsonc
{
  "schema_version": "1.0.0",
  "agent":   { "agent_id": "<machine-id derivado, estável a reboot>", "agent_version": "x.y.z",
               "hostname": "...", "scope": "<tenant/policy do cert>" },
  "collected_at": "<RFC3339 UTC>",
  "os":      { "family": "linux|darwin|windows", "distro": "debian|ubuntu|rhel|macos|windows|...",
               "release": "12 | 22.04 | 14.4 | 10.0.19045", "arch": "amd64|arm64", "kernel": "..." },
  "packages": [
    { "name": "openssl", "version": "3.0.11-1~deb12u1", "arch": "amd64",
      "source": "dpkg|rpm|pkgutil|app-bundle|homebrew|registry|winget",
      "full_name": "openssl-3.0.11-1~deb12u1.amd64" }   // formato Notus p/ Linux
  ],
  "facts": { "listening_ports_local": [ {"port":22,"proto":"tcp","process":"sshd"} ], "services": [ ] },
  "cycle_hash": "<sha256 do conteúdo normalizado — idempotência/dedupe>"
}
```

**Achado (após correlação)** — `schema/finding.schema.json`:
```jsonc
{
  "schema_version": "1.0.0", "agent_id": "...", "host": "...", "collected_at": "...",
  "findings": [{
    "oid": "1.3.6.1.4.1.25623.1.1.2.2023.1001",
    "cve": ["CVE-2023-xxxx"],            // resolvido da metadata da VT no feed (ver §11)
    "severity": 7.5, "severity_origin": "feed-vt-metadata",
    "package_observed": "openssl-3.0.11-1~deb12u1.amd64",
    "package_fixed":    "openssl-3.0.11-1~deb12u2.amd64", "specifier": ">=",
    "product": "Debian 12",
    "evidence": { "source": "dpkg", "matched_advisory": "debian_12.notus" },  // rastreável (§9)
    "detected_at": "..."
  }]
}
```
**Não-fabricação:** todo achado referencia um pacote concreto coletado + a advisory/OID que casou.
Sem evidência ⇒ o achado não existe.

---

## 7. Dados coletados (LGPD / minimização — vira `docs/data-inventory.md` na Fase 0)

**Coletamos (somente o necessário para correlação):** nome+versão+arch de pacotes/apps; distro/release/
arch/kernel do SO; portas em escuta **locais** e serviços; identidade do agente (machine-id derivado),
versão do agente. Tudo assinado/hasheado na origem.

**NÃO coletamos:** conteúdo de arquivos do usuário, histórico de navegação, credenciais, teclas,
telemetria comportamental, dados pessoais. Finalidade única: gestão de vulnerabilidade.

---

## 8. Riscos

| # | Risco | Sev | Mitigação |
|---|---|---|---|
| R1 | **Notus só cobre Linux** (rpm/deb). Windows/macOS sem advisory → tentação de fabricar achado | Alta | Decisão D1: correlação Linux/Notus na v1; Win/mac atrás da interface, fonte adequada depois. Nunca inferir sem dado |
| R2 | **Comparação de versão rpm/deb é sutil** (epoch, `~`, distro-specific) → falso pos/neg | Alta | Reusar semântica testada (libapt/librpm; parsers do ecossistema Trivy) + vetores de teste. Errar aqui viola não-fabricação |
| R3 | **Churn do scanner (ospd → openvasd/REST)** dentro do ciclo da v1 | Média | Interface `ResultSink` (B1 agora, openvasd depois) — landing trocável sem reescrever o agente |
| R4 | **OID → CVE/severity** depende da metadata de VT do gvmd (ver §11) | Média | Carregar severity no report (da nossa correlação) **e** o OID; validar enriquecimento do gvmd na Fase 2 |
| R5 | **Segurança do bootstrap token** (replay, rogue enroll, confused-deputy multi-tenant) | Alta | Token assinado, TTL curto, uso único/cap, scoped, revogável; CSR (PoP); download sem segredo em URL; recusa server-side de escopo (ver ADR-0002 §enrollment e §6.A do brief) |
| R6 | **Supply chain do auto-update** | Alta | Update assinado + verificado antes de aplicar + rollback por health; canal controlado pelo control plane |
| R7 | **Least privilege da coleta** (ler DB de pacotes, registro) | Média | Conta de serviço dedicada; elevar só onde a coleta exige; documentar privilégio e porquê |
| R8 | **Feed obsoleto** → correlação obsoleta | Baixa | Checagem de frescor do feed (reusa o feed-updater já existente) |
| R9 | **Mono-repo grande** (agente Go + stack GVM no mesmo repo) | Baixa | `agent/` isolado; CI separada; ver §10 (pode virar Decisão de estrutura) |

---

## 9. Plano de fases (per §12, refinado com os fatos verificados)

- **Fase 0 — Fundações:** este `PLAN.md`; ADRs A/B/C/D; scaffold do monorepo (§10); schema do
  inventário/achado versionado; CI com matriz Win/Linux/macOS; `data-inventory.md`.
- **Fase 1 — Núcleo + Linux:** agent core (Go); enrollment mTLS **consumindo bootstrap token**;
  geração/validação/revogação de tokens no control plane; coleta normalizada Linux (parse robusto de
  `dpkg status` + rpmdb, `/etc/os-release`); fila offline; push p/ ingest (stub). Testes verdes + build.
- **Fase 2 — Correlação + Bridge + Distribuição web:** correlation engine Notus-based (server-side,
  atrás de interface); **gmp-bridge** (`create_container_task` + `import_report`) → primeiro fluxo
  ponta-a-ponta visível na GSA; download do agente pela UI (bundle de enrollment, download autenticado,
  lista+revogação de tokens). **Antes de codar o bridge: reconfirmar o DTD exato do `<result>` e o
  caminho OID→CVE/severity (§11).**
- **Fase 3 — Windows + macOS:** coleta (registro Uninstall 32/64-bit, `pkgutil`/Info.plist/Homebrew) +
  integração de serviço (SCM, launchd); paridade de schema; cross-compile no CI. **Correlação Win/mac
  conforme Decisão D.**
- **Fase 4 — Hardening + Update + Packaging:** auto-update assinado + rollback; kill switch; pacotes
  (.deb/.rpm, .pkg **notarizado**, MSI **Authenticode**); least-privilege revisado.
- **Fase 5 — Observabilidade + Docs + e2e:** logs estruturados (JSON); health; runbooks
  deploy/enroll/uninstall; e2e por plataforma.

---

## 10. Estrutura do repo (encaixe no `suricatoos-infra` existente)

Repo atual: `compose/ hardening/ patches/ assets/ .github/ *.md` (stack GVM). Proposto adicionar:
```
agent/                  # Suricatoos Agent (Go) — cmd/, internal/{enroll,inventory{linux,darwin,windows},transport,service,update}, schema/
control-plane/          # orquestração, enrollment, policy/escopo — tokens/, distribution/
ingest/                 # data plane (recebe inventários/resultados)
correlation/            # engine Notus-based (interface plugável)
gmp-bridge/             # converte + importa no gvmd (python-gvm)
packaging/              # .deb/.rpm, .pkg notarizado, MSI/Authenticode
docs/                   # adr/, data-inventory.md, PLAN.md (este), runbooks
```
**Questão de estrutura (R9):** manter no mesmo repo (mono-repo, como pede o brief §10) **ou** repo
separado `suricatoos-agent`? Recomendo **mono-repo** com `agent/` isolado e CI própria. (Confirmar.)

---

## 11. A confirmar contra fonte oficial **antes da Fase 2** (per §13)

1. **DTD exato do `<result>`** aceito por `import_report` (campos host/port/nvt(oid)/threat/severity/
   qod/description e obrigatoriedade) — confirmar no gvmd GMP schema da 22.x.
2. **OID → CVE/severity:** confirmar se o gvmd **enriquece** os resultados importados (CVE/CVSS a
   partir do OID na metadata de VT do feed) ou se o report precisa carregar severity. Plano atual:
   carregar ambos (defensivo).
3. **Semântica de comparação de versão** rpm vs deb (epoch/tilde) — fixar a lib e os vetores de teste.
4. **openvasd como alvo futuro** do `ResultSink` (REST) — mapear o endpoint quando estabilizar.

> A pesquisa automatizada (5 agentes) bateu no **limite de sessão da conta** (reseta 4:10am
> America/Sao_Paulo); os fatos críticos acima foram verificados manualmente. As confirmações de §11
> são detalhes de implementação da Fase 2 e serão refeitas contra fonte oficial antes de codar o bridge.

---

## 12. Decisões que preciso que você confirme (antes da Fase 1)

| Decisão | Recomendação | Resumo |
|---|---|---|
| **A** | **A1** | Correlação baseada em pacote (Notus), passiva/local |
| **B** | **B1** | Bridge GMP `import_report`/container task, atrás de interface `ResultSink` (openvasd depois) |
| **C** | **C1** | Agente em Go; gmp-bridge em Python (`python-gvm`) |
| **D** | **D1** | v1 correlaciona Linux/Notus; Win/mac coletam e correlacionam depois (sem fabricar) |
| Estrutura | Mono-repo | `agent/` isolado no `suricatoos-infra`, CI própria |

Confirmadas (ou ajustadas), inicio a **Fase 0** (scaffold + schema + CI + ADRs finais) e só então a Fase 1.
