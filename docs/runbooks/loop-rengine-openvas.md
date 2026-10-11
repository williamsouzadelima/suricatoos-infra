# Runbook — Loop reNgine (score) → OpenVAS (scanner)

Operar a integração que faz o **reNgine** (`score.suricatoos.com`, `.124`) entregar
hosts/portas descobertos ao **GSA/OpenVAS** (`scanner.suricatoos.com`, `.97`), que
lança um scan real e devolve os achados. Ver [ADR-0006](../adr/0006-loop-rengine-openvas.md).

## TL;DR

- O scanner é **autoritativo e default-deny**: nada é escaneado enquanto
  `SCAN_HOST_ALLOWLIST` estiver vazia — mesmo com `SCAN_LAUNCH_ENABLED=true`.
- Só um cert mTLS com **`O=score-hub` e `OU=scan-requester`** (emitido pelo enroll do
  control-plane) alcança `POST /ingest/v1/scan-request`.
- Scans rodam como o usuário gvmd **`suricatoos-scan`** (role=User, NÃO admin); o admin
  os enxerga na GSA via uma permissão `Super`.
- **Kill switch** (do mais rápido ao mais forte): (1) reNgine `SURICATOOS_SCANNER_PUSH_ENABLED=False`;
  (2) ingest `SCAN_LAUNCH_ENABLED=false`; (3) `DELETE /ingest/v1/scan-request/{id}`;
  (4) revogar o token `score-hub` no control-plane (CRL passa a negar); (5) `SCAN_MAX_DURATION`.

## Config no gvmd (uma vez) — usuário escopado + visibilidade do admin

No `.97`, dentro do container gvmd. Cria o usuário de baixo privilégio e dá ao admin
uma permissão `Super` para ver as tasks dele na GSA.

```sh
C=greenbone-community-edition-gvmd-1
# 1) cria o usuário escopado (role User); guarde a senha gerada
docker exec $C gvmd --create-user=suricatoos-scan --role=User
# 2) descubra os UUIDs
SCAN_UID=$(docker exec $C gvmd --get-users --verbose | awk '/^suricatoos-scan /{print $2}')
# 3) admin enxerga tudo do usuário escopado (Super sobre o user)
docker exec $C gvmd --user=admin --xml="<create_permission><name>Super</name>\
<resource id=\"$SCAN_UID\"><type>user</type></resource>\
<subject id=\"ADMIN_UID\"><type>user</type></subject></create_permission>"
```

Coloque a senha do usuário em `/var/lib/suricatoos-cp/ingest.env` como
`SCAN_GVM_PASSWORD=...` (o compose lê daí; nunca commite a senha).

## Mint do token + enroll do reNgine (P2)

```sh
# no .97: mint de um token com tenant/policy do launcher
curl -sk -X POST https://scanner.suricatoos.com/agent/api/v1/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -d '{"tenant":"score-hub","policy":"scan-requester"}'    # → bundle de enroll (YAML)
# no .124: gera chave+CSR, enrola, grava secrets/score-hub.{crt,key,ca.crt}
python manage.py openvas_enroll
```

O CN pode rotacionar; a **posse** é keyed no `O` (tenant), então renovar o cert não
órfã jobs em andamento. Renovação: revogue o token antigo, re-enrole (CN novo); a CRL
+ TTL curto garantem que o cert antigo pare de funcionar.

## Habilitar (P3, canário)

```sh
# 1) adicione UM /32 nosso e autorizado ao allowlist (env do ingest)
#    SCAN_HOST_ALLOWLIST=203.0.113.10/32
# 2) habilite o launch
#    SCAN_LAUNCH_ENABLED=true
# 3) recrie só o ingest (não derruba gvmd/proxy)
docker compose up -d --no-deps ingest
```

Dispare um scan pelo reNgine e acompanhe: `docker logs -f greenbone-community-edition-ingest-1`
(linhas `scanlaunch:`), a task `suricatoos-rengine-{id}-{12 primeiros caracteres do request_id}`
na GSA (um nome por pedido, mais `-a{N}` a partir da 2ª tentativa — ver "Re-envio"; jobs
lançados antes disso seguem com `suricatoos-rengine-{id}`), e as `Vulnerability`
`source=openvas` no reNgine.

## Estados finais do job (o que o `GET` devolve em `state`/`error`)

Um scan só vira `COMPLETED` quando o relatório mostra que algo foi medido. Um "Done" vazio
nunca é apresentado como host limpo.

| `state` | `error` | Significado / o que fazer |
|---|---|---|
| `COMPLETED` | — | Done com host(s) medido(s). `findings` vazio = host medido sem achado (resultado legítimo). |
| `FAILED` | `scan não mediu nenhum host vivo (verifique alive test/alcance)` | Done com **0 hosts** no relatório: o alive test não achou host vivo ou o alvo é inalcançável a partir do scanner. **Não** é atestado de host limpo. Confira `SCAN_ALIVE_TEST` e o caminho de rede; o re-envio faz **scan novo** (task nova). |
| `FAILED` | `task Done sem relatório` | A task terminou sem relatório no gvmd (ex.: relatório apagado na GSA). O re-envio faz **scan novo**. |
| `FAILED` | `task Done, mas o relatório não foi obtido após N tentativa(s): …` | O scan terminou, mas buscar (ou cachear) o relatório falhou `SCAN_FETCH_RETRY_LIMIT` vezes seguidas (padrão 20 ≈ 10 min no tick de 30 s; mais se cada tentativa estourar o timeout de 5 min). O re-envio **re-lê** o relatório pronto da mesma task, sem novo scan. |
| `FAILED` | `scan Interrupted` / `scan Failed` | O gvmd interrompeu o scan (ou a task sumiu). O re-envio reinicia a mesma task. |
| `EXPIRED` | `scan ainda em execução além do limite de duração (SCAN_MAX_DURATION=…) — parado` | Passou do teto e foi parado no gvmd. |
| `EXPIRED` | `sem status do gvmd além do limite de duração (SCAN_MAX_DURATION=…, N falhas seguidas): …` | Passou do teto e o gvmd não respondeu ao `status` em **3 ticks seguidos** (≈1,5 min; qualquer status OK zera a contagem). O stop é best effort: com o gvmd fora, a task pode seguir rodando lá — confira na GSA. |
| `STOPPED` | — | Parado por `DELETE`. |

Um Done é buscado mesmo depois do `SCAN_MAX_DURATION`: o teto não descarta relatório pronto.

### Re-envio (retry)

Re-enviar o **mesmo** `rengine_scan_history_id` de um job `FAILED`/`STOPPED`/`EXPIRED` reabre o
mesmo job (mesmo `request_id`, volta a `PENDING`). Jobs `PENDING`/`RUNNING`/`COMPLETED` voltam
como estão (replay idempotente).

- Falhas "não mediu nada" (as duas primeiras linhas `FAILED` acima): o job passa para a próxima
  tentativa — target e task **novos** no gvmd (`…-a1`, `…-a2`), com o `SCAN_ALIVE_TEST` atual.
  Sem isso, o relançamento reencontraria a task Done e re-leria o mesmo relatório vazio.
- Demais falhas: relança na **mesma** task (sem scan duplo após um erro de launch; relatório
  pronto re-lido após o limite de fetch; task interrompida/parada é reiniciada).
- Um job parado por `DELETE` e re-enviado é lançado de novo (a marca de stop não passa adiante).
- Depois que o job terminal é expurgado (`SCAN_RESULT_RETENTION`, 48 h), o re-envio cria um job
  novo, com `request_id` e task novos — nunca reaproveita a task Done antiga.

### Ajustes

| Env (ingest) | Padrão | Efeito |
|---|---|---|
| `SCAN_MAX_DURATION` | `6h` | Teto de execução; além dele o scan é parado (`EXPIRED`). |
| `SCAN_FETCH_RETRY_LIMIT` | `20` (1–1000) | Tentativas de buscar/cachear o relatório de uma task Done antes de `FAILED`. |

A tolerância de 3 falhas seguidas de `status` além do teto é fixa no código
(`StatusFailuresToExpire`).

## Verificações

| Cenário | Esperado |
|---|---|
| `POST /ingest/v1/scan-request` sem cert | `403` (nginx) |
| Com cert válido, `SCAN_LAUNCH_ENABLED=false` | `503` |
| Host = hostname / IP fora da allowlist / metadata / RFC1918 / caixa irmã | `422` |
| Cert de agente comum (mesma CA, `OU=agent`) | `403` (DN não bate O/OU) |
| Serial revogado (após revoke no control-plane) | `403` (CRL) |
| `GET` de `request_id` de outro tenant | `404` (sem enumeração) |

## Rollback

- **Flag primeiro** (instantâneo, sem redeploy): `SCAN_LAUNCH_ENABLED=false` ou
  `SURICATOOS_SCANNER_PUSH_ENABLED=False`.
- **Imagem**: **esvazie antes** — `SCAN_MAX_CONCURRENT=0` (pausa lançamentos; recrie o ingest)
  e espere os jobs `RUNNING` terminarem, ou dê `DELETE` neles. A imagem anterior não conhece o
  nome de task por pedido: um scan em voo lançado pela versão nova viraria `FAILED scan
  Interrupted` com a task seguindo órfã no gvmd, fora do limite de concorrência. Depois:
  `docker tag ...suricatoos-ingest:stable-prev ...:stable` + `up -d --no-deps ingest`.
  (O deploy para a frente é seguro com jobs em voo: o bridge novo acha a task legada
  `suricatoos-rengine-{id}` pelo `gvm_task_id` do job.)
- **nginx**: restaure a conf boa, `docker compose exec nginx nginx -t`, `up -d --no-deps nginx`.
- **Schema reNgine** é aditivo (`ScanBridgeJob` + `Domain.send_to_scanner`); nada a reverter.

## Gotchas

- Imagens GHCR são privadas → build local + `docker save | ssh scanner docker load` (não `pull`).
- Recrie **só** o `ingest`/`nginx` com `--no-deps` para não reiniciar o gvmd nem o proxy.
- A allowlist é o freio real: deixá-la vazia é seguro por padrão. Um scan ativo contra um
  IP que não é nosso/autorizado é abuso — só adicione /32 de hosts com autorização explícita.
