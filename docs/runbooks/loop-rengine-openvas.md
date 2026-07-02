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
(linhas `scanlaunch:`), a task `suricatoos-rengine-{id}` na GSA, e as `Vulnerability`
`source=openvas` no reNgine.

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
- **Imagem**: `docker tag ...suricatoos-ingest:stable-prev ...:stable` + `up -d --no-deps ingest`.
- **nginx**: restaure a conf boa, `docker compose exec nginx nginx -t`, `up -d --no-deps nginx`.
- **Schema reNgine** é aditivo (`ScanBridgeJob` + `Domain.send_to_scanner`); nada a reverter.

## Gotchas

- Imagens GHCR são privadas → build local + `docker save | ssh scanner docker load` (não `pull`).
- Recrie **só** o `ingest`/`nginx` com `--no-deps` para não reiniciar o gvmd nem o proxy.
- A allowlist é o freio real: deixá-la vazia é seguro por padrão. Um scan ativo contra um
  IP que não é nosso/autorizado é abuso — só adicione /32 de hosts com autorização explícita.
