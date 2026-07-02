# Suricatoos Agent — container "docker run e funciona"

Um único container que, ao subir, **se enrola sozinho no tenant** e passa a reportar a
postura de vulnerabilidade do **host** onde roda. Feito para o time distribuir sem
configuração manual: copiar o comando, colar, e funciona.

## Comando (copie, troque só o `ENROLL_TOKEN`)

```sh
docker run -d --name suricatoos-agent --restart unless-stopped \
  --hostname "$(hostname)" \
  -e ENROLL_TOKEN="<TOKEN_DO_TENANT>" \
  -e CLOUD_BASE_URL="https://scanner.suricatoos.com/agent/v1" \
  -e CA_PIN="sha256:efe73e7165a52279de68e990ed7af48670db1b21e1d43be3ba54047c61c57faa" \
  -e AGENT_ID="$(hostname)" \
  -v /:/host:ro \
  -v suricatoos-agent:/var/lib/suricatoos-agent \
  ghcr.io/williamsouzadelima/suricatoos-agent:stable
```

Pronto. O container:
1. **Enrola** no tenant no 1º boot (troca o `ENROLL_TOKEN` por um cert mTLS `O=<tenant>`).
2. **Inventaria o HOST** (não o container) via `-v /:/host:ro` + `HOST_ROOT=/host`.
3. **Faz push** do inventário → correlação server-side (Notus) → achados na GSA/Score.
4. **Persiste a identidade** no volume `suricatoos-agent` → um restart NÃO re-enrola
   (o token é de uso único).

## Como o time obtém o `ENROLL_TOKEN`

O token é **por-tenant** e mintado na nuvem (admin-bearer):

```sh
curl -sk -X POST https://scanner.suricatoos.com/agent/api/v1/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"type":"deployment","tenant":"<TENANT>","policy":"agent-endpoint","ttl_hours":72,"max_uses":100}'
```

- `type:"deployment"` + `max_uses` = **um token serve para N hosts** do mesmo tenant
  (o time cola o mesmo comando em várias máquinas). Use `single_host` para 1 host.
- O token é **revogável** (`DELETE /agent/api/v1/tokens/{id}`) e tem TTL — se vazar,
  revoga.

## Variáveis

| Env | Obrigatório | O quê |
|---|---|---|
| `ENROLL_TOKEN` | 1º boot | bootstrap token do tenant |
| `CLOUD_BASE_URL` | 1º boot | `https://scanner.suricatoos.com/agent/v1` |
| `CA_PIN` | recomendado | fingerprint da CA de enroll (pin out-of-band contra MITM) |
| `AGENT_ID` | recomendado | id estável do host (senão usa o hostname do container, efêmero) |
| `COLLECT_INTERVAL` | opcional | ex.: `15m` (default) |
| `AGENT_STATE_DIR` | opcional | default `/var/lib/suricatoos-agent` |

## Notas

- **Imagem privada (GHCR):** a máquina precisa `docker login ghcr.io` (ou torne a
  imagem pública no GHCR se for distribuir amplamente — o binário do agente não
  contém segredos). Sem login/pública, o `docker run` falha no pull.
- **Só-leitura no host:** o mount é `:ro` — o agente é passivo, nunca escreve no host.
- **O que coleta:** distro/release + pacotes (dpkg/rpm) + portas locais em escuta.
  Nada de conteúdo de arquivo, credencial ou telemetria (ver `docs/data-inventory.md`).
- **compose** (equivalente, se preferir): as mesmas envs num `environment:` + os 2
  volumes, `image: ghcr.io/williamsouzadelima/suricatoos-agent:stable`.
