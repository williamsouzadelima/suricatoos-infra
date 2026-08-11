# Runbook — Controle de admissão do ospd + watchdog de scan travado

Fecha **três** modos de falha em que scans morrem sem erro visível. Nenhum tem issue
upstream aberta; nenhum upgrade resolve.

| # | Falha | Perna |
|---|---|---|
| 1 | vários scans partindo juntos matam o `ospd` e levam todos | flags no `command` |
| 2 | `openvas` trava mudo (deadlock no Boreas) e o `ospd` não detecta | watchdog |
| 3 | rota de API cacheada como HTML pelo navegador | `no-store` no nginx |

As três são independentes: dá para aplicar em qualquer ordem. Quem aplicar por
`git pull && docker compose up -d` recebe **só a perna 1** — o nginx e o watchdog
exigem passo próprio, sem erro e sem aviso.

## 0. Pré-requisitos

- Nenhum scan rodando (a perna 1 recria o `ospd-openvas`):

```sh
docker exec <pg-container> psql -U gvmd -d gvmd -tAc \
  "SELECT count(*) FROM tasks WHERE run_status=4;"     # tem que dar 0
ps -eo args | grep -c '[o]penvas --scan-start'          # tem que dar 0
```

- Descubra os nomes reais — **variam por deploy** (o projeto compose muda o prefixo):

```sh
docker ps --format '{{.Names}}' | grep -E 'ospd-openvas|pg-gvm|nginx'
```

- Se houver protocolo de coordenação no host (`soos-claim`), reivindique antes:
  `soos-claim take <projeto> "motivo"` e libere ao terminar.

---

## 1. Controle de admissão do ospd

**Raiz.** Cada `exec_scan` varre os índices 1..1024 do Redis **abrindo conexão nova
por índice** — ~2.048 comandos `KEYS` bloqueantes por scan. Com vários scans partindo
no mesmo segundo, o tempo agregado ultrapassa o `SOCKET_TIMEOUT = 60` **cravado** em
`ospd_openvas/db.py:21` (não é env, não é conf, não é CLI). O laço principal
(`run` → `scheduler` → `check_feed` → `LINDEX`) estoura junto, e `run()` só captura
`KeyboardInterrupt`: **o daemon morre e leva todos os scans**. No restart vira
crash-loop, porque `create_context` captura `(ConnectionError, FileNotFoundError)` e
`TimeoutError` **não** é subclasse de `ConnectionError`.

**Por que `--min-free-mem-scan-queue` e não só `--max-scans`.** O nome engana: além do
teto de memória, ele ativa o `MIN_TIME_BETWEEN_START_SCAN = 60s` (`ospd.py:1182-1191`)
— no máximo um scan parte por minuto, e as varreduras nunca se sobrepõem. E
`is_enough_free_memory()` lê relógio e memória livre real, **não**
`len(scan_processes)`; logo não existe slot preso por scan travado (*fail-open*).
`--max-scans` sozinho tem esse defeito: o dict só perde entrada em `delete_scan()`.

Vale também quando o disparo vem da **interface web** — é controle no daemon, não no
script de quem dispara.

Acrescente ao serviço `ospd-openvas` (no override do host, se houver):

```yaml
  ospd-openvas:
    pids_limit: 2048
    command:
      [
        "ospd-openvas", "-f",
        "--config", "/etc/gvm/ospd-openvas.conf",
        "--notus-feed-dir", "/var/lib/notus/advisories",
        "-m", "666",
        "--min-free-mem-scan-queue", "1024",
        "--max-scans", "2",
        "--scaninfo-store-time", "1",
      ]
```

⚠️ **O array `command` REPETE os argumentos do `compose.yaml`.** Se faltar um, o
override quebra o serviço. Confira token a token contra o base antes de aplicar.

⚠️ **NÃO editar `/etc/gvm/ospd-openvas.conf` dentro do container** — `/etc/gvm` não
tem volume, então a edição some no próximo `pull`/`up`. O array `command` tem
precedência sobre o `.conf`.

**`--min-free-mem-scan-queue 1024`** avalia memória livre do **host**, não do
container. Num host apertado esse limiar **bloquearia** scans em vez de espaçá-los —
confira `MemAvailable` antes:
`awk '/MemAvailable/{printf "%d MB\n", $2/1024}' /proc/meminfo`.

**`--scaninfo-store-time 1`** liga `clean_forgotten_scans()`, a única perna que devolve
o slot sem depender do gvmd nem do watchdog. Obrigatório se usar `--max-scans`.

**`pids_limit`**: sem ele o container herda o `DefaultTasksMax` do systemd. Fórmula:
`4 × max_scans × (1 + max_hosts × (1 + max_checks)) + 32`. Com `--max-scans 2`,
`max_hosts=20` e `max_checks=4` dá 840; 2048 deixa folga para subir `--max-scans` até 5
sem novo deploy. **Não** usar valores enormes: num host modesto isso fica acima do muro
de memória e troca um `EAGAIN` limpo por *swap-thrash* do host inteiro.

Aplicar e conferir:

```sh
docker compose config --quiet                          # valida antes
docker logs <ospd-container> > /tmp/ospd-pre-fix.log 2>&1   # preserva a evidência
docker compose up -d --force-recreate --no-deps ospd-openvas

docker inspect <ospd-container> --format '{{json .Config.Cmd}}'   # as 3 flags
docker inspect <ospd-container> --format '{{.HostConfig.PidsLimit}}'
```

Espere os VTs carregarem antes de disparar qualquer coisa:

```sh
docker logs <ospd-container> 2>&1 | grep -E 'Finished loading VTs|VTs were up to date'
```

**Convivência com o `scanlaunch`** (`ingest/scanlaunch/config.go`): mantenha
`SCAN_MAX_CONCURRENT` ≤ `--max-scans`. E reavalie `SCAN_MAX_DURATION` — com a fila
ligada, o tempo parado em `Queued` conta contra ele, criando risco de auto-stop num
scan que nem começou.

---

## 2. Watchdog de scan travado

**Raiz.** `stop_sniffer_thread()` do Boreas bloqueia para sempre em `pthread_join()`
quando o `pcap_breakloop()` não acorda o `poll()` pendente. Sem ele,
`put_finish_signal_on_queue` nunca roda e a thread principal fica presa em
`fork_sleep(1)`. O `gvm-libs` 23.9.0 **já tem** a espera limitada e o `pthread_cancel`,
e trava mesmo assim.

O `ospd` não detecta: seu laço não tem critério de "sem progresso há N minutos".

```sh
install -m 755 hardening/openvas-watchdog/openvas-watchdog.py /usr/local/bin/
install -m 644 hardening/openvas-watchdog/openvas-watchdog.{service,timer} /etc/systemd/system/

# OBRIGATÓRIO se o projeto compose não for o default:
echo 'PG_CONTAINER=<nome-real-do-pg>' > /etc/default/openvas-watchdog

systemctl daemon-reload && systemctl enable --now openvas-watchdog.timer
```

⚠️ **O default de `PG_CONTAINER` aponta para um projeto compose específico.** Se o seu
diferir e você não criar o `/etc/default/openvas-watchdog`, o watchdog fica **mudo com
o timer verde** — a consulta falha, o script sai em 0 e o systemd marca SUCCESS para
sempre. Rode o smoke test do `hardening/openvas-watchdog/README.md`.

---

## 3. `no-store` nas rotas de API do nginx

**Raiz.** Enquanto uma rota de API não existe, o catch-all da SPA devolve `index.html`
**com `ETag`/`Last-Modified` e sem `Cache-Control`**. O navegador grava esse HTML como
se fosse a resposta do endpoint JSON e continua servindo do cache mesmo depois da rota
passar a funcionar — `JSON.parse` quebra para sempre.

**O sintoma que denuncia:** o log do nginx **não registra requisição nenhuma** daquele
navegador. Se `curl` devolve JSON e o navegador insiste no erro, procure a **ausência**
de linhas no log, não a presença de erro. (`curl` não tem cache; por isso os testes de
servidor passam enquanto o usuário continua vendo o erro.)

⚠️ **Gotcha do `add_header`:** ele **não é herdado** quando a location declara o seu
próprio — as locations que ganharem `Cache-Control` param de receber os headers de
segurança do nível server (`include conf.d/headers.conf`). Por isso cada bloco
re-inclui o `headers.conf` **antes** do `add_header`. O `always` também é obrigatório,
senão o header não sai nas respostas `401`/`403`/`429`.

⚠️ **Gotcha do volume:** `nginx_config_vol` é montado **depois** do bind-mount do
`default.conf`, então o volume vence:

```sh
VOL=/var/lib/docker/volumes/<projeto>_nginx_config_vol/_data
cp compose/nginx/default.conf "$VOL/default.conf"
docker compose exec nginx nginx -t
docker compose exec nginx nginx -s reload      # reload, não restart
```

Verificar:

```sh
curl -skI https://127.0.0.1/agents/data.json | grep -iE 'cache-control|strict-transport'
# esperado: Cache-Control: no-store  E  os headers de segurança presentes
```

A entrada já envenenada no navegador **não** é reparada pelo `no-store` — só limpando
o cache uma vez (Safari: `Cmd+Option+E`).

---

## Rollback

```sh
# 1) ospd: restaure o compose anterior e recrie
cp <override>.bak <override>
docker compose up -d --force-recreate --no-deps ospd-openvas

# 2) watchdog: puramente aditivo, basta desligar
systemctl disable --now openvas-watchdog.timer

# 3) nginx: restaure o default.conf anterior no VOLUME, nginx -t, nginx -s reload
```

Nenhuma das três toca em dado: não há migração de schema, nem alteração de volume de
feed, nem mudança em relatório.

## Verificação final

```sh
docker inspect <ospd-container> --format '{{.RestartCount}}'        # 0
docker logs <ospd-container> 2>&1 | grep -c TimeoutError            # 0
systemctl is-active openvas-watchdog.timer                          # active
```

Com scans disparados, o esperado é ver `Currently N queued scans` no log do `ospd` e as
partidas espaçadas em ~60s — não todas no mesmo segundo.
