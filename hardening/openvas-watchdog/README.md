# openvas-watchdog

Detecta e mata scans do `openvas` que travaram **mudos** — processo vivo, 0% de CPU,
nenhum filho, progresso congelado — e que o `ospd-openvas` **não** detecta.

## O bug que isso cobre

O Boreas (fase de *alive detection*) sobe uma thread `pcap` para farejar as respostas
dos pings. Ao terminar de enviar, chama `stop_sniffer_thread()`, que faz
`pcap_breakloop()` seguido de **`pthread_join()` sem timeout**. Se nesse instante não
chega mais nenhum pacote no ring do pcap, o `poll()` pendente não acorda e o join
bloqueia para sempre. Sem ele, `put_finish_signal_on_queue` nunca roda e a thread
principal do `openvas` fica presa em `attack.c`:

```c
for (host = get_host_from_queue(...); !host && !ad_finished; )
    fork_sleep(1);
```

A condição de corrida depende do tráfego: se nenhum pacote que case com o filtro BPF
chega ao ring do pcap no instante do `pcap_breakloop()`, o `poll()` pendente não acorda
e o join bloqueia. Sob concorrência a janela fica mais fácil de acertar, porque os scans
terminam a fase de ping em momentos diferentes.

O `gvm-libs` 23.9.0 **já tem** a espera limitada (400 × `usleep 5ms`) e o
`pthread_cancel` antes do join, e trava mesmo assim. Não há issue upstream aberta com
este sintoma nem versão que corrija — daí o watchdog externo.

## Por que o ospd não detecta

O laço de `ospd_openvas/daemon.py` (`exec_scan`) só sai por três condições:
`target_is_finished`, processo morto, ou stop pedido pelo cliente. **Não existe
critério de "sem progresso há N minutos".** Um `openvas` vivo porém travado é
literalmente invisível para o ospd: continua reportando `Running` com o progresso
congelado, indefinidamente, até alguém intervir.

## O discriminador

Não usar "tempo desde o último fork": na cauda de um scan a fila de hosts drena e sobram
poucos alvos lentos, então um único host demorado mantém o scan sem forkar por horas sem
que ele esteja travado. Esse critério mataria scan bom.

O que separa *travado* de *lento* é a **contagem de descendentes**: num scan saudável a
janela com zero filhos se fecha em segundos — o último filho sai e o scan encerra em
seguida. Num scan travado ela não termina.

O watchdog exige as condições **simultâneas**, por `MIN_OBS` passagens consecutivas:

1. o `gvmd` considera a task `Running`
2. o processo `openvas` principal tem **zero** filhos
3. a CPU (`utime+stime`) **não** avançou desde a passagem anterior

Limiares (escolha de projeto, ajustáveis no topo do script): alerta em 20 min, `SIGKILL`
em 60 min, mínimo de 3 observações, no máximo uma morte por passada. O mínimo de 3
observações com o timer de 5 min garante ~15 min de corroboração antes de qualquer ação.


## Como mata

`SIGKILL` **apenas no PID principal**, nunca no process group: o `ospd` faz
`os.setsid()` no handler do scan, e o grupo inclui o processo que roda o post-mortem.
Matando só o `openvas`, o `ospd` detecta `not openvas_process_is_alive`, libera as KBs
do Redis e marca a task como **Interrupted** — bem melhor que recriar o container, que mata
todos os scans e deixa KB órfã.

Retomável pela GSA/gvmd. Atenção: para scans lançados pelo `scanlaunch`, `Interrupted`
é convertido em `FAILED` (`ingest/scanlaunch/reconciler.go`) e exige nova requisição.

## Instalação

```bash
install -m 755 openvas-watchdog.py /usr/local/bin/openvas-watchdog.py
install -m 644 openvas-watchdog.service /etc/systemd/system/
install -m 644 openvas-watchdog.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now openvas-watchdog.timer
```

Para sobrescrever os knobs, crie `/etc/default/openvas-watchdog` (lido pelo
`EnvironmentFile=-` do `.service`):

```bash
# confirme antes o nome real do container do Postgres
docker ps --format '{{.Names}}' | grep pg-gvm
echo 'PG_CONTAINER=<nome-real>' > /etc/default/openvas-watchdog
```

Configurável por ambiente (todos opcionais):

| Variável | Default |
|---|---|
| `WATCHDOG_STATE` | `/var/lib/openvas-watchdog/state.json` |
| `WATCHDOG_LOG` | `/var/log/openvas-watchdog.log` |
| `PG_CONTAINER` | `greenbone-community-edition-pg-gvm-1` |

## Verificar

```bash
systemctl list-timers openvas-watchdog.timer
tail -f /var/log/openvas-watchdog.log
```

Com nenhum scan rodando o script sai em 0 (grava apenas o `state.json` vazio).

**Smoke test obrigatório, com um scan rodando** — o modo de falha deste watchdog é ficar
mudo com o timer verde:

```bash
# 1) a consulta ao gvmd devolve pelo menos uma linha?
docker exec "$PG_CONTAINER" psql -U gvmd -d gvmd -tAc \
  "SELECT r.uuid FROM reports r JOIN tasks t ON t.id=r.task \
   WHERE t.run_status=4 AND COALESCE(r.end_time,0)=0;"

# 2) rodando a mao, ele enxerga o scan?
/usr/local/bin/openvas-watchdog.py
```

Se (1) vier vazio com scan ativo, o nome do container ou o enum `run_status` mudou —
ajuste via `/etc/default/openvas-watchdog`. Sem esse teste, uma falha de consulta faz o
script sair em 0 e o systemd marcar SUCCESS para sempre.
