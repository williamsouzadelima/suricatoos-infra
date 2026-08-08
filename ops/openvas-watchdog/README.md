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

Medido em produção: a latência do `stop_sniffer_thread` cresce com a concorrência —
`0s, 0s, 7s, ∞, ∞` na ordem em que 5 scans terminaram de enviar pings.

O `gvm-libs` 23.9.0 **já tem** a espera limitada (400 × `usleep 5ms`) e o
`pthread_cancel` antes do join, e trava mesmo assim. Não há issue upstream aberta com
este sintoma nem versão que corrija — daí o watchdog externo.

## Por que o ospd não detecta

O laço de `ospd_openvas/daemon.py` (`exec_scan`) só sai por três condições:
`target_is_finished`, processo morto, ou stop pedido pelo cliente. **Não existe
critério de "sem progresso há N minutos".** Um `openvas` vivo porém travado é
literalmente invisível — num incidente real ficou 21 h reportando "Running" com
progresso congelado.

## O discriminador (medido, não suposto)

Não usar "tempo desde o último fork": um scan **saudável** passou **1h43m** sem forkar
porque um único host levou 7.001 s. Esse critério mataria scan bom.

O que separa *travado* de *lento* é a **contagem de descendentes**:

| | janela com ZERO filhos |
|---|---|
| scan saudável | ~1 segundo |
| scan travado | ~21 horas |

O watchdog exige as condições **simultâneas**, por `MIN_OBS` passagens consecutivas:

1. o `gvmd` considera a task `Running`
2. o processo `openvas` principal tem **zero** filhos
3. a CPU (`utime+stime`) **não** avançou desde a passagem anterior

Limiares: alerta em 20 min, `SIGKILL` em 60 min, mínimo de 3 observações, no máximo
uma morte por passada.

## Como mata

`SIGKILL` **apenas no PID principal**, nunca no process group: o `ospd` faz
`os.setsid()` no handler do scan, e o grupo inclui o processo que roda o post-mortem.
Matando só o `openvas`, o `ospd` detecta `not openvas_process_is_alive`, libera as KBs
do Redis e marca a task como **Interrupted** (retomável) — bem melhor que recriar o
container, que mata todos os scans e deixa KB órfã.

## Instalação

```bash
install -m 755 openvas-watchdog.py /usr/local/bin/openvas-watchdog.py
install -m 644 openvas-watchdog.service /etc/systemd/system/
install -m 644 openvas-watchdog.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now openvas-watchdog.timer
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

Com nenhum scan rodando, o script sai em 0 sem escrever nada.
