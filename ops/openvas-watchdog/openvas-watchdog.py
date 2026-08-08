#!/usr/bin/env python3
"""
Watchdog de scan openvas travado (Greenbone CE / ospd-openvas).

CONTEXTO: o Boreas (alive detection) pode bloquear para sempre em
stop_sniffer_thread() -> pthread_join(), quando o pcap_breakloop nao acorda o
poll() pendente. Resultado: o processo `openvas --scan-start <uuid>` fica VIVO,
com 0% de CPU e ZERO filhos, e o ospd-openvas NAO detecta (o laco dele so sai
por scan terminado / processo morto / stop do cliente). Observado em producao:
~21 h de "Running" mentiroso antes de alguem perceber.

DISCRIMINADOR (medido, nao suposto):
  - scan SAUDAVEL: a janela com ZERO filhos durou ~1 segundo (o ultimo host
    terminou 20h46.25 e o scan terminou 20h46.26).
  - scan TRAVADO: ZERO filhos por ~21 horas, com CPU parada.
  NAO usar "tempo desde o ultimo fork": um scan saudavel passou 1h43m sem
  forkar (um unico host levou 7.001 s) — esse criterio mataria scan bom.

Exige as condicoes SIMULTANEAS, por MIN_OBS passagens consecutivas:
  1. o gvmd considera a task Running
  2. o processo openvas principal tem ZERO filhos
  3. a CPU (utime+stime) NAO avancou desde a passagem anterior

SIMPLIFICACAO DELIBERADA vs. o desenho original: nao le o openvas.log (12,8 GB,
taxa de 1,3 a 33 MB/min). O estado "congelado desde" e mantido em disco, o que
elimina a leitura do log, o rastreio de offset/inode e a classe inteira de erro
de "lacuna de leitura". Mesma deteccao, custo ~0.

MATA com SIGKILL apenas no PID principal, NUNCA no process group: o ospd faz
os.setsid() no handler do scan, e o grupo inclui o processo que roda o
post-mortem. Matando so o openvas, o ospd detecta 'not openvas_process_is_alive',
libera as KBs do redis e marca a task como Interrupted (retomavel).
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

STATE_FILE = os.environ.get("WATCHDOG_STATE", "/var/lib/openvas-watchdog/state.json")
LOG_FILE = os.environ.get("WATCHDOG_LOG", "/var/log/openvas-watchdog.log")
PG = os.environ.get("PG_CONTAINER", "greenbone-community-edition-pg-gvm-1")

ALERT_S = 20 * 60      # 20 min congelado -> alerta
KILL_S = 60 * 60       # 60 min congelado -> SIGKILL
MIN_OBS = 3            # observacoes consecutivas antes de qualquer acao
MAX_KILLS_PER_PASS = 1 # nunca matar dois scans na mesma passada


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} UTC | {msg}"
    print(line)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as fh:
            fh.write(line + "\n")
    except OSError as e:
        print(f"(nao consegui escrever em {LOG_FILE}: {e})")


def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, STATE_FILE)


def running_scan_uuids():
    """UUIDs dos reports cujas tasks o gvmd considera Running (run_status=4)."""
    try:
        out = subprocess.run(
            ["docker", "exec", PG, "psql", "-U", "gvmd", "-d", "gvmd", "-tAc",
             "SELECT r.uuid FROM reports r JOIN tasks t ON t.id=r.task "
             "WHERE t.run_status=4;"],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    except (subprocess.SubprocessError, OSError) as e:
        log(f"ERRO: nao consegui consultar o gvmd ({e}) — abortando a passada")
        return None
    if out.returncode != 0:
        log(f"ERRO: psql saiu {out.returncode}: {out.stderr.strip()[:200]}")
        return None
    return {u.strip() for u in out.stdout.split("\n") if u.strip()}


def openvas_procs():
    """{uuid: pid} dos processos `openvas --scan-start <uuid>` vivos no host."""
    procs = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        m = re.search(r"openvas\s+--scan-start\s+([0-9a-f-]{36})", cmd)
        if m:
            procs[m.group(1)] = int(pid)
    return procs


def child_count(pid):
    """Numero de filhos diretos. -1 se nao deu para ler."""
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as fh:
            return len(fh.read().split())
    except OSError:
        return -1


def cpu_ticks(pid):
    """utime+stime em ticks. None se nao deu para ler."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            parts = fh.read().rsplit(") ", 1)[1].split()
        return int(parts[11]) + int(parts[12])   # utime, stime
    except (OSError, IndexError, ValueError):
        return None


def main():
    now = time.time()
    state = load_state()
    running = running_scan_uuids()
    if running is None:
        sys.exit(0)                       # falha ao consultar: nao age

    procs = openvas_procs()
    kills = 0
    new_state = {}

    for uuid in sorted(running):
        pid = procs.get(uuid)
        if pid is None:
            log(f"{uuid[:8]}: gvmd diz Running mas nao ha processo openvas "
                f"(ospd deve reconciliar; watchdog nao age)")
            continue

        kids = child_count(pid)
        ticks = cpu_ticks(pid)
        if kids < 0 or ticks is None:
            log(f"{uuid[:8]}: nao consegui ler /proc/{pid} — ignorando a passada")
            continue

        prev = state.get(uuid, {})
        cpu_parado = (prev.get("ticks") == ticks)
        congelado = (kids == 0 and cpu_parado)

        if not congelado:
            if prev.get("desde"):
                log(f"{uuid[:8]}: VOLTOU (filhos={kids}, cpu "
                    f"{'parada' if cpu_parado else 'avancando'}) — zerando contador")
            new_state[uuid] = {"pid": pid, "ticks": ticks, "obs": 0, "desde": None}
            continue

        # congelado nesta passada
        obs = prev.get("obs", 0) + 1
        desde = prev.get("desde") or now
        parado_s = int(now - desde)
        new_state[uuid] = {"pid": pid, "ticks": ticks, "obs": obs, "desde": desde}

        if obs < MIN_OBS:
            log(f"{uuid[:8]} pid={pid}: 0 filhos + CPU parada "
                f"(obs {obs}/{MIN_OBS}, {parado_s}s) — observando")
            continue

        if parado_s >= KILL_S and kills < MAX_KILLS_PER_PASS:
            try:
                os.kill(pid, signal.SIGKILL)   # SO o pid, nunca -pid
                log(f"{uuid[:8]} pid={pid}: MATANDO com SIGKILL — congelado ha "
                    f"{parado_s}s ({parado_s//60} min), {obs} observacoes. "
                    f"O ospd deve marcar a task como Interrupted (retomavel).")
                kills += 1
                new_state[uuid] = {"pid": pid, "ticks": ticks, "obs": 0, "desde": None}
            except OSError as e:
                log(f"{uuid[:8]} pid={pid}: FALHOU ao matar: {e}")
        elif parado_s >= KILL_S:
            log(f"{uuid[:8]} pid={pid}: elegivel para SIGKILL mas ja matei "
                f"{kills} nesta passada — fica para a proxima")
        elif parado_s >= ALERT_S:
            log(f"{uuid[:8]} pid={pid}: ALERTA — congelado ha {parado_s//60} min "
                f"(0 filhos, CPU parada, {obs} obs). SIGKILL em "
                f"{(KILL_S - parado_s)//60} min se nao voltar.")
        else:
            log(f"{uuid[:8]} pid={pid}: congelado ha {parado_s}s "
                f"(obs {obs}) — abaixo do limiar de alerta")

    save_state(new_state)


if __name__ == "__main__":
    main()
