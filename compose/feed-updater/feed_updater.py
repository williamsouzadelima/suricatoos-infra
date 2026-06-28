#!/usr/bin/env python3
"""Suricatoos feed-updater: dispara/agenda a atualizacao dos feeds GVM.
Atualizar feed = `docker compose up -d --no-deps --pull always <feeds>`
(puxa a imagem de feed mais recente da Greenbone e re-copia os dados pro volume).
API (atras do nginx em /feed-sync/, protegida por auth_request da sessao GSA):
  GET  /status    -> estado do sync + agendamento
  POST /sync      -> dispara um sync agora (assincrono)
  GET  /schedule  -> agendamento atual
  POST /schedule  -> grava agendamento {enabled,frequency,weekday,time}
"""
import datetime
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE_DIR = '/state'
SCHEDULE_FILE = os.path.join(STATE_DIR, 'schedule.json')
STATUS_FILE = os.path.join(STATE_DIR, 'status.json')
COMPOSE_DIR = os.environ.get('COMPOSE_DIR', '/compose')
PORT = int(os.environ.get('PORT', '8008'))
FEEDS = [
    'data-objects', 'report-formats', 'scap-data', 'cert-bund-data',
    'dfn-cert-data', 'notus-data', 'gpg-data', 'vulnerability-tests',
]
DEFAULT_SCHEDULE = {
    'enabled': False, 'frequency': 'daily', 'weekday': 1, 'time': '02:00',
    'last_scheduled_run': None,
}
PROJECT = os.environ.get('COMPOSE_PROJECT_NAME', 'greenbone-community-edition')

_sync_lock = threading.Lock()


def _feed_image_ids():
    """Image ID atual de cada container de feed (p/ saber o que mudou no sync)."""
    ids = {}
    for f in FEEDS:
        try:
            p = subprocess.run(
                ['docker', 'inspect', '--format', '{{.Image}}', '%s-%s-1' % (PROJECT, f)],
                capture_output=True, text=True, timeout=20)
            ids[f] = (p.stdout.strip() or None) if p.returncode == 0 else None
        except Exception:
            ids[f] = None
    return ids


def _now_iso():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return dict(default) if isinstance(default, dict) else default


def save_json(path, data):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, path)


def get_schedule():
    sch = dict(DEFAULT_SCHEDULE)
    sch.update(load_json(SCHEDULE_FILE, {}))
    return sch


def get_status():
    return load_json(STATUS_FILE, {'state': 'idle', 'last_run': None, 'last_result': None, 'last_output': ''})


def set_status(**kw):
    st = get_status()
    st.update(kw)
    save_json(STATUS_FILE, st)
    return st


def run_sync(trigger='manual'):
    if not _sync_lock.acquire(blocking=False):
        return {'ok': False, 'error': 'Sincronizacao ja em andamento'}
    try:
        set_status(state='running', started=_now_iso(), trigger=trigger, last_result=None, last_output='', updated=[])
        before = _feed_image_ids()
        # `--pull always` (SEM --force-recreate): puxa a imagem mais nova de cada feed e
        # recria SO os que tem dado novo. NAO usar --force-recreate: recriar os 8 feeds em
        # paralelo causa race no `openvas --update-vt-info` (le NVT incompleto) -> scanner
        # falha ao carregar VTs e fica sem NVTs. O feedback de "updated" abaixo mostra o que mudou.
        cmd = ['docker', 'compose', 'up', '-d', '--no-deps', '--pull', 'always'] + FEEDS
        try:
            p = subprocess.run(cmd, cwd=COMPOSE_DIR, capture_output=True, text=True, timeout=2400)
            ok = p.returncode == 0
            out = (p.stdout + '\n' + p.stderr).strip()
        except subprocess.TimeoutExpired:
            ok, out = False, 'timeout apos 40min'
        except Exception as e:
            ok, out = False, str(e)
        after = _feed_image_ids()
        # feeds cuja imagem mudou = feeds efetivamente atualizados
        updated = [f for f in FEEDS if after.get(f) and before.get(f) != after.get(f)]
        set_status(state='idle', last_run=_now_iso(),
                   last_result='success' if ok else 'error',
                   last_output=out[-3000:], trigger=trigger, updated=updated)
        return {'ok': ok, 'updated': updated}
    finally:
        _sync_lock.release()


def scheduler_loop():
    while True:
        try:
            sch = get_schedule()
            if sch.get('enabled'):
                now = datetime.datetime.now()
                hh, mm = (sch.get('time') or '02:00').split(':')
                match_time = now.hour == int(hh) and now.minute == int(mm)
                freq = sch.get('frequency', 'daily')
                match_day = freq == 'daily' or (freq == 'weekly' and now.isoweekday() == int(sch.get('weekday', 1)))
                today = now.strftime('%Y-%m-%d')
                if match_time and match_day and sch.get('last_scheduled_run') != today:
                    sch['last_scheduled_run'] = today
                    save_json(SCHEDULE_FILE, sch)
                    threading.Thread(target=run_sync, args=('scheduled',), daemon=True).start()
        except Exception:
            pass
        time.sleep(25)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _path(self):
        return self.path.split('?')[0].rstrip('/') or '/'

    def do_GET(self):
        p = self._path()
        if p == '/status':
            st = get_status()
            st['schedule'] = get_schedule()
            st['feeds'] = FEEDS
            self._send(200, st)
        elif p == '/schedule':
            self._send(200, get_schedule())
        elif p in ('/', '/health'):
            self._send(200, {'ok': True, 'service': 'feed-updater'})
        else:
            self._send(404, {'error': 'not found'})

    def do_POST(self):
        p = self._path()
        length = int(self.headers.get('Content-Length', 0) or 0)
        raw = self.rfile.read(length) if length else b'{}'
        if p == '/sync':
            if get_status().get('state') == 'running':
                self._send(409, {'ok': False, 'message': 'Sincronizacao ja em andamento'})
                return
            threading.Thread(target=run_sync, args=('manual',), daemon=True).start()
            self._send(202, {'ok': True, 'message': 'Sincronizacao iniciada'})
        elif p == '/schedule':
            try:
                data = json.loads(raw or b'{}')
                sch = get_schedule()
                if 'enabled' in data:
                    sch['enabled'] = bool(data['enabled'])
                if data.get('frequency') in ('daily', 'weekly'):
                    sch['frequency'] = data['frequency']
                if 'weekday' in data:
                    sch['weekday'] = max(1, min(7, int(data['weekday'])))
                if 'time' in data:
                    hh, mm = str(data['time']).split(':')
                    sch['time'] = '%02d:%02d' % (int(hh), int(mm))
                save_json(SCHEDULE_FILE, sch)
                self._send(200, sch)
            except Exception as e:
                self._send(400, {'error': str(e)})
        else:
            self._send(404, {'error': 'not found'})

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print('feed-updater ouvindo em :%d (TZ=%s)' % (PORT, os.environ.get('TZ', 'UTC')), flush=True)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
