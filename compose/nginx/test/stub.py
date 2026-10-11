#!/usr/bin/env python3
"""Upstream-stub da matriz de rotas do nginx (só stdlib).

Responde pelos upstreams do compose — control-plane:8080, ingest:9090,
gsad:9392 e feed-updater:8008 — num único container com esses aliases de rede.
Cada requisição recebida vira UMA linha JSON (no arquivo de --log e no stdout)
ANTES da resposta, com: o upstream, o método, o caminho cru (com query), o id do
caso (header X-Case-Id) e os headers que a matriz confere. Header ausente fica
fora de "headers"; valores repetidos aparecem juntos, separados por ", ".

gsad, GET /gmp?cmd=get_capabilities&token=T: 200 só se T == good-token e o
Cookie tiver GSAD_SID=good-sid; senão 401 (é o que o auth_request consulta).
Qualquer outra requisição: 200 com a própria linha JSON como corpo.
"""
import argparse
import json
import signal
import sys
import threading
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORTAS = {8080: "control-plane", 9090: "ingest", 9392: "gsad", 8008: "feed-updater"}
CONFERIDOS = (
    "X-Suricatoos-Gate",
    "X-Client-Cert-DN",
    "X-Client-Cert-Verify",
    "X-Client-Cert-Serial",
    "X-Operator",
    "X-Suricatoos-UI",
)
TOKEN_BOM = "good-token"
SID_BOM = "good-sid"


class Registro:
    def __init__(self, caminho):
        self.trava = threading.Lock()
        self.arquivo = open(caminho, "a", encoding="utf-8") if caminho else None

    def grava(self, entrada):
        linha = json.dumps(entrada, sort_keys=True, ensure_ascii=False)
        with self.trava:
            if self.arquivo:
                self.arquivo.write(linha + "\n")
                self.arquivo.flush()
            print(linha, flush=True)
        return linha


def sessao_valida(caminho, headers):
    q = parse_qs(urlsplit(caminho).query, keep_blank_values=True)
    if q.get("cmd", [""])[0] != "get_capabilities" or q.get("token", [""])[0] != TOKEN_BOM:
        return False
    jar = SimpleCookie()
    try:
        jar.load(headers.get("Cookie", ""))
    except CookieError:
        return False
    return "GSAD_SID" in jar and jar["GSAD_SID"].value == SID_BOM


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "upstream-stub"

    def responde(self):
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho > 0:
            self.rfile.read(tamanho)
        upstream = self.server.upstream
        status = 200
        if upstream == "gsad" and urlsplit(self.path).path == "/gmp":
            status = 200 if sessao_valida(self.path, self.headers) else 401
        entrada = {
            "upstream": upstream,
            "method": self.command,
            "path": self.path,
            "case": self.headers.get("X-Case-Id", ""),
            "status": status,
            "headers": {
                h: ", ".join(self.headers.get_all(h))
                for h in CONFERIDOS
                if self.headers.get_all(h)
            },
        }
        corpo = (self.server.registro.grava(entrada) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = responde

    def log_message(self, fmt, *args):
        pass  # a linha JSON de Registro.grava já é o log de acesso


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", help="arquivo JSONL com uma linha por requisição recebida")
    opts = ap.parse_args()

    registro = Registro(opts.log)
    servidores = []
    for porta, nome in PORTAS.items():
        srv = ThreadingHTTPServer(("0.0.0.0", porta), Handler)
        srv.upstream = nome
        srv.registro = registro
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servidores.append(srv)
    print(
        "upstream-stub pronto: " + " ".join(f"{n}:{p}" for p, n in PORTAS.items()),
        flush=True,
    )

    parar = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: parar.set())
    signal.signal(signal.SIGINT, lambda *_: parar.set())
    while not parar.wait(1):
        pass
    for srv in servidores:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
