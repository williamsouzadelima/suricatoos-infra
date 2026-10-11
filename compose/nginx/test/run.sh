#!/usr/bin/env bash
# Matriz de rotas dos configs do nginx (compose/nginx/default.conf e
# standalone.conf). Feita para o CI (.github/workflows/nginx-ci.yml).
#
# Sobe o nginx da MESMA imagem do compose com o config do repositório e, atrás
# dele, um upstream-stub (stub.py) que responde por control-plane, ingest, gsad e
# feed-updater e grava cada requisição recebida. Cada caso confere o status que o
# nginx devolve e o que chegou (ou não chegou) ao upstream: método, caminho e os
# headers de portão e de identidade.
#
# Perfis:
#   default     PROXY protocol + mTLS (o vhost de produção)
#   standalone  sem PROXY protocol e sem mTLS
#   mutante     CONTROLE DE MUTAÇÃO: cópia temporária do default.conf com o
#               catch-all /agent/ reaberto (o bloco de proxy antigo). Os casos de
#               rota fechada TÊM de reprovar nela — prova de que a matriz
#               discrimina. O arquivo rastreado nunca é alterado.
#
# Precisa de docker, curl, openssl, jq e python3.
#   compose/nginx/test/run.sh            roda tudo
#   compose/nginx/test/run.sh --cleanup  remove containers e redes da matriz
# Ambiente (opcional):
#   NGINX_IMAGE    imagem do nginx (padrão: a do compose)
#   STUB_IMAGE     imagem com python3 para o stub (padrão: python:3.12-slim)
#   NGINX_CI_WORK  diretório-base de trabalho (padrão: $RUNNER_TEMP, $TMPDIR ou /tmp)
#   NGINX_CI_KEEP  1 = não remove containers/rede/arquivos no fim (o workflow
#                  imprime os logs em caso de falha e limpa depois)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_DIR="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$NGINX_DIR/../.." && pwd)"

NGINX_IMAGE="${NGINX_IMAGE:-registry.community.greenbone.net/community/nginx:latest}"
STUB_IMAGE="${STUB_IMAGE:-python:3.12-slim}"
LABEL_KEY="suricatoos-nginx-ci"
RUN_ID="${GITHUB_RUN_ID:-local}-$$"
LABEL="$LABEL_KEY=$RUN_ID"
NET="nginx-ci-$RUN_ID"
STUB_CTR="nginx-ci-stub-$RUN_ID"
HOST="scanner.suricatoos.com"
WORK="${NGINX_CI_WORK:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}/nginx-ci-$RUN_ID"
PKI="$WORK/pki"
STUB_LOG="$WORK/stub-log/requests.jsonl"

# Headers de portão e de identidade enviados pelo próprio cliente: as locations que
# não derivam esses valores têm de descartá-los.
FORGED=(-H 'X-Suricatoos-Gate: gsad-session' -H 'X-Client-Cert-DN: CN=forjado'
        -H 'X-Client-Cert-Verify: SUCCESS' -H 'X-Client-Cert-Serial: 0A'
        -H 'X-Operator: forjado')

# Estado da execução.
PASSED=0 FAILED=0 SEQ=0
FAILED_CASES=()
MODE=normal                     # normal | mutante
MUT_TOTAL=0 MUT_FAILED=0
MUT_NOT_FAILED=()
PROFILE="" NGINX_CTR="" PORT="" USE_PROXY_PROTOCOL=0
CLIENT_SERIAL=""                # serial do cert de cliente de teste (gen_pki)
CURL_BASE=()
CASE_ID="" CASE_DESC="" CASE_ERRS=()
REQ_DESC="" STATUS="" CURL_RC=0 LOG_LINES_BEFORE=0 UP_ENTRY=""

die() { printf 'ERRO: %s\n' "$*" >&2; exit 2; }
section() { printf '\n== %s\n' "$*"; }
record_failure() { FAILED=$((FAILED + 1)); FAILED_CASES+=("$*"); }

# ---------------------------------------------------------------- limpeza ----

cleanup_label() {  # cleanup_label FILTRO_DE_LABEL
  local ids
  ids=$(docker ps -aq --filter "label=$1" 2>/dev/null)
  # shellcheck disable=SC2086 # ids: lista de IDs hex, um por linha
  if [ -n "$ids" ]; then docker rm -f $ids >/dev/null 2>&1; fi
  ids=$(docker network ls -q --filter "label=$1" 2>/dev/null)
  # shellcheck disable=SC2086
  if [ -n "$ids" ]; then docker network rm $ids >/dev/null 2>&1; fi
  return 0
}

dump_logs() {
  local c
  for c in $(docker ps -aq --filter "label=$LABEL" 2>/dev/null); do
    printf '\n===== docker logs %s\n' "$(docker inspect -f '{{.Name}}' "$c" 2>/dev/null)"
    docker logs "$c" 2>&1 | tail -n 200
  done
}

on_exit() {
  local rc=$?
  if [ "${NGINX_CI_KEEP:-0}" != 1 ]; then
    if [ "$rc" -ne 0 ]; then dump_logs; fi
    cleanup_label "$LABEL"
    case "$WORK" in */nginx-ci-*) rm -rf "$WORK" 2>/dev/null ;; esac
  fi
  exit "$rc"
}

# ------------------------------------------------------------- preparação ----

pull() {  # pull IMAGEM — com novas tentativas (registro remoto)
  local i
  for i in 1 2 3; do
    if docker pull -q "$1" >/dev/null 2>&1; then return 0; fi
    printf 'docker pull %s falhou (tentativa %s)\n' "$1" "$i" >&2
    sleep $((i * 5))
  done
  docker pull "$1" || die "não consegui baixar $1"
}

# CA de teste, cert de servidor (scanner.suricatoos.com) e cert de cliente
# assinado pela CA (CN=test-agent, O=lab, OU=agent-endpoint). Configs próprios
# do openssl, para não depender do openssl.cnf da máquina.
gen_pki() {
  mkdir -p "$PKI" || die "não consegui criar $PKI"
  cat >"$PKI/req.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext
[dn]
CN = nginx-ci-test-ca
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  cat >"$PKI/server.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$HOST,DNS:localhost
EOF
  cat >"$PKI/client.ext" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
  {
    openssl req -x509 -new -newkey rsa:2048 -nodes -sha256 -days 2 \
      -config "$PKI/req.cnf" -keyout "$PKI/ca.key" -out "$PKI/ca.crt" &&
    openssl req -new -newkey rsa:2048 -nodes -config "$PKI/req.cnf" \
      -subj "/CN=$HOST" -keyout "$PKI/server.key" -out "$PKI/server.csr" &&
    openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
      -CAcreateserial -days 2 -sha256 -extfile "$PKI/server.ext" -out "$PKI/server.crt" &&
    openssl req -new -newkey rsa:2048 -nodes -config "$PKI/req.cnf" \
      -subj "/CN=test-agent/O=lab/OU=agent-endpoint" \
      -keyout "$PKI/client.key" -out "$PKI/client.csr" &&
    openssl x509 -req -in "$PKI/client.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
      -CAcreateserial -days 2 -sha256 -extfile "$PKI/client.ext" -out "$PKI/client.crt" &&
    openssl verify -CAfile "$PKI/ca.crt" "$PKI/server.crt" "$PKI/client.crt"
  } >"$PKI/openssl.log" 2>&1 || {
    cat "$PKI/openssl.log" >&2
    die "falha ao gerar o material de teste (openssl)"
  }
  # O serial que o nginx tem de repassar ($ssl_client_serial) nas rotas mTLS.
  CLIENT_SERIAL=$(openssl x509 -in "$PKI/client.crt" -noout -serial 2>/dev/null | cut -d= -f2)
  [ -n "$CLIENT_SERIAL" ] || die "não consegui ler o serial do cert de cliente"
}

# Tudo o que os dois configs referenciam (conferido nos próprios arquivos):
# headers.conf, certs do servidor (Let's Encrypt no default, /etc/nginx/certs no
# standalone), a CA de enrollment, o HTML da SPA, os scripts de instalação, o
# diretório do log de login e os diretórios de snippets locais (vazios).
prepare_tree() {
  mkdir -p "$WORK/html" "$WORK/certs" "$WORK/letsencrypt/live/$HOST" \
    "$WORK/admin-nets" "$WORK/extra" "$WORK/stub-log" || die "não consegui montar $WORK"
  printf '<!doctype html><title>nginx-ci</title>\n' >"$WORK/html/index.html"
  cp "$PKI/server.crt" "$WORK/letsencrypt/live/$HOST/fullchain.pem" &&
    cp "$PKI/server.key" "$WORK/letsencrypt/live/$HOST/privkey.pem" &&
    cp "$PKI/server.crt" "$WORK/certs/server.cert.pem" &&
    cp "$PKI/server.key" "$WORK/certs/server.key" || die "não consegui copiar os certs"
  cat >"$WORK/headers.conf" <<'EOF'
# headers.conf mínimo de teste (o real vem do gvm-config, no nginx_config_vol).
# Válido nos três contextos em que é incluído: http (conf.d/*.conf), server e location.
add_header X-Content-Type-Options "nosniff" always;
EOF
  : >"$STUB_LOG"
  chmod 0777 "$WORK/stub-log" && chmod 0666 "$STUB_LOG" || die "chmod no log do stub"
  [ -d "$REPO_ROOT/packaging/install" ] || die "falta $REPO_ROOT/packaging/install"
}

make_confd() {  # make_confd PERFIL ARQUIVO_CONF
  local dir="$WORK/$1"
  mkdir -p "$dir/conf.d" "$dir/log-sur" || return 1
  cp "$2" "$dir/conf.d/default.conf" && cp "$WORK/headers.conf" "$dir/conf.d/headers.conf" &&
    chmod 0777 "$dir/log-sur"
}

nginx_mounts() {  # nginx_mounts PERFIL — preenche MOUNTS
  MOUNTS=(
    -v "$WORK/$1/conf.d:/etc/nginx/conf.d:ro"
    -v "$WORK/$1/log-sur:/var/log/nginx-sur"
    -v "$WORK/html:/usr/share/nginx/html:ro"
    -v "$WORK/letsencrypt:/etc/letsencrypt:ro"
    -v "$PKI/ca.crt:/etc/nginx/enroll-ca.crt:ro"
    -v "$WORK/certs:/etc/nginx/certs:ro"
    -v "$WORK/admin-nets:/etc/nginx/admin-nets:ro"
    -v "$WORK/extra:/etc/nginx/extra:ro"
    -v "$REPO_ROOT/packaging/install:/usr/share/suricatoos/install:ro"
  )
}

start_stub() {
  docker run -d --name "$STUB_CTR" --label "$LABEL" --network "$NET" \
    --network-alias control-plane --network-alias ingest \
    --network-alias gsad --network-alias feed-updater \
    -v "$HERE/stub.py:/stub/stub.py:ro" -v "$WORK/stub-log:/stub-log" \
    "$STUB_IMAGE" python3 -u /stub/stub.py --log /stub-log/requests.jsonl >/dev/null || return 1
  local i out
  for i in $(seq 1 60); do
    out=$(docker logs "$STUB_CTR" 2>&1)
    case "$out" in *"upstream-stub pronto"*) return 0 ;; esac
    [ "$(docker inspect -f '{{.State.Running}}' "$STUB_CTR" 2>/dev/null)" = true ] || break
    sleep 0.5
  done
  printf '%s\n' "$out" >&2
  return 1
}

nginx_test() {  # nginx_test PERFIL — `nginx -t` num container descartável
  nginx_mounts "$1"
  timeout 120 docker run --rm --label "$LABEL" --network "$NET" "${MOUNTS[@]}" \
    --entrypoint nginx "$NGINX_IMAGE" -t
}

start_nginx() {  # start_nginx PERFIL
  NGINX_CTR="nginx-ci-$1-$RUN_ID"
  nginx_mounts "$1"
  docker run -d --name "$NGINX_CTR" --label "$LABEL" --network "$NET" \
    -p 127.0.0.1::443 "${MOUNTS[@]}" "$NGINX_IMAGE" >/dev/null || return 1
  local mapping
  mapping=$(docker port "$NGINX_CTR" 443/tcp 2>/dev/null | head -n 1)
  PORT="${mapping##*:}"
  [ -n "$PORT" ]
}

wait_ready() {  # espera o nginx responder (qualquer status HTTP) em /
  local i code
  for i in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Running}}' "$NGINX_CTR" 2>/dev/null)" = true ] || return 1
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${CURL_BASE[@]}" \
      "https://$HOST:$PORT/" 2>/dev/null)
    case "$code" in [1-5][0-9][0-9]) return 0 ;; esac
    sleep 0.5
  done
  return 1
}

# Mutante: troca o catch-all fechado pelo bloco de proxy antigo (o de antes desta
# mudança), numa cópia. Falha se não achar exatamente um bloco fechado.
mutate_conf() {  # mutate_conf ORIGEM DESTINO
  cat >"$WORK/catchall-antigo.conf" <<'EOF'
  location /agent/ {
    limit_req zone=agent_v1 burst=20 nodelay;
    resolver 127.0.0.11 valid=10s ipv6=off;
    set $cp_upstream control-plane;
    rewrite ^/agent/(.*)$ /$1 break;
    proxy_pass http://$cp_upstream:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Client-Cert-DN "";
    proxy_set_header X-Client-Cert-Verify "";
    proxy_set_header X-Client-Cert-Serial "";
    proxy_set_header X-Operator "";
    proxy_read_timeout 30s;
  }
EOF
  python3 - "$1" "$2" "$WORK/catchall-antigo.conf" <<'PY'
import re
import sys

src, dst, bloco = sys.argv[1:4]
texto = open(src, encoding="utf-8").read()
antigo = open(bloco, encoding="utf-8").read().rstrip("\n")
fechado = re.compile(r"^[ \t]*location /agent/ \{\s*return 404;\s*\}[ \t]*\r?$", re.M)
mutante, n = fechado.subn(lambda _m: antigo, texto)
if n != 1:
    sys.exit(f"esperava 1 bloco 'location /agent/ {{ return 404; }}' em {src}; achei {n}")
open(dst, "w", encoding="utf-8").write(mutante)
PY
}

# ------------------------------------------------------------------ casos ----

log_lines() {
  local n
  n=$(wc -l <"$STUB_LOG" 2>/dev/null) || n=0
  echo $((n + 0))
}

# Linhas do log do stub gravadas desde o último send.
new_entries() { tail -n "+$((LOG_LINES_BEFORE + 1))" "$STUB_LOG" 2>/dev/null; }

begin_case() {  # begin_case DESCRIÇÃO
  SEQ=$((SEQ + 1))
  CASE_ID="$PROFILE-$(printf '%03d' "$SEQ")"
  CASE_DESC="$1"
  CASE_ERRS=()
  UP_ENTRY=""
}

fail_case() { CASE_ERRS+=("$*"); }

send() {  # send MÉTODO CAMINHO [args extras do curl...]
  local method="$1" path="$2"
  shift 2
  local -a args=(-sS -o "$WORK/body" -w '%{http_code}' --max-time 15
    -X "$method" -H "X-Case-Id: $CASE_ID")
  if [ "$method" = POST ]; then
    args+=(--data-binary '{}' -H 'Content-Type: application/json')
  fi
  REQ_DESC="$method $path"
  LOG_LINES_BEFORE=$(log_lines)
  : >"$WORK/body"
  STATUS=$(curl "${CURL_BASE[@]}" "${args[@]}" "$@" "https://$HOST:$PORT$path" 2>"$WORK/curl.err")
  CURL_RC=$?
}

expect_status() {  # expect_status CÓDIGO
  [ "$STATUS" = "$1" ] || fail_case "status $STATUS, esperado $1"
}

# Nenhuma requisição chegou a upstream nenhum (nem a subrequisição de auth).
expect_no_upstream() {
  local n
  n=$(new_entries | grep -c . || true)
  [ "${n:-0}" = 0 ] || fail_case "o upstream recebeu $n requisição(ões); esperado nenhuma"
}

expect_not_at() {  # expect_not_at UPSTREAM
  local out rc
  out=$(new_entries | jq -c --arg u "$1" 'select(.upstream == $u)' 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then fail_case "jq falhou lendo o log do stub: $out"; return 0; fi
  [ -z "$out" ] || fail_case "chegou requisição ao $1; esperado nenhuma"
}

expect_upstream() {  # expect_upstream UPSTREAM MÉTODO CAMINHO_CRU
  local up="$1" method="$2" path="$3" out rc n got
  out=$(new_entries | jq -c --arg c "$CASE_ID" --arg u "$up" \
    'select(.case == $c and .upstream == $u)' 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then fail_case "jq falhou lendo o log do stub: $out"; return 0; fi
  n=$(printf '%s' "$out" | grep -c . || true)
  if [ "${n:-0}" != 1 ]; then
    fail_case "esperava 1 requisição no $up, chegaram ${n:-0}"
    return 0
  fi
  UP_ENTRY="$out"
  got=$(jq -r '.method' <<<"$UP_ENTRY")
  [ "$got" = "$method" ] || fail_case "o $up recebeu o método $got, esperado $method"
  got=$(jq -r '.path' <<<"$UP_ENTRY")
  [ "$got" = "$path" ] || fail_case "o $up recebeu o caminho $got, esperado $path"
}

header_of() {  # valor do header na requisição que chegou ao upstream
  jq -r --arg h "$1" 'if (.headers | has($h)) then .headers[$h] else "<ausente>" end' \
    <<<"$UP_ENTRY"
}

expect_header() {  # expect_header NOME VALOR
  [ -n "$UP_ENTRY" ] || return 0  # a falta da requisição já foi registrada
  local got
  got=$(header_of "$1")
  [ "$got" = "$2" ] || fail_case "header $1 no upstream: '$got', esperado '$2'"
}

expect_no_header() {  # expect_no_header NOME
  [ -n "$UP_ENTRY" ] || return 0
  local got
  got=$(header_of "$1")
  [ "$got" = "<ausente>" ] || fail_case "header $1 chegou ao upstream ('$got'); esperado ausente"
}

expect_header_contains() {  # expect_header_contains NOME TRECHO
  [ -n "$UP_ENTRY" ] || return 0
  local got
  got=$(header_of "$1")
  case "$got" in *"$2"*) ;; *) fail_case "header $1 no upstream: '$got', esperado conter '$2'" ;; esac
}

expect_header_lacks() {  # expect_header_lacks NOME TRECHO
  [ -n "$UP_ENTRY" ] || return 0
  local got
  got=$(header_of "$1")
  case "$got" in *"$2"*) fail_case "header $1 no upstream contém '$2': '$got'" ;; esac
}

# Serial em hex comparável: maiúsculo, sem ':' e sem zeros à esquerda — o mesmo
# número que o ingest e a CA comparam, seja qual for a grafia.
norm_serial() {
  local s
  s=$(printf '%s' "$1" | tr -d ':' | tr 'a-f' 'A-F')
  s="${s#"${s%%[!0]*}"}"
  printf '%s' "${s:-0}"
}

expect_header_serial() {  # expect_header_serial NOME SERIAL
  [ -n "$UP_ENTRY" ] || return 0
  local got
  got=$(header_of "$1")
  if [ "$got" = "<ausente>" ] || [ "$(norm_serial "$got")" != "$(norm_serial "$2")" ]; then
    fail_case "header $1 no upstream: '$got', esperado o serial do certificado '$2'"
  fi
}

diagnostics() {
  local p='           ' entries
  printf '%srequisição: %s  (caso %s, perfil %s)\n' "$p" "$REQ_DESC" "$CASE_ID" "$PROFILE"
  printf '%scurl: rc=%s, status=%s\n' "$p" "$CURL_RC" "$STATUS"
  if [ -s "$WORK/curl.err" ]; then sed "s/^/${p}curl stderr: /" "$WORK/curl.err"; fi
  printf '%scorpo da resposta (até 1 KiB):\n' "$p"
  head -c 1024 "$WORK/body" 2>/dev/null | sed "s/^/${p}| /"
  echo
  printf '%sstub — requisições recebidas desde o envio:\n' "$p"
  entries=$(new_entries)
  if [ -n "$entries" ]; then
    printf '%s\n' "$entries" | sed "s/^/${p}| /"
  else
    printf '%s| (nenhuma)\n' "$p"
  fi
  printf '%snginx (%s) — últimas 20 linhas de log:\n' "$p" "$NGINX_CTR"
  docker logs --tail 20 "$NGINX_CTR" 2>&1 | sed "s/^/${p}| /"
}

end_case() {
  local e
  if [ "$MODE" = mutante ]; then
    # Controle de mutação: aqui o esperado é REPROVAR.
    MUT_TOTAL=$((MUT_TOTAL + 1))
    if [ "${#CASE_ERRS[@]}" -gt 0 ]; then
      MUT_FAILED=$((MUT_FAILED + 1))
    else
      MUT_NOT_FAILED+=("$CASE_DESC")
    fi
    return 0
  fi
  if [ "${#CASE_ERRS[@]}" -eq 0 ]; then
    PASSED=$((PASSED + 1))
    printf 'ok     %s\n' "$CASE_DESC"
  else
    record_failure "[$PROFILE] $CASE_DESC"
    printf 'FALHOU %s\n' "$CASE_DESC"
    for e in "${CASE_ERRS[@]}"; do printf '         - %s\n' "$e"; done
    diagnostics
  fi
}

# (b) rotas fechadas: 404 e nada chega a upstream nenhum.
closed() {  # closed MÉTODO CAMINHO
  begin_case "rota fora da allowlist do CP → 404: $1 $2"
  send "$1" "$2"
  expect_status 404
  expect_no_upstream
  end_case
}

cases_closed() {
  closed GET /agent/ai/providers
  closed POST /agent/ai/providers
  closed DELETE /agent/ai/providers/x
  closed POST '/agent/agents/scan?id=x'
  closed GET /agent/admin/ai-providers
  closed GET /agent/healthz
  closed GET /agent/v1/naoexiste
  closed POST /agent/v1/enroll/x
}

# (c) rotas públicas explícitas: chegam ao CP no caminho certo e sem os headers
# de portão/identidade que o cliente mandou.
public_route() {  # public_route MÉTODO CAMINHO CAMINHO_NO_CP
  local h
  begin_case "rota pública do CP: $1 $2 → $3, sem marca de portão nem identidade do cliente"
  send "$1" "$2" "${FORGED[@]}"
  expect_status 200
  expect_upstream control-plane "$1" "$3"
  for h in X-Suricatoos-Gate X-Client-Cert-DN X-Client-Cert-Verify X-Client-Cert-Serial X-Operator; do
    expect_no_header "$h"
  done
  end_case
}

cases_public() {
  public_route POST /agent/v1/enroll /v1/enroll
  public_route GET '/agent/v1/update/check?os=linux&arch=amd64&current=1.0.0' \
    '/v1/update/check?os=linux&arch=amd64&current=1.0.0'
  public_route GET /agent/v1/crl.der /v1/crl.der
}

# (d) /agent/api/ (bearer no CP): chega ao CP sem a marca de portão do cliente.
case_bearer_api() {
  begin_case "/agent/api/ (bearer no CP) → /api/v1/tokens, sem marca de portão do cliente"
  send GET /agent/api/v1/tokens -H 'X-Suricatoos-Gate: gsad-session'
  expect_status 200
  expect_upstream control-plane GET /api/v1/tokens
  expect_no_header X-Suricatoos-Gate
  end_case
}

# (e) portão de sessão forte (auth_request → gsad: cookie E token).
cases_session_gate() {
  local api=/ai-providers/api/providers
  begin_case "portão de sessão /ai-providers/api/: sem cookie → 401, nada chega ao CP"
  send GET "$api?token=good-token"
  expect_status 401
  expect_not_at control-plane
  end_case

  begin_case "portão de sessão /ai-providers/api/: cookie sem token → 401, nada chega ao CP"
  send GET "$api" -H 'Cookie: GSAD_SID=good-sid'
  expect_status 401
  expect_not_at control-plane
  end_case

  begin_case "portão de sessão /ai-providers/api/: sessão que o gsad não reconhece → 401, nada chega ao CP"
  send GET "$api?token=good-token" -H 'Cookie: GSAD_SID=qualquer'
  expect_status 401
  expect_not_at control-plane
  end_case

  begin_case "portão de sessão /ai-providers/api/: sessão válida → CP /ai/providers com a marca, sem X-Operator do cliente"
  send GET "$api?token=good-token" -H 'Cookie: GSAD_SID=good-sid' \
    -H 'X-Operator: forjado' -H 'X-Suricatoos-Gate: forjado'
  expect_status 200
  expect_upstream control-plane GET '/ai/providers?token=good-token'
  expect_header X-Suricatoos-Gate gsad-session
  expect_no_header X-Operator
  end_case
}

# (f) portões só por cookie (comportamento atual, documentado).
cases_cookie_gate() {
  begin_case "portão por cookie /agents/scan: sem cookie → 401, nada chega ao CP"
  send POST '/agents/scan?id=a1'
  expect_status 401
  expect_not_at control-plane
  end_case

  begin_case "portão por cookie /agents/scan: com cookie → CP /agents/scan com a marca (comportamento atual)"
  send POST '/agents/scan?id=a1' -H 'Cookie: GSAD_SID=qualquer'
  expect_status 200
  expect_upstream control-plane POST '/agents/scan?id=a1'
  expect_header X-Suricatoos-Gate gsad-session
  end_case

  begin_case "portão por cookie /agent/provision/: sem cookie → 401, nada chega ao CP"
  send GET /agent/provision/tenants
  expect_status 401
  expect_not_at control-plane
  end_case

  begin_case "portão por cookie /agent/provision/: com cookie → CP /provision/tenants com a marca (comportamento atual)"
  send GET /agent/provision/tenants -H 'Cookie: GSAD_SID=qualquer'
  expect_status 200
  expect_upstream control-plane GET /provision/tenants
  expect_header X-Suricatoos-Gate gsad-session
  end_case
}

# (g) mTLS: sem cert → recusa (403, do próprio config); com cert → identidade do
# cert, nunca a do cliente, e sem a marca de portão.
cases_mtls() {
  begin_case "mTLS /agent/v1/commands: sem certificado de cliente → 403, nada chega ao CP"
  send GET /agent/v1/commands
  expect_status 403
  expect_no_upstream
  end_case

  begin_case "mTLS /agent/v1/commands: com certificado → CP /v1/commands com o DN do certificado, sem marca de portão"
  send GET /agent/v1/commands --cert "$PKI/client.crt" --key "$PKI/client.key" \
    -H 'X-Suricatoos-Gate: gsad-session' -H 'X-Client-Cert-DN: CN=forjado'
  expect_status 200
  expect_upstream control-plane GET /v1/commands
  expect_header_contains X-Client-Cert-DN CN=test-agent
  expect_header_lacks X-Client-Cert-DN forjado
  expect_no_header X-Suricatoos-Gate
  end_case

  begin_case "mTLS /ingest/v1/inventory: sem certificado de cliente → 403, nada chega ao ingest"
  send POST /ingest/v1/inventory
  expect_status 403
  expect_no_upstream
  end_case
}

# (h) identidade e revogação no canal do agente: com cert, o upstream recebe DN,
# verify e SERIAL do certificado — os que o cliente mandar são substituídos, então
# um agente não consegue se passar por outro nem esconder um cert revogado atrás de
# um serial alheio; sem cert, nem com os headers forjados algo chega ao upstream.
# A marca de portão forjada vai junto para que a checagem de que ela NÃO chega ao CP
# possa de fato reprovar (no ingest ela não significa nada).
FORGED_CERT=(-H 'X-Client-Cert-DN: CN=forjado' -H 'X-Client-Cert-Verify: FORJADO'
             -H 'X-Client-Cert-Serial: 0A' -H 'X-Suricatoos-Gate: gsad-session')

cases_agent_identity() {
  local cert=(--cert "$PKI/client.crt" --key "$PKI/client.key")

  begin_case "mTLS /agent/v1/commands: com certificado → CP recebe DN, verify e serial do certificado, não os forjados pelo cliente nem a marca de portão"
  send GET /agent/v1/commands "${cert[@]}" "${FORGED_CERT[@]}"
  expect_status 200
  expect_upstream control-plane GET /v1/commands
  expect_header_contains X-Client-Cert-DN CN=test-agent
  expect_header_lacks X-Client-Cert-DN forjado
  expect_header X-Client-Cert-Verify SUCCESS
  expect_header_serial X-Client-Cert-Serial "$CLIENT_SERIAL"
  expect_no_header X-Suricatoos-Gate
  end_case

  begin_case "mTLS /agent/v1/commands/ack: com certificado → CP /v1/commands/ack com o serial do certificado, não o forjado nem a marca de portão"
  send POST /agent/v1/commands/ack "${cert[@]}" "${FORGED_CERT[@]}"
  expect_status 200
  expect_upstream control-plane POST /v1/commands/ack
  expect_header_contains X-Client-Cert-DN CN=test-agent
  expect_header X-Client-Cert-Verify SUCCESS
  expect_header_serial X-Client-Cert-Serial "$CLIENT_SERIAL"
  expect_no_header X-Suricatoos-Gate
  end_case

  begin_case "mTLS /ingest/v1/inventory: com certificado → ingest recebe DN, verify e serial do certificado, não os forjados nem X-Suricatoos-UI"
  send POST /ingest/v1/inventory "${cert[@]}" "${FORGED_CERT[@]}" -H 'X-Suricatoos-UI: 1'
  expect_status 200
  expect_upstream ingest POST /v1/inventory
  expect_header_contains X-Client-Cert-DN CN=test-agent
  expect_header_lacks X-Client-Cert-DN forjado
  expect_header X-Client-Cert-Verify SUCCESS
  expect_header_serial X-Client-Cert-Serial "$CLIENT_SERIAL"
  expect_no_header X-Suricatoos-UI
  end_case

  begin_case "mTLS /ingest/v1/inventory: sem certificado e com X-Client-Cert-* forjados → 403, nada chega ao ingest"
  send POST /ingest/v1/inventory -H 'X-Client-Cert-DN: CN=test-agent,O=lab' \
    -H 'X-Client-Cert-Verify: SUCCESS' -H "X-Client-Cert-Serial: $CLIENT_SERIAL"
  expect_status 403
  expect_no_upstream
  end_case

  begin_case "mTLS /agent/v1/commands: sem certificado e com X-Client-Cert-* forjados → 403, nada chega ao CP"
  send GET /agent/v1/commands -H 'X-Client-Cert-DN: CN=test-agent,O=lab' \
    -H 'X-Client-Cert-Verify: SUCCESS' -H "X-Client-Cert-Serial: $CLIENT_SERIAL"
  expect_status 403
  expect_no_upstream
  end_case
}

cases_default() {
  cases_closed
  cases_public
  case_bearer_api
  cases_session_gate
  cases_cookie_gate
  cases_mtls
  cases_agent_identity
}

# Standalone: sem PROXY protocol e sem mTLS — nada de mTLS é afirmado aqui.
cases_standalone() {
  cases_closed
  cases_public
  case_bearer_api
  cases_session_gate
}

# ----------------------------------------------------------------- perfis ----

run_profile() {  # run_profile PERFIL ARQUIVO_CONF PROXY_PROTOCOL(0|1) FUNÇÃO_DE_CASOS
  local conf="$2" cases_fn="$4" out
  PROFILE="$1"
  USE_PROXY_PROTOCOL="$3"
  NGINX_CTR=""
  if [ "$MODE" = mutante ]; then
    section "controle de mutação: catch-all /agent/ reaberto numa cópia do default.conf"
  else
    section "perfil $PROFILE ($(basename "$conf"))"
  fi
  make_confd "$PROFILE" "$conf" || { record_failure "[$PROFILE] montar conf.d"; return 0; }

  if out=$(nginx_test "$PROFILE" 2>&1); then
    [ "$MODE" = mutante ] || echo "ok     nginx -t"
  else
    echo "FALHOU nginx -t"
    printf '%s\n' "$out" | sed 's/^/         | /'
    record_failure "[$PROFILE] nginx -t"
    return 0
  fi

  CURL_BASE=()
  if ! start_nginx "$PROFILE"; then
    echo "FALHOU o nginx não subiu"
    docker logs "$NGINX_CTR" 2>&1 | tail -n 50 | sed 's/^/         | /'
    record_failure "[$PROFILE] nginx não subiu"
    return 0
  fi
  CURL_BASE=(--resolve "$HOST:$PORT:127.0.0.1" --cacert "$PKI/ca.crt" --connect-timeout 5)
  if [ "$USE_PROXY_PROTOCOL" = 1 ]; then CURL_BASE+=(--haproxy-protocol); fi
  if ! wait_ready; then
    echo "FALHOU o nginx não respondeu em https://$HOST:$PORT/"
    docker logs "$NGINX_CTR" 2>&1 | tail -n 50 | sed 's/^/         | /'
    record_failure "[$PROFILE] nginx não respondeu"
    return 0
  fi

  "$cases_fn"
  docker stop -t 2 "$NGINX_CTR" >/dev/null 2>&1
  return 0
}

main() {
  if [ "${1:-}" = "--cleanup" ]; then
    cleanup_label "$LABEL_KEY"
    echo "limpeza: containers e redes da matriz removidos"
    return 0
  fi
  local bin
  for bin in docker curl openssl jq python3 timeout; do
    command -v "$bin" >/dev/null 2>&1 || die "falta '$bin' no PATH"
  done
  trap on_exit EXIT

  section "checagem estática: marca de portão nas locations que vão ao control-plane"
  PYTHONIOENCODING=utf-8 python3 "$HERE/gate_lint.py" \
    "$NGINX_DIR/default.conf" "$NGINX_DIR/standalone.conf" ||
    record_failure "checagem estática da marca de portão (gate_lint.py)"

  section "preparação"
  pull "$NGINX_IMAGE"
  pull "$STUB_IMAGE"
  echo "nginx: $NGINX_IMAGE ($(docker run --rm --entrypoint nginx "$NGINX_IMAGE" -v 2>&1 | tr -d '\r'))"
  echo "stub:  $STUB_IMAGE; curl: $(curl --version | head -n 1 | cut -d' ' -f1-2)"
  echo "trabalho: $WORK"
  gen_pki
  prepare_tree
  docker network create --label "$LABEL" "$NET" >/dev/null || die "não consegui criar a rede $NET"
  start_stub || die "o upstream-stub não subiu"

  run_profile default "$NGINX_DIR/default.conf" 1 cases_default
  run_profile standalone "$NGINX_DIR/standalone.conf" 0 cases_standalone

  if mutate_conf "$NGINX_DIR/default.conf" "$WORK/default-mutante.conf"; then
    MODE=mutante
    run_profile mutante "$WORK/default-mutante.conf" 1 cases_closed
    MODE=normal
  else
    record_failure "controle de mutação: não consegui gerar o mutante"
  fi

  section "resumo"
  local mut_ok=0 c
  if [ "$MUT_TOTAL" -gt 0 ] && [ "$MUT_FAILED" -eq "$MUT_TOTAL" ]; then
    mut_ok=1
    echo "controle de mutação: $MUT_FAILED/$MUT_TOTAL casos reprovados, como esperado"
  else
    echo "controle de mutação FALHOU: $MUT_FAILED de $MUT_TOTAL casos reprovaram com o catch-all reaberto"
    for c in "${MUT_NOT_FAILED[@]}"; do echo "  não reprovou: $c"; done
  fi
  echo "casos: $PASSED ok, $FAILED com falha"
  for c in "${FAILED_CASES[@]}"; do echo "  falhou: $c"; done
  if [ "$FAILED" -gt 0 ] || [ "$mut_ok" -ne 1 ]; then return 1; fi
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
  exit $?
fi
