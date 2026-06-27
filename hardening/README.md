# Hardening Suricatoos

## Exposicao / rede
- 443 publicado em 0.0.0.0 (`compose/compose.yaml`); UFW libera 443/tcp.
- nginx faz rate-limit no `/login`: 15 req/min, burst 10, por IP (`compose/nginx/default.conf`).

## fail2ban — jail do login GSA (ban via null-route, funciona com docker)
Requer o log dedicado `/var/log/suricatoos-nginx/login.log` (access_log no `location = /login`
+ volume em `compose/docker-compose.override.yml`). Instalar:

    cp fail2ban/filter.d/suricatoos-login.conf /etc/fail2ban/filter.d/
    cp fail2ban/jail.d/suricatoos-login.conf  /etc/fail2ban/jail.d/   # troque <SEU_IP_ADMIN>
    fail2ban-client reload

Regra: 8 falhas/10min -> ban 1h. `ignoreip` protege seu IP + redes docker (172.16.0.0/12).

## TLS — cert Let's Encrypt + auto-renovacao
- Cert `scanner.suricatoos.com` via certbot standalone (HTTP-01, porta 80). nginx aponta p/ `/etc/letsencrypt/live/...` (volume `/etc/letsencrypt:ro`).
- Renovacao: `certbot.timer` (systemd) roda `certbot renew`; o deploy-hook recarrega o nginx do container (`nginx -s reload` via `docker exec`).
- Instalar hook: `cp letsencrypt/renewal-hooks/deploy/reload-suricatoos-nginx.sh /etc/letsencrypt/renewal-hooks/deploy/ && chmod +x`.
- Provado: `certbot renew --force-renewal` gerou serial novo e o nginx passou a servir o cert renovado.
