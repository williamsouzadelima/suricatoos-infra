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
