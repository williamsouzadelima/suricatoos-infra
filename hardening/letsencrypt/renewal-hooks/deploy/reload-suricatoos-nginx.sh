#!/bin/bash
# recarrega o nginx do container p/ pegar o cert renovado (exec reload = confiavel)
docker exec greenbone-community-edition-nginx-1 nginx -s reload 2>/dev/null \
  || docker kill --signal=HUP greenbone-community-edition-nginx-1 2>/dev/null
