FROM docker:27-cli
# docker:27-cli (alpine) ja inclui o plugin `docker compose`; so falta python3 + tz
RUN apk add --no-cache python3 tzdata
ENV TZ=America/Sao_Paulo \
    COMPOSE_DIR=/compose \
    PORT=8008
COPY feed_updater.py /feed_updater.py
EXPOSE 8008
CMD ["python3", "/feed_updater.py"]
