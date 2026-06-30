# Suricatoos report-formats feed image.
#
# Forks the upstream Greenbone community report-formats feed image (the same
# pattern used for gsa/gsad) and adds the "Suricatoos Premium PDF" report format
# to the feed source.  Because the format is delivered via the feed path, gvmd
# installs it as predefined=1, trust=1 — it appears automatically in the GSA
# "Download report" format dropdown with NO frontend change and NO GPG signing.
#
# The upstream image ships one report-formats source directory per feed release
# under ${STORAGE_PATH} (e.g. .../gvmd/24.10/report-formats/); its /bin/init.sh
# copies ${STORAGE_PATH}/${FEED_RELEASE}/* into the shared data-objects volume
# that gvmd syncs.  We drop our combined feed object into every release dir so
# the format installs regardless of the configured FEED_RELEASE.  All stock
# formats are left untouched (this image is purely additive).
#
# Build:
#   python3 build-feed-xml.py   # regenerate the embedded XML from the bundle
#   docker build -t ghcr.io/williamsouzadelima/suricatoos-report-formats:stable \
#       report-formats
FROM registry.community.greenbone.net/community/report-formats

ARG FORMAT_XML=pdf-suricatoos-c6482c1b-57bb-406b-a501-c97eed86ad05.xml

USER root
COPY ${FORMAT_XML} /tmp/${FORMAT_XML}

# Install into every per-release report-formats source directory.
RUN set -eu; \
    found=0; \
    for d in "${STORAGE_PATH}"/*/report-formats; do \
        [ -d "$d" ] || continue; \
        cp "/tmp/${FORMAT_XML}" "$d/${FORMAT_XML}"; \
        found=$((found + 1)); \
    done; \
    rm -f "/tmp/${FORMAT_XML}"; \
    echo "Suricatoos: installed ${FORMAT_XML} into ${found} report-formats release dir(s)"; \
    [ "$found" -gt 0 ]
