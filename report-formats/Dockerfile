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
# The report ships as THREE per-language objects (EN / PT-BR / ES), one feed XML
# each (pdf-suricatoos-<uuid>.xml), so all three appear in the GSA "Download
# report" dropdown and the user picks the language there.
#
# Build:
#   python3 build-feed-xml.py   # regenerate the three embedded XMLs from the bundle
#   docker build -t ghcr.io/williamsouzadelima/suricatoos-report-formats:stable \
#       report-formats
FROM registry.community.greenbone.net/community/report-formats

USER root
COPY pdf-suricatoos-*.xml /tmp/suricatoos-formats/

# Install every Suricatoos feed object into every per-release report-formats
# source directory.
RUN set -eu; \
    count=$(ls -1 /tmp/suricatoos-formats/pdf-suricatoos-*.xml | wc -l); \
    [ "$count" -gt 0 ] || { echo "no feed XMLs to install" >&2; exit 1; }; \
    found=0; \
    for d in "${STORAGE_PATH}"/*/report-formats; do \
        [ -d "$d" ] || continue; \
        cp /tmp/suricatoos-formats/pdf-suricatoos-*.xml "$d/"; \
        found=$((found + 1)); \
    done; \
    rm -rf /tmp/suricatoos-formats; \
    echo "Suricatoos: installed ${count} report format(s) into ${found} release dir(s)"; \
    [ "$found" -gt 0 ]
