#!/bin/bash
set -e
cd /root/suricatoos/src/gsa
sed -i "147s/Greenbone/Suricatoos/" src/web/utils/Render.tsx
sed -i "s/Report for Greenbone Sensor/Report for Suricatoos Sensor/" src/web/pages/performance/PerformancePage.tsx
sed -i "s/Greenbone Vulnerability Manager report format/Suricatoos Vulnerability Manager report format/" src/web/pages/reports/DetailsPage.tsx
echo "=== fixes aplicados ==="
grep -n "Suricatoos" src/web/utils/Render.tsx | head -1
grep -n "Suricatoos Sensor" src/web/pages/performance/PerformancePage.tsx
grep -n "Suricatoos Vulnerability Manager report" src/web/pages/reports/DetailsPage.tsx
echo "=== ESCOPO total das mudancas gsa (git diff --stat) ==="
git diff --stat
echo "=== gsad ==="
cd ../gsad && git diff --stat
