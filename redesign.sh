#!/bin/bash
set -e
cd /root/suricatoos/src/gsa
A=/root/suricatoos/assets
# Header (barra preta): WHITE WORDMARK em vez do mark isolado
cp "$A/wordmark-white.svg" src/web/components/icon/svg/Greenbone_white_logo.svg
# contextos claros (NotFoundPage): navy wordmark
cp "$A/wordmark-navy.svg"  src/web/components/icon/svg/greenbone.svg
# splash: navy wordmark
cp "$A/wordmark-navy.svg"  public/img/gsa_splash.svg
# favicon: monograma limpo
cp "$A/favicon-clean.svg"  public/img/favicon.svg
# tamanho do logo do header: WIDE (p/ wordmark) em vez de quadrado
sed -i "s/'38px', '38px'/'170px', '40px'/" src/web/components/icon/GreenboneApplianceLogo.tsx
echo "=== logo size ==="; grep -n "170px\|38px" src/web/components/icon/GreenboneApplianceLogo.tsx | head -1
# remover o "S" GIGANTE (ProductImage) do login
sed -i "175,177d" src/web/pages/login/LoginForm.tsx
echo "=== ProductImage no JSX (esperado: so import+styled, sem <ProductImage/>) ==="; grep -nE "<ProductImage" src/web/pages/login/LoginForm.tsx || echo "removido do JSX OK"
echo "REDESIGN_APLICADO"
