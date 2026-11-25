#!/usr/bin/env bash
set -euo pipefail

# 用法：
#   ./tools/init-server.sh public vault.example.com
#   ./tools/init-server.sh internal 100.88.1.2 8443

MODE="${1:-public}"
HOSTNAME="${2:?用法: $0 <public|internal> <域名或IP> [HTTPS端口]}"
HTTPS_PORT="${3:-443}"
HTTP_PORT="${HTTP_PORT:-80}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROD_DIR="$REPO_ROOT/docker/production"

ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9!@#%^&*-_=+' </dev/urandom | head -c 24)}"

if command -v node >/dev/null 2>&1; then
  PHC="$(PWDSV_INIT_ADMIN_PWD="$ADMIN_PASSWORD" node "$SCRIPT_DIR/hash-admin.mjs")"
else
  PHC="$ADMIN_PASSWORD"
fi

if [ "$MODE" = "public" ]; then
  cp -f "$PROD_DIR/Caddyfile.public" "$PROD_DIR/Caddyfile"
elif [ "$MODE" = "internal" ]; then
  cp -f "$PROD_DIR/Caddyfile.internal" "$PROD_DIR/Caddyfile"
else
  echo "未知模式: $MODE (仅支持 public 或 internal)" >&2
  exit 1
fi

PORT_SUFFIX=""
[ "$HTTPS_PORT" != "443" ] && PORT_SUFFIX=":$HTTPS_PORT"
DOMAIN_URL="https://${HOSTNAME}${PORT_SUFFIX}"

cat >"$PROD_DIR/.env" <<EOF
# 自动生成 (模式: $MODE)
DOMAIN=$DOMAIN_URL
CADDY_HOST=$HOSTNAME
HTTP_PORT=$HTTP_PORT
HTTPS_PORT=$HTTPS_PORT
SIGNUPS_ALLOWED=true
WEBSOCKET_ENABLED=true
ALLOWED_CLIENT_ORIGINS=chrome-extension://*,tauri://localhost,http://tauri.localhost,https://tauri.localhost
ADMIN_TOKEN=$PHC
BACKUP_INTERVAL_SECONDS=86400
BACKUP_KEEP_DAYS=30
EOF

echo "PWDSV 配置已生成：$PROD_DIR/.env"
echo "  访问地址   : $DOMAIN_URL"
echo "  管理后台   : $DOMAIN_URL/admin"
echo "  管理员密码 : $ADMIN_PASSWORD"
echo "启动服务：docker compose -f docker/production/compose.yaml up -d --build"
