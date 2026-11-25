#!/bin/sh
set -eu

INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-86400}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"

mkdir -p /backups
echo "[pwdsv-backup] 定时热备已启动：间隔 ${INTERVAL_SECONDS}s，保留最近 ${KEEP_DAYS} 天。"

while true; do
    sleep "$INTERVAL_SECONDS"
    TS="$(date +%Y%m%d_%H%M%S)"
    if [ -f /data/db.sqlite3 ]; then
        echo "[pwdsv-backup] 开始执行在线备份 ($TS)..."
        /pwdsv backup || true
        for f in /data/db_*.sqlite3; do
            [ -e "$f" ] || continue
            mv "$f" "/backups/"
        done
        if [ -f /data/config.json ]; then
            cp -f /data/config.json "/backups/config_${TS}.json"
        fi
        find /backups -type f -mtime +"$KEEP_DAYS" -delete || true
        echo "[pwdsv-backup] 备份完成，当前快照数：$(ls -1 /backups | wc -l)"
    fi
done
