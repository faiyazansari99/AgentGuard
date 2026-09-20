#!/bin/sh
set -eu
: "${BACKUP_DIR:=./backups}"
: "${PGHOST:=postgres}"
: "${PGUSER:=agentguard}"
: "${PGDATABASE:=agentguard}"
mkdir -p "$BACKUP_DIR"
file="$BACKUP_DIR/agentguard-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump -Fc "$PGDATABASE" > "$file"
find "$BACKUP_DIR" -type f -name '*.dump' -mtime +14 -delete
printf 'Backup written to %s\n' "$file"
