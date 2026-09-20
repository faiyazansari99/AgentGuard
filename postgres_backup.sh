#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?DATABASE_URL is required}"
mkdir -p /backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump "$DATABASE_URL" | gzip > "/backups/agentguard_${STAMP}.sql.gz"
find /backups -type f -name 'agentguard_*.sql.gz' -mtime +7 -delete
