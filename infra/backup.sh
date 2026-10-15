#!/bin/bash
set -euo pipefail
umask 077
source /etc/lab-auth/deployment.env
cd /opt/lab-auth
docker compose -f compose.production.yaml exec -T db pg_dump -U lab_auth -d lab_auth --no-owner --no-acl | gzip | aws s3 cp - "s3://$ARTIFACT_BUCKET/backups/$(date -u +%Y-%m-%dT%H-%M-%SZ).sql.gz" --region "$REGION" --sse AES256 --only-show-errors
echo 'AUTH_LAB_BACKUP_COMPLETE'
