#!/bin/bash
set -euo pipefail
umask 077
# REGION, ARTIFACT_BUCKET and APP_DOMAIN are supplied by CloudFormation.
dnf install -y docker awscli2 python3
systemctl enable --now docker
install -d -m 755 /usr/local/lib/docker/cli-plugins
curl --fail --silent --show-error --location https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod 755 /usr/local/lib/docker/cli-plugins/docker-compose
install -d -m 700 /etc/lab-auth
install -d -m 755 /opt/lab-auth
printf 'REGION=%s\nARTIFACT_BUCKET=%s\nAPP_DOMAIN=%s\n' "$REGION" "$ARTIFACT_BUCKET" "$APP_DOMAIN" > /etc/lab-auth/deployment.env
for attempt in $(seq 1 180); do
  if aws s3 cp "s3://$ARTIFACT_BUCKET/releases/source.tar.gz" /opt/lab-auth/source.tar.gz --region "$REGION" --only-show-errors; then break; fi
  sleep 5
done
tar xzf /opt/lab-auth/source.tar.gz -C /opt/lab-auth
chmod 700 /opt/lab-auth/infra/update.sh /opt/lab-auth/infra/backup.sh
/opt/lab-auth/infra/update.sh
cat > /etc/systemd/system/lab-auth-backup.service <<'UNIT'
[Unit]
Description=Back up Auth Lab PostgreSQL to private encrypted S3
After=docker.service
[Service]
Type=oneshot
ExecStart=/opt/lab-auth/infra/backup.sh
UNIT
cat > /etc/systemd/system/lab-auth-backup.timer <<'UNIT'
[Unit]
Description=Daily Auth Lab database backup
[Timer]
OnCalendar=*-*-* 03:10:00 UTC
RandomizedDelaySec=600
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now lab-auth-backup.timer
touch /etc/lab-auth/bootstrap-complete
echo 'AUTH_LAB_BOOTSTRAP_COMPLETE'
