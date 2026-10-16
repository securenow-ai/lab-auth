#!/bin/bash
set -euo pipefail
umask 077
exec 9>/var/lock/lab-auth-deploy.lock
flock -n 9 || { echo 'AUTH_LAB_DEPLOY_ALREADY_RUNNING'; exit 0; }
source /etc/lab-auth/deployment.env
cd /opt/lab-auth
aws s3 cp "s3://$ARTIFACT_BUCKET/releases/source.tar.gz" /opt/lab-auth/source.tar.gz --region "$REGION" --only-show-errors
tar xzf source.tar.gz
# Never pass credential values as CLI arguments or print the secret response.
aws secretsmanager get-secret-value --secret-id lab-auth/runtime --region "$REGION" --query SecretString --output text > /etc/lab-auth/runtime.json
python3 - <<'PY'
import json, os, urllib.parse
from pathlib import Path
s = json.loads(Path('/etc/lab-auth/runtime.json').read_text())
domain = dict(line.split('=', 1) for line in Path('/etc/lab-auth/deployment.env').read_text().splitlines())['APP_DOMAIN']
values = {k: str(v) for k,v in s.items() if k in ('SESSION_SECRET','AUDIT_HMAC_SECRET','ADMIN_EMAIL','ADMIN_PASSWORD','GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET')}
values.update(DATABASE_URL='postgresql://lab_auth:'+urllib.parse.quote(s['POSTGRES_PASSWORD'],safe='')+'@db:5432/lab_auth', APP_ORIGIN='https://'+domain, TRUST_PROXY='1', NODE_ENV='production', HOST='0.0.0.0', PORT='3000')
assert all('\n' not in v and '\r' not in v for v in values.values())
# Docker env_file does not expand single-quoted dollar signs.
Path('/etc/lab-auth/app.env').write_text(''.join(k+"='"+v.replace('\\','\\\\').replace("'", "\\'")+"'\n" for k,v in values.items()))
Path('/opt/lab-auth/.env').write_text('POSTGRES_PASSWORD='+s['POSTGRES_PASSWORD']+'\nAPP_DOMAIN='+domain+'\n')
os.chmod('/etc/lab-auth/app.env',0o600)
os.chmod('/opt/lab-auth/.env',0o600)
# SecureNow runtime credential: `npx securenow credentials runtime --env test --stdout`, stored as the
# SECURENOW_CREDENTIALS_JSON string in the same secret. Readable only by the container's node user (uid 1000).
creds = s.get('SECURENOW_CREDENTIALS_JSON') or '{}'
json.loads(creds)
p = Path('/etc/lab-auth/securenow-credentials.json')
p.write_text(creds)
os.chown(p, 1000, 1000)
os.chmod(p, 0o400)
PY
docker compose -f compose.production.yaml build --pull app
docker compose -f compose.production.yaml up -d db
docker compose -f compose.production.yaml run --rm app npm run migrate
docker compose -f compose.production.yaml run --rm app npm run seed
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/lab-auth/app.env')
p.write_text(''.join(line+'\n' for line in p.read_text().splitlines() if not line.startswith(('ADMIN_PASSWORD=','ADMIN_EMAIL='))))
PY
docker compose -f compose.production.yaml up -d --remove-orphans
for attempt in $(seq 1 36); do
  if curl --fail --silent --show-error --max-time 10 "https://$APP_DOMAIN/readyz" > /dev/null; then
    echo 'AUTH_LAB_RELEASE_READY'
    exit 0
  fi
  sleep 5
done
echo 'AUTH_LAB_READINESS_FAILED' >&2
exit 1
