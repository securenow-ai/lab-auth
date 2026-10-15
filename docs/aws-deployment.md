# AWS deployment and operations

The deployment scripts create a dedicated single-host lab. The default region is `eu-west-3`; select an AWS account and Route 53 hosted zone that you control. This runbook describes a copy of the lab and does not grant access to the SecureNow-hosted instance.

## Resources and trust boundaries

- An Amazon Linux 2023 EC2 instance, with a `t3.small` baseline, encrypted EBS storage, and IMDSv2 required.
- Inbound TCP 80 and 443 for Caddy. There is no inbound SSH or PostgreSQL rule.
- Docker Compose services for Caddy, Express, and PostgreSQL. App/database ports are private to the container network.
- Route 53 DNS and Caddy-managed TLS certificates for the chosen domain.
- An instance role for Systems Manager, the specific runtime secret, and the private artifact/backup bucket.
- An encrypted private S3 bucket for source releases and database backups.
- An AWS Secrets Manager secret named `lab-auth/runtime`, holding deployment-specific secret values.

The database is on the same host as the app. This reduces lab cost but provides no multi-host failover. A host or volume failure can interrupt every service. Use a managed database and a separate availability design for a production adaptation.

## Provision a deployment

Prerequisites: AWS CLI v2 authenticated to the intended account, PowerShell, Node.js 22, Git, permission to provision the template resources, a Route 53 hosted zone, and control of the selected hostname. Supply a VPC and public subnet in the selected region with an Internet Gateway route and outbound connectivity for SSM, package/image downloads, Secrets Manager, S3, Google, and certificate issuance. Review the CloudFormation template and deployment script before running them.

```powershell
aws sts get-caller-identity
./infra/deploy.ps1 -Region eu-west-3 -VpcId YOUR_VPC_ID -SubnetId YOUR_PUBLIC_SUBNET_ID -HostedZoneId YOUR_ROUTE53_ZONE_ID -Domain lab-auth.labs.securenow.ai
```

For a fork, substitute your domain. Do not point a deployment at a hostname used by another service. Commit the reviewed source first: the script refuses a dirty checkout and packages `HEAD`, rather than arbitrary working-tree files. It provisions the dedicated stack, creates a generated runtime secret if that named secret does not already exist, and starts bootstrap. The host retrieves the source archive and runtime secret through its instance role. It never needs a committed AWS key.

The default bucket and secret names are designed for one lab per account/region. An existing `lab-auth/runtime` secret is reused. Inspect and intentionally rename resources before creating a second independent copy; changing `StackName` alone does not isolate those names.

Wait for stack creation, Systems Manager connectivity, bootstrap completion, DNS resolution, and certificate issuance. CloudFormation success alone does not establish application readiness.

```sh
curl --fail https://YOUR_LAB_HOST/healthz
curl --fail https://YOUR_LAB_HOST/readyz
```

Test a fictional account registration, valid and invalid login, role boundaries, logout, Google sign-in when configured, and rejected mutations without a valid CSRF token. Confirm database persistence after an app-container restart.

## Secrets and initial admin access

The runtime secret contains separate values for `POSTGRES_PASSWORD`, `SESSION_SECRET`, `AUDIT_HMAC_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET`. Keep Google fields blank when Google sign-in is disabled. Both must be supplied together to enable it.

An authorized operator can read the secret through the AWS Secrets Manager console or AWS CLI from a private terminal. Do not paste the secret JSON into issues, chat, recordings, CI logs, or documentation. Use its bootstrap email/password to enter the admin dashboard, then change the account password. This repository deliberately does not contain the deployed password.

On the host, runtime secret material is written under `/etc/lab-auth` with restrictive permissions and injected at runtime. The source archive and Docker build context exclude private environment and runtime-credential files. Google client configuration is covered in [Google OAuth setup](google-oauth.md).

## Operate through Systems Manager

Find the stack's instance ID and start a session using an authorized AWS principal:

```sh
aws ssm start-session --target YOUR_INSTANCE_ID --region eu-west-3
```

Session Manager may require the AWS Session Manager plugin on the operator's computer. Use `sudo` for the following host operations:

```sh
cd /opt/lab-auth
sudo docker compose -f compose.production.yaml ps
sudo docker compose -f compose.production.yaml logs --tail 100 app caddy
sudo systemctl status lab-auth-backup.timer
```

Log output is operational data. Redact any unexpected personal data before sharing it. Do not enable shell tracing while handling runtime secrets.

After publishing a new release artifact, or after updating the runtime secret, refresh with:

```sh
sudo /opt/lab-auth/infra/update.sh
```

The update script reads the secret, builds the app, runs migrations/bootstrap, and starts the Compose services. Re-run readiness and authentication smoke tests. Expect a brief interruption on this single-host deployment. Review migrations and take a backup before a schema-changing release. Source rollback alone does not reverse database migrations.

## Backup and restore exercises

The bootstrap installs `lab-auth-backup.timer`. It schedules an encrypted database dump to the private bucket daily at approximately **03:10 UTC**, with up to ten minutes of randomized delay. This is separate from app telemetry. Review backup success and perform a restore drill before relying on it.

To trigger a backup immediately:

```sh
sudo /opt/lab-auth/infra/backup.sh
sudo journalctl -u lab-auth-backup.service --since today
```

Backups contain authentication records and audit events. Restrict access, encrypt transport and storage, and avoid downloading them into the repository. A successful upload is not a verified restore.

The bucket is versioned. The template expires backup objects and their noncurrent versions after seven days, and old release versions after fourteen days. The bucket itself is retained when its stack is deleted. Review these settings against your retention requirements.

For a restore drill, download a backup to a private location and restore into a fresh isolated PostgreSQL database with the matching schema, never over the live lab. For example, using a local Compose PostgreSQL service:

```sh
docker compose exec -T postgres createdb -U lab_auth lab_auth_recovery
gzip -dc /PRIVATE/PATH/backup.sql.gz | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U lab_auth -d lab_auth_recovery
```

Point an isolated application copy at that restored database, confirm users/roles and fictional records, and sign in with a test account. Record recovery time and backup age. Keep the isolated copy off public DNS, rotate secrets before any later promotion, and delete the private drill data when finished.

## Monitor, rotate, and retire

Monitor host disk space, container health, readiness, backup results, certificate renewal, and unexpected authentication failures. The current lab does not include high-availability failover or a verified SecureNow alert configuration. Add those deliberately in the later tutorial phase.

Rotate session, audit-HMAC, database, Google, and runtime SDK credentials as separate changes with tests. Changing the session secret invalidates cookies; changing the audit-HMAC secret changes future IP correlation; changing a PostgreSQL password also requires changing the database role's actual password before updating the application connection string. Updating `POSTGRES_PASSWORD` on an initialized Docker volume alone does not change that database role.

When retiring a copy, first decide whether any backup or evidence needs private retention. Delete the dedicated stack, remove its DNS records if retained, remove the lab's runtime secret and unused Google client, and remove retained S3 objects/buckets according to your retention decision. Confirm these targets belong to this deployment before deleting them. Do not delete a shared hosted zone or a shared Google project.
