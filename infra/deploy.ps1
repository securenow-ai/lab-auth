param(
  [string]$Region = 'eu-west-3',
  [Parameter(Mandatory=$true)][string]$HostedZoneId,
  [Parameter(Mandatory=$true)][string]$VpcId,
  [Parameter(Mandatory=$true)][string]$SubnetId,
  [ValidatePattern('^[a-z0-9.-]+$')][string]$Domain = 'lab-auth.labs.securenow.ai',
  [string]$StackName = 'lab-auth'
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
function Invoke-Aws {
  param([string[]]$Arguments)
  $result = & aws @Arguments
  if ($LASTEXITCODE -ne 0) { throw "AWS command failed: $($Arguments[0..1] -join ' ')" }
  return $result
}
if ((git status --porcelain).Length -gt 0) { throw 'Commit all source changes before deploying. Deployments archive HEAD only.' }
New-Item -ItemType Directory -Path '.deployment' -Force | Out-Null
$null = & aws secretsmanager describe-secret --secret-id lab-auth/runtime --region $Region 2>$null
if ($LASTEXITCODE -ne 0) {
  node -e "const fs=require('fs'),c=require('crypto');const r=()=>c.randomBytes(48).toString('base64url');fs.writeFileSync('.deployment/runtime.json',JSON.stringify({POSTGRES_PASSWORD:r(),SESSION_SECRET:r(),AUDIT_HMAC_SECRET:r(),ADMIN_EMAIL:'lab-admin@securenow.ai',ADMIN_PASSWORD:r(),GOOGLE_CLIENT_ID:'',GOOGLE_CLIENT_SECRET:''}));"
  if ($LASTEXITCODE -ne 0) { throw 'Secret generation failed' }
  $null = Invoke-Aws -Arguments @('secretsmanager','create-secret','--name','lab-auth/runtime','--secret-string','file://.deployment/runtime.json','--region',$Region)
  Remove-Item -LiteralPath '.deployment/runtime.json'
}
$null = Invoke-Aws -Arguments @('cloudformation','deploy','--stack-name',$StackName,'--template-file','infra/cloudformation.json','--capabilities','CAPABILITY_IAM','--parameter-overrides',"VpcId=$VpcId","SubnetId=$SubnetId","HostedZoneId=$HostedZoneId","Domain=$Domain",'--region',$Region,'--no-fail-on-empty-changeset')
$outputs = (Invoke-Aws -Arguments @('cloudformation','describe-stacks','--stack-name',$StackName,'--region',$Region,'--query','Stacks[0].Outputs','--output','json') | ConvertFrom-Json)
$bucket = ($outputs | Where-Object OutputKey -eq ArtifactBucket).OutputValue
$instance = ($outputs | Where-Object OutputKey -eq InstanceId).OutputValue
git archive --format=tar.gz --output=.deployment/source.tar.gz HEAD
if ($LASTEXITCODE -ne 0) { throw 'Git archive failed' }
$null = Invoke-Aws -Arguments @('s3','cp','.deployment/source.tar.gz',"s3://$bucket/releases/source.tar.gz",'--sse','AES256','--region',$Region,'--only-show-errors')
for ($attempt = 0; $attempt -lt 60; $attempt++) {
  $online = Invoke-Aws -Arguments @('ssm','describe-instance-information','--filters',"Key=InstanceIds,Values=$instance",'--region',$Region,'--query','InstanceInformationList[0].PingStatus','--output','text')
  if ($online -eq 'Online') { break }
  Start-Sleep -Seconds 5
}
if ($online -ne 'Online') { throw 'Instance has not joined Systems Manager. The first release remains uploaded; inspect EC2 boot logs.' }
$parameters = @{commands=@('if test -f /etc/lab-auth/bootstrap-complete; then /usr/bin/bash /opt/lab-auth/infra/update.sh; else echo First-release-bootstrap-is-in-progress-check-cloud-init-output; fi')} | ConvertTo-Json
[System.IO.File]::WriteAllText((Join-Path (Get-Location) '.deployment/ssm-parameters.json'),$parameters)
$commandId = Invoke-Aws -Arguments @('ssm','send-command','--instance-ids',$instance,'--document-name','AWS-RunShellScript','--parameters','file://.deployment/ssm-parameters.json','--region',$Region,'--query','Command.CommandId','--output','text')
Write-Output "Release uploaded. Instance: $instance. SSM command: $commandId. App: https://$Domain"
Write-Output 'Inspect deployment status with aws ssm get-command-invocation and verify /readyz over HTTPS.'
