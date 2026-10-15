import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

// Deliberately small, offline guardrail. A passing scan is not proof that a file is safe.
const files = [...new Set(execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean))];
const findings = [];
const sensitivePath = /(^|\/)(?:\.deployment\/|backups\/)|(^|\/)(?:\.env(?:\..+)?|\.aws\/credentials|\.securenow\/(?:admin|runtime|credentials[^/]*)\.json)$|\.(?:pem|p12|pfx|key|dump|sql\.gz)$/i;
const signatures = [
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ['AWS access key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ['Google OAuth client secret', /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/],
  ['SecureNow runtime key', /\bsnk_live_[A-Za-z0-9_-]{20,}\b/],
];

for (const file of files) {
  if (file !== '.env.example' && sensitivePath.test(file)) {
    findings.push(`${file}: credential-like filename must not be published`);
    continue;
  }
  let contents;
  try {
    if (statSync(file).size > 2_000_000) continue;
    contents = readFileSync(file, 'utf8');
  } catch { continue; }
  if (contents.includes('\0')) continue;
  for (const [name, pattern] of signatures) {
    if (pattern.test(contents)) findings.push(`${file}: possible ${name}`);
  }
}

if (findings.length) {
  process.stderr.write(`Secret scan failed (values omitted):\n${findings.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Secret scan passed for ${files.length} Git-visible files.\n`);
}
