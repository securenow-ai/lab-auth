// Keeps one environment of the lab running like a process manager would (pm2 / systemd / Docker restart policy):
// start the server with the SecureNow preload, restart it 2 s after any exit, count the restarts.
// Usage: node ep7/supervise.mjs <staging|production>   (stop: create ep7/run/STOP)
// Each environment runs from ep7/run/<env>/ with its own .env and .securenow/runtime.json (gitignored).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EP7 = path.dirname(fileURLToPath(import.meta.url));
const RUN = path.join(EP7, 'run');
const ROOT = path.resolve(EP7, '..');
const env = process.argv[2];
const dir = path.join(RUN, env);
if (!fs.existsSync(dir)) throw new Error(`no run folder for ${env}`);
const log = fs.createWriteStream(path.join(dir, 'server.log'), { flags: 'a' });
let restarts = 0;

function start() {
  if (fs.existsSync(path.join(RUN, 'STOP'))) return;
  const child = spawn(process.execPath, ['-r', path.join(ROOT, 'node_modules', 'securenow', 'register.js'), path.join(ROOT, 'src', 'server.js')], { cwd: dir });
  child.stdout.pipe(log, { end: false });
  child.stderr.pipe(log, { end: false });
  child.on('exit', (code, signal) => {
    restarts++;
    const line = `${new Date().toISOString()} exit code=${code} signal=${signal} restarts=${restarts}`;
    log.write(`\n[supervisor] ${line}\n`);
    fs.writeFileSync(path.join(dir, 'restarts.txt'), `${restarts}\n${line}\n`);
    setTimeout(start, 2000);
  });
}
start();
