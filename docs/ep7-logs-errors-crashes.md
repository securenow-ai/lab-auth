# Episode 7 — Logs, errors and crashes, fixed by your agent

This branch (`tutorial/ep7-logs`) is the companion to the "How to Secure Your Apps" episode on monitoring logs,
errors and crashes with SecureNow and letting a coding agent fix them.

## What happened on this branch

1. `67cd739` moves the lab to `securenow@8.13.0`, the first version that records crashes (an uncaught exception or
   unhandled promise rejection becomes a `FATAL` log record with its stack trace before the process exits).
2. `69d2560` ships three small features **with three bugs planted on purpose** for the episode:
   - the notes CSV export counts words with `match(...).length`, which throws on a note with an empty body;
   - shareable invite links are built from `INVITE_LINK_BASE`, which staging never sets (`TypeError: Invalid URL`);
   - the invite expiry job queries a column that doesn't exist (`expires`) with no `try/catch`, so the server crashes
     every minute.
3. The same build ran locally as two environments, `staging` (port 3101) and `production` (port 3102), both reporting
   to one SecureNow app, with ordinary traffic from fictional users (`ep7/traffic.mjs`) for about 40 minutes.
4. A coding agent (Claude Code, headless) was asked, with the SecureNow MCP server connected:

   > Use the SecureNow MCP tools to pull the last 6 hours of error logs for the lab-auth app, across all environments.
   > Group them by root cause and tell me which environments each one hits. Then find each cause in this repo, fix it
   > with the smallest correct change, add a regression test for each fix, and run the test suite. Commit each fix
   > separately with a clear message, then push.

   It read about 370 error and crash records over MCP, grouped them into the three causes, and pushed
   `16f83c1`, `10da2a9` and `1d139aa` (21 tests passed) in 4 min 40 s.
5. After deploying `1d139aa` to both environments, the same query returned no errors and no crashes.
6. `d45b560` adds `.github/workflows/hourly-error-fixes.yml`: an hourly agent that reads the last hour of errors from
   SecureNow with a **Read Only** API key, opens one pull request per new root cause, and merges nothing on its own.
   It needs two repository secrets (`SECURENOW_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`) and only runs on schedule from
   the default branch.

## Reproduce it locally

1. Connect the lab to SecureNow (Episode 2), then create `ep7/run/staging/` and `ep7/run/production/` (gitignored),
   each with its own `.env` (different `PORT` and `APP_ORIGIN`; set `INVITE_LINK_BASE` only for production) and its
   own `.securenow/runtime.json` with `config.runtime.deploymentEnvironment` set to `staging` / `production`.
2. Check out `69d2560`, then run `node ep7/supervise.mjs staging`, `node ep7/supervise.mjs production` and
   `node ep7/traffic.mjs`. Create `ep7/run/STOP` to stop all three.
3. Connect your agent: `claude mcp add securenow -- npx securenow mcp`, and give it the prompt above.
