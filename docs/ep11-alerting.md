# Episode 11 — Turn any attack into an alert

This branch (`tutorial/ep11-alerting`) is the companion to the "How to Secure Your Apps" episode on SecureNow alert
rules: each rule is written in plain English, checked against the app's own data before it's saved, and then the lab is
attacked so you can watch it fire. Seven rungs, from one request to a baseline, and a coding agent writes the last one.

## Two kinds of rule

| | Instant | Periodic |
|---|---|---|
| Runs | on every request, as it arrives | on a schedule (every minute here), over a recent window |
| Sees | one request: path, method, user agent, status, body, headers, address, host | requests, security events (sign-ins, permission checks, account changes) and the app's own log lines |
| Good for | a single request that is enough evidence | counts, distinct counts, ratios, sequences, baselines |

Every new rule starts in **test mode**: it alerts and blocks nothing until you promote it.

## What's on this branch

- `ep11/attack.mjs`: ordinary traffic plus one attack per rung. LOCAL ONLY (addresses travel as X-Forwarded-For, which
  only the local lab trusts).

  | Scenario | Address | What it does | Rule it trips |
  |---|---|---|---|
  | `normal` | 198.51.100.230–.235, .40 | five colleagues, Dana, and an integration that exports notes every minute | none (it is the baseline) |
  | `scan` | 203.0.113.51 | asks for backup.sql, db.sql.gz, dump.sql, site.bak | instant |
  | `brute` | 192.0.2.77 | 12 wrong passwords on one account | threshold |
  | `stuffing` | 192.0.2.100–.139 | 3 tries each, one browser string, 6 accounts | distinct count |
  | `idor` | 203.0.113.60 | a signed-in account walks 30 note ids | ratio |
  | `takeover` | 203.0.113.253 | signs in as Dana from a new address, changes her password | sequence |
  | `exfil` | 203.0.113.252 | exports Dana's notes 8 times in two minutes | baseline |
  | `persistence` | 203.0.113.254 | password change, new org, admin invite to an outside address | the agent's rule |

- `ep11/agent-run.sh` + `ep11/agent-prompt.txt`: headless Claude Code with the SecureNow MCP server turns the
  persistence hypothesis into a rule (`build`), then confirms it fired after the attack (`verify`). Its only tools draft,
  create (test mode) and read rules and alerts.

## The rules, as we typed them

All with `--app <lab-auth key> --env staging` (or the dashboard's **Alert Rules → Describe in English**):

1. *Alert the moment anyone requests a database dump or backup file, like backup.sql, db.sql.gz, or anything ending in .bak* (dashboard)
2. `npx securenow alerts rules from-text "One IP address failing 10 or more sign-ins within 5 minutes"`
3. `… "Failed sign-ins that share one browser user agent, hitting 5 or more different accounts from 10 or more IP addresses within 10 minutes"`
4. `… "One signed-in user whose note reads in 10 minutes touch 15 or more different notes, counting both granted and denied permission checks, with at least half of those reads denied as not found"`
5. *A successful sign-in from an IP address the account has not used in the previous 7 days, followed within 5 minutes by a password change on the same account* (dashboard)
6. First `"An account exporting its notes 5 or more times within 10 minutes"` with `--draft-only`: its check flags the
   integration (normal for it). Then `"An account exporting its notes at least 5 times in the last 10 minutes, and at least
   5 times its own average per 10 minutes over the 2 hours before that. Check every minute."`
7. The agent: `bash ep11/agent-run.sh <app-key> build`, then `node ep11/attack.mjs persistence`, then `bash ep11/agent-run.sh <app-key> verify`.

Read every draft before you create it: the check shows what would alert today, and a draft can be wrong (our first
baseline divided the history by minutes instead of 10-minute periods; the check showed the integration alerting).

## Reproduce it locally

1. Connect the lab to SecureNow (Episode 2) and give the run its own environment, e.g. a run folder with
   `deploymentEnvironment: "staging"` on port 3105 (Episode 7 shows the setup).
2. `LAB_BASE=http://localhost:3105 NORMAL_MINUTES=420 node ep11/attack.mjs normal` and leave it running: the baseline
   rule compares each account with its own last two hours.
3. Create each rule, then run its scenario and watch the Threat Inbox (or `npx securenow notifications list --search "<rule name>"`).
4. Older armed rules on your app can fire first: an alert is skipped for an address that's already blocked.
