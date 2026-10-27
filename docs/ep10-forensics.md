# Episode 10 — Investigate an attack by asking questions

This branch (`tutorial/ep10-forensics`) is the companion to the "How to Secure Your Apps" episode on SecureNow's
forensics chat: one account-takeover investigation, asked in plain English, continued from the dashboard to the
terminal to a coding agent, all in the same conversation.

## What's on this branch

1. `src/app.js` writes one JSON log line per notes export: `{"event":"notes.export","userId":…,"notes":N}` (no titles
   or bodies). SecureNow stores it with the request's `trace_id`, so the investigation can tie it to the request.
2. `ep10/incident.mjs` plays a realistic incident against the local lab, with ordinary traffic around it, and records
   every request (`ep10/run/incident-log.jsonl`) and the ground truth (`ep10/run/incident-summary.json`), so every
   answer can be checked. All accounts are fictional; all addresses are documentation ranges (RFC 5737).

   | Who | Address | What |
   |---|---|---|
   | Five colleagues | 198.51.100.231–.235 | Browse, write notes; one mistypes a password once; one exports their own notes |
   | Dana | 198.51.100.230 | Signs in from her Mac, writes 7 notes, later can't sign in |
   | Credential stuffing | 192.0.2.100–.139 | 120 failed sign-ins in 2.5 minutes, one shared user agent, 6 accounts, no success |
   | The takeover | 203.0.113.252 | Signs in as Dana on the first try, then 40 requests in 26 seconds |

   The takeover, in order: recon (`/api/me`, `/api/dashboard`, `/api/notes`) · admin probes (`GET /api/admin/users`,
   `GET /api/security`, `PATCH /api/admin/users/:id/role`, all 403) · a walk over note ids 734–759 (7 × 200 = Dana's
   own notes, 19 × 404: the app answers "not found" for notes that aren't yours) · 3 exports of her 7 notes · a password
   change (which locks Dana out) · an org and an admin invite to an outside address.

3. `ep10/agent-run.sh` + `ep10/agent-prompt.txt`: headless Claude Code with the SecureNow MCP server picks up the
   dashboard conversation by id and finishes the investigation, read-only.

## The investigation

Ask these in one forensics conversation (lab-auth app, the environment you ran the incident in). Each one builds on
the previous answer: none of the follow-ups repeats the address, the time or the user.

Dashboard:

1. *A customer with user id `<Dana's id>` says she can't sign in and thinks someone else got into her account. Show her
   sign-ins, failed sign-ins and account changes (password, role, invites), oldest first: time, event, IP, user agent
   and reason.* → 12 events: her Safari sign-in, 5 failures from the stuffing wave, a Firefox/Linux sign-in from
   203.0.113.252, a password change and an invite from the same address 26 s later, then her 3 failed sign-ins.
2. *That successful sign-in from the new address: had this account ever been used from that IP or that browser before
   it? And did that IP ever fail a sign-in, on any account?* → No, and no: first try.
3. *Those five failed sign-ins on her account: were they part of something bigger? Across the whole app, group failed
   sign-ins by user agent: attempts, distinct IPs, distinct accounts, first and last time, and how many sign-ins
   succeeded with that user agent.* → One Chrome/118 user agent: 120 failures, 40 IPs, 6 accounts, 0 successes.
   The loud attack wasn't the one that got in.

Terminal (`npx securenow forensics conversations` to find it, then `--conversation <id>`):

4. *List every request from that new address, in order: time, method, route, status. How long did it all take?* →
   40 requests in 26.1 seconds. In our run the route column came back empty (this app's spans don't fill it), and one
   follow-up fixed it: *The route column came back empty. Show the request path instead (http.target), same order.*
5. *Did any of it reach something her account isn't allowed to? From the permission checks for that address, count
   denied and granted by route and reason.* → 3 role denials, 19 not-found, 7 granted.
6. *The granted note reads: which note ids, and who owns those notes?* → 7 notes, all Dana's.
7. *From the app's notes.export log lines: each export's time, its userId and note count from the log line, and the
   client IP of the request that wrote it.* → 3 exports of 7 notes under Dana's id from 203.0.113.252 (and one
   colleague's own 2-note export).

Agent: `bash ep10/agent-run.sh <conversation-id>` → reads the conversation, asks what would survive a password reset
(the org and the admin invite), and writes the incident report.

## Reproduce it locally

1. Connect the lab to SecureNow (Episode 2) and set up a run folder as in Episode 7 with its own environment, for
   example `deploymentEnvironment: "preview"` on port 3104, so the investigation only sees this incident.
2. Start it with the Episode 7 supervisor, then run `LAB_BASE=http://localhost:3104 node ep10/incident.mjs` (about
   12 minutes).
3. Ask the questions above in the dashboard (Forensics → lab-auth → your environment), or from the terminal:
   `npx securenow forensics chat --app <app-key> --env preview "<question>"`, then
   `npx securenow forensics chat --conversation <id> "<next question>"`.
4. For the agent: `claude mcp add securenow -- npx securenow mcp`, then give it the conversation id. MCP tools:
   `securenow_forensics_chat` (pass `conversationId` to continue), `securenow_forensics_conversation_get`,
   `securenow_forensics_conversations_list`.

Compare every answer with `ep10/run/incident-summary.json`.
