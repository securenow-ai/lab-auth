#!/usr/bin/env bash
# Episode 11, the agent segment: Claude Code with the SecureNow MCP server turns a hypothesis into a working
# alert rule. It may draft, create (always test mode) and read rules and notifications; nothing else.
# Usage: bash ep11/agent-run.sh <app-key> build     transcript -> ep11/run/agent-build.jsonl
#        bash ep11/agent-run.sh <app-key> verify    (after the persistence attack) -> ep11/run/agent-verify.jsonl
set -euo pipefail
cd "$(dirname "$0")/.."
APP_KEY="$1"
STEP="${2:-build}"
mkdir -p ep11/run
# The SecureNow MCP server over stdio, signed in with your `npx securenow login` credentials.
[ -f ep11/run/mcp.json ] || printf '%s\n' '{ "mcpServers": { "securenow": { "command": "npx", "args": ["securenow", "mcp"] } } }' > ep11/run/mcp.json
TOOLS="mcp__securenow__securenow_alert_rule_draft,mcp__securenow__securenow_alert_rule_draft_status,mcp__securenow__securenow_alert_rule_create,mcp__securenow__securenow_alert_rules_list,mcp__securenow__securenow_alert_rule_get,mcp__securenow__securenow_notifications_list,mcp__securenow__securenow_notifications_get,mcp__securenow__securenow_apps_list"
if [ "$STEP" = "build" ]; then
  PROMPT="$(sed "s/__APP_KEY__/$APP_KEY/" ep11/agent-prompt.txt)"
  claude -p "$PROMPT" --mcp-config ep11/run/mcp.json --strict-mcp-config --allowedTools "$TOOLS" \
    --max-turns 30 --output-format stream-json --verbose < /dev/null > ep11/run/agent-build.jsonl 2> ep11/run/agent-build.err
else
  claude -p "I ran the persistence attack. Did the rule you built fire? Check its alerts with the SecureNow MCP tools and tell me what it caught: the account, the address, the times." \
    --continue --mcp-config ep11/run/mcp.json --strict-mcp-config --allowedTools "$TOOLS" \
    --max-turns 15 --output-format stream-json --verbose < /dev/null > ep11/run/agent-verify.jsonl 2> ep11/run/agent-verify.err
fi
