#!/usr/bin/env bash
# Episode 10, the agent segment: headless Claude Code with the SecureNow MCP server picks up a forensics
# conversation someone started in the dashboard and finishes the investigation. Read-only: the only tools it
# may call read telemetry or ask the forensics chat (which itself only runs SELECT queries).
# Usage: bash ep10/agent-run.sh <conversation-id>      transcript -> ep10/run/agent-session.jsonl
set -euo pipefail
cd "$(dirname "$0")/.."
CONV="$1"
PROMPT="$(sed "s/__CONVERSATION__/$CONV/" ep10/agent-prompt.txt)"
date -u +%Y-%m-%dT%H:%M:%SZ > ep10/run/agent-started.txt
claude -p "$PROMPT" \
  --mcp-config ep10/run/mcp.json --strict-mcp-config \
  --allowedTools "mcp__securenow__securenow_forensics_conversations_list,mcp__securenow__securenow_forensics_conversation_get,mcp__securenow__securenow_forensics_chat,mcp__securenow__securenow_forensics_chat_status,mcp__securenow__securenow_ip_lookup,mcp__securenow__securenow_apps_list" \
  --max-turns 40 --output-format stream-json --verbose < /dev/null > ep10/run/agent-session.jsonl 2> ep10/run/agent-session.err
echo "exit=$?" >> ep10/run/agent-started.txt
