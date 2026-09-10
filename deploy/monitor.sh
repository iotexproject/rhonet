#!/bin/bash
# One health probe, from the outside and from the inside. Exits nonzero when the
# round needs a human. Run it from cron/launchd every few minutes and read the log.
set -uo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8642}
PUBLIC=${PUBLIC:-https://api.rhonet.dev}
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fail=0

local_body=$(curl -fsS --max-time 10 "http://127.0.0.1:$PORT/healthz" 2>/dev/null) || {
  echo "$ts LOCAL DOWN: coordinator is not answering on 127.0.0.1:$PORT"; fail=1; }
public_body=$(curl -fsS --max-time 15 "$PUBLIC/healthz" 2>/dev/null) || {
  echo "$ts PUBLIC DOWN: $PUBLIC/healthz unreachable (tunnel? DNS?)"; fail=1; }

if [ -n "${local_body:-}" ]; then
  read -r ok behind failures epoch <<<"$(printf '%s' "$local_body" | .venv/bin/python -c '
import json,sys
d=json.load(sys.stdin)
print(d["ok"], d["epochs_awaiting_close"], d["epoch_loop_failures"], d["epoch"])')"
  echo "$ts epoch=$epoch awaiting_close=$behind loop_failures=$failures ok=$ok"
  # One epoch behind is normal: closing waits out the audit response window.
  [ "$ok" = "True" ] || { echo "$ts DEGRADED: epoch loop has failed $failures times"; fail=1; }
  [ "$behind" -le 1 ] || { echo "$ts STALLED: $behind epochs are waiting to close"; fail=1; }
fi

# A round that stops accepting work is worth knowing about even while healthy.
status=$(curl -fsS --max-time 15 "$PUBLIC/api/status" 2>/dev/null | \
  .venv/bin/python -c 'import json,sys;d=json.load(sys.stdin);print(d["status"],int(d["steps_per_sec"]),d["active_contributors"])' 2>/dev/null) || true
[ -n "$status" ] && echo "$ts public: $status"
exit $fail
