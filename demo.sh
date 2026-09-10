#!/usr/bin/env bash
# End-to-end demo: fresh 56-bit round, coordinator, 3 honest walkers + 2 adversaries.
# Ends when the round is solved; checks k against the generator's secret.
set -euo pipefail
cd "$(dirname "$0")"
export RHONET_BEACON_URL=""
PY=.venv/bin/python
BITS=${BITS:-56}
PORT=${PORT:-8642}
LOG_DIR=${LOG_DIR:-logs}
mkdir -p data "$LOG_DIR"
DEMO_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rhonet-demo.XXXXXX")
mkdir -p "$DEMO_DIR/rounds"
$PY -m rhonet.gencurve --bits "$BITS" --round-id "demo-p$BITS" --out "$DEMO_DIR/rounds/demo.json" --epoch-seconds 15 --spot-check-rate 64

export RHONET_TICKET_IP_BURST=32 RHONET_TICKET_IP_RATE=8
export RHONET_TICKET_CONCURRENCY=4 RHONET_TICKET_QUEUE=64 RHONET_TICKET_WAIT_SECONDS=30
$PY -m rhonet.coordinator --round "$DEMO_DIR/rounds/demo.json" --db "$DEMO_DIR/demo.sqlite" --port "$PORT" > "$LOG_DIR/coordinator.log" 2>&1 &
COORD=$!
MINERS=()
cleanup() {
  kill "$COORD" "${MINERS[@]}" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1.5
kill -0 "$COORD"
echo "dashboard: http://127.0.0.1:$PORT/"
$PY -m rhonet.walker --coordinator "http://127.0.0.1:$PORT" --key data/alice.key --payout 0x00000000000000000000000000000000000a11ce --procs 3 > "$LOG_DIR/alice.log" 2>&1 &
MINERS+=("$!")
$PY -m rhonet.walker --coordinator "http://127.0.0.1:$PORT" --key data/mallory.key --payout 0x00000000000000000000000000000000000ba0d0 --procs 1 --cheat > "$LOG_DIR/mallory.log" 2>&1 &
MINERS+=("$!")
$PY -m rhonet.walker --coordinator "http://127.0.0.1:$PORT" --key data/evasive.key --payout 0x000000000000000000000000000000000000e0a5 --procs 1 --cheat-evasive > "$LOG_DIR/evasive.log" 2>&1 &
MINERS+=("$!")
$PY -m rhonet.walker --coordinator "http://127.0.0.1:$PORT" --key data/bob.key   --payout 0x0000000000000000000000000000000000000b0b --procs 2 > "$LOG_DIR/bob.log" 2>&1 &
MINERS+=("$!")
$PY -m rhonet.walker --coordinator "http://127.0.0.1:$PORT" --key data/carol.key --payout 0x000000000000000000000000000000000000ca01 --procs 1 > "$LOG_DIR/carol.log" 2>&1 &
MINERS+=("$!")
while true; do
  S=$(curl -sf "http://127.0.0.1:$PORT/api/status" || echo '{}')
  ST=$($PY -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('status','?'), f\"{d.get('progress',0)*100:.0f}%\", f\"{d.get('steps_per_sec',0)/1e6:.2f}M steps/s\", d.get('dps',0), 'DPs', d.get('active_contributors',0), 'active', d.get('slashed',0), 'slashed')" "$S")
  echo "  $ST"
  case "$ST" in solved*) break;; esac
  sleep 5
done
K=$(curl -s "http://127.0.0.1:$PORT/api/status" | $PY -c "import json,sys; print(json.load(sys.stdin)['solution']['k'])")
KS=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['k'])" "$DEMO_DIR/rounds/demo.secret.json")
echo "solved k=$K  secret k=$KS  match=$([ "$K" = "$KS" ] && echo yes || echo NO)"
[ "$K" = "$KS" ]
echo "--- payouts"; curl -s "http://127.0.0.1:$PORT/api/status" | $PY -c "import json,sys; [print(f\"  {p['payout_addr']}  {p['credits']:8.3f} credits  {p['share']*100:5.1f}%  {p['usdc']:8.2f} USDC\") for p in json.load(sys.stdin)['solution']['payouts']]"
echo "--- merkle proof for alice (latest payable epoch)"
ALICE_EPOCH=$(curl -sf "http://127.0.0.1:$PORT/api/proof/epochs?payout_addr=0x00000000000000000000000000000000000a11ce" | $PY -c 'import json,sys; print(json.load(sys.stdin)[-1])')
curl -s "http://127.0.0.1:$PORT/api/proof?payout_addr=0x00000000000000000000000000000000000a11ce&epoch=$ALICE_EPOCH" | $PY -m json.tool | head -12
curl -sf "http://127.0.0.1:$PORT/api/status" | $PY -c '
import json, sys
s = json.load(sys.stdin)
expected = {"0x00000000000000000000000000000000000a11ce", "0x0000000000000000000000000000000000000b0b", "0x000000000000000000000000000000000000ca01"}
payouts = s["solution"]["payouts"]
assert s["slashed"] == 2, s
assert {p["payout_addr"] for p in payouts} == expected, payouts
assert all(p["credits"] > 0 for p in payouts), payouts
print("PASS: three honest payouts; exactly two adversaries slashed")
search = s["total_executed_steps"] - s["total_ticket_steps"]
replayed = s["verification_replay_steps"]
print(f"verification: {replayed} replay / {search} search = {replayed/search:.6%}")'
echo "demo database: $DEMO_DIR/demo.sqlite"
