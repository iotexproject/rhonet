#!/usr/bin/env bash
# End-to-end demo: fresh 44-bit round, coordinator, 3 honest miners + 1 cheater.
# Ends when the round is solved; checks k against the generator's secret.
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
BITS=${BITS:-56}
PORT=${PORT:-8642}
mkdir -p data logs rounds
pkill -f "rhoswarm.coordinator --round rounds/demo" 2>/dev/null || true
$PY -m rhoswarm.gencurve --bits "$BITS" --round-id "demo-p$BITS" --out rounds/demo.json --epoch-seconds 15 --spot-check-rate 64
rm -f data/demo.sqlite*
$PY -m rhoswarm.coordinator --round rounds/demo.json --db data/demo.sqlite --port "$PORT" > logs/coordinator.log 2>&1 &
COORD=$!
sleep 1.5
echo "dashboard: http://127.0.0.1:$PORT/"
$PY -m rhoswarm.miner --coordinator "http://127.0.0.1:$PORT" --key data/alice.key --payout 0x00000000000000000000000000000000000a11ce --procs 3 > logs/alice.log 2>&1 &
$PY -m rhoswarm.miner --coordinator "http://127.0.0.1:$PORT" --key data/bob.key   --payout 0x0000000000000000000000000000000000000b0b --procs 2 > logs/bob.log 2>&1 &
$PY -m rhoswarm.miner --coordinator "http://127.0.0.1:$PORT" --key data/carol.key --payout 0x000000000000000000000000000000000000ca01 --procs 1 > logs/carol.log 2>&1 &
$PY -m rhoswarm.miner --coordinator "http://127.0.0.1:$PORT" --key data/mallory.key --payout 0x00000000000000000000000000000000000ba0d0 --procs 1 --cheat > logs/mallory.log 2>&1 &
while true; do
  S=$(curl -sf "http://127.0.0.1:$PORT/api/status" || echo '{}')
  ST=$($PY -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('status','?'), f\"{d.get('progress',0)*100:.0f}%\", f\"{d.get('steps_per_sec',0)/1e6:.2f}M steps/s\", d.get('dps',0), 'DPs', d.get('active_miners',0), 'active', d.get('slashed',0), 'slashed')" "$S")
  echo "  $ST"
  case "$ST" in solved*) break;; esac
  sleep 5
done
K=$(curl -s "http://127.0.0.1:$PORT/api/status" | $PY -c "import json,sys; print(json.load(sys.stdin)['solution']['k'])")
KS=$($PY -c "import json; print(json.load(open('rounds/demo.secret.json'))['k'])")
echo "solved k=$K  secret k=$KS  match=$([ "$K" = "$KS" ] && echo yes || echo NO)"
echo "--- payouts"; curl -s "http://127.0.0.1:$PORT/api/status" | $PY -c "import json,sys; [print(f\"  {p['payout_addr']}  {p['credits']:8.3f} credits  {p['share']*100:5.1f}%  {p['usdc']:8.2f} USDC\") for p in json.load(sys.stdin)['solution']['payouts']]"
echo "--- merkle proof for alice (latest epoch)"; curl -s "http://127.0.0.1:$PORT/api/proof?payout_addr=0x00000000000000000000000000000000000a11ce" | $PY -m json.tool | head -12
echo "coordinator still running (pid $COORD) so you can look at the dashboard; kill with: kill $COORD"
