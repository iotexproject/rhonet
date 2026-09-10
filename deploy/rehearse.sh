#!/bin/bash
# Launch rehearsal. Run this before opening a round, and after any change to
# intake, the audit or settlement. It exercises the production path -- the real
# start script, a real drand beacon, the loopback bind a tunnel fronts, CORS,
# /healthz, the monitor probe, publishing and independently re-deriving the audit
# trail -- on a round small enough to finish inside ten minutes.
#
# What it is looking for is not "does it solve". It is whether an honest walker
# comes out the far side unslashed, with nothing silent and nothing withheld. The
# first run of this script slashed two honest walkers, which no unit test had
# caught, because the failure only exists in aggregate.
#
# Launch rehearsal on the Studio: the exact production path (deploy/run-coordinator.sh,
# real drand beacon, tunnel-shaped loopback bind, CORS, /healthz, monitor probe)
# on a round small enough to finish, but with epochs long enough that drand moves.
set -uo pipefail
cd ~/rhonet-work/wip
PY=.venv/bin/python
rm -rf rehearsal && mkdir -p rehearsal logs

echo "== generating a 60-bit round with 60s epochs"
$PY -m rhonet.gencurve --bits 60 --round-id rehearsal --w 14 --ticket-d 18 --v 6 \
    --r 32 --spot-check-rate 32 --epoch-seconds 60 --quota 16384 --credit-unit-log2 14 \
    --out rehearsal/round.json || exit 1
$PY -c "import json;d=json.load(open('rehearsal/round.json'));print({k:d[k] for k in ('round_id','bits','w','v','ticket_d','epoch_seconds','max_walk_len_log2','expected_steps')})"

echo "== starting the coordinator through deploy/run-coordinator.sh"
ROUND=rehearsal/round.json DB=rehearsal/db.sqlite PORT=8643 \
  nohup deploy/run-coordinator.sh > logs/rehearsal-coord.log 2>&1 &
COORD=$!
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8643/healthz >/dev/null 2>&1 && break; sleep 1; done

echo "== healthz"; curl -fsS http://127.0.0.1:8643/healthz; echo
echo "== CORS (site origin, then a stranger)"
curl -fsS -o /dev/null -D - -H 'Origin: https://rhonet.dev' http://127.0.0.1:8643/api/status | grep -i 'access-control' || echo "  no header for rhonet.dev -- BAD"
curl -fsS -o /dev/null -D - -H 'Origin: https://evil.example' http://127.0.0.1:8643/api/status | grep -i 'access-control' && echo "  header for a stranger -- BAD" || echo "  correctly no header for a stranger"

echo "== two walkers, 4 procs each"
for i in 1 2; do
  $PY -m rhonet.walker --coordinator http://127.0.0.1:8643 --key rehearsal/w$i.key \
      --payout 0x$(printf '%040d' $i) --procs 4 --batch 48 --max-seconds 900 \
      > logs/rehearsal-w$i.log 2>&1 &
done

for t in $(seq 1 60); do
  sleep 20
  S=$(curl -fsS http://127.0.0.1:8643/api/status)
  echo "$S" | $PY -c "
import json,sys
d=json.load(sys.stdin)
ep=[e for e in d['epochs'] if e['audit_complete']]
print('t=%4ds status=%-9s epoch=%2d closed=%2d dps=%5d rate=%6.2fM/s active=%d slashed=%d replay=%d'%(
  $t*20, d['status'], d['epoch'], len(ep), d['dps'], d['steps_per_sec']/1e6,
  d['active_contributors'], d['slashed'], d['verification_replay_steps']))"
  [ "$(echo "$S" | $PY -c 'import json,sys;print(json.load(sys.stdin)["status"])')" = "solved" ] && break
done

echo "== audit outcome per epoch (silence here means an honest walker was failed)"
.venv/bin/python -c "
import sqlite3
db=sqlite3.connect('rehearsal/db.sqlite')
for row in db.execute('SELECT epoch,result,COUNT(*) FROM challenges GROUP BY epoch,result ORDER BY epoch'):
    print('  epoch %d %-9s %d'%row)
print('  withheld rows:', db.execute('SELECT COUNT(*) FROM withheld').fetchone()[0])
"

echo "== distinct drand beacons per epoch"
curl -fsS http://127.0.0.1:8643/api/status | $PY -c "
import json,sys
d=json.load(sys.stdin)
rev=[(e['idx'],(e.get('beacon_reveal') or '')[:16]) for e in d['epochs'] if e['audit_complete']]
print(rev)
vals=[r for _,r in rev if r]
print('epochs closed:',len(rev),' distinct beacons:',len(set(vals)),'OK' if len(set(vals))==len(vals) else 'REPEATED -- BAD')
print('beacon_mode:',d['beacon_mode'])"

echo "== final board"
curl -fsS http://127.0.0.1:8643/api/contributors | $PY -c "
import json,sys
for r in json.load(sys.stdin):
  print('%-10s dps=%5d credits=%9.3f checks=%3d fails=%d %s'%(r['status'],r['dps'],r['credits'],r['spot_checks'],r['spot_fails'],r.get('device') or ''))"

echo "== monitor probe"; PORT=8643 PUBLIC=http://127.0.0.1:8643 deploy/monitor.sh; echo "monitor exit=$?"

echo "== publish + independently re-derive the audit trail"
$PY tools/publish_epochs.py --db rehearsal/db.sqlite --out rehearsal/epochs && $PY tools/verify_audit.py rehearsal/epochs
echo "verify_audit exit=$?"

echo "== solution"
curl -fsS http://127.0.0.1:8643/api/status | $PY -c "import json,sys;d=json.load(sys.stdin);print(d['status'], json.dumps(d.get('solution'))[:400])"
$PY -c "
import json,sys
sys.path.insert(0,'.')
from rhonet import ec
spec=ec.RoundSpec.load('rehearsal/round.json')
sec=json.load(open('rehearsal/round.secret.json'))
sol=json.load(open('rehearsal/solution.json')) if False else None
print('secret k =',sec.get('k'))"
kill $COORD 2>/dev/null
wait 2>/dev/null
echo "== done"
