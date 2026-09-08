# RhoWalkers

**A crowd of Pollard rho walkers solving public elliptic-curve challenges together.**

A walker is one Pollard rho path on a curve. RhoWalkers is a crowd of them: anyone with a
GPU points it at a round, wanders the curve, and when any two walkers collide the whole crowd
is paid pro rata for the work it actually did.

Site: https://rhowalkers.pages.dev (mirror: https://iotexproject.github.io/rhowalkers) · Status: **MVP, protocol runs end to end on toy curves**

---

## Why

Certicom's ECCp-131 has been open since 1997 with a $20,000 prize, and is plausibly within
reach of a few hundred consumer GPUs running for weeks. Crowds have been organized for this
kind of problem before: ECCp-109 fell in 2002 to Chris Monico's volunteer effort of 10,308
participants across 247 teams over 549 days, ECC2K-130 was a multi-institution distributed
rho, and kangaroo pools with share accounting run against the Bitcoin puzzles today. What
none of them had was a way to pay strangers without trusting the organizer. The obstacles
are not mathematical:

- **Trust cliff.** Whoever coordinates sees the collision first and holds the key. Volunteers
  have no reason to believe they will be paid unless the prize is locked before the first step
  and released by a rule rather than by the operator's goodwill.
- **Cheating is cheap.** A distinguished point is a few dozen bytes; forging one costs nothing
  unless someone replays the walk that produced it, and the replay has to be unpredictable to
  the forger or it is simply avoided.
- **Nobody is paid until the end.** A round can run for months. Volunteers who leave early
  have historically gotten nothing.

RhoWalkers is a mining pool for cryptanalysis. It borrows what Bitcoin pools got right
(shares, proportional payout, pull-based claims) and adds what a cryptanalytic challenge needs:
permissionless admission through a curve-native ticket, sampled replay with slashing, and
on-chain pro-rata settlement of a prize locked before the first step.

## How it works

```
   round spec (static)          miner                      coordinator                  Ethereum L2
   ─────────────────       ────────────────           ─────────────────────         ────────────────
   curve, Q = k·G          Ed25519 identity  ──────►  ticket replayed once           PrizeVault
   w, r, ticket_d          curve-native ticket        slow-start quota               pool pre-funded
   credit unit             PRF-derived starts         signature + format checks
   prize pool              batched rho walks ──DPs──► 1-in-N segment replay          postRoot(epoch)
                           signed batches             slash on any failure              ▲
                                                      collision → solve k, verify       │ every epoch
                                                      credit = 2^w steps per DP  ───────┘
                                                      Merkle root per epoch            settle(root,total)
                           claim(steps, proof)  ◄───  proof served over HTTP  ───────► claim → USDC
```

**One unit of work is one credit.** A distinguished point with `w` trailing zero bits
represents `2^w` expected steps. One credit is `2^30` steps on real rounds (`2^20` on the
toy curves here). Credits are minted only for work that passed the checks below, and the
pool is divided once, after the collision, in proportion to credits minted in that round.
There is no block reward, no halving, no treasury, no vote.

**Nobody issues seeds.** A walker's start point is `PRF(round_id, pubkey, t)`. Anyone can
recompute any walk from public data, so the coordinator is stateless with respect to miners
and an auditor can re-verify any segment offline.

**Admission is the same kernel as mining.** A ticket is a walk from
`PRF(round_id, pubkey, nonce)` until `x` has `ticket_d` trailing zero bits. It costs a
weak device a few seconds and gives a botnet or an ASIC no advantage over an honest GPU.
The coordinator replays it once per identity; quota then doubles every epoch.

**Cheating is caught by replay, not by proof.** A deterministic `1/N` of submitted segments
are walked again from their PRF start. A forged segment cannot know whether it will be
picked. One failure slashes the identity, zeroes its credits and blocks re-admission under
that key. Both sides of a candidate collision are replayed before `k` is trusted.

**Settlement is pull-based.** Every epoch the coordinator posts one Merkle root of
`(payout address, credited steps)`. After the solve it posts the final root and the total;
each miner sends one `claim(steps, proof)` transaction. Operator gas does not scale with
the number of miners. Abort is a condition rather than a decision: an external solve, a
deadline, or coordinator silence must be provable on chain and callable by anyone, and each
sponsor recovers their own deposit.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install fastapi 'uvicorn[standard]' cryptography httpx
./demo.sh                     # 56-bit round, coordinator, 3 honest miners + 1 cheater, ~2 min
open http://127.0.0.1:8642    # dashboard
```

By hand:

```bash
python -m rhowalkers.gencurve --bits 56 --out rounds/r56.json     # prime-order curve + secret k (toy only)
python -m rhowalkers.coordinator --round rounds/r56.json          # http://127.0.0.1:8642
python -m rhowalkers.miner --procs 4 --payout 0x<your address>    # ticket, walk, submit
python -m rhowalkers.miner --cheat                                # watch it get slashed
python tests/test_ec.py                                           # offline math
cd contracts && forge install foundry-rs/forge-std --no-git && forge test
```

What a demo run looks like (56-bit curve, one laptop):

| | |
|---|---|
| Expected work | 3.1e8 steps (1.25·√n, no negation map) |
| Solved after | 74% of expected, ~100 s, k verified against the generator's secret |
| Miners | 3 honest (3/2/1 processes) paid 46% / 35% / 19%; 1 cheater slashed on its first replayed segment |
| Replays | 1 in 64 segments; 191 replays, 0 false positives |
| Ledger | 7 epoch roots; Merkle proofs verify in Python and in the Solidity vault |

## Layout

```
rhowalkers/ec.py           curve arithmetic, r-adding walks, batched inversion, PRF starts, tickets, replay, collision solve
rhowalkers/merkle.py       sha256 Merkle tree, byte-identical to PrizeVault.sol
rhowalkers/gencurve.py     random prime-order curves by BSGS point counting (toy sizes)
rhowalkers/coordinator.py  FastAPI + sqlite: admission, intake, replays, ledger, epochs, API, dashboard
rhowalkers/miner.py        identity, ticket, worker processes, signed batches, --cheat
rhowalkers/static/         dashboard (single file, no build)
contracts/                 PrizeVault.sol + forge tests against a Python-generated fixture
docs/                      project site (GitHub Pages)
tests/test_ec.py           offline checks
demo.sh                    end-to-end run
```

## API

```
GET  /api/round                    round spec
GET  /api/status                   progress, rate, counts, latest root, solution
GET  /api/miners                   leaderboard
GET  /api/epochs                   ledger roots
GET  /api/events                   admissions, replays, slashes, epochs, solve
GET  /api/proof?payout_addr=0x..   Merkle proof against the latest root
POST /api/ticket                   {round_id, pubkey, payout_addr, ticket:{nonce,steps,x}, sig}
POST /api/submit                   {round_id, pubkey, dps:[{x,y,a,b,t,steps}], sig}
```

## Roadmap

1. **Pre-mine 60–80 bit** rounds on this code to shake out the protocol. *(you are here)*
2. **GPU kernel** for the 131-bit field (RCKangaroo-class throughput: ~4e10 steps/s on an RTX 5090),
   negation map, look-ahead against fruitless cycles. Week-0 gate: measure real 131-bit throughput.
3. **ECCp-109** rerun, first closed then open, to calibrate quotas, replay rate and epoch size.
4. **ECCp-131**: ~6.5e19 steps at 1.25·√n, roughly 19 days on 1,000 RTX 5090s if the extrapolated
   rate of 4e10 steps per second per card holds. USDC pool in the vault plus the Certicom prize, which arrives weeks after the
   answer is submitted and so must be distributable after settlement, under the same root.
5. **v2 coordinator**: staked committee, each member running its own intake bucket, syncing
   only the replayed sample. Needed before a bearer-asset round.
6. **A bearer-asset round** (a Bitcoin puzzle) needs two things this code does not have: a
   Pollard kangaroo implementation, since a bounded interval is a different walk with a
   different collision equation, and a way to resolve the collision without any single party
   learning `k` first. Puzzle #135 was taken by a single solver on 28 July 2026; the community
   has repointed to #140. That outcome is the argument for both requirements.

## What is deliberately not here

- ZK proofs per distinguished point. Sampled replay is the right verifier here; proving every
  elliptic-curve step in zero knowledge costs orders of magnitude more than the work it proves.
- A transferable token, block rewards, halvings, governance. One round, one pool, one root.
- A data-availability layer. A distinguished point needs only a truncated `x` plus an identity
  and a counter, since the rest is recoverable by replay; the coordinator keeps the table,
  miners keep their own shards, daily snapshots are published. The MVP's sqlite schema stores
  decimal text and is far larger than that; the compact format is required before 131 bits.
- Any claim about P-256. Solving 131 bits says nothing about 256; the gap is 2^62.

## License

MIT
