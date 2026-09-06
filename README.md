# RhoWalkers

A community-owned compute network for public elliptic-curve discrete-log challenges
(Certicom ECCp-109/131, Bitcoin puzzle #135). Anyone with a GPU points it at a round,
runs Pollard rho, and is paid pro rata for verified work when the round is solved.

This repository is the **MVP**: the whole protocol end to end on a toy curve, in Python,
so every design decision can be exercised before a single GPU kernel is written.

```
python -m rhowalkers.gencurve --bits 56 --out rounds/r56.json     # a 56-bit prime-order curve + secret k
python -m rhowalkers.coordinator --round rounds/r56.json          # http://127.0.0.1:8642
python -m rhowalkers.miner --procs 4 --payout 0x<your address>    # mint a ticket, walk, submit DPs
./demo.sh                                                       # all of the above + 3 honest miners + 1 cheater
```

## What it does

| Stage | Where | What happens |
|---|---|---|
| Round spec | `rounds/*.json` | Curve, target `Q = k·G`, DP bits `w`, walk table size `r`, ticket difficulty, credit unit, prize pool. Static; never mutated once published. |
| Identity | `miner.py` | Ed25519 key. Every submission is signed, so nobody can frame a miner with fabricated DPs. |
| Ticket | `ec.ticket_solve` | Curve-native proof of work: walk from `PRF(round, pubkey, nonce)` until `x` has `ticket_d` trailing zero bits. Same kernel as mining, so botnets and ASICs get no edge over honest GPUs. Replayed once by the coordinator. |
| Start points | `ec.derive_start` | `(a0, b0) = PRF(round, pubkey, t)`. No seed server: anyone can recompute any walk from public data. |
| Walks | `ec.BatchWalker` | r-adding walk, `B` walks in lock-step, one modular inversion per step (Montgomery's trick, the shape of a real GPU kernel). ~500k steps/s per CPU core. |
| Distinguished points | `coordinator.submit` | Format, range, on-curve, quota (slow start doubling per epoch), uniqueness. A deterministic 1-in-N segments are **fully replayed**; one failure slashes the identity and zeroes its credits. |
| Collision | `ec.solve_collision` | Same `x` from two walks -> solve for `k`, check `k·G == Q`, close the round. |
| Ledger | `coordinator.close_epoch` | `1 credit = 2^credit_unit_log2` verified steps; a DP is worth `2^w` steps. Every epoch: Merkle root over `(payout address, credited steps)`. |
| Settlement | `contracts/src/PrizeVault.sol` | Operator posts roots; after the solve, `settle(root, total)`; each miner `claim(steps, proof)` pulls `pool × mine / total`. `abort()` refunds the depositor. Hashing matches `merkle.py` byte for byte (tested with a Python-generated fixture). |
| Dashboard | `static/index.html` | Progress against `1.25·√n` (a mean, not a deadline), network rate, miners, replays, slashes, epoch roots, and the payout table once solved. |

## Layout

```
rhowalkers/ec.py           curve arithmetic, walks, PRF starts, tickets, replay, collision solve
rhowalkers/merkle.py       sha256 Merkle tree (mirrors PrizeVault.sol)
rhowalkers/gencurve.py     random prime-order curve by BSGS point counting (<= ~64 bits)
rhowalkers/coordinator.py  FastAPI + sqlite: admission, intake, spot checks, ledger, epochs, API
rhowalkers/miner.py        identity, ticket, N worker processes, signed batches, --cheat mode
rhowalkers/static/         dashboard
contracts/               PrizeVault.sol + forge tests (forge test)
tests/test_ec.py         offline math checks (python tests/test_ec.py)
demo.sh                  end-to-end run
```

## API

```
GET  /api/round                    round spec
GET  /api/status                   progress, rate, counts, latest root, solution
GET  /api/miners                   leaderboard
GET  /api/epochs                   ledger roots
GET  /api/events                   admissions, replays, slashes, epochs, solve
GET  /api/proof?payout_addr=0x..   Merkle proof against the latest root (what you send to claim)
POST /api/ticket                   {round_id, pubkey, payout_addr, ticket:{nonce,steps,x}, sig}
POST /api/submit                   {round_id, pubkey, dps:[{x,y,a,b,t,steps}], sig}
```

## What the MVP proves, and what it does not

Proved end to end on 32/44/56-bit curves: PRF starts and tickets replay; batched walks
match the reference walk; a cheater who submits real-looking points with made-up
coefficients is slashed on the first replayed segment and cannot re-admit under the
same key; collisions solve `k` and the pool splits pro rata; Python roots verify inside
the Solidity vault.

Not in the MVP: the negation map (so expected work is `1.25·√n`, not `0.886·√n`), a GPU
kernel, the staked committee (v2 coordinator), IPFS/blob publication of the DP table,
commit-reveal of the final `k`, and any answer to the bearer-asset problem of puzzle #135.

## Setup

```
python3 -m venv .venv && .venv/bin/pip install fastapi 'uvicorn[standard]' cryptography httpx
cd contracts && forge install foundry-rs/forge-std --no-git && forge test
```
