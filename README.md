# RhoWalkers

**A crowd of Pollard rho walkers solving public elliptic-curve challenges together.**

A walker is one Pollard rho path on a curve. RhoWalkers is a crowd of them: anyone with a
GPU points it at a round, wanders the curve, and when any two walkers collide the whole crowd
is paid pro rata for the work it actually did.

Site: https://iotexproject.github.io/rhowalkers · Status: **MVP, protocol runs end to end on toy curves**

---

## Why

Certicom's ECCp-131 has been open since 1997 with a $20,000 prize. Bitcoin puzzle #135 holds
13.5 BTC. Both are within reach of a few hundred consumer GPUs running for weeks, and nobody
has organized that crowd. The reasons are not mathematical:

- **Trust cliff.** Whoever coordinates sees the collision first and holds the key. Volunteers
  have no reason to believe they will be paid.
- **Cheating is cheap.** A distinguished point is 24 bytes; forging one costs nothing unless
  someone replays the walk that produced it.
- **Nobody is paid until the end.** A round can run for months. Volunteers who leave early
  have historically gotten nothing.

RhoWalkers is a mining pool for cryptanalysis. It borrows what Bitcoin pools got right
(shares, proportional payout, pull-based claims) and adds what a cryptanalytic challenge needs
(verifiable work, deterministic replays, a prize locked in a contract before the first step).

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
that key. The colliding pair is always replayed in full before `k` is trusted.

**Settlement is pull-based.** Every epoch the coordinator posts one Merkle root of
`(payout address, credited steps)`. After the solve it posts the final root and the total;
each miner sends one `claim(steps, proof)` transaction. Operator gas does not scale with
the number of miners. If the round is aborted (external solve, timeout, coordinator
silence) the depositor is refunded and the credits stay recorded.

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
4. **ECCp-131**: ~4.5e19 steps, ~18 days on 1,000 RTX 5090s. USDC pool in the vault plus the
   Certicom prize claimed by a legal entity and distributed by the same root.
5. **v2 coordinator**: staked committee, each member running its own intake bucket, syncing
   only the replayed sample. Needed before a bearer-asset round.
6. **Bitcoin puzzle #135** only once the collision can be resolved without any single party
   learning `k` first (threshold computation, encrypted table snapshots), or explicitly as a
   trusted-operator round.

## What is deliberately not here

- ZK proofs per distinguished point. Replaying a `1/N` sample is optimal by a factor of
  10^5–10^7 over proving every step.
- A transferable token, block rewards, halvings, governance. One round, one pool, one root.
- A data-availability layer. The DP table is 24 bytes per point; the coordinator keeps it,
  miners keep their own shards, daily snapshots are published.
- Any claim about P-256. Solving 131 bits says nothing about 256; the gap is 2^62.

## License

MIT
