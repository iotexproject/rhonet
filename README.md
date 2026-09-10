# RhoNet

**Collective discovery for public cryptographic challenges.**

A crowd searches, every step is verified by replay, and whoever contributed shares the prize.

A walker is one Pollard rho path on a curve. RhoNet is a crowd of them: anyone with a
GPU points it at a round, wanders the curve, and when any two walkers collide the whole crowd
is paid pro rata for the work it actually did.

Site: https://rhonet.pages.dev (mirror: https://iotexproject.github.io/rhonet) · Status: **MVP, protocol runs end to end on toy curves**

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

Volunteer computing has existed since SETI@home, and it has never been able to pay a
stranger, because nobody could check what a stranger submitted. That is the part this
project builds. RhoNet borrows the accounting that mining pools got right (shares,
proportional payout, pull-based claims) and adds what a public cryptanalytic challenge
needs:
permissionless admission through a curve-native ticket, sampled replay with slashing, and
on-chain pro-rata settlement of a prize locked before the first step.

## How it works

```
   round spec (static)          walker                     coordinator                  Ethereum L2
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
recompute any walk from public data, so the coordinator issues no work
and an auditor can re-verify any segment offline.

**Admission is the same kernel as the search.** A ticket is a walk from
`PRF(round_id, pubkey, nonce)` until `x` has `ticket_d` trailing zero bits. It costs a
weak device a few seconds and gives a botnet or an ASIC no advantage over an honest GPU.
The coordinator replays it once per identity; quota then doubles every epoch.

**Cheating is caught by replay, not by proof.** A sample of submitted segments is walked
again from its PRF start. Selection happens after the batch is sealed, seeded by the epoch's
Merkle root mixed with a beacon no participant can compute in advance, so a forger cannot know
what will be picked. Work identifiers are deliberately unconstrained: the audit samples a
fixed fraction of each identity's submissions, so the count replayed follows how much you
submitted rather than which identifiers you chose, and choosing them freely buys nothing. A second pass re-audits older points the first pass never chose. One failure slashes
the identity, zeroes its credits and blocks re-admission under that key. Both sides of a
candidate collision are replayed before `k` is trusted.

**Settlement is pull-based.** Every epoch the coordinator posts one Merkle root of
`(payout address, credited steps)`. After the solve it posts the final root and the total;
each contributor sends one `claim(steps, proof)` transaction, so no operator gas is spent per
payout. Binding the denominator does cost the operator: `postRoot` now carries the full leaf
set so the contract can reconstruct the root itself, which is O(number of contributors) in
calldata every epoch. Decoupling that, a cheap root per epoch and one bound `settle`, is a
known follow-up. Abort is a condition rather than a decision: an external solve, a
deadline, or coordinator silence must be provable on chain and callable by anyone, and each
sponsor recovers their own deposit.

## The reference client is not the fast client

The coordinator verifies a submission by replaying a segment of the walk against the round
specification. It has no opinion about how the submission was produced. The Python client in
this repository therefore defines what *correct* means, not what *fast* means: it is a
reference implementation and it is slow.

Writing a faster client, in any language and on any hardware, is expected rather than
tolerated. Credit is proportional to verified work, so a better implementation is paid for
being better, and the board shows the client and the hardware next to the credit so the
difference is visible. The protocol's own numbers make the size of the opportunity plain:
one CPU core running this Python does roughly 0.7 million steps per second, and a hand-written
two-limb Montgomery implementation in C should be twenty to thirty times that per core before
anyone touches a GPU.

What a client must get right is small and fully specified: derive start points from the round
and its own public key, follow the adding walk, submit distinguished points with a Merkle
commitment to its checkpoint chain, sign the batch, and open a challenged segment on request.
A published specification and conformance vectors let an independent implementation prove
itself correct before it joins a round.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install fastapi 'uvicorn[standard]' cryptography httpx
./demo.sh                     # 56-bit round, coordinator, 3 honest contributors + 2 forgers
open http://127.0.0.1:8642    # dashboard
```

By hand:

```bash
python -m rhonet.gencurve --bits 56 --out rounds/r56.json     # prime-order curve + secret k (toy only)
python -m rhonet.coordinator --round rounds/r56.json          # http://127.0.0.1:8642
python -m rhonet.walker --procs 4 --payout 0x<your address>    # ticket, walk, submit
python -m rhonet.walker --cheat                                # watch it get slashed
python tests/test_ec.py                                           # offline math
cd contracts && forge install foundry-rs/forge-std --no-git && forge test
```

What a demo run looks like (56-bit curve, one laptop, three honest contributors and two forgers):

| | |
|---|---|
| Honest contributors | credited 47.8% / 35.4% / 16.8%, matching their process counts |
| Adversaries | a naive forger and one that filters its work identifiers to dodge the audit; both slashed |
| Solution | `k` verified against the generator's secret on every run |
| Ledger | epoch roots with published beacon commitments and reveals; proofs verify in Python and on chain |

A single run proves very little: rho completion has a standard deviation near half its mean.
The calibration below is 300 independent solves at each size, each checked against the secret.

| Bits | Solves | Mean, in units of √n | 3σ interval of the mean | 10th–90th percentile |
|---|---|---|---|---|
| 28 | 300 | 1.186 | 1.084 – 1.287 | 0.50 – 2.00 |
| 32 | 300 | 1.227 | 1.114 – 1.339 | 0.50 – 2.09 |
| 36 | 300 | 1.241 | 1.122 – 1.360 | 0.51 – 2.10 |
| 40 | 300 | 1.182 | 1.077 – 1.287 | 0.49 – 2.02 |

Theory puts the constant at 1.25 for an r-adding walk without the negation map. The fitted
scaling exponent is `0.5000` with `R² = 0.9998`.

## Layout

```
rhonet/ec.py           curve arithmetic, r-adding walks, batched inversion, PRF starts, tickets, replay, collision solve
rhonet/merkle.py       sha256 Merkle tree, byte-identical to PrizeVault.sol
rhonet/gencurve.py     random prime-order curves by BSGS point counting (toy sizes)
rhonet/coordinator.py  FastAPI + sqlite: admission, intake, replays, ledger, epochs, API, dashboard
rhonet/walker.py        identity, ticket, worker processes, signed batches, --cheat
rhonet/static/         dashboard (single file, no build)
contracts/                 PrizeVault.sol + forge tests against a Python-generated fixture
docs/                      project site (GitHub Pages)
tests/test_ec.py           offline checks
demo.sh                    end-to-end run
```

## API

```
GET  /api/round                    round spec
GET  /api/status                   progress, rate, counts, latest root, solution
GET  /api/contributors             leaderboard
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
  contributors keep their own shards, daily snapshots are published. The MVP's sqlite schema stores
  decimal text and is far larger than that; the compact format is required before 131 bits.
- Any claim about P-256. Solving 131 bits says nothing about 256; the gap is 2^62.

## License

MIT
