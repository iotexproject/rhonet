# RhoNet

**Collective discovery for public cryptographic challenges.**

A crowd searches, every step is verified by replay, and whoever contributed shares the prize.

A walker is one Pollard rho path on a curve. RhoNet is a crowd of them: anyone with a
GPU points it at a round, wanders the curve, and when any two walkers collide the whole crowd
is paid pro rata for the work it actually did.

Site: <https://iotexproject.github.io/rhonet> · Status: **Exercise 97 is specified and opening**

> `rhonet.dev` is serving a stale build and `api.rhonet.dev` does not resolve yet; both are
> blocked on a Cloudflare API token, and `tools/check_live.py` runs daily to say so rather
> than let it pass quietly. The GitHub Pages mirror above is current with `main`. The board
> will be at `https://api.rhonet.dev/api/status` when the round opens.

---

## Exercise 97: the first public round

**Status: opening.** The coordinator is not serving yet, so the round cannot be joined
today. Everything needed to be ready for it is published: the curve and its provenance, every
parameter with its reasoning, the wire specification, and conformance vectors an independent
client can check itself against before it ever connects. The client refuses to spend anything
on an admission ticket until the coordinator answers, so trying early costs nothing.

The round is Certicom's **ECCp-97** challenge — the original parameters, taken from
the client that solved it in March 1998 ([provenance](rounds/eccp97.provenance.md)) — about
**4.2 × 10¹⁴** elliptic-curve steps.

It has no prize, because it has a known answer. That is the reason to run it. When the
network reports a collision, the discrete logarithm it derives has to equal the number
published in 1998, so this round checks its own pipeline end to end on a real problem before
we run one whose answer nobody can check. Knowing the answer earns nobody credit: points are
paid for walks that replay from a PRF a walker does not control, and
[`tests/test_eccp97.py`](tests/test_eccp97.py) proves it.

Certicom's own word for the sub-109-bit problems is *exercises*. The parameters are real, the
difficulty is real, the prize is not.

| | |
|---|---|
| **Join** | [docs/JOIN.md](docs/JOIN.md) — register a GitHub identity, run the client, read the board |
| **Write a client** | [docs/PROTOCOL.md](docs/PROTOCOL.md) + [spec/vectors.json](spec/vectors.json) |
| **Why these parameters** | [docs/ROUND-97.md](docs/ROUND-97.md) |
| **Run the coordinator** | [docs/OPERATIONS.md](docs/OPERATIONS.md) |

After this: **ECCp-109** once a fast client exists, to measure the negation map at a
scale where it is measurable; then **ECCp-131**, unsolved since 1997, $20,000.

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
`(payout address, credited steps)`, at O(1) gas. Leaf totals are bound to that root exactly
once, at settlement, so the denominator cannot be understated and the operator does not pay
per-epoch calldata for the guarantee. After the solve, each contributor sends one
`claim(steps, proof)` transaction, so no operator gas is spent per payout. The residual
tradeoff is that an auditor needs the leaves off chain during the challenge window; they are
published. Abort is a condition rather than a decision: an external solve, a deadline, or
coordinator silence must be provable on chain and callable by anyone, and each sponsor
recovers their own deposit.

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
`tools/calibrate.py` solves many independent instances per size, checks every answer against
the generator's secret, and reports the mean with its 3σ interval. 1,460 solves:

| Bits | Solves | Mean, in units of √n | 3σ interval of the mean | 10th–90th percentile |
|---|---|---|---|---|
| 28 | 300 | 1.292 | 1.182 – 1.401 | 0.52 – 2.14 |
| 32 | 300 | 1.231 | 1.110 – 1.352 | 0.42 – 2.19 |
| 36 | 300 | 1.332 | 1.213 – 1.451 | 0.48 – 2.27 |
| 40 | 300 | 1.328 | 1.222 – 1.435 | 0.54 – 2.13 |
| 48 | 200 | 1.315 | 1.165 – 1.465 | 0.42 – 2.36 |
| 56 | 60 | 1.270 | 1.020 – 1.520 | 0.51 – 2.18 |

**Fitted exponent 0.5003 against n, R² = 0.9999.** Cost is square-root in the group size, with
no drift across seven doublings of the exponent's range.

The pooled mean is 1.295 against a theoretical 1.2533, and the 3.3% excess is accounted for
rather than waved at: Teske's deviation for `r = 32` adding walks is about `1 + 1/(2r)`, or
1.6%, and the batched walker discards its in-flight walks when the collision lands, which the
tool caps at 1% of the expected work per size. 1.2533 × 1.016 × 1.01 ≈ 1.285. What is left is
inside the 3σ intervals above.

Reproduce with `python -m tools.calibrate --bits 28,32,36,40 --solves 300`. Before the walk's
branch function was decorrelated from the distinguished-point test, every distinguished point
took the same branch out of 128 — a defect that would have surfaced only as a slightly wrong
constant, which is why this measurement exists at all.

## Layout

```
rhonet/ec.py           curve arithmetic, r-adding walks, batched inversion, PRF starts, tickets, replay, collision solve
rhonet/merkle.py       sha256 Merkle tree, byte-identical to PrizeVault.sol
rhonet/gencurve.py     random prime-order curves by BSGS point counting (toy sizes)
rhonet/coordinator.py  FastAPI + sqlite: admission, intake, replays, ledger, epochs, API, dashboard
rhonet/walker.py        identity, ticket, worker processes, signed batches, --cheat
rhonet/static/         dashboard (single file, no build)
contracts/             PrizeVault.sol + forge tests against a Python-generated fixture
rounds/eccp97.json     Exercise 97, with its provenance beside it
docs/PROTOCOL.md       the wire specification an independent client implements
spec/vectors.json      conformance vectors, generated and checked in CI
docs/index.html        the public site, deployed to rhonet.dev by CI
deploy/                launchd jobs, run script, health probe
tools/                 contributor registry, epoch publishing, audit re-derivation, vectors
tests/                 19 test files; every one runs standalone
demo.sh                end-to-end run: fresh curve, coordinator, honest walkers and forgers
```

## API

```
GET  /healthz                      liveness: status, epoch, epochs awaiting close
GET  /api/round                    round spec
GET  /api/status                   progress, rate, counts, latest root, verification cost
GET  /api/contributors             leaderboard, with GitHub logins and reported hardware
GET  /api/epochs                   ledger roots
GET  /api/epochs/{i}/audit         that epoch's audit plan and outcomes
GET  /api/events                   admissions, replays, slashes, epochs, solve
GET  /api/proof?payout_addr=0x..   Merkle proof against an epoch root
POST /api/ticket                   admission
POST /api/submit                   distinguished points
GET  /api/audit/targets?pubkey=..  outstanding challenges
POST /api/audit/open               answer one
POST /api/rotate                   change payout address
```

Request and response shapes, signed-byte encodings and client obligations are in
[docs/PROTOCOL.md](docs/PROTOCOL.md); [spec/vectors.json](spec/vectors.json) pins them with a
worked example that CI checks against the reference implementation on every push.

## Roadmap

1. **Toy rounds, 28–60 bit**, to shake out the protocol and calibrate the constant. *(done —
   1,200 solves, and the table above)*
2. **Exercise 97**: Certicom's real 97-bit curve, ~4.2 × 10¹⁴ steps, no prize and a known
   answer. Calibrates quotas, epoch size, replay rate and the audit under real contributors,
   against a result we can check. *(specified and opening — you are here)*
3. **A faster client.** The reference implementation is Python at ~0.7 M steps/s per core.
   A C or Metal or CUDA kernel with batched Montgomery inversion should be worth ten to
   thirty times that. (The negation map's 1.41× is *not* available to a client: it
   changes the step function, so adopting it unilaterally fails replay. It is a round
   parameter, and Exercise 97 does not set it.) We are not writing the kernel: the
   specification and the vectors are published so somebody else can, and the board shows the
   hardware next to the credit so a better client is visible as well as credited.
4. **ECCp-109**, gated on that kernel. Not a record to redo — it fell in 2002 to 10,308
   volunteers over 549 days — but the only rung between 10¹⁴ and 10¹⁹, which is where the
   coordinator's decimal-text record format has to stop being decimal text, ahead of the
   10¹⁰ points a 131-bit round produces. It is also where a negation map gets validated in
   the real kernel at real scale. The *constant* is cheaper to check than that, and worth
   checking early: a broken negation map does not crash and does not change throughput, it
   only silently costs the 1.41× it was meant to buy. `tools/calibrate.py` pins the mean at
   40 bits to ±2.8% with 300 solves in forty-six seconds, against a 29% shift — ten sigma,
   and 26 solves would do for three. So the arithmetic is catchable long before 109; what
   109 buys is everything that only appears at scale.
5. **ECCp-131**: ~4.6 × 10¹⁹ steps, $20,000 posted by Certicom, open since 1997. Needs the
   kernel from step 3, the negation map measured at step 4, plus a USDC pool in the vault,
   and a route for a prize awarded to a named entity to reach a contract that pays strangers.
6. **v2 coordinator**: staked committee, each member running its own intake bucket, syncing
   only the replayed sample. Needed before a bearer-asset round.
7. **A bearer-asset round** (a Bitcoin puzzle) needs two things this code does not have: a
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
