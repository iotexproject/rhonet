# Exercise 97: how the round is sized, and why

The parameters in `rounds/eccp97.json` are choices, and every one of them trades
something against something else. This is the reasoning, so a reviewer can disagree
with it specifically rather than in general.

The curve itself is not a choice: it is Certicom's, unchanged. See
`rounds/eccp97.provenance.md`.

## The size of the problem

`n` is a 97-bit prime, so plain Pollard rho with r-adding walks and no negation map
expects

    1.25 · √n  ≈  4.21 × 10¹⁴ steps

A client that implements the negation map does about 0.886·√n ≈ 2.98 × 10¹⁴, a
1.41× saving. The reference client does not implement it; a better client should.

Rho is a random process, not a schedule. Completion follows a Rayleigh
distribution: there is a 10% chance of finishing by 0.37× the expected work, a 50%
chance by 0.94×, and a 10% chance of still running at 1.71×. Any date we publish is
a median, and the spread is ±52%.

For scale, at 10 days:

| running | steps/s | machines for a 10-day round |
|---|---|---|
| reference Python, 8 cores | 6.2 M (measured) | ~79 |
| a 10× C or Metal kernel, 8 cores | 62 M | ~8 |
| one RTX 5090, plausibly | ~6 G | 1 |

The gap between the first row and the second is the entire invitation.

## `w = 29` — distinguished-point width

A point is submitted when `x mod 2²⁹ == 0`, so a walk is 2²⁹ ≈ 537 million steps
long on average and the round produces about **784,000 points**.

- Larger `w` means fewer, longer walks: less coordinator storage and less network
  traffic, but coarser credit and longer before a new contributor sees anything.
- Smaller `w` means more rows. At `w = 24` the round would produce 25 million
  points, which is more than one coordinator should be asked to hold.

784,000 rows is roughly 200 MB of SQLite, and it is comfortably in the range the
1998 effort operated in: they collected 186,364 points at an expected 2³⁰ steps
each. We are deliberately near a proven operating point rather than inventing one.

A walker on one reference-Python core produces a point every ~11 minutes; on eight
cores, every ~87 seconds; on a fast kernel, in seconds.

## `r = 32` — adding-walk table size

Teske showed that r-adding walks become statistically indistinguishable from a
random walk at around `r = 20`; below that the walk is measurably worse than the
√n heuristic predicts, above it there is nothing left to gain. 32 is the next power
of two, and a 32-entry table of curve points fits in L1 — or in registers — on
anything from a phone to an H100, which matters because the table is read on every
single step.

The branch index reads `(x >> w) & (r - 1)`: bits *above* the distinguished-point
bits. Reading the low bits would make every distinguished point take branch 0,
which is exactly the kind of bug that quietly destroys the randomness where it
matters most. There is a regression test for it.

## `v = 20` — checkpoint spacing, and the cost of verification

A walker records a checkpoint every 2²⁰ steps and commits to the chain with a
Merkle root. An audit challenge opens two adjacent checkpoints and replays the 2²⁰
steps between them, instead of replaying the whole 2²⁹-step walk.

    verification cost = (1 / spot_check_rate) · 2ᵛ / 2ʷ
                      = (1 / 32) · 2²⁰ / 2²⁹
                      = 0.0061% of the search

Over the whole round that is about 2.6 × 10¹⁰ replayed steps against 4.2 × 10¹⁴
searched: roughly nine CPU-hours of verification for a ten-day, eighty-machine
search. Verification has to be negligible or the coordinator becomes the
bottleneck, and this is negligible.

The cost on the walker's side is memory: about 513 checkpoints for a typical walk,
four integers each, held until the epoch containing that point has closed. A client
running 64 walks in parallel needs single-digit megabytes for this.

## `spot_check_rate = 32` — how often a point is challenged

Each identity owes `ceil(k / 32)` openings for the `k` points it submitted in an
epoch, on points chosen by entropy it could not predict when it submitted.

A point whose coefficients do not satisfy `a·G + b·Q = (x, y)` — the cheap forgery,
and the only one that actually saves work — is caught by *any* challenge that lands
on it, because every challenge re-checks that relation regardless of which segment
it opens. So a fabricator escapes with probability 31/32 per point:

| forged points | probability of getting away with all of them |
|---|---|
| 10 | 73% |
| 100 | 4.2% |
| 1,000 | 1.6 × 10⁻¹⁴ |

Cheating once is cheap to hide. Cheating at any scale worth cheating at is not, and
being caught forfeits every unmatured credit the identity holds. That asymmetry —
not a per-point guarantee — is what makes the accounting work.

The other case, a chain that verifies everywhere except one segment, escapes with
probability `1 - 1/(32 · 4096)`. It is a far weaker bound and it is the one we
quote publicly, but building such a chain requires doing every step except 2²⁰ of
2²⁹ — 0.2% saved — so nobody will.

Both bounds assume the audit entropy is unpredictable when the batch is sealed.
This exercise uses commit–reveal; a funded round must use an external beacon bound
to an event after the seal.

## `ticket_d = 30` — admission

A new identity walks until `x mod 2³⁰ == 0`, roughly 2³⁰ steps, using the same
kernel as the search. On the reference client that is about 22 minutes of one core,
under three minutes across eight; on a fast client it is under a minute.

`ticket_d > w` is a protocol invariant, not a tuning knob: a ticket must cost more
than a point, or minting identities would be a cheaper way to buy quota than
searching. The cost is real, and it is deliberately the *same work* the round is
made of — so a faster client mints tickets faster in exactly the proportion that it
searches faster, and buying your way in is never better than searching your way in.
No ASIC, no botnet, no GPU farm gets an edge here that it would not already have.

## `epoch_seconds = 3600`, `audit_response_seconds = 600`, `silence_epochs = 3`

Credit matures one epoch at a time. An hour is long enough that a single-core
contributor has something in most epochs, and short enough that a ten-day round has
240 settlement points rather than a cliff at the end.

Ten minutes is the *base* window. The deadline an identity actually gets is
`audit_response_seconds + challenges_owed / 2`, because an identity that submitted
more owes more openings, and each opening is a round trip and a replay. A flat
window silently demands an unbounded answer rate from the largest contributor,
which is the failure a launch rehearsal produced: two honest walkers, doing
everything right, slashed for "silence" they could not have avoided. A contributor
at 60 M steps/s owes about thirteen openings an hour and gets 606 seconds; one at
6 G steps/s owes about 1,250 and gets twenty minutes. It assumes a client polling
`/api/audit/targets` every twenty seconds or so, with room for a restart in
between. Silence across three
distinct epochs — three hours of ignoring challenges — costs the identity its
standing. Silence before that only *withholds*: the steps stay on the balance and a
late opening that verifies releases them. Destroying credit is reserved for an
answer that is wrong, never for an answer that is late.

## `quota_dps_per_epoch_base = 128`, doubling per epoch

A brand-new identity can submit 128 points in its first hour — about 6.9 × 10¹⁰
steps, far more than any single machine will do — and the ceiling doubles every
epoch it stays admitted. This is slow-start, not rationing: it bounds how fast an
unknown identity can flood the audit queue, and it stops being a constraint within
a few hours for anyone real.

A second gate sits behind the quota: at most 65,536 of one identity's points may
sit in a still-open epoch unverified (`RHONET_AUDIT_BACKLOG_DPS`). It bounds what
the coordinator is holding, not fraud — sampling bounds fraud whatever the volume,
and an unaudited point earns nothing until its epoch closes and is audited. The
old value, 4,096, worked out to about 600 M steps per second on this round: below
one current GPU, and therefore a throttle on exactly the contributors this round is
trying to attract. A launch rehearsal found it.

Points refused for `quota` or `audit backlog` are **not** fraud. The response says
which indices to retry and when; a client must resubmit them with the same `t` and
the same coefficients. An earlier version of this system slashed an honest
contributor because its client dropped deferred points instead of retrying them.

## `credit_unit_log2 = 29`

One credit is 2²⁹ steps — exactly one verified distinguished point. The board is
easier to read when the unit is the thing being counted.

## `funded = false`, `prize_pool_usdc = 0`

ECCp-97 was solved in March 1998 and the answer is public. There is no prize to
win, and pretending otherwise would be a lie. What the round produces is a
verifiable record of who contributed how much to a real 4 × 10¹⁴-step computation,
and a benchmark that any client can be measured against.

It also produces the one thing a first round most needs: a result we can check.
When the network reports a collision, the `k` it derives must equal
`0x16c86aa7cacf69f1dd28b3e2f`. If it does, the whole pipeline — walks, checkpoints,
audit, collision solving — is correct end to end, on the real thing rather than on
a toy. If it does not, we find out now rather than on a round that matters.
