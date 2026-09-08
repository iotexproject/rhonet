# External security review, 8 September 2026 — findings and remediation spec

An independent reviewer read the served site and the `main` branch and filed
4 critical, 6 high and 16 medium/low findings, plus an audit of public claims.
Two of the critical findings were reproduced locally before this spec was written.

**Rule for every fix below: the falsification test in §T must fail before the fix and
pass after it. A fix without its test does not count as done.**

---

## C-1 (critical) — The spot check is predictable, so the audit is fully evadable

`rhowalkers/coordinator.py`, `Coordinator.submit`.

```python
do_check = int.from_bytes(ec.H(spec.round_id, "spot", pubkey, t), "big") % spec.spot_check_rate == 0
```

All three inputs are known to the miner before it submits: `round_id` is published at
`/api/round`, `pubkey` is its own, and `t` is chosen freely by the miner
(`miner.py` draws `secrets.randbits(62)`; the coordinator only checks range and
`(pubkey,t)` uniqueness).

**Reproduced.** An adversary that filters `t` keeps audit-free work identifiers at a cost
of **1.015 SHA-256 hashes per submitted DP** and is never audited. Measured on
`rounds/r44.json` with `spot_check_rate = 64`.

**Required fix, both parts:**

1. **Post-commitment entropy.** Move audit selection out of the submission path into
   epoch close, and derive the seed from a value that does not exist until after the
   batch is sealed: the epoch's own Merkle root. The miner cannot predict it because it
   depends on every other participant's submissions in the same epoch. Auditability is
   retained because the root is published.
   ```python
   def audit_targets(self, epoch_root: bytes, rate: int):
       rows = self.db.execute(
           "SELECT pubkey, t FROM dps WHERE epoch=? AND checked=0", (ep,)).fetchall()
       return [(pk, t) for (pk, t) in rows
               if int.from_bytes(ec.H(epoch_root, "spot", pk, t), "big") % rate == 0]
   ```
   This requires storing `epoch` on each DP row. Failed audits at epoch close must slash
   exactly as an inline failure does today.
2. **Remove `t` as a free variable.** `t` must be sequential per identity, starting at
   zero, with gaps rejected. Store `next_t` per miner and enforce it at intake. This also
   closes the variant where an adversary grinds `pubkey` instead of `t`.

Additionally, hold back a small fraction of audits for a delayed, randomly seeded second
pass over already-accepted points, so a break in the primary selector does not imply
unbounded fraud.

## C-2 (critical) — Stored points are never re-verified; failed collisions are discarded in silence

`rhowalkers/coordinator.py` collision branch; `rhowalkers/ec.py` `solve_collision`.

On a candidate collision only the *incoming* point is replayed; the prior record is used
as data. `solve_collision` returns `None` when `k·G != Q`, and the caller treats `None`
as a non-event: nothing is logged, no replay is triggered, the record stays in `dps`
forever. An adversary submitting points with a genuine distinguished `x` but inconsistent
`(a,b)` therefore consumes and destroys the real collision when an honest walk later
lands on that `x`, with no attribution and no consequence. The `(pa,pb) == (a,b)` guard
catches only verbatim copying; perturbing one coefficient evades it with the same effect.

The README's "the colliding pair is always replayed in full before `k` is trusted" is
false as implemented. Fix the code, then the sentence is true.

**Required fix:**

1. Replay **both** sides of every candidate collision unconditionally, regardless of
   prior `checked` status. A collision is a once-per-round event; its verification cost
   is irrelevant.
2. Treat a verified-pair solve failure as a hard incident. If both replays pass and `k`
   still fails `k·G = Q`, that is a specification or arithmetic bug: halt the round
   (`status = "halted_for_review"`) and emit a loud event. If exactly one replay fails,
   slash that identity and publish the failing segment as evidence.
3. Retain and act on the degenerate cases separately: `b1 ≡ b2` (same-y branch) or
   `b1 + b2 ≡ 0` (opposite-y branch) are legitimately useless collisions with
   probability O(1/n). Count and log them under their own event kind so the two causes
   are never conflated.

## C-3 (critical) — The vault lets the operator take the pool; settlement totals are unconstrained

`contracts/src/PrizeVault.sol`. Four defects:

- **(a) Unconditional drain.** `abort()` transfers the whole pool to `operator` with no
  condition and no depositor accounting, while `fund()` is deliberately open to anyone
  ("community top-ups, sponsor prizes"). Any third party's deposit can be taken by the
  operator at any time before settlement. The site promises the pool returns *to its
  depositor* on external solve, timeout or coordinator silence. Neither the trigger
  conditions nor the recipient match.
- **(b) Unconstrained denominator.** `settle(_epoch, _root, _totalSteps)` accepts
  `_totalSteps` with no relation to the leaves committed in `_root`. Inflating it pays
  dust and strands the remainder; deflating it lets early claimants overdraw until
  `transfer` reverts, a first-come race with permanent loss for late claimants.
- **(c) Roots are unconstrained and non-monotone.** The doc comment asserts roots only
  grow a balance; `postRoot` checks only `_epoch > epoch`. Nothing links a new root to
  its predecessor. The assertion is also false by design elsewhere: `_slash` sets
  `credited_steps = 0`.
- **(d) No solution is ever proven on chain.** `settle` neither takes nor checks a
  discrete logarithm. `k·G = Q` is verifiable in microseconds and is the one thing this
  problem class offers for free.

**Required fix:**

1. Per-depositor refund accounting: record `deposits[msg.sender] += amount` in `fund()`;
   `abort` enables a `refundClaim()` returning each depositor's own contribution.
2. Gate `abort` on verifiable conditions, callable by anyone, not only the operator:
   a `deadline` timestamp set at construction; or a stall condition
   (`block.timestamp - lastRootAt > stallWindow`); or an external-solve proof, which for
   an ECDLP round is somebody else's `k` satisfying `k·G = Q`, checkable on chain.
3. Bind the denominator to the committed leaves: accumulate `claimedSteps` and require
   `claimedSteps <= totalSteps`, or publish the full leaf set for the settled epoch and
   run a challenge window before claims open.
4. Add a solution gate: `settle` must be preceded by a `reveal(k)` the contract verifies
   against the round's `(P, Q, n, p)`. Scalar multiplication over an 80- to 131-bit
   modulus is on the order of 1e5 to 4e5 gas, affordable once per round. Keep
   commit-reveal ordering so `k` is not exposed in the mempool before any external prize
   is secured.
5. Add a monotonicity or challenge mechanism for `postRoot`, and correct the doc comment
   to say that slashing reduces balances.

## C-4 (critical) — Attacker-controlled replay cost inside the global lock

`rhowalkers/ec.py` `ticket_verify`; `Coordinator.admit`; `ec.dp_verify`.

`ticket_verify` replays a submitter-supplied `steps` bounded only by `2^(ticket_d+3)`,
and `admit` calls it while holding `self.lock`, an `RLock` that serialises every other
coordinator operation. One POST with a fresh key, a valid signature and maximal `steps`
stalls all submissions for minutes. Signature verification is not a defence: keys are
free. Note the intended prover/verifier asymmetry is absent and adversarially inverted.
The same shape recurs at intake: `steps` is attacker-chosen up to `2^max_walk_len_log2`
and `dp_verify` replays exactly that many steps.

**Required fix:**

1. Do not accept `steps` for ticket verification. Recompute the walk from the PRF start
   to the first point satisfying the `ticket_d` predicate with a hard internal cap of
   about `4 · 2^d`, and compare the resulting `x`. Submitted `steps` becomes advisory.
2. Verify tickets outside `self.lock`; take the lock only for the database insert.
3. Per-IP and per-key rate limits on `/api/ticket` and `/api/submit`, plus a ticket queue
   with bounded concurrency.
4. Bound audit replay by a specification constant, not by submitted `steps`: replay a
   fixed-length segment from the nearest checkpoint. This is what the design documents
   specify (`2^v`-step segments from client-held checkpoints) and what the site calls
   "segments"; the implementation replays whole walks from the start instead.
5. Replace the single global `RLock` plus one sqlite connection with a short-transaction
   model. A real round has thousands of concurrent submitters.

## H-1 (high) — Branch selection and the DP predicate read the same bits

`ec.replay` and `ec.walk_to_dp` choose the branch by `j = P[0] & (r-1)`, the low
`log2(r)` bits of `x`. `ec.is_dp` tests the low `w` bits. **Reproduced:** with `r = 32`
and `w = 11`, the branch index taken out of 300 consecutive distinguished points was
`{0}` — every DP takes the same branch. The two functions are correlated whenever
`w >= log2(r)`. This deviates from the random-function model that the `1.25·√n` estimate
depends on, and would show up only as a scaling exponent slightly above 0.5.

**Fix:** derive the branch from bits disjoint from the predicate, or from a hash:
`j = int.from_bytes(ec.H(x), "big") & (r - 1)` (a GPU kernel would use disjoint high
bits instead). Then re-run the scaling fit across 40/48/56/64 bits and confirm slope 0.5
with R² > 0.99.

## H-2 (high) — The prize cannot be added after the round is solved

`PrizeVault.fund` requires `!settled && !aborted`. The roadmap states ECCp-131 runs with
a USDC pool plus the Certicom prize claimed by a legal entity and distributed through the
same root. A challenge prize is necessarily received *after* the answer is submitted to
the awarding body, typically weeks later. By then `settled` is true and `fund` reverts.

**Fix:** separate accrual from distribution. Allow `fund()` after settlement and have
`claim` compute against a per-claimant `alreadyClaimed` high-water mark, so later
deposits create additional claimable amounts pro rata under the same root. Equivalently,
implement the vault as a streaming-shares contract: shares fixed at settlement, deposits
unbounded in time, each claimant may withdraw
`shareᵢ × cumulativeDeposits − withdrawnᵢ` at any time. Add tests for a prize arriving
after settlement and for two prizes arriving months apart.

## H-3 (high) — Credit does not measure work

Credit is `credited += 1 << w` per accepted DP. Three categories of real work are never
counted: ticket mining (about `2^d` steps per identity, and `d > w` by intent), walks
abandoned at `max_walk_len` (already tracked as `abandoned` in `BatchWalker`), and the
tail after a collision has occurred but before the DP is reached. Conversely, slashed
identities have credit zeroed while their points remain in `dps` and continue to serve
the search. The site's "solved after 74% of expected" therefore compares an accounting
convention against `1.25·√n`, not executed work against it.

**Fix:** have miners report `steps_done` and `abandoned` as telemetry, distinct from
credited steps; record ticket cost per identity at admission; publish both series. Keep
credit proportional to verified DPs for *payment* purposes, which is correct and
incentive-compatible, but stop presenting credited steps as a work measurement. Report
executed-to-credited ratio as its own metric.

## H-4 (high) — `ticket_d > w` is documented but never enforced

`RoundSpec` annotates `ticket_d` with "(d > w)" and the Sybil argument depends on it: if
`d <= w`, minting an identity costs no more than producing an ordinary DP. Neither
`RoundSpec.from_dict`, nor `gencurve`, nor the coordinator validates it.

**Fix:** assert the invariant in `RoundSpec.from_dict` and refuse to start a round that
violates it. Validate the full set: `r` a power of two, `w >= 1`,
`max_walk_len_log2 > w` with headroom (e.g. `w + 6`), `spot_check_rate >= 1`, `Q` on the
curve and in `<P>`, `P` of order exactly `n`, and `n` prime.

## H-5 (high) — The epoch ledger develops permanent gaps; departing miners cannot obtain proofs

`close_epoch` computes `idx = current_epoch() - 1` and returns early if that index
exists. It never reconciles missed indices, so any downtime exceeding one epoch — exactly
what the module docstring advertises as safe — leaves holes in `epochs` that are never
filled. Separately, `proof()` serves only `ORDER BY idx DESC LIMIT 1` and 404s for an
address absent from that epoch. A miner who contributes for a month and then stops has no
way to obtain a proof until final settlement, and if slashed or merely at
`credited_steps = 0` in the latest window, it is excluded from the tree entirely. This is
the "paid only at the end" problem the site claims to have fixed.

**Fix:** loop over all unclosed indices from the last recorded epoch to
`current_epoch() - 1`, emitting a root for each including empty ones. Accept an `epoch`
parameter in `/api/proof` and serve leaves for any closed epoch. Make the leaf value a
*cumulative* balance so a single latest proof suffices for all prior work, which is also
what the L2 claim pattern needs.

## H-6 (high) — One run is presented as validation of a high-variance process

The site reports a single 56-bit round solved at 74% of expected work. Pollard rho's
completion count has a standard deviation of roughly 52% of its mean, so a single
observation anywhere between about 20% and 250% is unremarkable. The figure neither
validates the constant factor nor would detect a substantial regression.

**Fix:** calibrate on hundreds of small instances, where each solve is milliseconds.
500 runs gives roughly a ±7% band at 3σ. Publish the mean, the empirical distribution and
the fitted scaling exponent across at least four bit sizes, and replace the single-run
number on the site with that, reporting the measured ratio to `1.25·√n` with a confidence
interval.

## Medium

- **M-1** `gencurve` accepts any prime-order curve found by BSGS. It does not reject
  anomalous curves (`n = p`, Smart's attack, polynomial time) or curves of small
  embedding degree (`n | p^d − 1` for small `d`, MOV/Frey-Rück). A toy round can
  therefore be far easier than `√n`, silently invalidating any timing measured on it.
  Reject `n = p` and test `n ∤ p^d − 1` for `d <= 20`.
- **M-2** `r = 32` costs about `1 + 1/(2r)` extra steps, roughly 1.6% versus `r >= 128`.
  Cheap to fix and worth fixing before publishing any cost curve.
- **M-3** The site states the DP table is 24 bytes per point. The schema stores `x, y, a,
  b` as decimal `TEXT` with a `TEXT` index on `x`: roughly 160-200 bytes per row plus
  index for a 131-bit round, against a design projection of 170 GB. Store truncated `x`
  (96 bits), identity index, `t` and `i` as fixed-width integers; drop `y, a, b`, which
  are recoverable by replay; move to an LSM key-value store keyed on truncated `x`. Until
  then, correct the claim on the site.
- **M-4** `ec.canonical` signs `json.dumps(sort_keys=True, separators=(",",":"))`. The
  project promises clients in any language, and canonical JSON is a well-known source of
  cross-language signature failures (integer versus string encoding of big values,
  unicode escaping, key ordering over non-ASCII keys). Sign a length-prefixed binary
  encoding of an explicit field list, and publish signing test vectors.
- **M-5** `load_or_create_key` writes the PKCS8 private key and only afterwards calls
  `os.chmod(path, 0o600)`. Create with `os.open(path, O_CREAT|O_WRONLY|O_EXCL, 0o600)`.
- **M-6** `eta_seconds = (expected_steps - total) / rate` goes negative-then-null past
  expectation and implies a deadline the process does not have. For rho the conditional
  expected remaining work at 1× expectation is about 0.5×, and at 2× about 0.3×. Publish
  the posterior: completion probability, median and 90% interval of remaining time.
- **M-7** No TLS, no rate limiting, no submission freshness. Signed bodies contain no
  nonce, timestamp or expiry, so a captured batch is replayable, harmless today only
  because of the `(pubkey,t)` uniqueness constraint. Require TLS, add per-key and per-IP
  limits, include `epoch` plus a monotonic counter in the signed body.

## Low

- **L-1** Integer division in `payout` leaves dust no function can withdraw. Add an
  operator sweep after a long claim window, or give the remainder to the last claimant.
- **L-2** `admit` checks `int(payout_addr, 16) >= 0`, vacuous for any parsed hex string;
  and because `admit` returns early for a known key, a miner can never update a
  compromised payout address. Validate as 20-byte hex and provide a signed
  address-rotation endpoint.
- **L-3** Non-standard ERC-20s (no return value, fee-on-transfer, rebasing) will
  misbehave. Use `SafeERC20` and document that only standard, non-rebasing tokens are
  supported.
- **L-4** `_slash` zeroes `credited_steps` but leaves the identity's DPs in the table,
  where they continue to advance the search for everyone else. Decide explicitly whether
  slashed points are purged (safer under C-2) or retained (better for the search), and
  consider retaining verified-segment credit up to the first failure.
- **L-5** `_epoch_loop` catches `Exception`, records an event and continues, so a
  persistent fault produces an endless quiet event stream rather than an alert. Count
  consecutive failures and surface them in `/api/status`.

## Public claims to correct

| Claim as published | Assessment |
|---|---|
| "nobody has organized that crowd" / "Why nobody has done this" | **Incorrect.** ECCp-109 was solved in 2002 by Chris Monico's volunteer effort: 10,308 participants, 247 teams, 549 days, with public per-team credit. ECC2K-130 (Bailey et al., 2009) was a multi-institution distributed rho with published DP handling. Distributed kangaroo pools with share accounting run against Bitcoin puzzles today. Claim the actual novelty instead: permissionless admission, curve-native tickets, sampled replay with slashing, and on-chain pro-rata settlement. |
| "a forger cannot know which [segments are replayed]" | **False as implemented.** See C-1. Remove until fixed, then restate with the post-commitment seed. |
| "the colliding pair is always replayed in full before k is trusted" (README) | **False.** Only the incoming point is replayed. See C-2. |
| "the coordinator keeps no per-miner state" | **Incorrect.** A `miners` table holds status, quota, counters, ticket and payout address. The intended point is narrower and still good: "The coordinator issues no work: starts are derived from `PRF(round, pubkey, t)`, so any walk is recomputable from public data." |
| Refund on abort "returns the pool to its depositor" | **Not implemented.** Returns the aggregate to the operator, unconditionally. See C-3. |
| Puzzle #135 as an open bearer target, and roadmap item 6 | **Solved.** #135 was solved on 28 July 2026 by RetiredCoder, reportedly about 5 months on 200 GPUs; the community has repointed to #140. Retire the roadmap item. It is also a live demonstration of the external-solve risk that C-3's missing abort conditions fail to handle. |
| #135 on the same ladder, "same walk" | **Category error.** #135 is a bounded-interval problem for Pollard kangaroo with tame/wild herds: different start construction, different collision equation. No kangaroo mode exists in the code. Say "same tickets, credit and vault; a different walk, requiring a kangaroo implementation." |
| ECCp-131 at 4.5e19 steps / 18 days | **Inconsistent.** That is the `0.886·√n` post-negation figure, while the code and README correctly use `1.25·√n`. Consistently: about 5.2e19 steps and about 21 days at the same assumed rate. |
| ECCp-163 "13,000 years" | **Arithmetic error.** About 3,400 years at the rate used for the other rows. |
| "a few hundred consumer GPUs running for weeks" | **Unmeasured.** Rests on 4e10 steps/s per RTX 5090 on a 131-bit prime field, extrapolated from 256-bit secp256k1 kangaroo rates. Label as an extrapolation pending measurement. |
| "beats proving every step by 1e5" (site) versus "1e5-1e7" (README) | **Internally inconsistent** and unsourced. Pick one and show the derivation, or state it qualitatively. |

## §T Falsification tests

Each test must **fail** against current `main` and **pass** after the corresponding fix.

- **T1 (C-1).** Add a `--cheat-evasive` mode to `miner.py` that draws candidate `t`,
  computes the audit selector, and submits fabricated points only when the result is
  non-zero. Run `demo.sh` with three honest miners and this adversary. *Under the
  finding:* the adversary accrues credit for the whole round, `spot_checks` for it
  remains 0, and it is never slashed. *After the fix:* it is slashed.
- **T2 (C-2).** Have an adversary submit a point whose `x` is copied from the public
  table (or from its own genuine walk) with `b` incremented by one. Then let honest
  miners run to a collision on that `x`. *Under the finding:* `solve_collision` returns
  `None`, no event is logged, the round continues, the adversary retains credit.
  *After the fix:* the round halts or the adversary is slashed, with an event.
- **T3 (C-3).** In Foundry: fund the vault from address `A` (a sponsor), then call
  `abort()` as the operator. *Under the finding:* the operator's balance increases by
  `A`'s deposit. Then test `settle` with `_totalSteps` at half and at double the true
  leaf sum, confirming overdraw-then-revert and dust-payout respectively. Then confirm
  `fund()` reverts after `settle` (H-2).
- **T4 (C-4).** POST a signed ticket with a fresh key and `steps = 2^(d+3)` while honest
  miners are submitting. Measure the stall in accepted submissions. *Under the finding:*
  throughput drops to zero for the duration of the replay.
- **T5 (H-1).** Instrument `walk_to_dp` to record the branch index taken from each
  distinguished point. *Under the finding:* all zero for `w >= log2(r)`.
- **T6 (H-6).** Solve 500 instances at each of 40, 48, 56 and 64 bits. Report mean steps
  over `√n` with a 3σ interval, the empirical distribution, and the fitted exponent.
  *After the fixes:* mean about 1.25, exponent 0.5 with R² > 0.99.

## Remediation order

| # | Change | Gate |
|---|---|---|
| 1 | C-1: post-commitment audit seed; sequential `t` | T1 shows the evasive cheater slashed |
| 2 | C-2: replay both sides; act on failed solves; audit stored points | T2 shows poisoning attributed and slashed |
| 3 | C-4: value-independent verifier cost; checkpoint segments; locking and rate limits | T4 shows no stall |
| 4 | H-4, M-1: enforce spec invariants; reject weak curves | round spec validation refuses bad rounds |
| 5 | H-1, M-2: decorrelate branch from predicate; raise `r` | T5, T6 |
| 6 | C-3, H-2: rewrite the vault | T3 plus a full Foundry suite |
| 7 | H-5: epoch backfill; proofs for any epoch | departing miner can claim |
| 8 | H-3, M-6: executed-work telemetry; posterior ETA | dashboard shows both series |
| 9 | M-3: record format and storage engine | irrelevant at toy scale, required for 131-bit |
| 10 | M-4, M-5, M-7, L-1 to L-5 | one hardening pass |
| 11 | Site and README corrections | costs nothing, do immediately |
