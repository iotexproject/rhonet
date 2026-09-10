# RhoNet wire protocol, version 1

This document is what you need to write a RhoNet client in any language. It
describes the search, the commitments a searcher makes, the audit it must be able
to answer, and the exact bytes of every signed message. `spec/vectors.json` pins
all of it down with worked examples; if your implementation reproduces those
vectors, it will interoperate.

The Python code in `rhonet/` is the reference implementation. It is deliberately
slow — it exists to define behaviour, not to compete. Writing a fast client is the
open part of this project.

Everything below is version `rhonet-v1`. A change to any encoding is a new version
with a new magic string, never a silent redefinition.

---

## 1. The round

A round is a static JSON document, published once and never mutated. Fields:

| field | meaning |
|---|---|
| `round_id` | string; seeds every PRF in the round, so two rounds never share a walk |
| `curve` | `{p, a, b, n, gx, gy}`: short Weierstrass `y² = x³ + ax + b` over `F_p`, base point `G = (gx, gy)` of prime order `n` |
| `qx`, `qy` | the target point `Q`. The round is solved by finding `k` with `k·G = Q` |
| `bits` | approximate size of `n`, for display |
| `w` | distinguished-point width: a point is distinguished when `x mod 2^w == 0` |
| `r` | adding-walk table size; a power of two |
| `ticket_d` | admission difficulty, `ticket_d > w` |
| `v` | checkpoint spacing exponent: a checkpoint every `2^v` steps |
| `max_walk_len_log2` | hard cap on a single walk's length |
| `credit_unit_log2` | one credit is `2^credit_unit_log2` verified steps |
| `spot_check_rate` | the audit challenges 1 in this many submitted points, per identity |
| `epoch_seconds` | accounting period |
| `quota_dps_per_epoch_base` | starting per-identity intake quota |
| `audit_response_seconds` | how long you have to answer a challenge |
| `silence_epochs` | unanswered challenges in this many epochs costs the identity its standing |
| `prize_pool_usdc`, `funded` | the prize, and whether it is actually escrowed |

A client should reject a round it cannot validate: `p` and `n` prime, the curve
nonsingular, `G` on the curve with `n·G = ∞`, `Q` on the curve with `n·Q = ∞`, `n`
inside the Hasse interval, `n ≠ p`, and no embedding degree ≤ 20. The reference
check is `RoundSpec.validate`.

## 2. Hashing

One hash is used everywhere. `H(parts...)` is SHA-256 over the concatenation of,
for each part, its four-byte big-endian length followed by its bytes. Integers and
strings are converted with their decimal / UTF-8 representation before length
prefixing. Length prefixing means no two different argument lists collide.

    H("abc")            = d04b72a650ce0f8ce4963330a53ee2832733d2baeffff3c1d8e256cca096d120
    H("a", 1, 0xff)     see spec/vectors.json → "hash"

## 3. The walk table

    R_j = c_j·G + d_j·Q,   j = 0 .. r-1
    c_j = H(round_id, "table-c", j) mod n,  or 1 if that is 0
    d_j = H(round_id, "table-d", j) mod n,  or 1 if that is 0

If `R_j` is the point at infinity, retry with an extra counter argument:
`H(round_id, "table-c", j, counter)` for `counter = 1, 2, ...`. This never happens
on a real round, but the rule has to be stated because it is part of the
deterministic table.

The table is derived from the round alone. Everyone computes the same one; nobody
issues it.

## 4. Start points

There is no seed server. A searcher picks any 63-bit integer `t` it has not used
before and derives its own start:

    a0 = H(round_id, "walk", pubkey_hex, t, "a") mod n
    b0 = H(round_id, "walk", pubkey_hex, t, "b") mod n,  or 1 if that is 0
    P0 = a0·G + b0·Q

`pubkey_hex` is the searcher's Ed25519 public key, 32 bytes, lowercase hex. Two
identities therefore never collide on a start, and any auditor can reconstruct the
start of any walk from `(round_id, pubkey, t)` alone. If `P0` is the point at
infinity, skip that `t`.

Admission tickets use the same derivation with the tag `"ticket"` in place of
`"walk"`, and `t` is called `nonce`.

## 5. The step

Given a current point `P = (x, y)` with coefficients `(a, b)`:

    j = (x >> w) & (r - 1)          # branch bits, disjoint from the DP bits
    P ← P + R_j
    a ← (a + c_j) mod n
    b ← (b + d_j) mod n

The branch index deliberately reads bits *above* the distinguished-point bits. If
it read the low bits, every distinguished point would take the same branch, and the
walk would stop being pseudorandom exactly where it matters.

A walk stops when `x mod 2^w == 0` after at least one step. It is abandoned, with
no credit, if it reaches `min(2^max_walk_len_log2, 2^(w+3))` steps or degenerates
(`P` becomes infinity, or `P` and `R_j` have equal x). Abandon and start a new `t`.

`spec/vectors.json → trace` gives 32 consecutive states from a known start,
including the branch index taken at each one.

## 6. Checkpoints and the commitment

Credit is not paid for a claim; it is paid for work someone can check. Checking a
whole walk costs as much as doing it, so a walk is committed in segments and the
audit opens one.

Record a checkpoint `[a, b, x, y]`:

- at step 0 (the derived start), and
- whenever `steps mod 2^v == 0`, and
- at the distinguished point that ends the walk.

For a walk of `L` steps this gives `ceil(L / 2^v) + 1` checkpoints, indexed from 0.
Segment `i` is the `2^v` steps (or fewer, for the last one) from checkpoint `i` to
checkpoint `i+1`.

Commit to the chain with a binary Merkle tree:

    leaf(i)      = H("checkpoint-leaf-v1", i, canonical([a, b, x, y]))
    node(l, r)   = H("checkpoint-node-v1", l, r)

Layers are built left to right in pairs; an odd final node is paired **with
itself**, not promoted. `canonical` is JSON with sorted keys and no whitespace —
here it is a list of four integers, so it is `[a,b,x,y]` with commas and no spaces.
(This is the one place the protocol still uses JSON in a hash. It is an internal
digest, never a signature, and the vectors pin it.)

**Budget for this.** A chain is `ceil(L / 2^v) + 1` checkpoints of four field
elements, and it has to survive until the epoch containing that point has closed.
On Exercise 97 a typical walk is 513 checkpoints, which is about 33 KB packed as
four 16-byte integers — trivial for one walk, and 3 GB for a client producing
100,000 points an hour. A fast client should pack them as fixed-width integers
rather than language objects, and is free to spill them to disk: they are read once,
if at all. Discarding them is not an option, because a chain you cannot open is
credit you cannot collect.

An opening for segment `i` is `{"start": {point, proof}, "end": {point, proof}}`
where each `proof` is the sibling path from that leaf to the root, exactly
`ceil(log2(count))` hashes, lowest layer first. Sibling selection when a layer is
odd is `layer[min(pos ^ 1, len(layer) - 1)]` — the self-pairing rule again.

## 7. Verifying a segment

This is what the coordinator does, and what any third party can do from published
data. Given the submitted point `dp`, a segment index `i` and an opening:

1. `segments = ceil(dp.steps / 2^v)`; require `0 ≤ i < segments`.
2. Both openings verify against `dp.checkpoint_root` as leaves `i` and `i+1` of a
   tree with `segments + 1` leaves.
3. Both checkpoint states are in range and on the curve, and satisfy
   `a·G + b·Q == (x, y)`.
4. If `i == 0`, the start checkpoint equals `derive_start(round, pubkey, dp.t)`.
5. The **submitted** coefficients satisfy `dp.a·G + dp.b·Q == (dp.x, dp.y)`,
   regardless of which segment was challenged. This is why fabricated coefficients
   are caught by *any* challenge, not only by the one covering the endpoint.
6. If `i == segments - 1`, the end checkpoint equals the submitted point.
7. Replaying `min(2^v, dp.steps - i·2^v)` steps from the start checkpoint lands
   exactly on the end checkpoint.

The work this costs is one segment: `2^v` steps, against a walk of `2^w` expected
steps, sampled at 1 in `spot_check_rate`.

## 8. Admission tickets

A new identity must produce a curve-native proof of work before it can submit: from
the ticket start for some `nonce`, walk until `x mod 2^ticket_d == 0`, within
`4·2^ticket_d` steps. Submit `{nonce, steps, x}`. The coordinator recomputes the
walk and requires both `x` and `steps` to match; the submitted `steps` is advisory
until then.

The ticket uses the same kernel as the search itself. A faster client mints tickets
faster in exactly the proportion that it searches faster, so buying admission gives
no edge that searching would not already have given — which is the point.

## 9. Signed messages

Transport is JSON over HTTP, which is convenient and lossy. Signatures cover a
binary encoding, which is neither.

    encode(domain, fields) =
        "rhonet-v1\0"
        || uvarint(len(domain)) || domain
        || uvarint(len(fields))
        || for each field: tag || uvarint(len(value)) || value

    tag 0x00   bytes, verbatim
    tag 0x01   unsigned integer, minimal big-endian; zero is the empty string
    tag 0x02   UTF-8 text
    tag 0x03   nested list; value is the concatenation of its items' encodings

`uvarint` is unsigned LEB128. There is no key ordering to agree on, no escaping,
and no number formatting: every value has exactly one representation. Field
**order** is part of the specification for each message type below; names never
appear on the wire, so two clients cannot agree on the names while disagreeing on
the bytes.

Signature: Ed25519 over those bytes, by the identity key, lowercase hex in the
JSON field `sig`.

| domain | fields, in order |
|---|---|
| `rhonet/admission-v1` | round_id, pubkey, payout, ticket.nonce, ticket.steps, ticket.x, epoch, seq, device |
| `rhonet/submission-v1` | round_id, pubkey, epoch, seq, steps_done, abandoned, [per point: t, steps, x, y, a, b, checkpoint_root] |
| `rhonet/opening-v1` | round_id, pubkey, audit_epoch, t, segment, H("opening", canonical(opening)) |
| `rhonet/rotate-v1` | round_id, pubkey, payout, epoch, seq |
| `rhonet/contributor-v1` | github, pubkey, payout |

`pubkey` and `payout` are raw bytes (payout is the 20 address bytes, no `0x`);
`round_id`, `device` and `github` are text; everything else is an unsigned integer.
The point list is a nested list of nested lists.

**Freshness.** Every request except the contributor statement carries `epoch` and
`seq`. The coordinator requires `|epoch - current| ≤ 1` and `seq` strictly greater
than the last accepted `seq` for that identity. `seq` is monotonic per identity and
survives coordinator restarts, so a captured request cannot be replayed.

## 10. Endpoints

Base URL is the coordinator's. All POST bodies are JSON objects carrying `sig`.

| endpoint | body | effect |
|---|---|---|
| `GET /api/round` | — | the round document and the derived parameters |
| `GET /api/status` | — | round state, totals, rate, ETA, verification cost |
| `GET /api/contributors` | — | the board: identity, GitHub login, device, credited steps |
| `GET /api/epochs` | `limit`, `before` | closed epochs with their payment roots |
| `GET /api/epochs/{i}/audit` | `limit`, `offset`, `kind` | that epoch's audit plan and outcomes |
| `GET /api/proof` | `payout_addr`, `epoch` | Merkle proof of a payment leaf |
| `POST /api/ticket` | round_id, pubkey, payout_addr, ticket, device, epoch, seq | admission |
| `POST /api/submit` | round_id, pubkey, epoch, seq, steps_done, abandoned, dps | submit points |
| `GET /api/audit/targets` | `pubkey` | outstanding challenges: epoch, t, segment, deadline |
| `POST /api/audit/open` | round_id, pubkey, audit_epoch, t, opening, epoch, seq | answer one |
| `POST /api/rotate` | round_id, pubkey, payout_addr, epoch, seq | change payout address |

`/api/submit` responds with `accepted`, `rejected` (index and reason), and capacity
hints: `retry_indices`, `retry_after`, `batch_limit`, `quota_left`. **A client must
honour these.** Points rejected for `quota` or `audit backlog` are not fraud and
must be resubmitted, with the same `t` and the same coefficients, rather than
dropped. Dropping them wastes the work; re-deriving new ones wastes it twice.

`429`, `502`, `503`, `504` and a `400 stale submission` are all retryable with
backoff.

## 11. Audit obligations

Answering challenges is not optional and is not free-form. After each epoch closes,
each identity owes `ceil(k / spot_check_rate)` openings, where `k` is the number of
points it submitted in that epoch. Which points, and which segment of each, is
determined by the epoch's sealed batch commitment and a beacon value that is not
known until after the batch is sealed.

Poll `GET /api/audit/targets` at roughly `audit_response_seconds / 10` — prompt
enough that a challenge is answered long before it expires, slow enough that a
thousand clients polling is not itself the load. On Exercise 97 that is about every
twenty seconds. For each target, answer with the opening for the named segment.

Do not poll `/api/status` per request. The epoch is a clock: `started_at` and
`epoch_seconds` come from the round, so derive it locally and resync only when the
coordinator answers `400 stale submission`. The reference client used to fetch the
status before every signed message, which made the most expensive read on the
server the hottest one.

- A **wrong** answer forfeits the epoch and slashes the identity. Credit already
  matured in earlier epochs is untouched; it was committed.
- **Silence** withholds rather than destroys: the epoch's steps stay on the balance
  but are not payable. A late opening that verifies releases them. Silence across
  `silence_epochs` distinct epochs costs the identity its standing.

The practical consequence for a client: keep your checkpoint chains until the epoch
they belong to has closed and its challenges are answered, and do not exit on
"solved" with challenges outstanding.

## 12. Credit and settlement

A verified point is worth `2^w` steps of credit — its expected cost, not its
claimed cost, so overstating `steps` buys nothing. One credit is
`2^credit_unit_log2` steps.

At the end of each epoch the coordinator seals the batch, runs the audit, and only
then builds the payment tree over the surviving balances:

    leaf = SHA256(addr20 || uint256 steps)
    node = SHA256(min(l, r) || max(l, r))

Sorted pairs, so proofs carry no side bits. An odd node is promoted, not duplicated
(note this differs from the checkpoint tree, which pairs an odd node with itself —
the payment tree matches the Solidity verifier byte for byte). The empty tree's
root is 32 zero bytes.

Roots are posted per epoch and can be reconstructed from the published leaves. The
prize is split pro rata by credited steps across the round.

## 13. Identity

The identity key is an Ed25519 keypair the client generates and keeps. It is not
tied to anything by itself. To appear on the board under a GitHub login, commit
`contributors/<login>.json` containing the public key, the payout address, and a
signature by that key over the `rhonet/contributor-v1` encoding. CI checks the
signature; GitHub proves the pull request author owns the login. The signature
proves the key holder claims the login and the PR proves the login claims the key,
so neither half can be forged alone.

The `device` string is self-reported and signed by nobody but the claimant. It is
displayed as a claim, not as a fact.

## 14. Conformance

`spec/vectors.json` contains, for a fixed 32-bit round and a fixed public test key:
the uvarint and integer encodings, `H` outputs, four `encode` cases, the walk table
head, tail and digest, five PRF starts, 32 consecutive walk states with their branch
indices, a complete 240-step walk with its 61 checkpoints and Merkle root, three
segment openings with their proofs and replay counts, a valid admission ticket, the
exact signed bytes and signatures for all five message types plus a contributor
statement, and a payment Merkle tree with proofs.

Regenerate with `python -m tools.gen_vectors`; check with `--check`. CI runs the
check, and `tests/test_vectors.py` recomputes every value from the reference
implementation. The wire format can only move in a commit that moves the vectors on
purpose.
