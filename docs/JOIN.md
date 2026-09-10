# Join Exercise 97

You will run a client that searches for a collision on a 97-bit elliptic curve, and
a public board will show what you contributed. There is no prize. There is a
verifiable record, a real benchmark, and an open invitation to beat our client.

Five minutes to read; about half an hour before your first point appears.

> **The round has not opened yet.** The coordinator is not serving, so step 3 will
> exit immediately and tell you so. It checks before spending anything, so nothing
> is lost by trying. Steps 1 and 2 work now, and so does everything in section 6 —
> the specification and the vectors are published, which means a client can be
> written and proved correct before the round exists to run it against.
> Current status is on <https://rhonet.dev>.

---

## What you are actually doing

The round is Certicom's ECCp-97 challenge, first solved in March 1998 by 588 people
running 1,288 machines over 53 days. The parameters are the originals
(`rounds/eccp97.provenance.md`), and the answer has been public for twenty-eight
years — which is the point. When this network finds the answer, we can check it
against the published one. That is not true of any round that matters, and it is
exactly why you do this one first.

Your machine walks pseudo-random paths on the curve. Occasionally a walk lands on a
*distinguished point* — one whose x-coordinate ends in 29 zero bits — and you
submit it. Two walks that reach the same point solve the problem. Everything up to
that moment is bookkeeping, and the bookkeeping is the hard part: you get credit
for a point only if you can prove, on demand, that you actually walked to it.

Expect the round to take about 4.2 × 10¹⁴ steps in total.

## 1. Get the client

    git clone https://github.com/iotexproject/rhonet
    cd rhonet
    python3 -m venv .venv
    .venv/bin/pip install fastapi "uvicorn[standard]" cryptography httpx

Python 3.11 or newer.

## 2. Register a GitHub identity

The board shows GitHub logins, not raw keys, and that binding is something you
create rather than something we assert.

Generate a key and sign a statement naming your login:

    .venv/bin/python -m rhonet.walker --help          # creates nothing yet
    .venv/bin/python -m tools.contributor sign \
        --github <your-login> \
        --key walker.key \
        --payout 0x<20-byte-hex-address> \
        > contributors/<your-login>.json

(The first run of the walker creates `walker.key` if it does not exist; you can
also let step 3 create it and come back here.)

Then open a pull request adding only that one file. CI checks two things: that the
signature verifies under the key in the file, and that the pull request author is
the login the signature names. The signature proves the key holder claims the
login; the pull request proves the login claims the key. Neither half can be forged
alone, and no server has to be trusted for either.

`--payout` is where credit accrues. For this exercise it settles nothing — there is
no prize — but it is the identity your rows are grouped under, so use an address
you control and will keep.

You can search before your pull request merges. The board will show your key until
it lands, and your login afterwards.

## 3. Run

    .venv/bin/python -m rhonet.walker \
        --coordinator https://api.rhonet.dev \
        --key walker.key \
        --payout 0x<the same address> \
        --procs 8

`--procs` defaults to half your cores. `--batch` (default 64) is how many walks run
in lock-step per process; higher amortises the modular inversion better and costs
more memory.

What happens, in order:

1. **The client mints an admission ticket.** It walks until it hits an
   `x mod 2³⁰ == 0` point — the same work the search itself is made of, roughly
   twice the cost of one contributed point. On the reference client that is about
   22 minutes on one core, under three across eight. This is deliberate: it is what
   stops someone minting a thousand identities to farm quota, and it uses the same
   kernel as the search, so a faster client mints tickets faster in exactly the
   proportion that it searches faster. Buying your way in is never better than
   searching your way in.
2. **It searches**, printing a line every couple of seconds with your local rate,
   points sent and credits earned.
3. **It answers audits.** After each hour-long epoch, the coordinator challenges
   about one in thirty-two of your points and asks you to open one segment of the
   walk that produced it. Your client answers automatically. This is not optional
   and it is where credit actually comes from. The deadline scales with how many
   openings you owe — ten minutes plus half a second per challenge — so
   contributing more never means being given less time.

## 4. Read the board

<https://rhonet.dev> shows, per contributor: GitHub login, self-reported hardware,
points submitted, credits, share, and audit record. One credit is 2²⁹ steps —
exactly one verified point.

`https://api.rhonet.dev/api/status` is the same data as JSON, plus the round
parameters, the network rate, the ETA posterior and the running verification cost.
Every closed epoch publishes a Merkle root over `(address, steps)` and the leaves
that build it, so you can recompute your own row rather than believe ours.

Two things worth knowing about the ETA: it is a median, and rho's completion time
is Rayleigh-distributed. There is a 10% chance of finishing at 0.37× the expected
work and a 10% chance of still running at 1.71×. A round that is "behind schedule"
is usually just a round.

## 5. What happens if you drop off

Nothing bad, as long as you do not leave a challenge unanswered.

- **Stop cleanly, or crash, with no outstanding challenges.** Credit already
  matured stays yours permanently; it is committed in a published epoch root.
  Restart whenever, with the same key, and carry on.
- **Miss a challenge window.** The epoch's credit is *withheld*, not destroyed. The
  steps stay on your balance and become payable the moment you come back and open
  the challenge — even long after the deadline. Silence is not fraud, and we do not
  treat it as fraud.
- **Stay silent across three separate epochs.** The identity loses standing. Three
  hours of ignoring challenges is not an outage, it is a client that does not
  answer, and the coordinator cannot tell that apart from one that cannot.
- **Answer wrong.** That is different. A failed replay forfeits the whole pending
  epoch and slashes the identity. Matured credit from earlier epochs is untouched —
  it was already committed — but nothing pending survives.

The practical rule for anyone writing a client: **keep your checkpoint chains until
the epoch containing that point has closed**, and do not exit on "solved" with
challenges outstanding. Our own client got this wrong once and left an honest
contributor unpaid for 1,536 points it had genuinely produced.

Three other things a client must do, because they are the ones people get wrong:

- Answer *every* challenge in `GET /api/audit/targets`, and retry a `429` rather
  than dropping the answer. The response carries the deadline; use it as your
  retry budget.

- Points refused for `quota` or `audit backlog` are **not** rejections. Resubmit
  them with the same `t` and the same coefficients — the response tells you which
  indices and when. Dropping them wastes the work; re-deriving them wastes it twice.
- Retry on `429`, `502`, `503`, `504` and on `400 stale submission`, with backoff.

## 6. Write a faster client

This is the part we care about most.

The reference implementation is Python. It does 0.7–0.8 M steps per second per
core, and there is no scenario in which that is a good number. A C or Metal or CUDA
kernel doing batched Montgomery-trick inversions across many walks should be worth
ten to thirty times that, and implementing the negation map is another 1.41× on top
— the reference client does not implement it.

We are not going to write those kernels. That is the open problem, and it is
yours if you want it.

What you need is all published:

- `docs/PROTOCOL.md` — the complete wire specification: the walk, the checkpoint
  commitment, the audit obligation, and the exact bytes of every signed message.
- `spec/vectors.json` — conformance vectors. A fixed round and a fixed public test
  key, with every intermediate value pinned: 32 consecutive walk states with their
  branch indices, a 240-step walk with its 61 checkpoints and Merkle root, three
  segment openings, and the exact signed bytes and signatures for every message
  type. If your client reproduces those, it will interoperate.
- `rhonet/ec.py` — the reference implementation, written to be read.

There is no approval step and no whitelist. A client is legitimate if its points
replay, and that is checked the same way for everyone, including us. The board
shows self-reported hardware next to the rate, so a client that is genuinely faster
is visible as faster.

## Questions worth answering before you start

**Is this mining?** No. Nothing is issued, there is no chain, and the work is not
arbitrary — it is a specific, published, twenty-eight-year-old open problem. What
we borrowed from that world is only the part that works: verify by replay, pay for
what verifies.

**Can I cheat?** You can submit fabricated points, and about one in thirty-two of
them will be challenged with entropy you could not predict when you submitted. Ten
forged points get away with it 73% of the time; a thousand get away with it once in
sixty trillion. Being caught forfeits everything unmatured. The security here is
not a per-point guarantee, it is that cheating at any scale worth cheating at
doesn't work.

**What if I know the 1998 answer?** Everyone does. It buys you nothing. Credit is
paid for points whose walks replay from `PRF(round_id, pubkey, t)`, and you do not
get to choose the coefficients a PRF-derived walk arrives with. There is a test for
this: `tests/test_eccp97.py`.

**What is this for?** Exercise 97 is the calibration round. What comes after is
ECCp-131 — unsolved since 1997, $20,000 posted by Certicom, and about 10⁵ times
this much work. Getting the accounting right on a problem whose answer we can check
is the only sensible way to arrive there.
