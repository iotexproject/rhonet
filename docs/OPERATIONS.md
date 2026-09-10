# Running the round

The coordinator is a single process with a SQLite database. It is not clustered
and it is not meant to be: one operator, one round, one file. What makes that
acceptable is that everything it asserts is independently checkable — the audit
plan, the epoch roots and the leaves are all published, and CI re-derives them from
public data on every push. An operator who lies gets caught by anyone who looks; an
operator who disappears stops the round without being able to rewrite it.

## What runs where

| piece | where | how |
|---|---|---|
| the site, `rhonet.dev` | Cloudflare Workers | pushed by CI on every green `main` |
| the coordinator | one always-on machine, loopback only | `deploy/run-coordinator.sh` under launchd |
| `api.rhonet.dev` | Cloudflare Tunnel to that machine | `cloudflared tunnel run` under launchd |
| audit beacon | drand mainnet | fetched per epoch, after the batch seals |

The coordinator never listens on a public interface. The tunnel is outbound-only,
so there is no inbound port, no firewall exception, and no certificate to renew.

## First-time setup

**1. A Cloudflare API token.** One token covers both the site deploy and the
tunnel. Create it at Cloudflare → My Profile → API Tokens → Create Token → Custom:

- Account → Workers Scripts → Edit  (the site)
- Account → Cloudflare Tunnel → Edit  (the connector)
- Zone → DNS → Edit, on `rhonet.dev`  (the `api` record)

Scope it to the account that holds `rhonet.dev` and nothing else.

We use a token rather than `cloudflared login` deliberately. A browser login writes
an account-scoped `cert.pem` and binds the machine to whichever Cloudflare account
happened to be signed in at that moment; that has silently broken this project's
deploys twice. A token names its account.

Add it to the repository as the secret `CLOUDFLARE_API_TOKEN`, alongside
`CLOUDFLARE_ACCOUNT_ID`. Until both exist the `deploy` job fails on purpose, with a
message saying so, and `rhonet.dev` keeps serving whatever it last served.

**2. The tunnel.**

    export CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=...
    python -m tools.cf_tunnel --hostname api.rhonet.dev --service http://127.0.0.1:8642

It creates or reuses a tunnel named `rhonet`, stores the ingress rule on
Cloudflare's side, points `api.rhonet.dev` at it, and prints a connector token.
Put that token in `deploy/tunnel.token` (gitignored) on the coordinator host.

**3. The services.** Copy both plists from `deploy/`, replace `REPO` with the
checkout path, and load them:

    sed "s|REPO|$PWD|g" deploy/dev.rhonet.coordinator.plist > ~/Library/LaunchAgents/dev.rhonet.coordinator.plist
    sed "s|REPO|$PWD|g" deploy/dev.rhonet.tunnel.plist      > ~/Library/LaunchAgents/dev.rhonet.tunnel.plist
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.rhonet.coordinator.plist
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.rhonet.tunnel.plist

**4. Confirm.**

    curl -fsS https://api.rhonet.dev/healthz
    curl -fsS https://api.rhonet.dev/api/status | python -m json.tool | head -40

The site picks up live data on its own: it polls `/api/status` and
`/api/contributors` every fifteen seconds and replaces the static board. If the API
is unreachable the page stays exactly as written, which is why nothing on it is
left blank waiting for a response.

## The beacon

`RHONET_BEACON_URL` defaults to `https://api.drand.sh/public/latest`. drand
publishes a fresh 32-byte value every thirty seconds from a threshold network the
operator has no part in.

The order matters more than the source. Each epoch is sealed first — membership,
addresses and the batch commitment are frozen — and only then is the beacon
fetched. A contributor deciding what to submit cannot know which of its points will
be challenged, because the value did not exist yet.

Two guards worth knowing about:

- A fetch failure **aborts the epoch close** rather than falling back to the
  operator's own entropy. The epoch stays open and closes on the next attempt. An
  audit is not something to degrade quietly.
- A beacon value identical to the previous epoch's is **refused**. A pinned URL, a
  cached response, an endpoint returning a constant — whatever the cause, a
  repeating beacon makes the audit predictable, and the epoch stays open instead.

For an unfunded exercise the built-in commit–reveal fallback would also be
defensible, but there is no reason to use it when drand is a URL away, and a funded
round must not.

## Watching it

`deploy/monitor.sh` probes the coordinator from inside and from outside, prints one
line per run, and exits nonzero when something needs a person:

    */5 * * * * cd /path/to/rhonet && deploy/monitor.sh >> logs/monitor.log 2>&1

What it flags:

- **LOCAL DOWN** — the process is gone. launchd restarts it; if it does not,
  read `logs/coordinator.log`.
- **PUBLIC DOWN** — the process is fine but nobody can reach it. Tunnel or DNS.
- **DEGRADED** — the epoch loop has failed three times running. Usually the
  beacon. The status endpoint reports this too, publicly, as `degraded`.
- **STALLED** — more than one epoch is waiting to close. Being one behind is
  normal: closing waits out the audit response window.

## Things that will happen, and what they mean

**An epoch will not close.** Almost always the beacon: drand unreachable, or the
same value twice. The round is not stuck — contributors keep searching and
submitting, and everything settles when the epoch finally closes. Nothing is lost.

**A contributor is slashed.** A challenged segment did not replay. The event log
carries the reproduction: the identity, the identifier, the claimed values and the
replayed ones. Look before assuming it is a cheat; a broken third-party client
looks exactly the same from here, which is a good reason for
`tests/test_vectors.py` to exist.

**The round halts for review.** Two walks met, the collision produced a `k`, and
`k·G ≠ Q`. This should be impossible and means something upstream is wrong. The
round stops accepting work rather than settling on a wrong answer. For Exercise 97
the correct answer is known — `0x16c86aa7cacf69f1dd28b3e2f` — so this is
diagnosable rather than mysterious.

**The database grows.** Exercise 97 expects about 784,000 points, on the order of
200 MB. Back up `data/exercise-97.sqlite` on a schedule. It is the round.

**The machine reboots.** launchd brings both services back. The coordinator resumes
from the database: sealed epochs stay sealed, the audit plan is durable, and
sequence numbers survive, so a captured request still cannot be replayed.

## Publishing the audit trail

After epochs close, publish them so a third party can re-derive the selection:

    python tools/publish_epochs.py --db data/exercise-97.sqlite --out public/epochs
    python tools/verify_audit.py public/epochs      # what CI runs

Commit the result. CI re-derives every published epoch on every push, so a
tampered file fails the build rather than sitting there looking official.

## Ending the round

When two walks meet, the coordinator solves the collision, verifies `k·G = Q`,
moves to `settling`, and closes a final epoch. Clients see `solved` and drain their
outstanding audit challenges before exiting — they must not walk away from work
they can still prove they did.

For Exercise 97 the last step is the one that matters: check the answer against the
one published in March 1998. If it matches, the pipeline is correct end to end on a
real problem. If it does not, we found that out on a round where finding out was
free.
