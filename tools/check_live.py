"""Hold the published site to what it claims, from outside our own network.

Two delivery failures survived a full review cycle here: the apex served a build
two revisions old, and the join instructions pointed at a hostname that did not
resolve. Neither is a design flaw and neither was caught by anything, because
nothing checked the deployed artefact against the repository.

    python -m tools.check_live                       # both checks
    python -m tools.check_live --skip-deploy         # only the round-state check

Exit code 1 on any failure, with the reason on stderr.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs/index.html"
APEX = "https://rhonet.dev/"
API = "https://api.rhonet.dev"
UA = {"User-Agent": "rhonet-check-live"}


def fetch(url, timeout=20):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", "replace")


def meta(html: str, name: str):
    match = re.search(rf'<meta\s+name="{name}"\s+content="([^"]*)"', html)
    return match.group(1) if match else None


def check_round_state(problems):
    """The site may not advertise a round the coordinator does not serve.

    'opening' claims nothing and always passes. 'open' is a promise about a
    hostname, and this is the only thing that checks it.
    """
    local = SITE.read_text()
    state = meta(local, "rhonet-round-state")
    if state not in ("opening", "open"):
        problems.append(f"docs/index.html declares rhonet-round-state={state!r}; "
                        "it must be 'opening' or 'open'")
        return
    if state == "opening":
        print("round state: opening (claims nothing about the coordinator)")
        return
    round_id = meta(local, "rhonet-round-id")
    try:
        status, body = fetch(API + "/healthz")
    except (urllib.error.URLError, OSError) as exc:
        problems.append(
            f"the site says the round is OPEN, but {API}/healthz is unreachable "
            f"({type(exc).__name__}). Either bring the coordinator up or set "
            "rhonet-round-state back to 'opening'. A contributor who follows the "
            "published instructions fails at the first network call.")
        return
    if status != 200 or f'"round_id":"{round_id}"' not in body.replace(" ", ""):
        problems.append(f"{API}/healthz returned {status} and does not serve "
                        f"{round_id!r}: {body[:200]}")
        return
    print(f"round state: open, and {API} serves {round_id}")


def check_deployed(problems):
    """The canonical domain must serve what is in the repository."""
    local = SITE.read_text()
    try:
        status, served = fetch(APEX)
    except (urllib.error.URLError, OSError) as exc:
        problems.append(f"{APEX} is unreachable ({type(exc).__name__})")
        return
    if status != 200:
        problems.append(f"{APEX} returned {status}")
        return
    if served.strip() == local.strip():
        print(f"{APEX} serves docs/index.html exactly")
        return
    # Say what drifted, not just that something did. The useful signal is which
    # of the corrections this project has already made is missing from the apex.
    detail = []
    for marker, what in (
            ('name="rhonet-round-state"', "the round-state declaration"),
            ("Verification cost", "the verification-cost section"),
            ("Exercise 97", "Exercise 97"),
            ("collective discovery", "the category line")):
        if marker in local and marker not in served:
            detail.append(what)
    problems.append(
        f"{APEX} does not serve the committed page"
        + (f"; missing: {', '.join(detail)}" if detail else "")
        + f" (served {len(served)} bytes, repository has {len(local)})."
        " Redeploy from main, or point the apex at a build that is current.")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-deploy", action="store_true",
                    help="skip the served-page comparison (useful before the first deploy)")
    args = ap.parse_args(argv)
    problems: list[str] = []
    check_round_state(problems)
    if not args.skip_deploy:
        check_deployed(problems)
    for problem in problems:
        print("FAIL: " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
