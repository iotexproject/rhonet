"""Contributor registry: bind a GitHub account to a walker key, verifiably.

A contributor commits `contributors/<github-login>.json` containing its walker
public key, the address credit should accrue to, and a signature by that key over
a canonical statement naming the GitHub login. Anyone, including CI, can check the
binding without trusting a server: the signature proves the key holder claims that
login, and GitHub proves the pull request author owns it.

    python -m tools.contributor sign   --github <login> --key walker.key --payout 0x..
    python -m tools.contributor verify contributors/<login>.json --expect-author <login>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from rhonet import ec

STATEMENT = "rhonet-contributor-v1"
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def statement(github: str, pubkey: str, payout: str) -> bytes:
    """Exactly what is signed. Order and encoding are fixed by ec.canonical."""
    return ec.canonical({"statement": STATEMENT, "github": github.lower(),
                         "pubkey": pubkey.lower(), "payout": payout.lower()})


def sign(github: str, key_path: str, payout: str, device: str | None) -> dict:
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw).hex()
    body = {"statement": STATEMENT, "github": github.lower(), "pubkey": pub,
            "payout": payout.lower()}
    body["sig"] = key.sign(statement(github, pub, payout)).hex()
    if device:
        body["device"] = device  # advisory, not signed: it changes when hardware does
    return body


def verify(path: str, expect_author: str | None = None) -> tuple[bool, str]:
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable: {e}"

    stem = os.path.splitext(os.path.basename(path))[0]
    for field in ("statement", "github", "pubkey", "payout", "sig"):
        if not isinstance(d.get(field), str):
            return False, f"missing or non-string field: {field}"
    if d["statement"] != STATEMENT:
        return False, f"wrong statement: {d['statement']!r}"
    if not LOGIN_RE.match(d["github"]):
        return False, f"not a GitHub login: {d['github']!r}"
    if d["github"] != d["github"].lower() or stem.lower() != d["github"]:
        return False, f"filename {stem!r} must be the lowercased login {d['github']!r}"
    if not ADDR_RE.match(d["payout"]) or d["payout"] != d["payout"].lower():
        return False, "payout must be a lowercase 0x-prefixed 20-byte address"
    if len(d["pubkey"]) != 64:
        return False, "pubkey must be 32 bytes of hex"
    if expect_author and expect_author.lower() != d["github"]:
        return False, f"pull request author {expect_author!r} does not own {d['github']!r}"
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(d["pubkey"]))
        pk.verify(bytes.fromhex(d["sig"]), statement(d["github"], d["pubkey"], d["payout"]))
    except (ValueError, InvalidSignature) as e:
        return False, f"signature does not verify: {type(e).__name__}"
    if "device" in d and (not isinstance(d["device"], str) or len(d["device"]) > 80):
        return False, "device must be a short string"
    return True, f"{d['github']} -> {d['pubkey'][:16]}… paying {d['payout']}"


def load_registry(directory: str = "contributors") -> dict[str, dict]:
    """pubkey -> entry, for every file that verifies. Invalid files are ignored."""
    out = {}
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        ok, _ = verify(path)
        if ok:
            with open(path) as f:
                e = json.load(f)
            out[e["pubkey"]] = e
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--github", required=True)
    s.add_argument("--key", default="walker.key")
    s.add_argument("--payout", required=True)
    s.add_argument("--device", default=None, help="advisory hardware label, e.g. 'RTX 5090'")
    s.add_argument("--out", default=None)
    v = sub.add_parser("verify")
    v.add_argument("paths", nargs="+")
    v.add_argument("--expect-author", default=None)
    a = ap.parse_args(argv)

    if a.cmd == "sign":
        if not os.path.exists(a.key):
            key = Ed25519PrivateKey.generate()
            fd = os.open(a.key, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            print(f"generated a new walker key at {a.key}", file=sys.stderr)
        body = sign(a.github, a.key, a.payout, a.device)
        out = a.out or os.path.join("contributors", f"{a.github.lower()}.json")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w") as f:
            json.dump(body, f, indent=2)
            f.write("\n")
        print(out)
        return 0

    bad = 0
    for p in a.paths:
        ok, why = verify(p, a.expect_author)
        print(("OK   " if ok else "FAIL ") + p + "  " + why)
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
