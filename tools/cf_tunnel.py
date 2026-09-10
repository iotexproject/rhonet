"""Create (or reuse) the Cloudflare Tunnel that puts the coordinator on the internet.

The coordinator binds to 127.0.0.1 and is never exposed directly. A tunnel makes
the origin outbound-only -- no port forwarding, no inbound firewall hole, no
certificate to renew -- and Cloudflare terminates TLS at api.rhonet.dev.

This uses an API token rather than an interactive `cloudflared login`, because a
browser login writes an account-scoped cert.pem and silently binds the machine to
whichever Cloudflare account happened to be signed in. That has broken this
project's deploys twice. A token names its account explicitly.

    export CLOUDFLARE_API_TOKEN=...        # Account: Cloudflare Tunnel: Edit
    export CLOUDFLARE_ACCOUNT_ID=...       #          Zone: DNS: Edit on the zone
    python -m tools.cf_tunnel --hostname api.rhonet.dev --service http://127.0.0.1:8642

It prints the connector token. Nothing else needs it, and nothing else should see
it: it authorises a connection into the account, so treat it like a password.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"


def call(method: str, path: str, token: str, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.load(r)
    except urllib.error.HTTPError as e:
        payload = json.load(e)
    if not payload.get("success"):
        raise SystemExit("Cloudflare API refused %s %s:\n  %s" % (
            method, path, json.dumps(payload.get("errors"), indent=2)))
    return payload["result"]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostname", default="api.rhonet.dev")
    ap.add_argument("--service", default="http://127.0.0.1:8642")
    ap.add_argument("--name", default="rhonet")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not token or not account:
        raise SystemExit("set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID first; see DEPLOY.md")
    zone_name = args.hostname.split(".", 1)[1]

    if args.dry_run:
        print(f"would create tunnel {args.name!r} in account {account},"
              f" route {args.hostname} -> {args.service}, and CNAME it in zone {zone_name}")
        return 0

    existing = [t for t in call("GET", f"/accounts/{account}/cfd_tunnel?is_deleted=false", token)
                if t["name"] == args.name]
    if existing:
        tunnel = existing[0]
        print(f"reusing tunnel {args.name} ({tunnel['id']})", file=sys.stderr)
    else:
        tunnel = call("POST", f"/accounts/{account}/cfd_tunnel", token,
                      {"name": args.name, "config_src": "cloudflare"})
        print(f"created tunnel {args.name} ({tunnel['id']})", file=sys.stderr)

    # Ingress is stored on Cloudflare's side, so the origin holds no config file
    # and a route change does not need a restart. The catch-all 404 is required.
    call("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel['id']}/configurations", token,
         {"config": {"ingress": [
             {"hostname": args.hostname, "service": args.service,
              "originRequest": {"connectTimeout": "30s", "keepAliveTimeout": "90s"}},
             {"service": "http_status:404"}]}})
    print(f"routed {args.hostname} -> {args.service}", file=sys.stderr)

    zones = call("GET", f"/zones?name={zone_name}", token)
    if not zones:
        raise SystemExit(f"zone {zone_name} is not in account {account}; "
                         "the token must be scoped to the account that holds it")
    zone = zones[0]["id"]
    target = f"{tunnel['id']}.cfargotunnel.com"
    records = call("GET", f"/zones/{zone}/dns_records?name={args.hostname}", token)
    record = {"type": "CNAME", "name": args.hostname, "content": target, "proxied": True,
              "comment": "rhonet coordinator, via tunnel " + args.name}
    if records:
        if records[0]["content"] != target or records[0]["type"] != "CNAME":
            call("PUT", f"/zones/{zone}/dns_records/{records[0]['id']}", token, record)
            print(f"repointed {args.hostname} -> {target}", file=sys.stderr)
        else:
            print(f"{args.hostname} already points at {target}", file=sys.stderr)
    else:
        call("POST", f"/zones/{zone}/dns_records", token, record)
        print(f"created {args.hostname} -> {target}", file=sys.stderr)

    secret = call("GET", f"/accounts/{account}/cfd_tunnel/{tunnel['id']}/token", token)
    print(secret)
    print("\nRun the connector on the coordinator host with:\n"
          f"  cloudflared tunnel run --token <the token printed above>\n"
          "Store it in deploy/tunnel.token (gitignored) and the launchd job will use it.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
