# Contributor registry

One file per contributor, named for its GitHub login, binding that account to a
walker key and the address credit should accrue to. The leaderboard shows the
GitHub account rather than a hex string, and the binding is verifiable by anyone:
the signature proves the key holder claims the account, and the pull request
proves the account holder made the claim.

To register:

```bash
python -m tools.contributor sign \
  --github <your-login> --key walker.key \
  --payout 0x<address> --device "RTX 5090"
```

That writes `contributors/<your-login>.json`, generating `walker.key` if it does
not exist. Keep `walker.key`; it is the identity your credit accrues to. Open a
pull request with the JSON file only. CI checks that the signature verifies, that
the filename matches the login, and that the pull request author owns that login.

`device` is advisory and unsigned: it labels the hardware on the board and can
change without re-registering. Everything else is covered by the signature.
