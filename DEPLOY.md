# Deploying the site

`rhonet.dev` is a Cloudflare Workers static-assets deployment of `docs/`, published
automatically by the `deploy` job in `.github/workflows/verify.yml`.

Every push to `main` runs the contributor-registry check, the audit-trail
re-derivation, the protocol tests and the Foundry suite. The deploy job runs only
after all four pass, so the public site can never be published from a red tree.
Pull requests run the checks and deploy nothing.

## One-time setup

The workflow needs a Cloudflare API token. It deliberately does not use anyone's
`wrangler login`: a local OAuth session belongs to whoever logged in last on that
machine, which has already caused two failed deploys.

1. In the Cloudflare dashboard, as a user with access to the account that owns the
   `rhonet` Worker, go to **My Profile → API Tokens → Create Token → Create Custom Token**.
2. Permissions: **Account → Workers Scripts → Edit**. Add **Account → Workers Routes → Edit**
   if custom domains will be changed from CI. Scope it to that one account.
3. Add two repository secrets under **Settings → Secrets and variables → Actions**:
   - `CLOUDFLARE_API_TOKEN` — the token from step 2
   - `CLOUDFLARE_ACCOUNT_ID` — the account that owns the Worker

The job fails with a readable message rather than a stack trace if either is absent.

## Deploying by hand

Rarely needed, and it depends on your local login being the right account:

```bash
CLOUDFLARE_ACCOUNT_ID=<account> npx wrangler deploy
```

## What gets deployed

`wrangler.jsonc` publishes the `docs/` directory as static assets on the `rhonet`
Worker, bound to `rhonet.dev` and `www.rhonet.dev` as custom domains. Nothing in
`rhonet/`, `contracts/` or `public/` is served; the coordinator is not hosted here.
