#!/bin/bash
# Start the Exercise 97 coordinator. Bound to loopback on purpose: the only way in
# is the Cloudflare Tunnel, which terminates TLS at api.rhonet.dev.
set -euo pipefail
cd "$(dirname "$0")/.."

ROUND=${ROUND:-rounds/eccp97.json}
PORT=${PORT:-8642}
DB=${DB:-data/exercise-97.sqlite}

# Public randomness for audit selection, fetched only after a batch is sealed, so
# no contributor can know which of its points will be challenged. drand's mainnet
# chain publishes a fresh value every 30 seconds; the coordinator refuses to close
# an epoch whose beacon repeats the previous one.
export RHONET_BEACON_URL=${RHONET_BEACON_URL:-https://api.drand.sh/public/latest}
export RHONET_ALLOWED_ORIGINS=${RHONET_ALLOWED_ORIGINS:-https://rhonet.dev,https://www.rhonet.dev}

mkdir -p data logs
exec .venv/bin/python -m rhonet.coordinator \
    --round "$ROUND" --db "$DB" --host 127.0.0.1 --port "$PORT"
