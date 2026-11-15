#!/usr/bin/env bash
# Build, push, and deploy the travel agent to DigitalOcean App Platform, then smoke-test it.
# Idempotent: creates the app on first run, redeploys with the new image tag after that.
#
# Requires: doctl, docker buildx, envsubst, curl, jq.
# Env: DIGITALOCEAN_ACCESS_TOKEN, GROQ_API_KEY, OPENAI_API_KEY
#      STATE_ORACLE_TOKEN (>= 32 chars): bearer token for GET /oracle/state, shared with the
#      evaluator that reads it (Red Swarm's TARGET_STATE_ORACLE_TOKEN)
#      AGENT_MODEL_ID (default: llama-3.3-70b-versatile on Groq)
# Prints the public base URL (ending in /v1) on the last line of stdout.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DIGITALOCEAN_ACCESS_TOKEN:?}" "${GROQ_API_KEY:?}" "${OPENAI_API_KEY:?}"
: "${STATE_ORACLE_TOKEN:?}"
[ "${#STATE_ORACLE_TOKEN}" -ge 32 ] || { echo "STATE_ORACLE_TOKEN must be at least 32 characters." >&2; exit 1; }
export AGENT_MODEL_ID="${AGENT_MODEL_ID:-llama-3.3-70b-versatile}"
REGISTRY=registry.digitalocean.com/vijil

# One image per commit, so a certificate can name the exact code it covers.
[ -z "$(git status --porcelain)" ] || { echo "Working tree is dirty; commit first." >&2; exit 1; }
export IMAGE_TAG="$(git rev-parse --short HEAD)"

# Preflight: the agent turns a provider error into a polite refusal, so a retired
# model would still pass the chat smoke test. Check the model exists before building.
curl -fsS https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY" \
  | jq -e --arg m "$AGENT_MODEL_ID" 'any(.data[]; .id == $m)' >/dev/null \
  || { echo "Groq does not serve model '$AGENT_MODEL_ID' for this key." >&2; exit 1; }

doctl registry login --expiry-seconds 1200 >&2
docker buildx build --platform linux/amd64 --push -t "$REGISTRY/travel-agent:$IMAGE_TAG" . >&2

envsubst '${IMAGE_TAG} ${AGENT_MODEL_ID} ${GROQ_API_KEY} ${OPENAI_API_KEY} ${STATE_ORACLE_TOKEN}' < deploy/do-app.yaml \
  | doctl apps create --upsert --wait --spec - --output json >/dev/null

URL="$(doctl apps list --output json | jq -r '.[] | select(.spec.name=="vijil-travel-agent") | .live_url')"
[ -n "$URL" ] && [ "$URL" != null ] || { echo "No live URL for vijil-travel-agent." >&2; exit 1; }

# Smoke test: the card and chat must answer; the admin API must not be public.
curl -fsS "$URL/.well-known/agent.json" | jq -e '.name' >&2
curl -fsS -m 120 "$URL/v1/chat/completions" -H 'Content-Type: application/json' \
  -d '{"model":"travel-agent","messages":[{"role":"user","content":"What can you help me with?"}]}' \
  | jq -e '.choices[0].message.content | length > 0' >&2
code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/admin/api-keys")"
[ "$code" = 404 ] || { echo "SECURITY: /admin/api-keys returned $code, expected 404." >&2; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/oracle/state?conversation_id=smoke")"
[ "$code" = 401 ] || { echo "SECURITY: /oracle/state without a token returned $code, expected 401." >&2; exit 1; }

echo "$URL/v1"
