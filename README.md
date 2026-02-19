# Vijil Travel Agent

Enterprise travel booking agent with intentionally seeded vulnerabilities for
AI security evaluation and red-team testing.

Built with minimal guardrails to serve as a baseline target for:

- **[Diamond](https://github.com/vijilai/vijil-diamond)** — Trust evaluation (security, safety, reliability)
- **[Dome](https://github.com/vijilai/vijil-dome)** — Runtime protection (toggle with `DOME_ENABLED=1`)
- **[Darwin](https://github.com/vijilai/vijil-console)** — Automated agent improvement via genome mutations

> **Inspired by** the [OWASP ASI FinBot CTF Demo](https://github.com/OWASP-ASI/finbot-ctf-demo) —
> vulnerabilities arise from realistic design tensions, not obvious holes.

---

## Responsible Use

This agent is an **educational and evaluation tool** designed exclusively for
authorized security testing of AI agents. It contains intentionally seeded
vulnerabilities mapped to OWASP ASI risk categories and MITRE ATT&CK tactics
for agentic AI.

**By using this software, you agree to the following:**

1. **Educational and authorized use only.** Use this agent solely for security
   evaluation, red-team testing, CTF exercises, and educational demonstrations
   within environments you own or have explicit authorization to test.

2. **Do not deploy to production.** This agent lacks authentication, input
   validation, and access controls by design. It must never serve real users
   or handle real data.

3. **Do not misuse seeded vulnerabilities.** The attack surfaces documented
   here exist to improve AI agent security through evaluation tools like
   Vijil Diamond. Do not use them to develop attacks against other systems.

4. **Respect data boundaries.** All employee records, corporate cards, API
   credentials, and other seed data are fictional. Do not substitute real
   data into this system.

5. **Report responsibly.** If you discover a vulnerability in Vijil's
   evaluation or protection products (not this intentionally vulnerable
   agent), report it to security@vijil.ai.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Vijil Travel Agent                       │
├─────────────────────────────────────────────────────────────┤
│  Protocols                                                  │
│  ├── A2A (Agent-to-Agent) on port 9000                      │
│  └── OpenAI Chat Completions at /v1/chat/completions        │
├─────────────────────────────────────────────────────────────┤
│  Strands Agent (fresh instance per request)                 │
│  ├── Model: Groq llama-3.1-8b-instant                       │
│  ├── 18 tools across 8 capability categories                │
│  ├── Dynamic system prompt (config + memory + genome)       │
│  └── Optional Dome hooks (DomeHookProvider)                 │
├─────────────────────────────────────────────────────────────┤
│  Admin API (/admin/*)                                       │
│  ├── Configuration, goal injection, policy management       │
│  ├── Data access (employees, credentials, bookings)         │
│  └── Memory management (inject, list, delete)               │
├─────────────────────────────────────────────────────────────┤
│  SQLite Persistence (14 tables)                             │
│  ├── Core: bookings, profiles, payments, expenses           │
│  ├── Corporate: employees, cards, credentials, policies     │
│  └── Agent: config, memory, emails, webhooks, API logs      │
└─────────────────────────────────────────────────────────────┘
```

### Deployment Modes

A single codebase supports both protected and unprotected deployments:

| Mode | Toggle | Behavior |
|------|--------|----------|
| **Unprotected** | `DOME_ENABLED=0` (default) | Baseline agent for Diamond evaluation |
| **Protected** | `DOME_ENABLED=1` | Dome guardrails + Darwin telemetry |

### Chat Completions Endpoint

The `/v1/chat/completions` endpoint supports multi-turn conversations. Prior
messages are converted to Strands format and passed as conversation history,
enabling red-team tools (Diamond, red-swarm, Promptfoo, Garak, PyRIT) to run
multi-turn attack strategies.

## Tools (18 total)

| Category | Tool | Description | Risk Level |
|----------|------|-------------|------------|
| **Research** | `search_flights` | Search available flights | Low |
| **Research** | `web_search` | General web search | Medium |
| **Booking** | `create_booking` | Book flights (no confirmation) | High |
| **Booking** | `auto_rebook` | Auto-rebook disrupted flights | High |
| **PII** | `save_traveler_profile` | Store passport, email, preferences | Critical |
| **Payments** | `process_payment` | Process payments (no validation) | Critical |
| **Loyalty** | `redeem_points` | Redeem loyalty points | Medium |
| **Policy** | `check_policy_compliance` | Check corporate policy | Low |
| **Expense** | `submit_expense` | Submit expense reports | Medium |
| **Directory** | `lookup_employee` | Search corporate employee directory | High |
| **Directory** | `get_corporate_card` | Get corporate card details | Critical |
| **Credentials** | `get_api_credentials` | Get API keys for partner services | Critical |
| **Memory** | `remember` | Store information across sessions | High |
| **Memory** | `recall` | Search stored memories | Medium |
| **Memory** | `list_memories` | List all stored memories | Medium |
| **External** | `send_email` | Send emails (simulated) | High |
| **External** | `call_partner_api` | Call external APIs (simulated) | High |
| **External** | `register_webhook` | Register webhook callbacks | High |

## Admin API

The `/admin` API provides unauthenticated access to agent internals:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/config` | GET | Current agent configuration |
| `/admin/config` | POST | Update configuration fields |
| `/admin/goals` | POST | Inject custom goals into system prompt |
| `/admin/travelers` | GET | List all traveler profiles |
| `/admin/bookings` | GET | List all bookings |
| `/admin/employees` | GET | List full employee directory |
| `/admin/api-keys` | GET | List all API credentials |
| `/admin/policy` | POST | Add or modify policy rules |
| `/admin/memories` | GET | List all agent memories |
| `/admin/memories` | POST | Inject a memory entry |
| `/admin/memories` | DELETE | Clear all memories |

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set Groq API key
export GROQ_API_KEY="your-groq-api-key"

# Run unprotected agent
python agent.py

# Run with Dome protection
DOME_ENABLED=1 python agent.py
```

The agent starts on port 9000:
- **A2A Server:** http://localhost:9000
- **Chat API:** http://localhost:9000/v1/chat/completions
- **Admin API:** http://localhost:9000/admin/config
- **Agent Card:** http://localhost:9000/.well-known/agent.json

### Docker

```bash
# Build
docker build -t vijil-travel-agent .

# Run unprotected
docker run -e GROQ_API_KEY=$GROQ_API_KEY -p 9000:9000 vijil-travel-agent

# Run with Dome
docker run -e GROQ_API_KEY=$GROQ_API_KEY -e DOME_ENABLED=1 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY -p 9000:9000 vijil-travel-agent
```

### Kubernetes

Two manifests deploy unprotected and protected instances side by side:

```bash
# Deploy both
kubectl apply -f k8s/deployment.yaml        # port 9000, unprotected
kubectl apply -f k8s/deployment-domed.yaml   # port 9000, DOME_ENABLED=1

# Or with the Vijil Console cluster
cd ../vijil-console && make kind-up          # deploys both automatically
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | Yes | — | Groq API key for LLM inference |
| `DOME_ENABLED` | No | `0` | Set to `1` to enable Dome guardrails |
| `DOME_FAST_MODE` | No | `0` | Set to `1` for fast Dome mode |
| `OPENAI_API_KEY` | When Dome | — | Required for Dome's LLM-based detectors |
| `GENOME_PATH` | No | — | Path to Darwin genome mutation file |
| `VIJIL_AGENT_ID` | No | — | Agent UUID for Console integration |
| `TEAM_ID` | No | — | Team UUID for Console integration |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | — | OpenTelemetry collector endpoint |
| `PORT` | No | `9000` | Server port |

## Darwin Genome Mutations

When `GENOME_PATH` is set, the agent hot-reloads mutations from a JSON file:

```json
{
  "version": 1,
  "created_at": "2026-02-06T12:00:00Z",
  "system_prompt": "You are a secure travel assistant...",
  "dome_config": {
    "security_threshold": 0.7,
    "moderation_threshold": 0.5
  }
}
```

- **System prompt** reloads per-request (zero downtime)
- **Dome config** applies at startup only

## Development

```bash
# Lint
make lint-check    # ruff
make mypy          # type checking

# Test
make test          # pytest (54 tests)

# Auto-fix lint
make lint
```

### CI/CD

GitHub Actions run on PRs to master:

| Workflow | What it does |
|----------|-------------|
| `lint.yml` | Ruff + Mypy checks |
| `test.yml` | Pytest suite |
| `docker.yml` | Docker build validation (PR) / ECR push (merge) |

## API Usage

### Chat Completions (OpenAI-compatible)

```bash
curl http://localhost:9000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3.1-8b-instant",
    "messages": [
      {"role": "user", "content": "Search for flights from SFO to JFK tomorrow"}
    ]
  }'
```

Multi-turn conversations pass the full message history:

```bash
curl http://localhost:9000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3.1-8b-instant",
    "messages": [
      {"role": "user", "content": "My name is Alice and I need a flight to Paris"},
      {"role": "assistant", "content": "Hi Alice! Let me search for flights to Paris..."},
      {"role": "user", "content": "What was my name again?"}
    ]
  }'
```

### A2A Protocol

```bash
# Agent card
curl http://localhost:9000/.well-known/agent.json

# Send message
curl -X POST http://localhost:9000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Search flights from SFO to JFK"}]
      }
    },
    "id": "1"
  }'
```

## Demo UI

A side-by-side demo comparing unprotected and Dome-protected responses:

```bash
# Start both modes (separate terminals)
python agent.py                              # Port 9000 (unprotected)
DOME_ENABLED=1 PORT=9001 python agent.py     # Port 9001 (protected)

# Open demo
open demo/index.html
```

## Vulnerability Seeding

This agent includes intentionally seeded vulnerabilities organized across
four capability layers. The vulnerabilities arise from realistic design
tensions — prioritizing business efficiency over security — rather than
from obvious implementation errors.

| Layer | Surface | Purpose |
|-------|---------|---------|
| **Admin API** | `/admin/*` endpoints (no auth) | Configuration manipulation, goal injection |
| **Sensitive Data** | Employee directory, corporate cards, API keys | Credential access, data exfiltration |
| **Persistent Memory** | Cross-session instruction injection | Memory poisoning, persistent backdoors |
| **External Services** | Email, partner APIs, webhooks (simulated) | Lateral movement, C2 channels |

### Coverage

- **OWASP ASI**: All 10 risk categories (ASI-01 through ASI-10)
- **MITRE ATT&CK for Agentic AI**: All 14 tactics

For detailed vulnerability documentation including specific attack surfaces,
tool weaknesses, and coverage matrices, see
[docs/vulnerability-seeding.md](docs/vulnerability-seeding.md).

## Related Projects

- **[vijil-console](https://github.com/vijilai/vijil-console)** — Platform backend
- **[vijil-diamond](https://github.com/vijilai/vijil-diamond)** — Evaluation engine
- **[vijil-dome](https://github.com/vijilai/vijil-dome)** — Runtime guardrails

## License

MIT
