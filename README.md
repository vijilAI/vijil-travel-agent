# Vijil Travel Agent

Enterprise travel booking agent demonstrating Vijil's trust evaluation capabilities.

## Purpose

This agent is **intentionally built with minimal guardrails** to serve as a baseline for:

- **[Vijil Diamond](https://github.com/vijilai/vijil-diamond)** - Trust evaluation (security, safety, reliability)
- **[Vijil Darwin](https://github.com/vijilai/vijil-console)** - Automated agent improvement
- **[Vijil Dome](https://github.com/vijilai/vijil-dome)** - Runtime protection (see `vijil-domed-travel-agent`)

The agent handles sensitive operations (payments, PII, bookings) without production-grade validation, making it ideal for demonstrating how Diamond detects vulnerabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Vijil Travel Agent                       │
├─────────────────────────────────────────────────────────────┤
│  A2A Protocol (Agent-to-Agent)                              │
│  ├── ConcurrentA2AExecutor (fresh agent per request)        │
│  └── Starlette/uvicorn server on port 9000                  │
├─────────────────────────────────────────────────────────────┤
│  Strands Agent                                              │
│  ├── Model: Groq llama-3.1-8b-instant                       │
│  └── 9 Tools across 5 capability tiers                      │
├─────────────────────────────────────────────────────────────┤
│  SQLite Persistence                                         │
│  └── Bookings, profiles, payments, expenses                 │
└─────────────────────────────────────────────────────────────┘
```

## Tools (9 total)

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

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set Groq API key
export GROQ_API_KEY="your-groq-api-key"

# Run agent
python agent.py

# Agent available at:
# - A2A Server: http://localhost:9000
# - Agent Card: http://localhost:9000/.well-known/agent.json
```

### Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f k8s/

# Or with the Vijil Console cluster
cd ../vijil-console
make kind-up  # Deploys travel agents automatically
```

## Demo UI

A side-by-side demo comparing this unprotected agent with the Dome-protected version.

```bash
# Start both agents (in separate terminals)
python agent.py                    # Port 9000 (this agent)
cd ../vijil-domed-travel-agent
python agent.py                    # Port 9001 (protected)

# Open demo UI
open demo/index.html
```

Or configure agent URLs via query params:
```
demo/index.html?unprotected=http://localhost:9000&protected=http://localhost:9001
```

The demo includes:
- Side-by-side chat panels
- "Send to Both" for simultaneous comparison
- Quick prompts including attack examples
- Visual highlighting when Dome blocks attacks

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GROQ_API_KEY` | Yes | Groq API key for LLM inference |
| `PORT` | No | Server port (default: 9000) |

## A2A Protocol

This agent implements the [A2A (Agent-to-Agent) protocol](https://github.com/google/a2a) for inter-agent communication.

### Agent Card

```bash
curl http://localhost:9000/.well-known/agent.json
```

### Send Message

```bash
curl -X POST http://localhost:9000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Search for flights from SFO to JFK tomorrow"}]
      }
    },
    "id": "1"
  }'
```

## Diamond Evaluation

Run a trust evaluation against this agent:

```bash
# Using the Vijil Console API
curl -X POST "http://localhost:8000/evaluations/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "<agent-uuid>",
    "team_id": "<team-uuid>",
    "harness_names": ["security", "safety", "reliability"]
  }'
```

## Intentional Vulnerabilities

This agent includes intentional weaknesses for trust evaluation:

| Vulnerability | Location | Diamond Detection |
|---------------|----------|-------------------|
| No booking confirmation | `tools/booking.py` | Reliability harness |
| No payment validation | `tools/payments.py` | Security harness |
| PII stored without encryption | `tools/profile.py` | Security harness |
| No input sanitization | All tools | Security harness |
| Minimal system prompt | `agent.py` | Safety harness |

## Concurrency

The agent supports **unlimited concurrent requests** via `ConcurrentA2AExecutor`:

- Fresh `Agent` instance created per request
- No `ConcurrencyException` from Strands SDK
- Memory overhead: ~60KB per concurrent request
- Bottleneck: Groq API rate limits (not local resources)

## Related Projects

- **[vijil-domed-travel-agent](../vijil-domed-travel-agent)** - Same agent with Dome protection
- **[vijil-console](../vijil-console)** - Platform backend
- **[vijil-diamond](../vijil-diamond)** - Evaluation engine

## License

MIT
