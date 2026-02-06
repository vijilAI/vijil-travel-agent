# CLAUDE.md - vijil-travel-agent

**Company context:** @../CLAUDE.md

Demo travel agent for testing Vijil evaluation and protection systems.

## Purpose

This is a simple travel booking agent used to:
- Demonstrate Diamond evaluation capabilities
- Test security probes and safety harnesses
- Validate Dome protection guardrails (via vijil-domed-travel-agent)

## Repository Structure

```
vijil-travel-agent/
├── agent.py              # Main agent implementation (A2A protocol)
├── tools/                # Agent tools (booking, search, payments, etc.)
├── db/                   # SQLite database for bookings
├── demo/                 # Side-by-side comparison UI
│   ├── index.html        # Main UI (Songlines Travel Agent)
│   ├── style.css         # Styling with tabbed prompts
│   └── app.js            # A2A client, tab switching, message handling
├── Dockerfile            # Container build
└── k8s/                  # Kubernetes manifests
```

## Demo UI

The `demo/` folder contains a browser-based comparison UI that sends the same prompts to both:
- **Unprotected agent** (vijil-travel-agent) on port 9000
- **Protected agent** (vijil-domed-travel-agent with Dome) on port 9001

### Running the Demo UI

**Preferred method (served by nginx - no separate server needed):**
```bash
# 1. Deploy travel agents and demo (from vijil-console)
cd /Users/ciphr/Code/Vijil/vijil-console
make kind-deploy-travel-agents

# 2. Open http://localhost:8000/demo/
#    Everything is served from the same origin - no CORS issues!
```

**Alternative (standalone with Python HTTP server):**
```bash
# Use URL params to override endpoints
cd demo && python3 -m http.server 8080
# Open http://localhost:8080?unprotected=http://localhost:9000&protected=http://localhost:9001

# Start port-forwards in background
kubectl port-forward -n vijil-console deploy/vijil-travel-agent 9000:9000 &
kubectl port-forward -n vijil-console deploy/vijil-domed-travel-agent 9001:9000 &
```

### UI Features
- **Skills bar**: Shows agent capabilities with hover tooltips (risk levels)
- **Two chat panels**: Unprotected vs Protected (Vijil Dome) side-by-side
- **Tabbed quick prompts**: Research, Booking, Profile & Payments, Corporate, Attack Scenarios
- **Attack scenarios**: Prompt injection, jailbreak, data exfiltration tests

### A2A Protocol

The UI communicates via JSON-RPC to the A2A endpoint:
```javascript
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "<uuid>",
      "role": "user",
      "parts": [{ "type": "text", "text": "<prompt>" }]
    }
  }
}
```

Response format: `result.artifacts[].parts[].text` (with `kind: 'text'`)

## Deployment

### Local Development
```bash
source ../.env
python agent.py  # Runs on port 9000
```

### Kind Cluster
```bash
cd /Users/ciphr/Code/Vijil/vijil-console

# Full deploy (build, load, restart, demo)
make kind-deploy-travel-agents

# Individual steps (if needed)
make kind-build-travel-agents    # Build Docker images with git SHA tags
make kind-load-travel-agents     # Load images into Kind cluster
make kind-restart-travel-agents  # Restart deployments with new images
make kind-deploy-travel-demo     # Deploy demo UI ConfigMap
```

## Related Repos

| Repo | Purpose |
|------|---------|
| `vijil-domed-travel-agent` | Same agent with Dome protection layer |
| `vijil-dome` | The protection/guardrails service |
| `vijil-console` | Platform backend, Kind cluster setup |

## Evaluation

This agent is a target for Diamond evaluation. See `vijil-console/scripts/test_darwin.py` for GEPA optimization tests.
