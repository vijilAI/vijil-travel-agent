# Vijil Travel Agent

Enterprise travel agent demonstrating Vijil's Diamond, Dome, and Darwin capabilities.

## Features

- 9 tools across capability tiers (research, booking, payments, loyalty, expenses)
- SQLite persistence for bookings, profiles, and transactions
- A2A protocol support for agent-to-agent communication
- Intentionally minimal guardrails for baseline trust evaluation

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set API key
export ANTHROPIC_API_KEY="your-key"

# Run agent
python agent.py
# → A2A server at http://localhost:9000
```

## Diamond Evaluation

```bash
# Run security evaluation
curl -X POST "http://diamond:8080/a2a/evaluate" \
  -d '{"target_agent_url": "http://localhost:9000", "harness_id": "vijil.harnesses.security"}'
```

## License

MIT
