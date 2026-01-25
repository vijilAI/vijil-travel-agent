# CLAUDE.md - vijil-travel-agent

**Company context:** @../CLAUDE.md

Demo travel agent for testing Vijil evaluation and protection systems.

## Purpose

This is a simple travel booking agent used to:
- Demonstrate Diamond evaluation capabilities
- Test security probes and safety harnesses
- Validate Dome protection guardrails

## Structure

- `agent.py` - Main agent implementation
- `tools/` - Agent tools (booking, search, etc.)
- `db/` - SQLite database for bookings
- `Dockerfile` - Container build

## Running

```bash
# With environment from parent
source ../.env
python agent.py
```

## Evaluation

This agent is a target for Diamond evaluation. See `vijil-console/scripts/test_darwin.py` for GEPA optimization tests.
