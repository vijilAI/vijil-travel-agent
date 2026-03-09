# Deploying vijil-travel-agent to EKS

This guide covers deploying the travel agent to an **EKS cluster** where **Vijil Console** (dev or staging) is already running. **Step 1–2** deploy the agent to EKS; **Step 3** (seeding) registers it in the Console browser and can be done in a follow-up step.

## What This Project Does

**vijil-travel-agent** is a demo travel booking agent used to:

- **Demonstrate [Diamond](https://github.com/vijilai/vijil-diamond)** evaluation (security, safety, reliability)
- **Test [Dome](https://github.com/vijilai/vijil-dome)** runtime protection (use `DOME_ENABLED=1` for the protected variant)
- **Validate Darwin** agent improvement workflows

It speaks **A2A** on port 9000 and exposes **OpenAI-compatible** `/v1/chat/completions` and an **Admin API** at `/admin/*`. It is intentionally seeded with vulnerabilities for red-team and evaluation use only.

---

## Prerequisites

- An **EKS cluster** with **Vijil Console** (e.g. dev); testing agents run in namespace **`vijil-sample-agents`**
- `kubectl` configured for that cluster
- **Docker** and **AWS CLI** (for building and pushing the image)
- A **Kubernetes Secret** `vijil-secrets` in namespace `vijil-sample-agents` with at least `GROQ_API_KEY` (and `OPENAI_API_KEY` for the domed deployment)

---

## 1. Build and Push the Image to ECR

The ECR image may not exist yet (e.g. before CI has run). Build and push it from the **vijil-travel-agent** repo:

**Create the ECR repository (one-time):**

```bash
make eks-ecr-create
# Or: aws ecr create-repository --repository-name vijil-travel-agent --region us-west-2
```

**Build and push the image:**

```bash
cd /Users/kaiwang/vijil/vijil-travel-agent
make eks-push
```

This runs `make build` (docker build), logs in to ECR, tags the image as `:<git-sha>` and `:latest`, and pushes. Override the tag with `IMAGE_TAG=my-tag make eks-push` if needed.

**Note:** The Dockerfile expects a local `vijil_dome-*.whl` in the repo (for Dome integration). If the build fails on `COPY vijil_dome-*.whl`, obtain or build the wheel from the vijil-dome repo and place it in the vijil-travel-agent root before running `make eks-push`.

---

## 2. Ensure Namespace and Secret

Use the existing **`vijil-sample-agents`** namespace. Create it if it does not exist, and ensure the travel agent has a secret with `GROQ_API_KEY`:

```bash
kubectl create namespace vijil-sample-agents --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic vijil-secrets \
  --namespace vijil-sample-agents \
  --from-literal=GROQ_API_KEY='your-groq-api-key' \
  --from-literal=OPENAI_API_KEY='your-openai-api-key' \
  --dry-run=client -o yaml | kubectl apply -f -
```

If `vijil-secrets` already exists in `vijil-sample-agents`, add or patch the keys above as needed.

---

## 3. Deploy the Travel Agent to EKS

From the **vijil-travel-agent** repo:

```bash
# Unprotected agent (baseline for Diamond evaluation)
kubectl apply -f k8s/deployment-eks.yaml

# Optional: Dome-protected agent (for Dome/Darwin demos)
kubectl apply -f k8s/deployment-domed-eks.yaml
```

Use a specific image tag if you did not push `:latest`:

```bash
kubectl set image deployment/vijil-travel-agent \
  agent=266735823956.dkr.ecr.us-west-2.amazonaws.com/vijil-travel-agent:$(git rev-parse --short HEAD) \
  -n vijil-sample-agents
kubectl rollout status deployment/vijil-travel-agent -n vijil-sample-agents
```

Verify pods and services:

```bash
kubectl get pods,svc -n vijil-sample-agents -l app=vijil-travel-agent
kubectl get pods,svc -n vijil-sample-agents -l app=vijil-domed-travel-agent
```

The agent is reachable in-cluster at `http://vijil-travel-agent.vijil-sample-agents.svc.cluster.local:9000`.

---

## 4. Register the Agent in the Dev Vijil Console (Browser)

The Console’s **Agent Registry** stores agents (including “Vijil Travel Agent” and “Vijil Domed Travel Agent”) so Diamond can evaluate them. Because the travel agent runs in **`vijil-sample-agents`**, its `agent_url` should be the in-cluster URL:

- Unprotected: `http://vijil-travel-agent.vijil-sample-agents.svc.cluster.local:9000/v1`
- Domed (later): `http://vijil-domed-travel-agent.vijil-sample-agents.svc.cluster.local:9000/v1`

### 4.1 Create only the Vijil Travel Agent (what we did)

From the **vijil-console** repo:

```bash
cd /path/to/vijil-console

# Point at your dev Console API (example for dev05):
export TEAMS_SERVICE_URL="https://console-api.dev05.vijil.ai"
export BOOTSTRAP_USER_EMAIL="vijil-admin@vijil.ai"   # or your admin user
export BOOTSTRAP_USER_PASSWORD="admin"               # or your password
```

Create just this one agent pointing at the EKS service and give it a dummy API key (Diamond requires an API key field, even if the agent ignores it):

```bash
poetry run python - << 'PY'
import os, time, httpx

base_url = os.getenv("TEAMS_SERVICE_URL", "http://localhost:8000").rstrip("/")
email = os.environ["BOOTSTRAP_USER_EMAIL"]
password = os.environ["BOOTSTRAP_USER_PASSWORD"]

with httpx.Client(verify=False, timeout=30.0) as client:
    # Login
    r = client.post(f"{base_url}/auth/jwt/login", json={"email": email, "password": password})
    r.raise_for_status()
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "agent_name": "Vijil Travel Agent",
        "purpose": "Plan trips, find destinations, and provide travel recommendations using real-time search tools.",
        "model_name": "llama-3.1-70b-versatile",
        "hub": "custom",
        "protocol": "a2a",
        "rate_limit_requests_per_minute": 60,
        "access_level": "white_box",
        "status": "active",
        "agent_url": "http://vijil-travel-agent.vijil-sample-agents.svc.cluster.local:9000/v1",
        "agent_system_prompt": (
            "You are a travel assistant. Help users plan trips, find destinations, "
            "and provide travel recommendations. Be helpful and informative."
        ),
        "agent_metadata": {
            "role": "Travel Assistant",
            "job_description": "Plan trips, find destinations, and provide travel recommendations using real-time search tools.",
            "tags": ["demo", "travel", "vijil", "testing", "a2a"],
            "author": "Vijil",
            "version": "1.0.0",
        },
        "capabilities": {
            "streaming": True,
            "memory": True,
            "tools": ["search_destinations", "book_flights", "find_hotels"],
        },
        "white_box_config": {
            "repo_url": "https://github.com/vijil-ai/vijil-travel-agent",
            "entry_point": "agent/main.py",
        },
        "import_metadata": {
            "source": "manual",
            "source_url": "https://github.com/vijil-ai/vijil-travel-agent",
            "imported_at": int(time.time()),
        },
        # Diamond expects an API key field; use a dummy value if the agent ignores it.
        "api_key": "dummy",
    }

    r = client.post(f"{base_url}/agent-configurations/", json=payload, headers=headers)
    print("Status:", r.status_code)
    print("Response:", r.text[:300])
PY
```

After this, open your dev Console (e.g. `https://console.dev05.vijil.ai`) and confirm **Vijil Travel Agent** appears in the Agent Registry. You can now run Diamond evaluations against it.

### 4.2 (Alternative) Seed the full catalog

If you prefer to seed all 10 curated agents (including both travel agents) instead of just one, you can still use the existing seed script:

```bash
cd /path/to/vijil-console

export TEAMS_SERVICE_URL="https://console-api.your-dev-domain.com"
export BOOTSTRAP_USER_EMAIL="your-bootstrap-user@example.com"
export BOOTSTRAP_USER_PASSWORD="your-bootstrap-password"

poetry run python scripts/seed_agents.py
# Or update only existing agents’ URLs/model/hub:
# poetry run python scripts/seed_agents.py --update
```

- **Local dev:** If the Console is running locally and you use port-forward to the EKS API, use that URL, e.g. `export TEAMS_SERVICE_URL="http://localhost:8000"`.
- After seeding, open the **dev Vijil Console** in the browser: you should see **Vijil Travel Agent** and **Vijil Domed Travel Agent** in the Agent Registry. You can then run evaluations (Diamond) or use the demo flows against these agents.

---

## 5. Summary Checklist

- [ ] ECR repo exists; image built and pushed (`make eks-ecr-create` then `make eks-push`).
- [ ] Namespace `vijil-sample-agents` exists; secret `vijil-secrets` has `GROQ_API_KEY` (and `OPENAI_API_KEY` for domed).
- [ ] Applied `k8s/deployment-eks.yaml` (and optionally `k8s/deployment-domed-eks.yaml`).
- [ ] Pods `vijil-travel-agent` (and `vijil-domed-travel-agent`) are Running in `vijil-sample-agents`.
- [ ] (Next step) Either create **only** the Vijil Travel Agent via the one-off script in §4.1, or run `scripts/seed_agents.py` to seed the full catalog; open dev Console and confirm agents in the registry.
