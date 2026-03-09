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
- A **Kubernetes Secret** `vijil-secrets` in namespace `vijil-sample-agents` with at least `GROQ_API_KEY`

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
```

The agent is reachable in-cluster at `http://vijil-travel-agent.vijil-sample-agents.svc.cluster.local:9000`.

---

## 4. Register the Agent in the Dev Vijil Console (Browser)

The Console’s **Agent Registry** stores agents (e.g. “Vijil Travel Agent”) so Diamond can evaluate them. For the in-cluster agent, `agent_url` should be the in-cluster URL:

- Unprotected (in-cluster): `http://vijil-travel-agent.vijil-sample-agents.svc.cluster.local:9000/v1`
- Protected (Dome): use the Lambda + API Gateway path from §6 and register that agent URL in the Console.

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
- After seeding, open the **dev Vijil Console** in the browser: you should see **Vijil Travel Agent** in the Agent Registry. You can then run evaluations (Diamond) or use the demo flows. A Dome-protected agent can be added via the Lambda + API Gateway path (§6).

---

## 6. (Optional) Expose via API Gateway + Lambda

To expose the EKS travel agent over **public HTTPS** (e.g. for Diamond or the Console from outside the cluster), you can put an **AWS Lambda** in front of it and expose that via **API Gateway**. The Lambda can offer two routes:

- **Unprotected** — proxy requests directly to the travel agent (via the internal NLB from §3).
- **Protected** — run each request through **Dome** input/output detection, then the agent; use `VIJIL_AGENT_ID` so Dome telemetry is tied to the protected agent in the Console.

### 6.1 Prerequisites

- EKS travel agent deployed with the **internal NLB** Service (`vijil-travel-agent-nlb`) from `k8s/deployment-eks.yaml`.
- Lambda running in the **same VPC** as the NLB (or with network path to it), and an HTTP API (API Gateway v2) with routes for the two paths.

### 6.2 Lambda handler (`handler.py`)

This repo includes **`handler.py`**, a small Lambda handler (stdlib only; no extra dependencies) that:

1. **Unprotected path** (e.g. `/travel-agent/unprotected` or `/travel-agent/unprotected/v1/chat/completions`): forwards the request body to `UNPROTECTED_URL` (the NLB `http://<nlb-host>:9000/v1/chat/completions`) and returns the response.
2. **Protected path** (e.g. `/travel-agent/protected` or `/travel-agent/protected/v1/chat/completions`):  
   - Calls Dome **input_detection** (GET with `api_key`, `input_str`, `agent_id`).  
   - If Dome flags the input, returns the Dome response and does not call the agent.  
   - Otherwise calls the agent at `UNPROTECTED_URL`, then calls Dome **output_detection** (GET with `api_key`, `output_str`, `agent_id`).  
   - If Dome flags the output, returns the Dome response; otherwise returns the agent response.

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `UNPROTECTED_URL` | Yes | Full URL to the agent’s chat completions endpoint (e.g. `http://<nlb>:9000/v1/chat/completions`). |
| `DOME_URL` | Yes (protected path) | Dome base URL (e.g. `https://dome.dev05.vijil.ai`). |
| `DOME_API_KEY` | No | API key for Dome (default `abc-123`). |
| `VIJIL_AGENT_ID` | No | Agent configuration UUID in the Console; when set, Dome associates telemetry with this agent. |

Package `handler.py` (and any dependencies) into a zip, deploy as the Lambda function, and configure the API Gateway routes to invoke it for the two paths. Ensure the Lambda has outbound access to the NLB and to `DOME_URL`.

### 6.3 Registering the Lambda-backed agents in the Console

Create (or update) two agent configurations in the dev Vijil Console:

- **Unprotected via Lambda:**  
  - `agent_url`: `https://<api-gateway-host>/<stage>/travel-agent/unprotected/v1`  
  - Use this for Diamond or other tools that call the agent without Dome.

- **Protected via Dome:**  
  - `agent_url`: `https://<api-gateway-host>/<stage>/travel-agent/protected/v1`  
  - Set the Lambda env `VIJIL_AGENT_ID` to this agent’s configuration UUID so Dome telemetry (e.g. `dome_input_requests_total`) is scoped to this agent in the Console.

Use the same pattern as in §4.1 (e.g. `agent_url`, `api_key: "dummy"`, etc.) when creating these configurations via the Console API or UI.

---

## 5. Summary Checklist

- [ ] ECR repo exists; image built and pushed (`make eks-ecr-create` then `make eks-push`).
- [ ] Namespace `vijil-sample-agents` exists; secret `vijil-secrets` has `GROQ_API_KEY`.
- [ ] Applied `k8s/deployment-eks.yaml`. The manifest includes an optional internal NLB Service (`vijil-travel-agent-nlb`) for Lambda/API Gateway access.
- [ ] Pods `vijil-travel-agent` are Running in `vijil-sample-agents`.
- [ ] Either create **only** the Vijil Travel Agent via the one-off script in §4.1, or run `scripts/seed_agents.py` to seed the full catalog; open dev Console and confirm agents in the registry.
- [ ] (Optional) To expose via HTTPS: deploy the Lambda handler (`handler.py`) and API Gateway as in §6; register the unprotected and protected Lambda-backed agents in the Console and set `VIJIL_AGENT_ID` for the protected agent so Dome telemetry is scoped correctly.
