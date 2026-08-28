Attack Classification API

A standalone, Kubernetes-deployed microservice version of the hybrid rule-based + LLM attack classification engine originally built for the AI-Classified Honeypot Attack Monitor project — extracted into its own independently deployable, scalable service with a full DevOps stack around it.

Architecture
Client → POST /classify → FastAPI service
                              ↓
                    Rule-based filter (free, instant)
                              ↓
                    Google Gemini API (novel cases only)
                              ↓
                    JSON response

Deployed to Kubernetes (2 replicas) with:

Prometheus scraping custom metrics from /metrics
Grafana dashboards visualizing classification patterns, method split, and latency in real time
Kubernetes Secrets for API key management (never hardcoded)
Liveness/readiness probes hitting /health
Resource requests/limits for real capacity planning
Why a standalone service, not just a script

The original honeypot project's classification logic was tightly coupled to one VM's local files. Extracting it into a REST API makes it independently deployable, horizontally scalable, and usable by any future project (or a second honeypot instance) without duplicating logic — a real microservice decomposition pattern.

What this demonstrates
Kubernetes: real Deployment/Service manifests, health probes, resource limits, horizontal scaling (2 replicas)
Observability: hand-written Prometheus metrics (Counter, Histogram) — not just consuming a dashboard, but instrumenting the application code itself
Container registries: built, tagged, and pushed a real image to Docker Hub
Infrastructure debugging: diagnosed a real issue where Docker Desktop's Kubernetes runs via a kind-based architecture with an isolated node image store, invisible to the host's local Docker images — resolved by switching to registry-based image distribution instead of fighting the local cache
Secrets management: API credentials injected via Kubernetes Secrets, not environment files or hardcoded values
API

POST /classify

json
{
  "session_id": "example-001",
  "events": [{"eventid": "cowrie.login.failed"}]
}

Returns a structured classification (attack_type, confidence, summary, notable_commands, classified_by).

GET /health — Kubernetes probe target.

GET /metrics — Prometheus-format metrics.

Local Setup
bash
docker build -t classifier-api:latest .
docker run -d -p 8000:8000 -e GEMINI_API_KEY=your_key classifier-api:latest
Kubernetes Deployment
bash
kubectl create secret generic classifier-secrets --from-literal=gemini-api-key=your_key
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/prometheus-config.yaml
kubectl apply -f k8s/prometheus-deployment.yaml
kubectl apply -f k8s/grafana-deployment.yaml
Real Results

Tested against a varied batch of simulated attack patterns (port scans, brute-force attempts, credential stuffing, and multi-command sessions involving malware download and cryptomining patterns):

Rule-based classification: near-instant (microsecond-level average latency)
LLM-based classification (genuinely novel sessions only): real API round-trip latency, reserved specifically for cases the rule engine can't confidently resolve
Classification method split visualized live in Grafana, directly reflecting the same cost-optimization strategy proven in the original honeypot project (~80% reduction in LLM API calls via rule-based pre-filtering)
