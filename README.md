
# LocalAegis-AI
### Autonomous Policy-as-Code & Self-Healing Local Cloud Infrastructure

## What It Does
A developer writes Terraform infrastructure code targeting a local cloud environment.
Before deployment, a static analyzer checks for security violations.
If a high-severity flaw is caught, a Python AI Agent intercepts the error,
refactors the Terraform code via an LLM API, validates it, and deploys it safely
onto LocalStack — logging all metrics to Grafana.

## Stack
- Local Cloud: LocalStack 3.8.1 (port 4566)
- IaC: Terraform 1.14.9
- Security Gate: Checkov 3.3.1
- Orchestrator: Python 3.13
- AI Engine: Groq API (llama-3.3-70b-versatile)
- Telemetry: Prometheus + Grafana (Minikube)

## Structure
terraform/    → Terraform manifests (scanned by Checkov)
agent/        → Python orchestration scripts
policies/     → Custom security policies
logs/         → Runtime pipeline logs
reports/      → Checkov JSON scan output

## Status
V1 INIT — Day 1
